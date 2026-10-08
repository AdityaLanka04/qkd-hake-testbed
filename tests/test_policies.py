import csv
import json

import pytest

from qkd_hake.benchmarks.policies import (
    POLICIES, PolicyConfig, decide, jain_index, peer_schedule, run_case, run_policy_comparison,
)
from qkd_hake.benchmarks.suite import SimulatedClock
from qkd_hake.mitigations.mitigations import MitigationManager, QuotaExceededError
from qkd_hake.qkd_mock.pool import QKDKeyPool


def test_quota_clock_and_exact_window_boundary():
    clock = SimulatedClock()
    manager = MitigationManager(1, clock=clock)
    manager.check_quota('alice')
    clock.current_time = .999
    with pytest.raises(QuotaExceededError):
        manager.check_quota('alice')
    manager.check_quota('carol')  # independent peer
    clock.current_time = 1
    manager.check_quota('alice')


@pytest.mark.parametrize('policy', POLICIES)
def test_explicit_modes_and_accounting(policy):
    clock = SimulatedClock()
    pool = QKDKeyPool(refill_bps=0, depth=8, initial_keys=1, clock=clock)
    manager = MitigationManager(1, clock=clock)
    assert decide(policy, 'alice', pool, manager).mode == 'HYBRID_QKD'
    assert not pool._issued and not pool._outstanding
    result = decide(policy, 'alice', pool, manager)
    assert result.mode == ('PQC_ONLY' if policy == 'explicit_downgrade' else 'REJECTED')
    assert result.remaining_keys == 0


def test_admission_boundary_and_quota_are_separate_policies():
    manager = MitigationManager(1)
    exact = QKDKeyPool(refill_bps=0, depth=20, initial_keys=1)
    assert decide('admission_control', 'alice', exact, manager).mode == 'HYBRID_QKD'
    below = QKDKeyPool(refill_bps=0, depth=100, initial_keys=4)
    assert decide('admission_control', 'alice', below, manager).reason == 'reserve_below_5_percent'
    assert decide('per_peer_quota', 'alice', below, manager).mode == 'HYBRID_QKD'
    assert decide('per_peer_quota', 'alice', below, manager).reason == 'request_quota_exceeded'
    assert below.status()['stored_key_count'] == 3


def test_paired_schedules_and_resource_conservation():
    config = PolicyConfig(measurement_seconds=2, warmup_seconds=0, quota_per_second=1)
    schedules = []
    for policy in POLICIES:
        events = []
        summary, peers = run_case(config, policy=policy, supply=1, rate=20, depth=8,
                                  workload='skewed', repeat=1, schedule_seed=7, emit=events.append)
        schedules.append([(row['simulation_time_s'], row['peer']) for row in events])
        assert summary['attempts'] == len(events) == 40
        assert summary['hybrid'] + summary['pqc_only'] + summary['rejected'] == 40
        assert summary['hybrid'] <= 2000 // 256
        assert summary['hybrid'] == sum(row['hybrid'] for row in peers)
        assert summary['qkd_keys_consumed'] == summary['hybrid']
        assert all(0 <= row['remaining_keys'] <= 8 for row in events)
        if policy == 'explicit_downgrade':
            assert summary['rejected'] == 0
        else:
            assert summary['pqc_only'] == 0
    assert all(schedule == schedules[0] for schedule in schedules)


def test_quota_cost_under_abundant_supply():
    config = PolicyConfig(measurement_seconds=3, warmup_seconds=1, quota_per_second=1)
    counts = {}
    for policy in ('reject_on_empty', 'per_peer_quota'):
        summary, _ = run_case(config, policy=policy, supply=100, rate=20, depth=8,
                              workload='skewed', repeat=1, schedule_seed=3, emit=lambda _: None)
        counts[policy] = summary
    assert counts['reject_on_empty']['hybrid'] == 60
    assert counts['per_peer_quota']['quota_rejections'] > 0
    assert counts['per_peer_quota']['hybrid'] < 60


def test_raw_csv_metadata_warmup_and_no_overwrite(tmp_path):
    config = PolicyConfig(measurement_seconds=1, warmup_seconds=1, repeats=1,
                          pool_depths=(8,), rates=(5,), supplies_kbps=(1,), workloads=('balanced',))
    output = tmp_path / 'result'
    run_policy_comparison(output, config)
    events = list(csv.DictReader((output / 'policy_events.csv').open()))
    summaries = list(csv.DictReader((output / 'policy_summary.csv').open()))
    assert len(events) == 20 and len(summaries) == 4
    assert all(float(row['simulation_time_s']) > 1 for row in events)
    assert all(int(row['warmup_attempts']) == 5 for row in summaries)
    assert all(int(row['decision_wall_ns']) >= int(row['policy_wall_ns']) >= 0 for row in events)
    metadata = json.loads((output / 'metadata.json').read_text())
    assert metadata['config']['seed'] == config.seed and metadata['source_sha256']
    assert not {'key', 'key_id', 'session_key', 'secret_key'} & set(events[0])
    with pytest.raises(FileExistsError):
        run_policy_comparison(output, config)


def test_workload_reproducibility_and_fairness_definition():
    assert peer_schedule(100, 'skewed', 7) == peer_schedule(100, 'skewed', 7)
    assert peer_schedule(100, 'skewed', 7) != peer_schedule(100, 'skewed', 8)
    assert jain_index([.5, .5]) == 1
    assert jain_index([1, 0]) == .5
    assert jain_index([0, 0]) is None


@pytest.mark.parametrize('kwargs', [{'measurement_seconds': 0}, {'warmup_seconds': -1},
                                   {'repeats': 0}, {'pool_depths': ()}, {'quota_per_second': 0}])
def test_invalid_configuration(kwargs):
    with pytest.raises(ValueError):
        PolicyConfig(**kwargs).validate()


def test_report_aggregates_raw_counts_and_guard_percentiles(tmp_path):
    pytest.importorskip('matplotlib')
    from qkd_hake.benchmarks.policy_report import build_report
    from qkd_hake.benchmarks.suite import np_percentile
    import statistics

    config = PolicyConfig(measurement_seconds=1, warmup_seconds=0, repeats=2,
                          pool_depths=(8,), rates=(5,), supplies_kbps=(1,), workloads=('balanced',))
    output = tmp_path / 'result'
    run_policy_comparison(output, config)
    report = build_report(output)
    with (output / 'policy_events.csv').open() as stream:
        events = list(csv.DictReader(stream))
    with (output / 'policy_aggregate.csv').open() as stream:
        aggregate = list(csv.DictReader(stream))
    assert len(aggregate) == 4
    for row in aggregate:
        selected = [event for event in events if event['policy'] == row['policy']]
        times = [int(event['policy_wall_ns']) for event in selected]
        assert int(row['attempts']) == len(selected) == 10
        assert float(row['guard_median_us']) == statistics.median(times) / 1000
        assert float(row['guard_p95_us']) == np_percentile(times, 95) / 1000
        for field, mode in [('hybrid', 'HYBRID_QKD'), ('pqc_only', 'PQC_ONLY'), ('rejected', 'REJECTED')]:
            assert float(row[field + '_pct']) == 100 * sum(event['mode'] == mode for event in selected) / len(selected)
    assert (output / 'policy_outcomes.png').read_bytes().startswith(b'\x89PNG')
    assert 'not handshake or network latencies' in report.read_text()
