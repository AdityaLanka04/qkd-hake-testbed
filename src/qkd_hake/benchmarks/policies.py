"""Paired resource-policy experiments; no network or KEM latency is simulated.

Virtual arrival times drive the production pool and mitigation checks. Real
perf/process timers measure local decision costs, excluding CSV output. Keys
are retrieved immediately and discarded; output never contains key material.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time
from typing import Callable

from qkd_hake.benchmarks.suite import SimulatedClock, np_percentile
from qkd_hake.mitigations.mitigations import (
    AdmissionControlError, MitigationManager, QuotaExceededError,
)
from qkd_hake.qkd_mock.pool import PoolExhausted, QKDKeyPool


POLICIES = ('reject_on_empty', 'explicit_downgrade', 'per_peer_quota', 'admission_control')
WORKLOADS = ('balanced', 'skewed')
DESCRIPTIONS = {
    'reject_on_empty': 'Control: attempt QKD; reject if unavailable.',
    'explicit_downgrade': 'Attempt QKD; explicitly select PQC_ONLY if unavailable.',
    'per_peer_quota': 'Sliding 1-second request quota per peer; reject on quota or empty pool.',
    'admission_control': 'Reject below 5% occupancy or on empty pool; no fallback.',
}


@dataclass(frozen=True)
class PolicyConfig:
    measurement_seconds: float = 60
    warmup_seconds: float = 10
    repeats: int = 3
    pool_depths: tuple[int, ...] = (128,)
    rates: tuple[int, ...] = (1, 5, 10, 20, 50, 100)
    supplies_kbps: tuple[int, ...] = (1, 10, 100)
    quota_per_second: int = 10
    seed: int = 20261008
    workloads: tuple[str, ...] = WORKLOADS

    def validate(self) -> None:
        if (not math.isfinite(self.measurement_seconds) or self.measurement_seconds <= 0
                or not math.isfinite(self.warmup_seconds) or self.warmup_seconds < 0
                or self.repeats < 1 or self.quota_per_second < 1):
            raise ValueError('invalid duration, repeats, or quota')
        for values in (self.pool_depths, self.rates, self.supplies_kbps):
            if not values or any(type(value) is not int or value <= 0 for value in values):
                raise ValueError('depths, rates and supplies must be positive integers')
        if not self.workloads or any(name not in WORKLOADS for name in self.workloads):
            raise ValueError('invalid workloads')


@dataclass(frozen=True)
class Decision:
    mode: str
    reason: str
    policy_wall_ns: int
    policy_cpu_ns: int
    decision_wall_ns: int
    decision_cpu_ns: int
    remaining_keys: int


def decide(policy: str, peer: str, pool: QKDKeyPool, manager: MitigationManager) -> Decision:
    """One modeled request. Exceptions other than resource failures propagate."""
    if policy not in POLICIES:
        raise ValueError('unknown policy')
    wall = time.perf_counter_ns()
    cpu = time.process_time_ns()
    reason = ''
    try:
        if policy == 'per_peer_quota':
            manager.check_quota(peer)
        elif policy == 'admission_control':
            status = pool.status()
            manager.check_admission_control(status['stored_key_count'], status['max_key_count'])
    except QuotaExceededError:
        reason = 'request_quota_exceeded'
    except AdmissionControlError:
        reason = 'reserve_below_5_percent'
    policy_cpu = time.process_time_ns() - cpu
    policy_wall = time.perf_counter_ns() - wall
    mode = 'REJECTED'
    if not reason:
        try:
            delivered = pool.issue(peer, 'bob')[0]
        except PoolExhausted:
            reason = 'pool_exhausted'
            if policy == 'explicit_downgrade':
                mode = 'PQC_ONLY'
        else:
            # A successful modeled handshake consumes one key, with no pending
            # partner retrieval. This prevents issued-key memory accumulating.
            pool.retrieve(peer, 'bob', [delivered.key_id])
            mode, reason = 'HYBRID_QKD', 'qkd_available'
    decision_cpu = time.process_time_ns() - cpu
    decision_wall = time.perf_counter_ns() - wall
    return Decision(mode, reason, policy_wall, policy_cpu, decision_wall,
                    decision_cpu, pool.status()['stored_key_count'])


def peer_schedule(count: int, workload: str, seed: int) -> list[str]:
    """Periodic aggregate arrivals; seeded peer selection, not seeded crypto."""
    if workload not in WORKLOADS:
        raise ValueError('unknown workload')
    weights = (1, 1, 1, 1) if workload == 'balanced' else (7, 1, 1, 1)
    return random.Random(seed).choices(('peer0', 'peer1', 'peer2', 'peer3'), weights=weights, k=count)


def jain_index(values: list[float]) -> float | None:
    """Fairness of per-peer hybrid service fractions, not unequal raw demand."""
    denominator = len(values) * sum(value * value for value in values)
    return sum(values) ** 2 / denominator if denominator else None


def run_case(config: PolicyConfig, *, policy: str, supply: int, rate: int,
             depth: int, workload: str, repeat: int, schedule_seed: int,
             emit: Callable[[dict], None]) -> tuple[dict, list[dict]]:
    clock = SimulatedClock()
    pool = QKDKeyPool(refill_bps=supply * 1000, depth=depth, initial_keys=0, clock=clock)
    manager = MitigationManager(config.quota_per_second, clock=clock)
    warmup_count = int(config.warmup_seconds * rate)
    count = max(1, int(config.measurement_seconds * rate))
    peers = peer_schedule(warmup_count + count, workload, schedule_seed)
    base = dict(policy=policy, supply_kbps=supply, request_rate=rate, pool_depth=depth,
                workload=workload, repeat=repeat, schedule_seed=schedule_seed)
    modes: Counter[str] = Counter()
    peer_modes: dict[str, Counter] = defaultdict(Counter)
    timings: dict[str, list[int]] = defaultdict(list)
    occupancy: list[int] = []
    reasons: Counter[str] = Counter()
    start_occupancy = 0
    for index, peer in enumerate(peers):
        # Set from index rather than accumulating floating point deltas.
        clock.current_time = (index + 1) / rate
        if index == warmup_count:
            start_occupancy = pool.status()['stored_key_count']
        decision = decide(policy, peer, pool, manager)
        if index < warmup_count:
            continue
        event = asdict(decision)
        emit({**base, 'request_index': index - warmup_count + 1,
              'simulation_time_s': clock(), 'peer': peer, **event})
        modes[decision.mode] += 1
        peer_modes[peer][decision.mode] += 1
        reasons[decision.reason] += 1
        occupancy.append(decision.remaining_keys)
        for name in ('policy_wall_ns', 'policy_cpu_ns', 'decision_wall_ns', 'decision_cpu_ns'):
            timings[name].append(event[name])
    peer_rows = []
    for peer, counts in sorted(peer_modes.items()):
        attempts = sum(counts.values())
        peer_rows.append({**base, 'peer': peer, 'attempts': attempts,
                          'hybrid': counts['HYBRID_QKD'], 'pqc_only': counts['PQC_ONLY'],
                          'rejected': counts['REJECTED'],
                          'hybrid_fraction': counts['HYBRID_QKD'] / attempts})
    summary = {**base, 'attempts': count, 'measurement_seconds_actual': count / rate,
               'warmup_attempts': warmup_count, 'initial_keys': 0,
               'measurement_start_keys': start_occupancy,
               'hybrid': modes['HYBRID_QKD'], 'pqc_only': modes['PQC_ONLY'],
               'rejected': modes['REJECTED'], 'qkd_keys_consumed': modes['HYBRID_QKD'],
               'hybrid_pct': 100 * modes['HYBRID_QKD'] / count,
               'pqc_only_pct': 100 * modes['PQC_ONLY'] / count,
               'rejected_pct': 100 * modes['REJECTED'] / count,
               'modeled_completion_pct': 100 * (count - modes['REJECTED']) / count,
               'hybrid_per_second': modes['HYBRID_QKD'] * rate / count,
               'quota_rejections': reasons['request_quota_exceeded'],
               'reserve_rejections': reasons['reserve_below_5_percent'],
               'empty_pool_decisions': reasons['pool_exhausted'],
               'final_keys': occupancy[-1], 'minimum_keys': min(occupancy),
               'mean_keys': statistics.mean(occupancy),
               'hybrid_service_fraction_jain': jain_index([row['hybrid_fraction'] for row in peer_rows])}
    for name, values in timings.items():
        summary[name + '_median'] = statistics.median(values)
        summary[name + '_p95'] = np_percentile(values, 95)
    return summary, peer_rows


def write_rows(path: Path, rows: list[dict]) -> None:
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_policy_comparison(output: Path, config: PolicyConfig = PolicyConfig()) -> Path:
    config.validate()
    # Unique, exclusive directory: previous measurements cannot be overwritten.
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    summaries: list[dict] = []
    peers: list[dict] = []
    with (output / 'policy_events.csv').open('w', newline='') as stream:
        writer = None
        def emit(row: dict) -> None:
            nonlocal writer
            if writer is None:
                writer = csv.DictWriter(stream, fieldnames=list(row))
                writer.writeheader()
            writer.writerow(row)
        for supply in config.supplies_kbps:
            for rate in config.rates:
                for depth in config.pool_depths:
                    for workload in config.workloads:
                        for repeat in range(1, config.repeats + 1):
                            schedule_seed = config.seed + repeat
                            # Rotate policy order across repeats to reduce timing order bias.
                            order = POLICIES[repeat % len(POLICIES):] + POLICIES[:repeat % len(POLICIES)]
                            for policy in order:
                                summary, peer_rows = run_case(
                                    config, policy=policy, supply=supply, rate=rate, depth=depth,
                                    workload=workload, repeat=repeat, schedule_seed=schedule_seed, emit=emit)
                                summaries.append(summary)
                                peers.extend(peer_rows)
    write_rows(output / 'policy_summary.csv', summaries)
    write_rows(output / 'policy_peers.csv', peers)
    sources = Path(__file__).resolve().parents[1]
    try:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=sources,
                                           text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = None
    metadata = {
        'started_utc': started, 'completed_utc': datetime.now(timezone.utc).isoformat(),
        'python': sys.version, 'platform': platform.platform(), 'machine': platform.machine(),
        'processor': platform.processor(), 'revision': revision, 'config': asdict(config),
        'policies': DESCRIPTIONS, 'cases': len(summaries),
        'measurement_scope': 'Virtual-time pool/policy model; no KEM, REST, TCP, queue, file transfer or network latency.',
        'timing_scope': 'Real local guard and decision timings; includes timer overhead; excludes CSV and post-decision occupancy observation. Admission guard includes pool.status. Decision includes issue/retrieve and random key/UUID generation on hybrid success.',
        'warmup': 'Each policy starts empty; warmup advances state but emits no measured rows. Warmup does not prove stationarity for every quota/reserve configuration.',
        'workloads': 'Aggregate periodic arrivals; seeded categorical peer choice. balanced weights 1:1:1:1; skewed 7:1:1:1. Same sequence for every policy in a case.',
        'randomness': 'Only workload assignment is seeded; secrets.token_bytes and UUIDs remain unseeded. No secret material is recorded.',
        'fairness': 'Jain index of per-peer HYBRID/attempt fractions, omitting peers with zero offered requests. Blank when all fractions are zero.',
        'assumptions': 'Immediate partner retrieval; no pending-key quota; all modeled PQC fallbacks complete; strict policies reject rather than queue. Quota counts admitted quota checks even if pool later empty. No hybrid admission floor in the quota-only arm.',
        'source_sha256': {str(p.relative_to(sources)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(sources.rglob('*.py'))},
        'packages': {name: importlib.metadata.version(name) for name in ('fastapi', 'httpx', 'cryptography')},
    }
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(f'Policy comparison: {len(summaries)} cases; raw events, summaries, peers and metadata in {output}')
    return output
