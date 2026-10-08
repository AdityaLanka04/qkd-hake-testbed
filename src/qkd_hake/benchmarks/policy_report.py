"""Generate tables and figures from recorded policy CSVs, without rerunning them."""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from html import escape
import json
from pathlib import Path
import statistics

from qkd_hake.benchmarks.policies import POLICIES
from qkd_hake.benchmarks.suite import np_percentile


def build_report(directory: Path) -> Path:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    metadata = json.loads((directory / 'metadata.json').read_text())
    with (directory / 'policy_summary.csv').open() as stream:
        rows = list(csv.DictReader(stream))
    groups: dict[tuple, list[dict]] = defaultdict(list)
    columns = ('supply_kbps', 'request_rate', 'pool_depth', 'workload', 'policy')
    for row in rows:
        groups[tuple(row[key] for key in columns)].append(row)
    # Pool event timings, never average percentiles from different repeats.
    timings: dict[tuple, list[int]] = defaultdict(list)
    with (directory / 'policy_events.csv').open() as stream:
        for row in csv.DictReader(stream):
            group = tuple(row[key] for key in columns)
            timings[group].append(int(row['policy_wall_ns']))
    aggregate = []
    for group, cases in sorted(groups.items()):
        total = sum(int(row['attempts']) for row in cases)
        record = dict(zip(columns, group))
        record['attempts'] = total
        for name in ('hybrid', 'pqc_only', 'rejected'):
            record[name + '_pct'] = 100 * sum(int(row[name]) for row in cases) / total
        record['mean_remaining_keys'] = statistics.mean(float(row['mean_keys']) for row in cases)
        fairness = [float(row['hybrid_service_fraction_jain']) for row in cases
                    if row['hybrid_service_fraction_jain']]
        record['mean_jain'] = statistics.mean(fairness) if fairness else None
        record['guard_median_us'] = statistics.median(timings[group]) / 1000
        record['guard_p95_us'] = np_percentile(timings[group], 95) / 1000
        aggregate.append(record)
    with (directory / 'policy_aggregate.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(aggregate[0]))
        writer.writeheader()
        writer.writerows(aggregate)

    max_rate = max(int(row['request_rate']) for row in aggregate)
    max_depth = max(int(row['pool_depth']) for row in aggregate)
    supplies = sorted({int(row['supply_kbps']) for row in aggregate})
    workloads = sorted({row['workload'] for row in aggregate})
    selected = [row for row in aggregate if int(row['request_rate']) == max_rate
                and int(row['pool_depth']) == max_depth]
    fig, axes = plt.subplots(len(workloads), len(supplies), squeeze=False,
                             figsize=(5 * len(supplies), 3.7 * len(workloads)), sharey=True)
    labels = ['Empty-pool\ncontrol', 'Explicit\nfallback', 'Peer\nquota', '5% admission\nthreshold']
    for i, workload in enumerate(workloads):
        for j, supply in enumerate(supplies):
            ax = axes[i][j]
            cells = {row['policy']: row for row in selected
                     if row['workload'] == workload and int(row['supply_kbps']) == supply}
            bottom = [0.0] * len(POLICIES)
            for name, color in [('hybrid', '#267b70'), ('pqc_only', '#e7ad52'), ('rejected', '#ba5358')]:
                values = [cells[policy][name + '_pct'] for policy in POLICIES]
                ax.bar(labels, values, bottom=bottom, color=color, label=name.replace('_', ' '))
                bottom = [a + b for a, b in zip(bottom, values)]
            ax.set_title(f'{supply} kbps · {workload} peers')
            ax.set_ylim(0, 100)
            ax.set_ylabel('Offered requests (%)')
    handles, legend_labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, legend_labels, loc='lower center', ncol=3)
    fig.suptitle(f'Policy outcomes: {max_rate} requests/s, pool depth {max_depth}\nVirtual-time model; means across paired seeded repeats')
    fig.tight_layout(rect=(0, .05, 1, .92))
    fig.savefig(directory / 'policy_outcomes.png', dpi=180)
    plt.close(fig)

    html_rows = []
    for row in aggregate:
        cells = [str(row[key]) for key in columns]
        cells += [f'{row[key]:.2f}' for key in ('hybrid_pct', 'pqc_only_pct', 'rejected_pct', 'mean_remaining_keys')]
        cells += ['—' if row['mean_jain'] is None else f"{row['mean_jain']:.3f}"]
        cells += [f'{row[key]:.3f}' for key in ('guard_median_us', 'guard_p95_us')]
        html_rows.append('<tr>' + ''.join('<td>' + escape(cell) + '</td>' for cell in cells) + '</tr>')
    headings = ['Supply kbps', 'Requests/s', 'Depth', 'Workload', 'Policy', 'Hybrid %', 'PQC %',
                'Rejected %', 'Mean keys', 'Mean Jain', 'Guard median µs', 'Guard p95 µs']
    report = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>Policy comparison</title>
<style>body{font:16px/1.6 system-ui;margin:40px;color:#19313b}table{border-collapse:collapse;font-size:13px}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:right}th{position:sticky;top:0;background:#edf3f5}img{width:100%;max-width:1500px}a{color:#165f91}</style>
<h1>QKD policy comparison</h1><p>Recorded pool and policy experiment. Every number below is derived from the adjacent CSV files.</p>
<p><b>Interpretation:</b> fallback preserves modeled completion by accepting PQC_ONLY. Strict quota and admission policies trade availability for resource control. A quota can leave QKD capacity unused when demand is concentrated on one peer. A 5% check is a pre-request threshold, not an atomic guarantee that 5% remains after consumption.</p>
<p><b>Timing:</b> guard times are measured local Python execution, including timer overhead. They are not handshake or network latencies. Outcome mixtures differ between policies. Use policy_events.csv to inspect each outcome; do not call the difference a cryptographic speedup.</p>
<p><b>Fairness:</b> Jain index compares per-peer hybrid success fractions, averaged across repeats here. 1 means equal fractions; blank means no hybrid service. Equal absolute throughput under unequal demand can lower this index.</p>
<p><b>Scope:</b> starts empty; warmup excluded, with state retained. Seeded peer assignment; four peers; 70%/10%/10%/10% expected demand in skewed workloads. Immediate key retrieval. No measured KEM, network, queuing or transport costs. Model completion assumes all allowed PQC handshakes would succeed.</p>
<p><a href="metadata.json">Exact configuration, source hashes and host</a> · <a href="policy_events.csv">Raw requests</a> · <a href="policy_summary.csv">Per-repeat summaries</a> · <a href="policy_peers.csv">Peer outcomes</a> · <a href="policy_aggregate.csv">Aggregate table</a></p>
<img src="policy_outcomes.png" alt="Stacked bars showing hybrid, fallback and rejected requests by policy, supply and workload">
<h2>All configurations</h2><table><thead><tr>'''
    html = report + ''.join('<th>' + escape(name) + '</th>' for name in headings)
    html += '</tr></thead><tbody>' + ''.join(html_rows) + '</tbody></table>'
    html += '<p>Recorded at ' + escape(metadata['completed_utc']) + '.</p></html>'
    path = directory / 'report.html'
    path.write_text(html)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(build_report(parser.parse_args().directory))


if __name__ == '__main__':
    main()
