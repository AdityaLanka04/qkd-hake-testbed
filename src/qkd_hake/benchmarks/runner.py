from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from pathlib import Path
import statistics
import time

from qkd_hake.protocol.combiner import derive_keys


@dataclass(frozen=True, slots=True)
class Sample:
    run: int
    wall_time_ns: int
    cpu_time_ns: int
    mode: str


def smoke_benchmark(runs: int, output: Path) -> dict[str, float]:
    """Measures only the combiner wiring; full KEM benchmarks are a later task."""
    output.parent.mkdir(parents=True, exist_ok=True)
    samples: list[Sample] = []
    for run in range(runs):
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        keys = derive_keys(
            static_kem_secret=b"s" * 32,
            ephemeral_kem_secret=b"e" * 32,
            qkd_key=b"q" * 32,
            transcript=f"smoke-{run}".encode(),
            allow_explicit_pqc_fallback=False,
        )
        cpu_elapsed = time.process_time_ns() - cpu_start
        wall_elapsed = time.perf_counter_ns() - wall_start
        samples.append(Sample(run, wall_elapsed, cpu_elapsed, keys.mode.value))

    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=asdict(samples[0]).keys())
        writer.writeheader()
        writer.writerows(asdict(sample) for sample in samples)

    ordered = sorted(sample.wall_time_ns for sample in samples)
    p95_index = max(0, int(0.95 * len(ordered)) - 1)
    return {
        "median_wall_time_ns": statistics.median(ordered),
        "p95_wall_time_ns": float(ordered[p95_index]),
    }
