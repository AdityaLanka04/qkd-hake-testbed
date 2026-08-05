from __future__ import annotations

import argparse
import base64
from pathlib import Path

import uvicorn

from qkd_hake.benchmarks.runner import smoke_benchmark
from qkd_hake.benchmarks.suite import run_performance_benchmarks, sweep_bottleneck_analysis
from qkd_hake.qkd_mock.pool import QKDKeyPool


def demo() -> None:
    pool = QKDKeyPool(
        refill_bps=10_000,
        depth=8,
        initial_keys=2,
        key_size_bits=256,
    )
    alice_key = pool.issue("alice", "bob")[0]
    bob_key = pool.retrieve("alice", "bob", [alice_key.key_id])[0]
    assert alice_key.key == bob_key.key
    print(f"QKD key ID: {alice_key.key_id}")
    print(f"Both SAEs received the same 256-bit key: {alice_key.key == bob_key.key}")
    print(f"Encoded key length: {len(base64.b64encode(alice_key.key))} bytes")
    summary = smoke_benchmark(20, Path("results/smoke.csv"))
    print(f"Smoke benchmark: {summary}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid QKD-PQC HAKE testbed")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("server", help="run the mock ETSI QKD 014 KME")
    subparsers.add_parser("demo", help="run a local smoke demo")
    
    benchmark_parser = subparsers.add_parser("benchmark", help="run the full performance benchmark")
    benchmark_parser.add_argument("--runs", type=int, default=1000, help="number of benchmark runs")
    
    subparsers.add_parser("sweep", help="run the rate vs supply bottleneck sweep analysis")
    
    args = parser.parse_args()
    if args.command == "server":
        uvicorn.run("qkd_hake.qkd_mock.server:app", host="127.0.0.1", port=8000)
    elif args.command == "demo":
        demo()
    elif args.command == "benchmark":
        run_performance_benchmarks(runs=args.runs)
    elif args.command == "sweep":
        sweep_bottleneck_analysis()


if __name__ == "__main__":
    main()

