"""Run repository commands and an actual loopback REST-backed HAKE check.

This verification harness leaves historical results untouched and records no keys.
Run with .venv/bin/python docs/architecture/run_verification.py.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output" / "verification" / "2026-10-06"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "MPLBACKEND": "Agg"}
    commands = [
        ("tests", ["make", "test"], ROOT),
        ("demo", [sys.executable, "-m", "qkd_hake.cli", "demo"], OUT),
        ("benchmark", [sys.executable, "-m", "qkd_hake.cli", "benchmark", "--runs", "1000", "--warmup-runs", "100"], OUT),
        ("sweep", [sys.executable, "-m", "qkd_hake.cli", "sweep", "--measurement-seconds", "60", "--repeats", "5", "--pool-depths", "16", "64", "128"], OUT),
        ("performance_plots", [sys.executable, "-m", "qkd_hake.benchmarks.plot_performance_figures"], OUT),
        ("starvation_plots", [sys.executable, "-m", "qkd_hake.benchmarks.plot_wp6"], OUT),
    ]
    metadata: dict = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip() if sys.platform == "darwin" else platform.processor(),
        "cpu_count": os.cpu_count(),
        "packages": {name: importlib.metadata.version(name) for name in ["liboqs-python", "fastapi", "httpx", "pytest", "pandas", "matplotlib"]},
        "cryptographic_randomness": "Native KEM randomness and secrets are unseeded; no secret values are retained in this evidence bundle.",
        "sweep_randomness": "Deterministic request schedule and virtual clock; random key bytes and UUIDs do not affect occupancy accounting.",
        "parameters": {"recorded_pairs_per_algorithm": 1000, "warmups_per_mode_per_algorithm": 100, "sweep_measurement_seconds": 60, "sweep_repeats": 5, "depths": [16,64,128]},
        "commands": [],
    }
    for name, argv, cwd in commands:
        print(f"Running {name}", flush=True)
        start = time.perf_counter()
        with (OUT / f"{name}.log").open("w") as log:
            proc = subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
        metadata["commands"].append({"name": name, "argv": argv, "cwd": str(cwd), "returncode": proc.returncode, "elapsed_seconds": time.perf_counter()-start})
        (OUT / "verification.json").write_text(json.dumps(metadata, indent=2))
        if proc.returncode:
            raise RuntimeError(f"{name} returned {proc.returncode}; see its log")
    import httpx
    import oqs
    from qkd_hake.crypto.kem import OQSKEM, SUPPORTED_ALGORITHMS
    from qkd_hake.protocol.hake import AliceSession, BobSession
    from qkd_hake.qkd_mock.client import QKDClient

    metadata["liboqs_version"] = oqs.oqs_version()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server_log = (OUT / "server.log").open("w")
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "qkd_hake.qkd_mock.server:app", "--host", "127.0.0.1", "--port", str(port)], cwd=ROOT, stdout=server_log, stderr=subprocess.STDOUT)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                if httpx.get(f"{base}/health").status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("Loopback KME did not become ready")
        ca = QKDClient(base, "alice", "bob")
        cb = QKDClient(base, "bob", "alice")

        def acquire(action: str):
            return ca.get_status() if action == "status" else ca.get_key()

        checks = []
        for alg in SUPPORTED_ALGORITHMS:
            kem = OQSKEM(alg)
            ka, kb = kem.generate_keypair(), kem.generate_keypair()
            a = AliceSession("alice", ka.public_key, ka.secret_key, "bob", kb.public_key, alg)
            b = BobSession("alice", ka.public_key, "bob", kb.public_key, kb.secret_key, alg)
            m2 = b.message2(a.message1())
            m3 = a.message3(m2, acquire, allow_explicit_fallback=False)
            tag, rb = b.message4(m3, cb.retrieve_key)
            ra = a.derive_and_verify(tag)
            assert ra.session_key == rb.session_key
            assert ra.transcript == rb.transcript
            assert ra.security_mode == rb.security_mode == "HYBRID_QKD"
            checks.append({"algorithm": alg, "key_agreement": True, "transcript_agreement": True, "mode": ra.security_mode})
        metadata["loopback_rest_handshakes"] = checks
        print("4 REST-backed handshakes passed", flush=True)
    finally:
        server.terminate()
        server.wait(timeout=10)
        server_log.close()
    metadata["csv_rows"] = {p.name: sum(1 for _ in csv.DictReader(p.open())) for p in (OUT / "results").glob("*.csv")}
    metadata["source_sha256"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "src").rglob("*.py"))}
    metadata["completed_utc"] = datetime.now(timezone.utc).isoformat()
    (OUT / "verification.json").write_text(json.dumps(metadata, indent=2))
    print(json.dumps({"completed": True, "csv_rows": metadata["csv_rows"]}), flush=True)


if __name__ == "__main__":
    main()
