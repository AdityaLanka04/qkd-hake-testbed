from __future__ import annotations

from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import random
import socket
import subprocess
import sys
import time
from typing import Any, Callable, Iterator
import uuid

import httpx

from qkd_hake.transfer.identity import provision
from qkd_hake.transfer.queue import FileQueue


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def _wait_ready(predicate: Callable[[], bool], process: subprocess.Popen, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Demo service exited; inspect its local log')
        try:
            if predicate():
                return
        except (httpx.HTTPError, OSError):
            pass
        time.sleep(.05)
    raise RuntimeError('Demo service startup timed out')


@contextmanager
def _services(root: Path, identity_dir: Path, initial: int, refill: int) -> Iterator[tuple[str, int]]:
    root.mkdir(parents=True, exist_ok=True)
    kme_port, bob_port = _port(), _port()
    while bob_port == kme_port:
        bob_port = _port()
    url = f'http://127.0.0.1:{kme_port}'
    env = {**os.environ, 'QKD_POOL_DEPTH': '8', 'QKD_INITIAL_KEYS': str(initial),
           'QKD_REFILL_BPS': str(refill), 'QKD_PER_PEER_QUOTA': '0', 'QKD_KEY_SIZE_BITS': '256'}
    children = []
    with (root / 'kme.log').open('w') as kme_log, (root / 'bob.log').open('w') as bob_log:
        try:
            kme = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'qkd_hake.qkd_mock.server:app',
                                    '--host', '127.0.0.1', '--port', str(kme_port),
                                    '--log-level', 'warning', '--no-access-log'],
                                   stdout=kme_log, stderr=subprocess.STDOUT, env=env)
            children.append(kme)
            _wait_ready(lambda: httpx.get(url + '/health', timeout=.5).status_code == 200, kme)
            bob = subprocess.Popen([sys.executable, '-m', 'qkd_hake.cli', 'transfer', 'receive',
                                    '--identity', str(identity_dir / 'bob.json'), '--port', str(bob_port),
                                    '--kme', url, '--output', str(root / 'received'),
                                    '--audit', str(root / 'bob-audit.jsonl')],
                                   stdout=bob_log, stderr=subprocess.STDOUT)
            children.append(bob)
            _wait_ready(lambda: 'Bob listening' in (root / 'bob.log').read_text(), bob)
            yield url, bob_port
        finally:
            for process in reversed(children):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _alice(root: Path, identity_dir: Path, url: str, port: int, command: list[str], label: str) -> subprocess.CompletedProcess[str]:
    args = [sys.executable, '-m', 'qkd_hake.cli', 'transfer', *command,
            '--identity', str(identity_dir / 'alice.json'), '--kme', url, '--port', str(port),
            '--queue-dir', str(root / 'queue'), '--audit', str(root / 'alice-audit.jsonl')]
    result = subprocess.run(args, capture_output=True, text=True, timeout=45)
    (root / f'{label}.log').write_text(result.stdout + result.stderr)
    (root / f'{label}-command.json').write_text(json.dumps(args, indent=2))
    return result


def _job(root: Path) -> dict[str, Any]:
    jobs = FileQueue(root / 'queue').list()
    if len(jobs) != 1:
        raise RuntimeError('Unexpected demo queue contents')
    return jobs[0]


def _verified(root: Path, job: dict[str, Any], source: Path) -> bool:
    return bool(job['saved_as']) and (root / 'received' / job['saved_as']).read_bytes() == source.read_bytes()


def verify_demo(output: Path, algorithm: str = 'ML-KEM-768') -> Path:
    """Real KME + Bob + Alice subprocesses; no simulated success results."""
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    run = output.resolve() / f'{stamp}-{uuid.uuid4().hex[:6]}'
    run.mkdir(parents=True, mode=0o700)
    identity_dir = run / 'private-identities'
    provision(identity_dir, algorithm)
    seed = 20261006
    rng = random.Random(seed)
    source = run / 'research-dataset.csv'
    source.write_text('sample,value\n' + ''.join(f'{i},{rng.random():.12f}\n' for i in range(4096)))
    rows = []
    started = time.monotonic()
    for name, initial, policy, tamper in [
        ('hybrid', 8, 'hybrid-required', False),
        ('explicit-pqc-fallback', 0, 'allow-pqc', False),
        ('tampered-ciphertext', 8, 'hybrid-required', True),
    ]:
        root = run / name
        with _services(root, identity_dir, initial, 0) as (url, port):
            result = _alice(root, identity_dir, url, port,
                            ['send', str(source), '--policy', policy] + (['--tamper'] if tamper else []), 'alice')
            job = _job(root)
            verified = _verified(root, job, source)
            expected_mode = 'PQC_ONLY' if initial == 0 else 'HYBRID_QKD'
            passed = (result.returncode == (1 if tamper else 0)
                      and job['state'] == ('FAILED' if tamper else 'DELIVERED')
                      and job['mode'] == expected_mode
                      and (not list((root / 'received').iterdir()) if tamper else verified))
            if tamper:
                passed = passed and job['reason'] == 'authentication_failed'
            rows.append({'scenario': name, 'passed': passed, 'state': job['state'], 'mode': job['mode'],
                         'reason': job['reason'], 'bytes': job['bytes'], 'attempts': job['attempts'],
                         'duration_ms': job['duration_ms'], 'identical_file': verified,
                         'alice_exit_code': result.returncode})
            print(json.dumps(rows[-1]), flush=True)
    # Slow real refill leaves time to observe the durable queue before a key appears.
    root = run / 'queued-then-refilled'
    with _services(root, identity_dir, 0, 32) as (url, port):
        initial = _alice(root, identity_dir, url, port,
                         ['send', str(source), '--policy', 'hybrid-required'], 'alice-queued')
        job = _job(root)
        empty = not list((root / 'received').iterdir())
        rows.append({'scenario': 'hybrid-required-queued', 'passed': initial.returncode == 2 and job['state'] == 'QUEUED' and empty,
                     'state': job['state'], 'mode': job['mode'], 'reason': job['reason'],
                     'bytes': job['bytes'], 'attempts': job['attempts'], 'duration_ms': job['duration_ms'],
                     'identical_file': False, 'alice_exit_code': initial.returncode})
        print(json.dumps(rows[-1]), flush=True)
        resumed = _alice(root, identity_dir, url, port,
                         ['work', '--wait', '--interval', '0.5', '--max-wait', '25'], 'alice-retried')
        job = _job(root)
        events = [json.loads(line) for line in (root / 'alice-audit.jsonl').read_text().splitlines()]
        attempts = [event['attempt_id'] for event in events if event['event'] == 'handshake_started']
        fresh = len(attempts) >= 2 and len(set(attempts)) == len(attempts)
        verified = _verified(root, job, source)
        rows.append({'scenario': 'refill-resumes-with-fresh-handshake',
                     'passed': resumed.returncode == 0 and job['state'] == 'DELIVERED' and job['mode'] == 'HYBRID_QKD' and fresh and verified,
                     'state': job['state'], 'mode': job['mode'], 'reason': job['reason'],
                     'bytes': job['bytes'], 'attempts': job['attempts'], 'duration_ms': job['duration_ms'],
                     'identical_file': verified, 'alice_exit_code': resumed.returncode})
        print(json.dumps(rows[-1]), flush=True)
    import oqs
    metadata = {'time_utc': stamp, 'platform': platform.platform(), 'machine': platform.machine(),
                'python': sys.version.split()[0], 'liboqs': oqs.oqs_version(), 'algorithm': algorithm,
                'cryptography': importlib.metadata.version('cryptography'), 'fixture_seed': seed,
                'warmup_runs': 0, 'runs_per_scenario': 1, 'purpose': 'functional verification, not a performance benchmark',
                'fixture_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'total_seconds': round(time.monotonic() - started, 3),
                'all_passed': all(row['passed'] for row in rows), 'results': rows}
    (run / 'results.json').write_text(json.dumps(metadata, indent=2) + '\n')
    with (run / 'results.csv').open('w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    freeze = subprocess.run([sys.executable, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True)
    (run / 'requirements-freeze.txt').write_text(freeze.stdout)
    lines = ['# File-transfer verification', '', f'Algorithm: {algorithm}; liboqs {metadata["liboqs"]}; '
             f'cryptography {metadata["cryptography"]}.', '',
             'Separate Alice, Bob and mock KME processes communicated over localhost TCP and HTTP.', '',
             '| Scenario | Result | State | Mode | Attempts | File verified |',
             '|---|---|---|---|---:|---|']
    for row in rows:
        lines.append(f'| {row["scenario"]} | {"PASS" if row["passed"] else "FAIL"} | {row["state"]} | '
                     f'{row["mode"] or "none"} | {row["attempts"]} | {row["identical_file"]} |')
    lines += ['', 'The queued case intentionally returns exit code 2; the tampered case intentionally returns 1.',
              'No received file was published for either case before successful verification.',
              'All successful files were compared byte-for-byte with the source. Each retry used a fresh HAKE nonce.',
              'Fixture randomness is reproducible; cryptographic randomness is deliberately unseeded.',
              'One functional run per scenario, no warm-up; durations are observations, not benchmark estimates.', '',
              'Audit logs contain modes, policy reasons, sizes and durations, never key material.',
              'Private provisioning files are under private-identities/ with mode 0600; do not include them in a report bundle.',
              '', 'See results.json for environment and raw results; scenario directories contain commands and both terminal logs.']
    (run / 'REPORT.md').write_text('\n'.join(lines) + '\n')
    print(f'Verification report: {run / "REPORT.md"}', flush=True)
    if not metadata['all_passed']:
        raise RuntimeError('A functional scenario failed; inspect results.json')
    return run
