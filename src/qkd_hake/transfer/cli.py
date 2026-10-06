from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from qkd_hake.crypto.kem import SUPPORTED_ALGORITHMS
from qkd_hake.qkd_mock.client import QKDClient
from qkd_hake.transfer.audit import Audit
from qkd_hake.transfer.identity import Identity, provision
from qkd_hake.transfer.queue import FileQueue
from qkd_hake.transfer.receiver import Receiver
from qkd_hake.transfer.sender import Sender, pool_status
from qkd_hake.transfer.storage import POLICIES
from qkd_hake.transfer.wire import TransferError


def configure(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser('transfer', help='policy-aware encrypted file transfer')
    commands = parser.add_subparsers(dest='transfer_command', required=True)
    init = commands.add_parser('init', help='provision pinned local Alice/Bob identities')
    init.add_argument('--directory', type=Path, default=Path('transfer-demo/identities'))
    init.add_argument('--algorithm', choices=SUPPORTED_ALGORITHMS, default='ML-KEM-768')
    receive = commands.add_parser('receive', help='start Bob in a separate terminal')
    receive.add_argument('--identity', type=Path, default=Path('transfer-demo/identities/bob.json'))
    receive.add_argument('--port', type=int, default=9000)
    receive.add_argument('--kme', default='http://127.0.0.1:8000')
    receive.add_argument('--output', type=Path, default=Path('transfer-demo/received'))
    receive.add_argument('--audit', type=Path, default=Path('transfer-demo/bob-audit.jsonl'))
    for command in ('send', 'enqueue', 'work', 'queue'):
        child = commands.add_parser(command)
        child.add_argument('--queue-dir', type=Path, default=Path('transfer-demo/queue'))
        if command in ('send', 'enqueue'):
            child.add_argument('file', type=Path)
            child.add_argument('--policy', choices=POLICIES, default='hybrid-required')
        if command in ('send', 'work'):
            child.add_argument('--identity', type=Path, default=Path('transfer-demo/identities/alice.json'))
            child.add_argument('--kme', default='http://127.0.0.1:8000')
            child.add_argument('--port', type=int, default=9000)
            child.add_argument('--audit', type=Path, default=Path('transfer-demo/alice-audit.jsonl'))
            child.add_argument('--wait', action='store_true', help='retry queued jobs with fresh handshakes')
            child.add_argument('--interval', type=float, default=1)
            child.add_argument('--max-wait', type=float, default=60)
            child.add_argument('--rate-limit', type=float, default=10)
            child.add_argument('--tamper', action='store_true', help='negative test: flip one encrypted byte')
    status = commands.add_parser('status', help='live QKD pool occupancy')
    status.add_argument('--kme', default='http://127.0.0.1:8000')
    status.add_argument('--watch', action='store_true')
    status.add_argument('--interval', type=float, default=1)
    status.add_argument('--count', type=int, default=0, help='0 means unlimited watch')
    verify = commands.add_parser('verify-demo', help='run all five scenarios with separate real processes')
    verify.add_argument('--output', type=Path, default=Path('output/file-transfer'))
    verify.add_argument('--algorithm', choices=SUPPORTED_ALGORITHMS, default='ML-KEM-768')


def run(args: argparse.Namespace) -> int:
    command = args.transfer_command
    if command == 'init':
        provision(args.directory, args.algorithm)
        print(f'Provisioned Alice and Bob in {args.directory}; algorithm={args.algorithm}', flush=True)
        return 0
    if command == 'receive':
        identity = Identity.load(args.identity, 'bob')
        audit = Audit(args.audit, 'bob')
        with Receiver(('127.0.0.1', args.port), identity, args.kme, args.output, audit) as server:
            print(f'Bob listening on 127.0.0.1:{server.server_address[1]} | output={args.output}', flush=True)
            try:
                server.serve_forever(poll_interval=.2)
            except KeyboardInterrupt:
                pass
        return 0
    if command == 'status':
        if args.interval <= 0 or args.count < 0:
            raise ValueError('invalid status interval or count')
        kme = QKDClient(args.kme)
        count = 0
        while True:
            print(json.dumps(pool_status(kme)), flush=True)
            count += 1
            if not args.watch or (args.count and count >= args.count):
                return 0
            time.sleep(args.interval)
    if command == 'verify-demo':
        from qkd_hake.transfer.verification import verify_demo
        verify_demo(args.output, args.algorithm)
        return 0
    queue = FileQueue(args.queue_dir)
    if command == 'queue':
        for job in queue.list():
            print(json.dumps({k: job[k] for k in ('transfer_id', 'filename', 'bytes', 'policy', 'state',
                                                'mode', 'reason', 'attempts', 'duration_ms')}, sort_keys=True))
        return 0
    identifier = None
    if command in ('send', 'enqueue'):
        identifier = queue.enqueue(args.file, args.policy)
        print(f'QUEUED {identifier} | {args.file.name} | {args.policy}', flush=True)
    if command == 'enqueue':
        return 0
    if args.rate_limit < 0:
        raise ValueError('rate limit must be nonnegative')
    sender = Sender(Identity.load(args.identity, 'alice'), args.kme, ('127.0.0.1', args.port),
                    queue, Audit(args.audit, 'alice'), args.rate_limit)
    jobs = sender.run(watch=args.wait, interval=args.interval, max_wait=args.max_wait,
                      identifier=identifier, tamper=args.tamper)
    if any(job['state'] in ('FAILED', 'UNKNOWN') for job in jobs):
        return 1
    return 2 if any(job['state'] == 'QUEUED' for job in jobs) else 0
