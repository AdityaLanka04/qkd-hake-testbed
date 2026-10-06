from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterator
import uuid

from qkd_hake.transfer.storage import POLICIES, validate_offer
from qkd_hake.transfer.wire import MAX_FILE_BYTES, TransferError


class FileQueue:
    """Durable file references, not plaintext/key copies. One worker per queue."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / 'queue.sqlite3'
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS jobs (
                transfer_id TEXT PRIMARY KEY, path TEXT NOT NULL, filename TEXT NOT NULL,
                bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, policy TEXT NOT NULL,
                state TEXT NOT NULL, reason TEXT NOT NULL, mode TEXT,
                attempts INTEGER NOT NULL DEFAULT 0, duration_ms REAL NOT NULL DEFAULT 0,
                created REAL NOT NULL, saved_as TEXT)''')
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, path: Path, policy: str) -> str:
        if policy not in POLICIES:
            raise TransferError('invalid_policy')
        path = path.resolve(strict=True)
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            raise TransferError('file_too_large_or_not_regular')
        with path.open('rb') as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        identifier = str(uuid.uuid4())
        record = {'transfer_id': identifier, 'filename': path.name, 'bytes': len(data),
                  'sha256': hashlib.sha256(data).hexdigest(), 'policy': policy, 'mode': 'HYBRID_QKD'}
        validate_offer(record, 'HYBRID_QKD')
        with self.connect() as db:
            db.execute('''INSERT INTO jobs
                (transfer_id,path,filename,bytes,sha256,policy,state,reason,created)
                VALUES (?,?,?,?,?,?,'QUEUED','pending',?)''',
                (identifier, str(path), path.name, len(data), record['sha256'], policy, time.time()))
        return identifier

    def get(self, identifier: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute('SELECT * FROM jobs WHERE transfer_id=?', (identifier,)).fetchone()
        if row is None:
            raise TransferError('unknown_transfer')
        return dict(row)

    def list(self, state: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            query = 'SELECT * FROM jobs' + (' WHERE state=?' if state else '') + ' ORDER BY created'
            rows = db.execute(query, (state,) if state else ()).fetchall()
        return [dict(row) for row in rows]

    def update(self, identifier: str, **fields: Any) -> None:
        allowed = {'state', 'reason', 'mode', 'attempts', 'duration_ms', 'saved_as'}
        if not fields or set(fields) - allowed:
            raise ValueError('invalid queue update')
        with self.connect() as db:
            db.execute('UPDATE jobs SET ' + ','.join(f'{key}=?' for key in fields)
                       + ' WHERE transfer_id=?', (*fields.values(), identifier))

    @contextmanager
    def worker(self) -> Iterator[None]:
        fd = os.open(self.directory / 'worker.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise TransferError('queue_worker_already_running') from exc
            # A prior process may have died after Bob saved a file but before its ACK.
            # Do not blindly retransmit those records after a restart.
            with self.connect() as db:
                db.execute("UPDATE jobs SET state='UNKNOWN', reason='interrupted_in_flight' WHERE state='SENDING'")
            yield
        finally:
            os.close(fd)
