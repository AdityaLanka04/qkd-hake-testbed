from __future__ import annotations

import hashlib
import json
from pathlib import Path
import socket
import time
from typing import Any

import httpx

from qkd_hake.mitigations.mitigations import MitigationManager
from qkd_hake.protocol.hake import HandshakeError, QKDUnavailableError
from qkd_hake.qkd_mock.client import QKDClient
from qkd_hake.transfer.audit import Audit
from qkd_hake.transfer.channel import SecureChannel
from qkd_hake.transfer.handshake import client_handshake, mode_label
from qkd_hake.transfer.identity import Identity
from qkd_hake.transfer.queue import FileQueue
from qkd_hake.transfer.wire import (MAX_FILE_BYTES, TransferError, b64, canonical,
                                    receive_frame, send_frame, unb64)


def pool_status(kme: QKDClient) -> dict[str, Any]:
    try:
        status = kme.get_status()
        available, capacity = status['stored_key_count'], status['max_key_count']
        return {'available_keys': available, 'capacity': capacity,
                'occupancy_percent': round(100 * available / capacity, 2), 'reason': 'status_available'}
    except (httpx.HTTPError, KeyError, ValueError, ZeroDivisionError):
        return {'available_keys': None, 'capacity': None, 'occupancy_percent': None,
                'reason': 'qkd_status_unavailable'}


class Sender:
    def __init__(self, identity: Identity, kme_url: str, address: tuple[str, int],
                 queue: FileQueue, audit: Audit, rate_limit: float = 10) -> None:
        self.identity, self.address, self.queue, self.audit = identity, address, queue, audit
        self.kme = QKDClient(kme_url, 'alice', 'bob')
        self.manager = MitigationManager(rate_limit_per_peer=rate_limit)

    def attempt(self, identifier: str, tamper: bool = False) -> dict[str, Any]:
        job = self.queue.get(identifier)
        if job['state'] != 'QUEUED':
            return job
        started = time.monotonic()
        attempts = job['attempts'] + 1
        self.queue.update(identifier, state='SENDING', attempts=attempts)
        fields = {'transfer_id': identifier, 'filename': job['filename'], 'bytes': job['bytes'],
                  'policy': job['policy'], 'attempts': attempts}
        self.audit.emit('pool_status', **pool_status(self.kme))
        mode, reason, saved_as = None, 'pending', None
        data_started = False
        try:
            with Path(job['path']).open('rb') as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
            if len(data) != job['bytes'] or hashlib.sha256(data).hexdigest() != job['sha256']:
                raise TransferError('queued_source_changed')
            with socket.create_connection(self.address, timeout=15) as sock:
                sock.settimeout(15)
                result, reason = client_handshake(sock, self.identity, self.kme, self.manager,
                                                  fallback=job['policy'] == 'allow-pqc',
                                                  on_start=lambda attempt_id: self.audit.emit(
                                                      'handshake_started', **fields, attempt_id=attempt_id))
                mode = mode_label(result.security_mode)
                channel = SecureChannel(result, 'alice')
                self.audit.emit('session_confirmed', **fields, mode=mode, reason=reason,
                                confirmed=True, handshake_id=channel.transcript_hash[:16],
                                algorithm=self.identity.algorithm)
                offer = {key: job[key] for key in ('transfer_id', 'filename', 'bytes', 'sha256', 'policy')}
                offer['mode'] = mode
                send_frame(sock, channel.seal('offer', canonical(offer)))
                record = channel.seal('file', data)
                if tamper:
                    corrupted = bytearray(unb64(record['ciphertext']))
                    corrupted[len(corrupted) // 2] ^= 1
                    record['ciphertext'] = b64(bytes(corrupted))
                data_started = True
                send_frame(sock, record)
                receipt = json.loads(channel.open(receive_frame(sock), 'receipt'))
                if not isinstance(receipt, dict):
                    raise TransferError('invalid_receipt')
                if receipt.get('status') == 'REJECTED':
                    # An authenticated rejection is definitive, not an ambiguous delivery.
                    data_started = False
                    reason = receipt.get('reason')
                    raise TransferError(reason if reason in ('authentication_failed', 'duplicate_transfer',
                                                             'file_verification_failed') else 'receiver_rejected')
                if any(receipt.get(key) != value for key, value in {
                    'status': 'DELIVERED', 'transfer_id': identifier, 'mode': mode,
                    'bytes': len(data), 'sha256': offer['sha256'],
                }.items()):
                    raise TransferError('invalid_receipt')
                saved_as = receipt['saved_as']
                state = 'DELIVERED'
        except QKDUnavailableError as exc:
            state, reason = 'QUEUED', exc.reason_code
        except (TransferError, HandshakeError, httpx.HTTPError, OSError, ValueError, KeyError, TypeError) as exc:
            state = 'UNKNOWN' if data_started else 'FAILED'
            reason = str(exc) if isinstance(exc, TransferError) else 'handshake_or_transport_failed'
        elapsed = round((time.monotonic() - started) * 1000, 3)
        self.queue.update(identifier, state=state, reason=reason, mode=mode, duration_ms=elapsed, saved_as=saved_as)
        self.audit.emit(state.lower(), **fields, state=state, mode=mode, reason=reason,
                        duration_ms=elapsed, saved_as=saved_as)
        return self.queue.get(identifier)

    def run(self, *, watch: bool = False, interval: float = 1, max_wait: float = 60,
            identifier: str | None = None, tamper: bool = False) -> list[dict[str, Any]]:
        if interval <= 0 or max_wait < 0:
            raise ValueError('invalid retry interval or deadline')
        deadline = time.monotonic() + max_wait
        with self.queue.worker():
            while True:
                pending = self.queue.list('QUEUED')
                if identifier:
                    pending = [job for job in pending if job['transfer_id'] == identifier]
                for job in pending:
                    self.attempt(job['transfer_id'], tamper=tamper)
                remaining = [job for job in self.queue.list('QUEUED')
                             if identifier is None or job['transfer_id'] == identifier]
                if not watch or not remaining or time.monotonic() >= deadline:
                    break
                time.sleep(min(interval, max(0, deadline - time.monotonic())))
        return [self.queue.get(identifier)] if identifier else self.queue.list()
