from __future__ import annotations

import json
from pathlib import Path
import socketserver
import time

import httpx

from qkd_hake.protocol.hake import HandshakeError
from qkd_hake.qkd_mock.client import QKDClient
from qkd_hake.transfer.audit import Audit
from qkd_hake.transfer.channel import SecureChannel
from qkd_hake.transfer.handshake import server_handshake, mode_label
from qkd_hake.transfer.identity import Identity
from qkd_hake.transfer.storage import publish_file, validate_offer
from qkd_hake.transfer.wire import (MAX_FRAME_BYTES, TransferError, canonical,
                                    receive_frame, send_frame)


class Receiver(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], identity: Identity, kme_url: str,
                 output: Path, audit: Audit) -> None:
        self.identity, self.output, self.audit = identity, output, audit
        self.kme = QKDClient(kme_url, 'bob', 'alice')
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        super().__init__(address, ReceiveHandler)


class ReceiveHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: Receiver = self.server
        self.request.settimeout(15)
        started = time.monotonic()
        channel = None
        offer = None
        mode = None
        committed = False
        try:
            result = server_handshake(self.request, server.identity, server.kme)
            channel = SecureChannel(result, 'bob')
            mode = mode_label(result.security_mode)
            metadata = json.loads(channel.open(receive_frame(self.request), 'offer'))
            if not isinstance(metadata, dict):
                raise TransferError('invalid_offer')
            validate_offer(metadata, mode)
            offer = metadata
            server.audit.emit('session_confirmed', transfer_id=offer['transfer_id'],
                              filename=offer['filename'], bytes=offer['bytes'],
                              policy=offer['policy'], mode=mode, confirmed=True,
                              handshake_id=channel.transcript_hash[:16])
            plaintext = channel.open(receive_frame(self.request, MAX_FRAME_BYTES), 'file')
            target = publish_file(server.output, offer, plaintext)
            committed = True
            receipt = {'status': 'DELIVERED', 'transfer_id': offer['transfer_id'],
                       'mode': mode, 'bytes': len(plaintext), 'sha256': offer['sha256'],
                       'saved_as': target.name}
            # Commit event precedes the acknowledgement: a lost ACK is not a lost file.
            server.audit.emit('delivered', transfer_id=offer['transfer_id'], filename=offer['filename'],
                              bytes=len(plaintext), policy=offer['policy'], mode=mode,
                              reason='aead_and_digest_verified', saved_as=target.name,
                              duration_ms=round((time.monotonic() - started) * 1000, 3))
            send_frame(self.request, channel.seal('receipt', canonical(receipt)))
        except (TransferError, HandshakeError, httpx.HTTPError, OSError, ValueError, KeyError, TypeError) as exc:
            reason = str(exc) if isinstance(exc, TransferError) else 'handshake_or_transport_failed'
            fields = {'mode': mode, 'reason': 'receipt_delivery_failed' if committed else reason,
                      'duration_ms': round((time.monotonic() - started) * 1000, 3)}
            if offer is not None:
                fields.update(transfer_id=offer['transfer_id'], filename=offer['filename'],
                              bytes=offer['bytes'], policy=offer['policy'])
            server.audit.emit('receipt_lost' if committed else 'rejected', **fields)
            if channel is not None and not committed:
                try:
                    send_frame(self.request, channel.seal('receipt', canonical(
                        {'status': 'REJECTED', 'reason': reason})))
                except (OSError, TransferError):
                    pass
