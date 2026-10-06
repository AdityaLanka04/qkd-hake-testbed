from __future__ import annotations

import hashlib
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from qkd_hake.protocol.hake import HandshakeResult
from qkd_hake.transfer.wire import TransferError, b64, canonical, unb64


class SecureChannel:
    """Directional keys and strictly ordered records; one fresh HAKE per file.

    Each direction uses its own HKDF-derived AES-256-GCM key. The 96-bit
    counter nonce is used once per direction/key. Replay, type substitution,
    transcript changes and ciphertext modification all fail closed.
    """

    def __init__(self, result: HandshakeResult, role: str) -> None:
        if role not in ('alice', 'bob') or len(result.session_key) != 32:
            raise ValueError('invalid channel parameters')
        self.transcript_hash = hashlib.sha256(result.transcript).hexdigest()
        keys = HKDF(
            algorithm=hashes.SHA256(), length=64,
            salt=bytes.fromhex(self.transcript_hash),
            info=b'qkd-hake-file-transfer/v1/directional-keys',
        ).derive(result.session_key)
        self.send_direction = 'alice-to-bob' if role == 'alice' else 'bob-to-alice'
        self.recv_direction = 'bob-to-alice' if role == 'alice' else 'alice-to-bob'
        self.sender = AESGCM(keys[:32] if role == 'alice' else keys[32:])
        self.receiver = AESGCM(keys[32:] if role == 'alice' else keys[:32])
        self.send_sequence = 0
        self.recv_sequence = 0

    def _aad(self, direction: str, sequence: int, kind: str) -> bytes:
        return canonical({'version': 1, 'direction': direction, 'sequence': sequence,
                          'type': kind, 'transcript': self.transcript_hash})

    def seal(self, kind: str, plaintext: bytes) -> dict[str, Any]:
        sequence = self.send_sequence
        if sequence >= 2**96:
            raise TransferError('nonce_space_exhausted')
        self.send_sequence += 1
        ciphertext = self.sender.encrypt(sequence.to_bytes(12, 'big'), plaintext,
                                         self._aad(self.send_direction, sequence, kind))
        return {'type': kind, 'sequence': sequence, 'ciphertext': b64(ciphertext)}

    def open(self, record: dict[str, Any], kind: str) -> bytes:
        if (record.get('type') != kind or type(record.get('sequence')) is not int
                or record['sequence'] != self.recv_sequence):
            raise TransferError('record_order_or_type_invalid')
        try:
            plaintext = self.receiver.decrypt(
                self.recv_sequence.to_bytes(12, 'big'), unb64(record['ciphertext']),
                self._aad(self.recv_direction, self.recv_sequence, kind),
            )
        except InvalidTag as exc:
            raise TransferError('authentication_failed') from exc
        self.recv_sequence += 1
        return plaintext
