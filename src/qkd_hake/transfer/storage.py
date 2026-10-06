from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import uuid
from typing import Any

from qkd_hake.transfer.wire import MAX_FILE_BYTES, TransferError

POLICIES = ('hybrid-required', 'allow-pqc')


def validate_offer(offer: dict[str, Any], mode: str) -> None:
    name = offer.get('filename')
    if (not isinstance(name, str) or not name or name in ('.', '..')
            or '/' in name or '\\' in name or len(name.encode()) > 180
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise TransferError('unsafe_filename')
    try:
        if str(uuid.UUID(offer['transfer_id'])) != offer['transfer_id']:
            raise ValueError()
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise TransferError('invalid_transfer_id') from exc
    if type(offer.get('bytes')) is not int or not 0 <= offer['bytes'] <= MAX_FILE_BYTES:
        raise TransferError('invalid_file_size')
    if offer.get('policy') not in POLICIES or offer.get('mode') != mode:
        raise TransferError('invalid_policy_or_mode')
    if offer['policy'] == 'hybrid-required' and mode != 'HYBRID_QKD':
        raise TransferError('hybrid_policy_violation')
    digest = offer.get('sha256')
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise TransferError('invalid_file_digest')


def publish_file(directory: Path, offer: dict[str, Any], plaintext: bytes) -> Path:
    """Only called after AEAD authentication. Atomically publish without overwrite."""
    if len(plaintext) != offer['bytes'] or hashlib.sha256(plaintext).hexdigest() != offer['sha256']:
        raise TransferError('file_verification_failed')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = directory / f"{offer['transfer_id']}-{offer['filename']}"
    fd, temporary = tempfile.mkstemp(prefix='.verified-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(plaintext)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError as exc:
            raise TransferError('duplicate_transfer') from exc
    finally:
        os.unlink(temporary)
    return target
