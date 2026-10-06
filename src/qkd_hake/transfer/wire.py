from __future__ import annotations

import base64
import json
import socket
import struct
from typing import Any

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FRAME_BYTES = 24 * 1024 * 1024
HANDSHAKE_LIMIT = 256 * 1024


class TransferError(Exception):
    """Public errors are fixed diagnostic codes, never key material."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode('ascii')


def unb64(value: str) -> bytes:
    if not isinstance(value, str):
        raise TransferError('invalid_encoding')
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise TransferError('invalid_encoding') from exc


def _read(sock: socket.socket, length: int) -> bytes:
    parts = bytearray()
    while len(parts) < length:
        block = sock.recv(min(65536, length - len(parts)))
        if not block:
            raise TransferError('connection_closed')
        parts.extend(block)
    return bytes(parts)


def send_frame(sock: socket.socket, value: dict[str, Any]) -> None:
    payload = canonical(value)
    if len(payload) > MAX_FRAME_BYTES:
        raise TransferError('frame_too_large')
    sock.sendall(struct.pack('!I', len(payload)) + payload)


def receive_frame(sock: socket.socket, limit: int = HANDSHAKE_LIMIT) -> dict[str, Any]:
    length = struct.unpack('!I', _read(sock, 4))[0]
    if not 0 < length <= limit:
        raise TransferError('invalid_frame_length')
    try:
        result = json.loads(_read(sock, length))
    except (ValueError, UnicodeError) as exc:
        raise TransferError('invalid_json') from exc
    if not isinstance(result, dict):
        raise TransferError('invalid_frame')
    return result


def require_type(frame: dict[str, Any], expected: str) -> None:
    if frame.get('type') != expected:
        raise TransferError('unexpected_message')
