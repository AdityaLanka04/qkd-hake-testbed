from __future__ import annotations

import hashlib
import hmac


HASH_LEN = hashlib.sha3_256().digest_size
SUITE_ID = b"QKD-HAKE-TESTBED-v1"


def _field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(HASH_LEN)
    return hmac.new(salt, ikm, hashlib.sha3_256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0 or length > 255 * HASH_LEN:
        raise ValueError("invalid HKDF output length")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha3_256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def labelled_extract(salt: bytes, label: str, ikm: bytes) -> bytes:
    labelled_ikm = _field(SUITE_ID) + _field(label.encode("utf-8")) + _field(ikm)
    return hkdf_extract(salt, labelled_ikm)


def labelled_expand(prk: bytes, label: str, context: bytes, length: int) -> bytes:
    info = (
        length.to_bytes(2, "big")
        + _field(SUITE_ID)
        + _field(label.encode("utf-8"))
        + _field(context)
    )
    return hkdf_expand(prk, info, length)
