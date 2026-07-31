from __future__ import annotations

from dataclasses import dataclass


SUPPORTED_ALGORITHMS = (
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    "FrodoKEM-976-AES",
)


class OQSUnavailable(RuntimeError):
    pass


def _oqs():
    try:
        import oqs
    except ImportError as exc:
        raise OQSUnavailable(
            "liboqs-python is not installed; install the project with the pqc extra"
        ) from exc
    return oqs


@dataclass(frozen=True, slots=True)
class KEMKeyPair:
    public_key: bytes
    secret_key: bytes


class OQSKEM:
    def __init__(self, algorithm: str) -> None:
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"unsupported project algorithm: {algorithm}")
        self.algorithm = algorithm

    def generate_keypair(self) -> KEMKeyPair:
        oqs = _oqs()
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            return KEMKeyPair(public_key, kem.export_secret_key())

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        oqs = _oqs()
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        oqs = _oqs()
        with oqs.KeyEncapsulation(self.algorithm, secret_key=secret_key) as kem:
            return kem.decap_secret(ciphertext)
