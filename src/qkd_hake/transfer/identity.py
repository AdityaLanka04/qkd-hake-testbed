from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path

from qkd_hake.crypto.kem import OQSKEM, SUPPORTED_ALGORITHMS
from qkd_hake.transfer.wire import b64, unb64


@dataclass(frozen=True, repr=False)
class Identity:
    role: str
    algorithm: str
    public_key: bytes
    secret_key: bytes
    peer_public_key: bytes

    @classmethod
    def load(cls, path: Path, role: str) -> 'Identity':
        obj = json.loads(path.read_text())
        if obj['role'] != role or obj['algorithm'] not in SUPPORTED_ALGORITHMS:
            raise ValueError('identity role or algorithm mismatch')
        return cls(role, obj['algorithm'], unb64(obj['public_key']),
                   unb64(obj['secret_key']), unb64(obj['peer_public_key']))


def provision(directory: Path, algorithm: str = 'ML-KEM-768') -> None:
    """Out-of-band local provisioning; never overwrite existing identities."""
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    kem = OQSKEM(algorithm)
    alice, bob = kem.generate_keypair(), kem.generate_keypair()
    for role, own, peer in [('alice', alice, bob), ('bob', bob, alice)]:
        path = directory / f'{role}.json'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as file:
            json.dump({'role': role, 'algorithm': algorithm, 'public_key': b64(own.public_key),
                       'secret_key': b64(own.secret_key), 'peer_public_key': b64(peer.public_key)}, file)
