from __future__ import annotations

import json
import os
from qkd_hake.crypto.kem import OQSKEM


class KeyStore:
    """Manages storage and registration of long-term identity KEM keys."""

    def __init__(self, storage_dir: str = "keys_store") -> None:
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)

    def register_user(self, user_id: str, algorithm: str = "ML-KEM-512") -> tuple[bytes, bytes]:
        """Generate and store long-term KEM keys for a user."""
        kem = OQSKEM(algorithm)
        kp = kem.generate_keypair()
        
        user_path = os.path.join(self.storage_dir, f"{user_id}.json")
        data = {
            "user_id": user_id,
            "algorithm": algorithm,
            "public_key_hex": kp.public_key.hex(),
            "secret_key_hex": kp.secret_key.hex()
        }
        with open(user_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
        return kp.public_key, kp.secret_key

    def get_public_key(self, user_id: str) -> bytes:
        """Retrieve registered public key of a user."""
        user_path = os.path.join(self.storage_dir, f"{user_id}.json")
        if not os.path.exists(user_path):
            raise FileNotFoundError(f"No registered keys found for user {user_id}")
        with open(user_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return bytes.fromhex(data["public_key_hex"])

    def get_secret_key(self, user_id: str) -> bytes:
        """Retrieve registered secret key of a user."""
        user_path = os.path.join(self.storage_dir, f"{user_id}.json")
        if not os.path.exists(user_path):
            raise FileNotFoundError(f"No registered keys found for user {user_id}")
        with open(user_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return bytes.fromhex(data["secret_key_hex"])
