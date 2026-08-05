from __future__ import annotations

import base64
import httpx


class QKDClient:
    """ETSI GS QKD 014 REST Client for Mock KME Server."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        local_sae_id: str = "alice",
        peer_sae_id: str = "bob",
    ) -> None:
        self.base_url = base_url
        self.local_sae_id = local_sae_id
        self.peer_sae_id = peer_sae_id

    def get_status(self) -> dict:
        url = f"{self.base_url}/api/v1/keys/{self.peer_sae_id}/status"
        headers = {"X-SAE-ID": self.local_sae_id}
        response = httpx.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def get_key(self) -> tuple[bytes, str]:
        url = f"{self.base_url}/api/v1/keys/{self.peer_sae_id}/enc_keys"
        headers = {"X-SAE-ID": self.local_sae_id}
        response = httpx.post(url, headers=headers, json={"number": 1, "size": 256})
        response.raise_for_status()
        key_data = response.json()["keys"][0]
        return base64.b64decode(key_data["key"]), key_data["key_ID"]

    def retrieve_key(self, key_id: str) -> bytes:
        url = f"{self.base_url}/api/v1/keys/{self.peer_sae_id}/dec_keys"
        headers = {"X-SAE-ID": self.local_sae_id}
        response = httpx.post(url, headers=headers, json={"key_IDs": [{"key_ID": key_id}]})
        response.raise_for_status()
        key_data = response.json()["keys"][0]
        return base64.b64decode(key_data["key"])
