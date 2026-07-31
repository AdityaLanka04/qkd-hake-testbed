from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import base64
import secrets
import threading
import time
import uuid


class PoolExhausted(RuntimeError):
    pass


class PeerQuotaExceeded(RuntimeError):
    pass


class UnknownKeyID(KeyError):
    pass


@dataclass(frozen=True, slots=True)
class DeliveredKey:
    key_id: str
    key: bytes

    def as_json(self) -> dict[str, str]:
        return {
            "key_ID": self.key_id,
            "key": base64.b64encode(self.key).decode("ascii"),
        }


class QKDKeyPool:
    """Thread-safe finite key pool with lazy, rate-limited refill."""

    def __init__(
        self,
        *,
        refill_bps: int,
        depth: int,
        initial_keys: int,
        key_size_bits: int = 256,
        per_peer_quota: int = 0,
        clock=time.monotonic,
    ) -> None:
        if depth <= 0 or not 0 <= initial_keys <= depth:
            raise ValueError("invalid pool depth or initial key count")
        if key_size_bits <= 0 or key_size_bits % 8:
            raise ValueError("key size must be a positive multiple of 8")
        self.refill_bps = refill_bps
        self.depth = depth
        self.key_size_bits = key_size_bits
        self.per_peer_quota = per_peer_quota
        self._available = initial_keys
        self._fractional_bits = 0.0
        self._clock = clock
        self._last_refill = clock()
        self._issued: dict[tuple[str, str, str], bytes] = {}
        self._outstanding: Counter[str] = Counter()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._last_refill)
        self._last_refill = now
        self._fractional_bits += elapsed * self.refill_bps
        new_keys = int(self._fractional_bits // self.key_size_bits)
        if new_keys:
            room = self.depth - self._available
            accepted = min(room, new_keys)
            self._available += accepted
            self._fractional_bits -= accepted * self.key_size_bits
            if accepted < new_keys:
                self._fractional_bits = min(
                    self._fractional_bits, float(self.key_size_bits - 1)
                )

    def status(self) -> dict[str, int]:
        with self._lock:
            self._refill_locked()
            return {
                "stored_key_count": self._available,
                "max_key_count": self.depth,
                "key_size": self.key_size_bits,
            }

    def issue(self, master_sae: str, slave_sae: str, number: int = 1) -> list[DeliveredKey]:
        if number < 1:
            raise ValueError("number must be positive")
        peer_key = f"{master_sae}->{slave_sae}"
        with self._lock:
            self._refill_locked()
            if self.per_peer_quota and self._outstanding[peer_key] + number > self.per_peer_quota:
                raise PeerQuotaExceeded(peer_key)
            if self._available < number:
                raise PoolExhausted(f"requested {number}, available {self._available}")

            delivered: list[DeliveredKey] = []
            for _ in range(number):
                key_id = str(uuid.uuid4())
                key = secrets.token_bytes(self.key_size_bits // 8)
                self._issued[(master_sae, slave_sae, key_id)] = key
                delivered.append(DeliveredKey(key_id, key))
            self._available -= number
            self._outstanding[peer_key] += number
            return delivered

    def retrieve(self, master_sae: str, slave_sae: str, key_ids: list[str]) -> list[DeliveredKey]:
        peer_key = f"{master_sae}->{slave_sae}"
        with self._lock:
            lookups = [(master_sae, slave_sae, key_id) for key_id in key_ids]
            if any(item not in self._issued for item in lookups):
                raise UnknownKeyID("one or more keys specified are not found on KME")
            delivered = [DeliveredKey(item[2], self._issued.pop(item)) for item in lookups]
            self._outstanding[peer_key] -= len(delivered)
            if self._outstanding[peer_key] <= 0:
                self._outstanding.pop(peer_key, None)
            return delivered
