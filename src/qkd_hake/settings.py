from __future__ import annotations

from dataclasses import dataclass
import os


def _int_env(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    refill_bps: int = 10_000
    pool_depth: int = 128
    initial_keys: int = 128
    key_size_bits: int = 256
    per_peer_quota: int = 0

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            refill_bps=_int_env("QKD_REFILL_BPS", 10_000),
            pool_depth=_int_env("QKD_POOL_DEPTH", 128),
            initial_keys=_int_env("QKD_INITIAL_KEYS", 128),
            key_size_bits=_int_env("QKD_KEY_SIZE_BITS", 256),
            per_peer_quota=_int_env("QKD_PER_PEER_QUOTA", 0),
        )
        if settings.pool_depth == 0:
            raise ValueError("QKD_POOL_DEPTH must be greater than zero")
        if settings.key_size_bits == 0 or settings.key_size_bits % 8:
            raise ValueError("QKD_KEY_SIZE_BITS must be a positive multiple of 8")
        if settings.initial_keys > settings.pool_depth:
            raise ValueError("QKD_INITIAL_KEYS cannot exceed QKD_POOL_DEPTH")
        return settings
