from __future__ import annotations
import time
from collections import defaultdict

class AdmissionControlError(Exception):
    pass

class QuotaExceededError(Exception):
    pass

class MitigationManager:
    def __init__(self, rate_limit_per_peer: float = 10.0) -> None:
        self.rate_limit_per_peer = rate_limit_per_peer
        self.peer_request_history: dict[str, list[float]] = defaultdict(list)

    def check_quota(self, peer_id: str) -> None:
        """Enforce maximum QKD requests per second per peer session."""
        if not self.rate_limit_per_peer:
            return
        now = time.time()
        self.peer_request_history[peer_id] = [
            t for t in self.peer_request_history[peer_id] if now - t < 1.0
        ]
        if len(self.peer_request_history[peer_id]) >= self.rate_limit_per_peer:
            raise QuotaExceededError(
                f"Peer {peer_id} exceeded request rate quota of {self.rate_limit_per_peer}/s"
            )
        self.peer_request_history[peer_id].append(now)

    @staticmethod
    def check_admission_control(stored_keys: int, max_keys: int) -> None:
        """Fail-fast when pool occupancy drops below 5%."""
        if max_keys > 0 and (stored_keys / max_keys) < 0.05:
            raise AdmissionControlError(
                f"KMS Pool occupancy ({stored_keys}/{max_keys}) below 5% admission control floor"
            )
