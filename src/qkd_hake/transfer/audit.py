from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from typing import Any

FIELDS = frozenset({'event', 'transfer_id', 'filename', 'bytes', 'policy', 'mode', 'reason',
                    'duration_ms', 'attempts', 'state', 'available_keys', 'capacity',
                    'occupancy_percent', 'saved_as', 'handshake_id', 'attempt_id', 'confirmed', 'algorithm'})


class Audit:
    def __init__(self, path: Path, role: str, echo: bool = True) -> None:
        self.path, self.role, self.echo = path, role, echo
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.Lock()

    def emit(self, event: str, **fields: Any) -> None:
        if set(fields) - FIELDS:
            raise ValueError('unsupported audit fields')
        record = {'time': datetime.now(timezone.utc).isoformat(), 'role': self.role,
                  'event': event, **fields}
        line = json.dumps(record, sort_keys=True, ensure_ascii=True)
        with self.lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(line + '\n')
            if self.echo:
                print(line, flush=True)
