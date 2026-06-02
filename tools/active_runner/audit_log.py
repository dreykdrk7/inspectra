from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def audit_event(event: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "event": event,
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "details": details or {},
    }
