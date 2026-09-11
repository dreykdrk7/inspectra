from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from typing import Any


AUDIT_LOGGER = logging.getLogger("inspectra.audit")


def log_audit_event(event: str, **details: Any) -> None:
    """Emit a small JSON audit event without request bodies, URLs, or secrets."""
    payload = {
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event": event,
        **{key: value for key, value in details.items() if value is not None},
    }
    AUDIT_LOGGER.info("%s", json.dumps(payload, sort_keys=True, separators=(",", ":")))
