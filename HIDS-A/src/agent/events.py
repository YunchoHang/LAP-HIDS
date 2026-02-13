from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict
import json

@dataclass(frozen=True)
class Event:
    ts: str
    source: str
    kind: str
    severity: str
    summary: str
    details: Dict[str, Any]

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def create(
        source: str,
        kind: str,
        summary: str,
        details: Dict[str, Any] | None = None,
        severity: str = "INFO"
    ) -> "Event":
        return Event(
            ts=Event.now_iso(),
            source=source,
            kind=kind,
            severity=severity,
            summary=summary,
            details=details or {}
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    @staticmethod
    def from_json(s: str) -> "Event":
        obj = json.loads(s)
        return Event(**obj)