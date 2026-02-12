from __future__ import annotations
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
        """Create a new event with current timestamp."""
        return Event(
            ts=Event.now_iso(),
            source=source,
            kind=kind,
            severity=severity,
            summary=summary,
            details=details or {}
        )

    def to_json(self) -> str:
        """Serialize event to JSON string."""
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    @staticmethod
    def from_json(s: str) -> "Event":
        """Deserialize event from JSON string."""
        obj = json.loads(s)
        return Event(**obj)

    def __repr__(self) -> str:
        return f"Event({self.ts}, {self.kind}, {self.severity}, {self.summary})"