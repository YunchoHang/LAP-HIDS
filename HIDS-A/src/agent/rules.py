from __future__ import annotations
from agent.events import Event

def classify_severity(e: Event) -> str:
    """
    Classify event severity based on event type and details.
    Returns: CRITICAL, HIGH, WARN, or INFO.
    """
    
    # SSH/Auth failures
    if e.kind == "ssh_fail":
        fail_count = int(e.details.get("fail_count", 1))
        if fail_count >= 10:
            return "CRITICAL"
        if fail_count >= 5:
            return "HIGH"
        return "WARN"
    
    if e.kind == "ssh_success_suspicious":
        return "HIGH"
    
    # Process monitoring
    if e.kind in ("proc_suspicious", "proc_privilege_escalation"):
        return "CRITICAL"
    
    if e.kind == "proc_unusual_port":
        return "HIGH"
    
    # File integrity
    if e.kind == "file_change":
        path = str(e.details.get("path", ""))
        if path.startswith("/etc/") or path.startswith("/usr/bin/") or path.startswith("/usr/sbin/"):
            return "HIGH"
        if path.startswith("/opt/"):
            return "WARN"
        return "INFO"
    
    if e.kind == "integrity_mismatch":
        path = str(e.details.get("path", ""))
        if path.startswith("/etc/") or path.startswith("/usr/bin/") or path.startswith("/usr/sbin/"):
            return "CRITICAL"
        return "HIGH"
    
    # Default: use event's severity if provided
    return e.severity or "INFO"


def should_alert(e: Event) -> bool:
    """Determine if an event should trigger an alert."""
    severity = classify_severity(e)
    return severity in ("CRITICAL", "HIGH")