from agent.events import Event

def classify_severity(e: Event) -> str:
    if e.kind == "ssh_fail":
        fail_count = int(e.details.get("fail_count", 1))
        if fail_count >= 10:
            return "CRITICAL"
        if fail_count >= 5:
            return "HIGH"
        return "WARN"
    if e.kind in ("proc_suspicious", "proc_privilege_escalation"):
        return "CRITICAL"
    if e.kind == "proc_unusual_port":
        return "HIGH"
    if e.kind == "file_change":
        path = str(e.details.get("path", ""))
        if path.startswith("/etc/") or path.startswith("/usr/bin/") or path.startswith("/usr/sbin/"):
            return "HIGH"
        return "WARN"
    if e.kind == "integrity_mismatch":
        path = str(e.details.get("path", ""))
        if path.startswith("/etc/") or path.startswith("/usr/bin/") or path.startswith("/usr/sbin/"):
            return "CRITICAL"
        return "HIGH"
    return e.severity or "INFO"