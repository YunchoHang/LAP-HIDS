from agent.events import Event
from agent.rules import classify

def test_rules_ssh_fail_warn_then_high():
    e = Event.create("logins","ssh_fail","",{"fail_count":3})
    assert classify(e) == "WARN"
    e2 = Event.create("logins","ssh_fail","",{"fail_count":6})
    assert classify(e2) == "HIGH"

def test_rules_integrity_critical_for_etc():
    e = Event.create("integrity","integrity_mismatch","",{"path":"/etc/passwd"})
    assert classify(e) == "CRITICAL"

def test_rules_proc_suspicious_high():
    e = Event.create("processes","proc_suspicious","",{"pid":1})
    assert classify(e) == "HIGH"
