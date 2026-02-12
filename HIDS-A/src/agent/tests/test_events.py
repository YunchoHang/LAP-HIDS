from agent.events import Event

def test_event_json_roundtrip():
    e = Event.create("logins", "ssh_fail", "x", {"ip":"1.2.3.4"}, severity="WARN")
    s = e.to_json()
    e2 = Event.from_json(s)
    assert e2.source == e.source
    assert e2.details["ip"] == "1.2.3.4"

def test_event_has_iso_ts():
    e = Event.create("system", "agent_started", "ok", {})
    assert "T" in e.ts
