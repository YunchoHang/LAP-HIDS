import json
from manager.receiver import parse_line

def test_parse_line_ok():
    env = {"sig":"abc","event":{"ts":"t","source":"s","kind":"k","severity":"INFO","summary":"x","details":{}}}
    out = parse_line(json.dumps(env))
    assert out["event"]["source"] == "s"