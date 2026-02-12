import os, tempfile
from manager.storage import Storage

def test_storage_insert_and_read():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        s = Storage(db)
        s.insert({"ts":"t","source":"x","kind":"y","severity":"INFO","summary":"z","details":{}}, raw="raw")
        rows = s.latest(10)
        assert len(rows) == 1
        assert rows[0][3] == "x"
