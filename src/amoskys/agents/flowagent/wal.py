import sqlite3, time, os
from typing import Callable
from amoskys.proto import messaging_schema_pb2 as pb

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS wal (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  idem TEXT NOT NULL,
  ts_ns INTEGER NOT NULL,
  bytes BLOB NOT NULL,
  checksum BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS wal_idem ON wal(idem);
CREATE INDEX IF NOT EXISTS wal_ts ON wal(ts_ns);
"""

class SQLiteWAL:
    def __init__(self, path="wal.db", max_bytes=200*1024*1024):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self.max_bytes = max_bytes
        self.db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        self.db.executescript(SCHEMA)

    def append(self, env: pb.Envelope) -> None:
        data = env.SerializeToString()
        checksum = sqlite3.Binary(bytes(memoryview(data)))
        try:
            self.db.execute(
                "INSERT INTO wal(idem, ts_ns, bytes, checksum) VALUES(?,?,?,?)",
                (env.idempotency_key, env.ts_ns, sqlite3.Binary(data), checksum)
            )
        except sqlite3.IntegrityError:
            return
        self._enforce_backlog()

    def backlog_bytes(self) -> int:
        row = self.db.execute("SELECT IFNULL(SUM(length(bytes)),0) FROM wal").fetchone()
        return int(row[0] or 0)

    def drain(self, publish_fn: Callable[[pb.Envelope], object], limit: int = 1000) -> int:
        cur = self.db.execute("SELECT id, bytes FROM wal ORDER BY id LIMIT ?", (limit,))
        rows = cur.fetchall()
        drained = 0
        for rowid, blob in rows:
            env = pb.Envelope()
            env.ParseFromString(bytes(blob))
            ack = publish_fn(env)
            try:
                status = getattr(ack, 'status', None)
            except Exception:
                break
            
            if status == 1:  # RETRY - stop processing
                break
            
            # For OK (0) or error statuses (2, 3, etc.), delete the record
            if status is not None:
                self.db.execute("DELETE FROM wal WHERE id = ?", (rowid,))
                drained += 1
        return drained

    def _enforce_backlog(self):
        total = self.backlog_bytes()
        if total <= self.max_bytes: return
        to_free = total - self.max_bytes
        freed = 0
        cur = self.db.execute("SELECT id, length(bytes) FROM wal ORDER BY id")
        for rowid, sz in cur:
            self.db.execute("DELETE FROM wal WHERE id=?", (rowid,))
            freed += sz
            if freed >= to_free: break
