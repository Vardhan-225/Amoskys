import tempfile, os
from types import SimpleNamespace
from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.agents.flowagent.wal_sqlite import SQLiteWAL


def make_env(idem="k1", ts=1):
    flow = pb.FlowEvent(
        src_ip="1.1.1.1",
        dst_ip="8.8.8.8",
        src_port=1,
        dst_port=53,
        protocol="UDP",
        bytes_sent=10,
        bytes_recv=20,
        flags=0,
        start_time=1,
        end_time=2,
        bytes_tx=1,
        bytes_rx=2,
        proto="UDP",
        duration_ms=3,
    )
    return pb.Envelope(
        version="v1", ts_ns=ts, idempotency_key=idem, flow=flow, sig=b"", prev_sig=b""
    )


def test_dedup_and_drain_ok(tmp_path):
    wal_path = tmp_path / "wal.db"
    wal = SQLiteWAL(path=str(wal_path), max_bytes=10_000_000)

    # dedupe on idempotency_key
    wal.append(make_env("same", 1))
    wal.append(make_env("same", 2))  # should be ignored by unique index
    wal.append(make_env("other", 3))
    assert wal.backlog_bytes() > 0

    # drain with OK acks
    def pub_ok(env):
        return SimpleNamespace(status=pb.PublishAck.OK)

    drained = wal.drain(pub_ok, limit=10)
    assert drained == 2
    assert wal.backlog_bytes() == 0


def test_retry_stops_then_ok_continues(tmp_path):
    wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=10_000_000)
    wal.append(make_env("a", 1))
    wal.append(make_env("b", 2))

    calls = {"n": 0}

    def pub_retry_then_ok(env):
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(status=pb.PublishAck.RETRY)
        return SimpleNamespace(status=pb.PublishAck.OK)

    # first drain should stop on RETRY without deleting any
    drained = wal.drain(pub_retry_then_ok, limit=10)
    assert drained == 0

    # second drain should delete first (OK), then second (OK)
    drained2 = wal.drain(pub_retry_then_ok, limit=10)
    assert drained2 == 2
    assert wal.backlog_bytes() == 0


def test_backlog_cap_drops_oldest(tmp_path):
    wal = SQLiteWAL(path=str(tmp_path / "wal.db"), max_bytes=1)  # force tiny cap
    wal.append(make_env("x", 1))
    # enforcement should drop to <= cap
    assert wal.backlog_bytes() <= wal.max_bytes
