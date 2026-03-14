-- Migration 012: Snapshot dedup — baseline tables + historical cleanup
--
-- Problem: FIM and Persistence agents emit full snapshots every cycle.
-- With ~15s intervals this produces 925K+ FIM and 485K+ Persistence
-- duplicate rows (54% of DB), bloating queries from 2.6M to millions of
-- redundant rows.
--
-- Solution (Layer 1 of 3-layer perf architecture):
-- 1. Create baseline tables (already in SCHEMA, but need them on existing DBs)
-- 2. Populate baselines from latest snapshot per resource
-- 3. Delete duplicate snapshot rows (keep latest per content hash)

-- ══════════════════════════════════════════════════════════════════════
-- 1. Ensure baseline tables exist (idempotent)
-- ══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS _fim_baseline (
    device_id    TEXT NOT NULL,
    path         TEXT NOT NULL,
    content_hash TEXT,
    mtime        TEXT,
    size         INTEGER,
    updated_ns   INTEGER NOT NULL,
    PRIMARY KEY (device_id, path)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS _persistence_baseline (
    device_id    TEXT NOT NULL,
    mechanism    TEXT NOT NULL,
    entry_id     TEXT NOT NULL,
    content_hash TEXT,
    command      TEXT,
    updated_ns   INTEGER NOT NULL,
    PRIMARY KEY (device_id, mechanism, entry_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS dashboard_rollups (
    rollup_type TEXT NOT NULL,
    bucket_key  TEXT NOT NULL,
    bucket_hour TEXT NOT NULL,
    value       INTEGER NOT NULL DEFAULT 0,
    updated_ns  INTEGER NOT NULL,
    PRIMARY KEY (rollup_type, bucket_key, bucket_hour)
) WITHOUT ROWID;

-- ══════════════════════════════════════════════════════════════════════
-- 2. Populate baselines from existing snapshot events
-- ══════════════════════════════════════════════════════════════════════

INSERT INTO _fim_baseline (device_id, path, content_hash, mtime, size, updated_ns)
SELECT device_id, path, new_hash, mtime, size, MAX(timestamp_ns)
FROM fim_events
WHERE change_type = 'snapshot' AND device_id IS NOT NULL AND path != ''
GROUP BY device_id, path
ON CONFLICT(device_id, path) DO UPDATE SET
    content_hash = excluded.content_hash,
    mtime        = excluded.mtime,
    size         = excluded.size,
    updated_ns   = excluded.updated_ns;

INSERT INTO _persistence_baseline
    (device_id, mechanism, entry_id, content_hash, command, updated_ns)
SELECT device_id, mechanism, entry_id, content_hash, command, MAX(timestamp_ns)
FROM persistence_events
WHERE change_type = 'snapshot'
  AND device_id IS NOT NULL
  AND mechanism IS NOT NULL AND mechanism != ''
  AND entry_id IS NOT NULL AND entry_id != ''
GROUP BY device_id, mechanism, entry_id
ON CONFLICT(device_id, mechanism, entry_id) DO UPDATE SET
    content_hash = excluded.content_hash,
    command      = excluded.command,
    updated_ns   = excluded.updated_ns;

-- ══════════════════════════════════════════════════════════════════════
-- 3. Delete duplicate snapshots (keep latest per content hash)
-- ══════════════════════════════════════════════════════════════════════

DELETE FROM fim_events
WHERE change_type = 'snapshot'
  AND id NOT IN (
      SELECT MAX(id)
      FROM fim_events
      WHERE change_type = 'snapshot'
      GROUP BY device_id, path, new_hash
  );

DELETE FROM persistence_events
WHERE change_type = 'snapshot'
  AND id NOT IN (
      SELECT MAX(id)
      FROM persistence_events
      WHERE change_type = 'snapshot'
      GROUP BY device_id, mechanism, entry_id, content_hash
  );

-- Refresh planner stats after bulk deletes
ANALYZE _fim_baseline;
ANALYZE _persistence_baseline;
ANALYZE fim_events;
ANALYZE persistence_events;
