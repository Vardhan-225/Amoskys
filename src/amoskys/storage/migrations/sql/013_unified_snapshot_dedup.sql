-- Migration 013: Unified snapshot dedup across ALL snapshot-heavy tables
--
-- Extends the per-table dedup (migration 012, FIM + Persistence only)
-- to a unified _snapshot_baseline table covering all snapshot-producing
-- agents: process, peripheral, and discovery observations.
--
-- Impact estimate (based on pre-migration analysis):
--   process_events:      302K rows, 4,973 unique -> ~297K deletions (98%)
--   peripheral_events:   578 rows, ~1 unique     -> ~577 deletions (99%)
--   observation(discovery): 66K rows, 1,339 unique -> ~64K deletions (97%)
--   Total: ~362K additional rows eliminated

-- Step 1: Create unified baseline table
CREATE TABLE IF NOT EXISTS _snapshot_baseline (
    table_name   TEXT NOT NULL,
    dedup_key    TEXT NOT NULL,
    content_hash TEXT,
    updated_ns   INTEGER NOT NULL,
    PRIMARY KEY (table_name, dedup_key)
) WITHOUT ROWID;

-- Step 2: Migrate existing baselines from legacy tables into unified table
INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
SELECT 'fim_events', device_id || '|' || path, content_hash, updated_ns
FROM _fim_baseline;

INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
SELECT 'persistence_events',
       device_id || '|' || mechanism || '|' || entry_id,
       content_hash, updated_ns
FROM _persistence_baseline;

-- Step 3: Seed baselines for process_events
INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
SELECT 'process_events',
       device_id || '|' || pid || '|' || COALESCE(exe, ''),
       COALESCE(cmdline, ''),
       MAX(timestamp_ns)
FROM process_events
WHERE device_id IS NOT NULL AND pid IS NOT NULL
GROUP BY device_id, pid, exe;

-- Step 4: Seed baselines for peripheral_events
INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
SELECT 'peripheral_events',
       device_id || '|' || peripheral_device_id,
       COALESCE(connection_status, '') || '|' || COALESCE(device_name, ''),
       MAX(timestamp_ns)
FROM peripheral_events
WHERE device_id IS NOT NULL
GROUP BY device_id, peripheral_device_id;

-- Step 5: Seed baselines for observation_events (discovery domain)
INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
SELECT 'observation_events',
       device_id || '|discovery|' || COALESCE(attributes, ''),
       COALESCE(attributes, ''),
       MAX(timestamp_ns)
FROM observation_events
WHERE domain = 'discovery' AND device_id IS NOT NULL
GROUP BY device_id, attributes;

-- Step 6: Deduplicate process_events (keep latest per unique combo)
DELETE FROM process_events
WHERE id NOT IN (
    SELECT MAX(id)
    FROM process_events
    GROUP BY device_id, pid, exe, cmdline
);

-- Step 7: Deduplicate peripheral_events
DELETE FROM peripheral_events
WHERE id NOT IN (
    SELECT MAX(id)
    FROM peripheral_events
    GROUP BY device_id, peripheral_device_id, connection_status, device_name
);

-- Step 8: Deduplicate observation_events (discovery domain only)
DELETE FROM observation_events
WHERE domain = 'discovery'
  AND id NOT IN (
      SELECT MAX(id)
      FROM observation_events
      WHERE domain = 'discovery'
      GROUP BY device_id, attributes
  );

-- Step 9: Refresh planner stats
ANALYZE _snapshot_baseline;
ANALYZE process_events;
ANALYZE peripheral_events;
ANALYZE observation_events;
