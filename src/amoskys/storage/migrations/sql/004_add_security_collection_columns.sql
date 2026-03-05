-- UP
-- Add collection metadata columns to security_events.
-- Uses a no-op guard: if column already exists the ALTER will fail,
-- which the migration runner handles gracefully.

ALTER TABLE security_events ADD COLUMN collection_agent TEXT;
ALTER TABLE security_events ADD COLUMN agent_version TEXT;

-- DOWN
-- SQLite < 3.35 cannot DROP COLUMN.
