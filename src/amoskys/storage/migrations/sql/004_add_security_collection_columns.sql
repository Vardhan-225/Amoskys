-- UP
-- Add collection metadata columns to security_events.

ALTER TABLE security_events ADD COLUMN collection_agent TEXT;
ALTER TABLE security_events ADD COLUMN agent_version TEXT;

-- DOWN
-- SQLite < 3.35 cannot DROP COLUMN.
