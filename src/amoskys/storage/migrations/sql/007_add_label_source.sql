-- 007: Add label_source column for GBC supervised training labels
-- Tracks where event labels originate: manual (analyst triage),
-- ioc_strong (IOC-confirmed), incident (investigation-confirmed)
--
-- UP:
ALTER TABLE security_events ADD COLUMN label_source TEXT DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_label_source ON security_events(label_source);

-- DOWN:
-- SQLite cannot DROP COLUMN; recreate table without label_source if needed.
