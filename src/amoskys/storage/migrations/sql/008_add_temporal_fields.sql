-- Migration 008: Add temporal fields to security_events
-- Preserves probe-local detection timestamps that were previously lost
-- at the WAL → SQL boundary (event_timestamp_ns from TelemetryEvent proto).

ALTER TABLE security_events ADD COLUMN event_timestamp_ns INTEGER DEFAULT NULL;
ALTER TABLE security_events ADD COLUMN event_id TEXT DEFAULT NULL;
ALTER TABLE security_events ADD COLUMN probe_latency_ns INTEGER DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_security_event_timestamp
  ON security_events(event_timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_security_event_id
  ON security_events(event_id);
