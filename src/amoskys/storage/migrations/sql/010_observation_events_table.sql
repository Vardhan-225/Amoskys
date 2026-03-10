-- Migration 010: Generic observation_events table for P3 agent domains
-- Domains: applog, db_activity, discovery, http, internet_activity,
--          security_monitor, unified_log
-- Stores raw observations as JSON attributes for domains without dedicated tables.

CREATE TABLE IF NOT EXISTS observation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    event_type TEXT DEFAULT 'observation',
    attributes TEXT NOT NULL,  -- JSON blob of all observation fields
    risk_score REAL DEFAULT 0.0,
    event_source TEXT DEFAULT 'observation',
    collection_agent TEXT,
    agent_version TEXT
);

CREATE INDEX IF NOT EXISTS idx_observation_events_device_ts
    ON observation_events(device_id, timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_observation_events_domain
    ON observation_events(domain);
CREATE INDEX IF NOT EXISTS idx_observation_events_ts
    ON observation_events(timestamp_ns);
