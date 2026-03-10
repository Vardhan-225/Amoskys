-- Migration 009: Observability-first schema updates
-- Adds missing columns to domain tables so raw collector data can be stored.
-- Adds event_source column to distinguish observations from probe detections.

-- ── process_events: missing fields from ProcessSnapshot ──
ALTER TABLE process_events ADD COLUMN name TEXT;
ALTER TABLE process_events ADD COLUMN parent_name TEXT;
ALTER TABLE process_events ADD COLUMN create_time REAL;
ALTER TABLE process_events ADD COLUMN status TEXT;
ALTER TABLE process_events ADD COLUMN cwd TEXT;
ALTER TABLE process_events ADD COLUMN is_own_user BOOLEAN DEFAULT 0;
ALTER TABLE process_events ADD COLUMN process_guid TEXT;
ALTER TABLE process_events ADD COLUMN event_source TEXT DEFAULT 'observation';

CREATE INDEX IF NOT EXISTS idx_process_guid ON process_events(process_guid);
CREATE INDEX IF NOT EXISTS idx_process_name ON process_events(name);
CREATE INDEX IF NOT EXISTS idx_process_event_source ON process_events(event_source);

-- ── flow_events: missing fields from Connection ──
ALTER TABLE flow_events ADD COLUMN pid INTEGER;
ALTER TABLE flow_events ADD COLUMN process_name TEXT;
ALTER TABLE flow_events ADD COLUMN conn_user TEXT;
ALTER TABLE flow_events ADD COLUMN state TEXT;
ALTER TABLE flow_events ADD COLUMN collection_agent TEXT;
ALTER TABLE flow_events ADD COLUMN agent_version TEXT;
ALTER TABLE flow_events ADD COLUMN event_source TEXT DEFAULT 'observation';

CREATE INDEX IF NOT EXISTS idx_flow_process ON flow_events(process_name);
CREATE INDEX IF NOT EXISTS idx_flow_state ON flow_events(state);
CREATE INDEX IF NOT EXISTS idx_flow_event_source ON flow_events(event_source);

-- ── dns_events: missing fields from DNSQuery ──
ALTER TABLE dns_events ADD COLUMN response_ips TEXT;
ALTER TABLE dns_events ADD COLUMN ttl INTEGER;
ALTER TABLE dns_events ADD COLUMN response_size INTEGER;
ALTER TABLE dns_events ADD COLUMN is_reverse BOOLEAN DEFAULT 0;
ALTER TABLE dns_events ADD COLUMN event_source TEXT DEFAULT 'observation';

CREATE INDEX IF NOT EXISTS idx_dns_event_source ON dns_events(event_source);

-- ── persistence_events: missing fields from PersistenceEntry ──
ALTER TABLE persistence_events ADD COLUMN content_hash TEXT;
ALTER TABLE persistence_events ADD COLUMN program TEXT;
ALTER TABLE persistence_events ADD COLUMN label TEXT;
ALTER TABLE persistence_events ADD COLUMN run_at_load BOOLEAN DEFAULT 0;
ALTER TABLE persistence_events ADD COLUMN keep_alive BOOLEAN DEFAULT 0;
ALTER TABLE persistence_events ADD COLUMN event_source TEXT DEFAULT 'observation';

CREATE INDEX IF NOT EXISTS idx_persistence_event_source ON persistence_events(event_source);

-- ── fim_events: add event_source ──
ALTER TABLE fim_events ADD COLUMN event_source TEXT DEFAULT 'observation';

CREATE INDEX IF NOT EXISTS idx_fim_event_source ON fim_events(event_source);

-- ── peripheral_events: add event_source ──
ALTER TABLE peripheral_events ADD COLUMN event_source TEXT DEFAULT 'observation';

CREATE INDEX IF NOT EXISTS idx_peripheral_event_source ON peripheral_events(event_source);

-- ── audit_events: add event_source ──
ALTER TABLE audit_events ADD COLUMN event_source TEXT DEFAULT 'observation';

CREATE INDEX IF NOT EXISTS idx_audit_event_source ON audit_events(event_source);
