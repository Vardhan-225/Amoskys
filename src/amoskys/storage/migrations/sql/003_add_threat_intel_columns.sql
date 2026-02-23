-- UP
-- A4.3: Add threat intelligence match columns to domain tables.

ALTER TABLE flow_events ADD COLUMN threat_intel_match BOOLEAN DEFAULT 0;
ALTER TABLE flow_events ADD COLUMN threat_source TEXT;
ALTER TABLE flow_events ADD COLUMN threat_severity TEXT;

ALTER TABLE security_events ADD COLUMN threat_intel_match BOOLEAN DEFAULT 0;
ALTER TABLE security_events ADD COLUMN threat_source TEXT;
ALTER TABLE security_events ADD COLUMN threat_severity TEXT;

ALTER TABLE dns_events ADD COLUMN threat_intel_match BOOLEAN DEFAULT 0;
ALTER TABLE dns_events ADD COLUMN threat_source TEXT;
ALTER TABLE dns_events ADD COLUMN threat_severity TEXT;

ALTER TABLE fim_events ADD COLUMN threat_intel_match BOOLEAN DEFAULT 0;
ALTER TABLE fim_events ADD COLUMN threat_source TEXT;
ALTER TABLE fim_events ADD COLUMN threat_severity TEXT;

-- DOWN
-- SQLite < 3.35 cannot DROP COLUMN.
