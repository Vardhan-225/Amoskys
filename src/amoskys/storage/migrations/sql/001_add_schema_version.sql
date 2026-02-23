-- UP
-- A3.2: Add schema_version column to all domain tables.
-- Default value 1 marks all existing rows as schema version 1.

ALTER TABLE process_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE device_telemetry ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE flow_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE security_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE peripheral_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE metrics_timeseries ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE dns_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE audit_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE persistence_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE fim_events ADD COLUMN schema_version INTEGER DEFAULT 1;

-- DOWN
-- SQLite does not support DROP COLUMN before 3.35.0.
-- For rollback on older SQLite, recreate tables without the column.
-- On 3.35+, these statements work directly:
-- ALTER TABLE process_events DROP COLUMN schema_version;
-- ALTER TABLE device_telemetry DROP COLUMN schema_version;
-- ALTER TABLE flow_events DROP COLUMN schema_version;
-- ALTER TABLE security_events DROP COLUMN schema_version;
-- ALTER TABLE peripheral_events DROP COLUMN schema_version;
-- ALTER TABLE metrics_timeseries DROP COLUMN schema_version;
-- ALTER TABLE dns_events DROP COLUMN schema_version;
-- ALTER TABLE audit_events DROP COLUMN schema_version;
-- ALTER TABLE persistence_events DROP COLUMN schema_version;
-- ALTER TABLE fim_events DROP COLUMN schema_version;
