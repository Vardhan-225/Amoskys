-- Migration 005: Add composite indexes for query performance
-- With 1.8M+ security_events and 1.7M+ fim_events, queries filtering
-- by device_id cause full table scans without these indexes.
-- Expected: 100-1000x speedup on dashboard queries.

-- security_events: device_id composite indexes
CREATE INDEX IF NOT EXISTS idx_security_device ON security_events(device_id);
CREATE INDEX IF NOT EXISTS idx_security_device_timestamp ON security_events(device_id, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_security_device_classification ON security_events(device_id, final_classification, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_security_collection_agent ON security_events(collection_agent, timestamp_ns DESC);

-- fim_events: device_id composite indexes
CREATE INDEX IF NOT EXISTS idx_fim_device ON fim_events(device_id);
CREATE INDEX IF NOT EXISTS idx_fim_device_timestamp ON fim_events(device_id, timestamp_ns DESC);

-- dns_events
CREATE INDEX IF NOT EXISTS idx_dns_device_timestamp ON dns_events(device_id, timestamp_ns DESC);

-- peripheral_events
CREATE INDEX IF NOT EXISTS idx_peripheral_host_timestamp ON peripheral_events(device_id, timestamp_ns DESC);

-- persistence_events
CREATE INDEX IF NOT EXISTS idx_persistence_device_timestamp ON persistence_events(device_id, timestamp_ns DESC);

-- audit_events
CREATE INDEX IF NOT EXISTS idx_audit_device_timestamp ON audit_events(device_id, timestamp_ns DESC);

-- Optimize query planner statistics
ANALYZE;
