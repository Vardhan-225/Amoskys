-- AMOSKYS fleet_cache.db read-path indexes (2026-07-01)
-- Cuts the Command dashboard's build_model() from ~1.3s to ~140ms on the 50MB
-- production DB by covering the globe GROUP BY and the timestamp range scans.
-- Safe/idempotent, data-preserving. Apply with:
--   sqlite3 /opt/amoskys/data/fleet_cache.db < scripts/fleet_cache_indexes.sql
CREATE INDEX IF NOT EXISTS idx_flow_geo ON flow_events(geo_dst_latitude, geo_dst_longitude, asn_dst_org);
CREATE INDEX IF NOT EXISTS idx_flow_ts  ON flow_events(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_sec_ts   ON security_events(timestamp_ns);
ANALYZE;
