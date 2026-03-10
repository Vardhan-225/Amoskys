-- Migration 011: Targeted indexes for slow dashboard query methods
--
-- Problem: 5 dashboard endpoints are unacceptably slow:
--   get_device_posture()          — 9.2s  (8 sequential full-table scans)
--   get_fim_stats()               — 5.4s  (COUNT + GROUP BY on 734K rows, no covering index)
--   get_observation_domain_stats()— 2.4s  (COUNT + GROUP BY on 1.08M rows, no composite index)
--   get_flow_stats()              — 1.2s  (7-column aggregate, no covering index)
--   get_persistence_stats()       — 1.2s  (3 sequential queries, no covering indexes)
--
-- Solution: Covering indexes that let SQLite satisfy the queries from the
-- index B-tree alone, without touching the table pages (index-only scans).
-- Also a composite index on observation_events(timestamp_ns, domain) to
-- avoid the post-filter on timestamp_ns when grouping by domain.

-- ══════════════════════════════════════════════════════════════════════
-- 1. get_device_posture  → _query_domain_posture per table
--    Query: SELECT COUNT(*), MAX(timestamp_ns), MAX(risk_col), AVG(risk_col)
--           FROM <table> WHERE timestamp_ns > ?
--
--    Each table needs a covering index on (timestamp_ns, <risk_col>)
--    so the range scan + aggregate can be satisfied from the index alone.
-- ══════════════════════════════════════════════════════════════════════

-- process_events: risk_col = anomaly_score
CREATE INDEX IF NOT EXISTS idx_posture_process
    ON process_events(timestamp_ns, anomaly_score);

-- flow_events: risk_col = threat_score
CREATE INDEX IF NOT EXISTS idx_posture_flow
    ON flow_events(timestamp_ns, threat_score);

-- dns_events: risk_col = risk_score
CREATE INDEX IF NOT EXISTS idx_posture_dns
    ON dns_events(timestamp_ns, risk_score);

-- audit_events: risk_col = risk_score
CREATE INDEX IF NOT EXISTS idx_posture_audit
    ON audit_events(timestamp_ns, risk_score);

-- fim_events: risk_col = risk_score
CREATE INDEX IF NOT EXISTS idx_posture_fim
    ON fim_events(timestamp_ns, risk_score);

-- persistence_events: risk_col = risk_score
CREATE INDEX IF NOT EXISTS idx_posture_persistence
    ON persistence_events(timestamp_ns, risk_score);

-- peripheral_events: risk_col = risk_score
CREATE INDEX IF NOT EXISTS idx_posture_peripheral
    ON peripheral_events(timestamp_ns, risk_score);

-- observation_events: risk_col = risk_score
CREATE INDEX IF NOT EXISTS idx_posture_observation
    ON observation_events(timestamp_ns, risk_score);

-- security_events COUNT for posture endpoint
-- (already has idx_security_timestamp but adding covering index)
CREATE INDEX IF NOT EXISTS idx_posture_security
    ON security_events(timestamp_ns);

-- ══════════════════════════════════════════════════════════════════════
-- 2. get_fim_stats
--    Query 1: SELECT COUNT(*), SUM(CASE change_type=...), SUM(CASE risk_score>0.3)
--             FROM fim_events WHERE timestamp_ns > ?
--    Query 2: SELECT file_extension, COUNT(*)
--             FROM fim_events WHERE timestamp_ns > ? AND file_extension IS NOT NULL
--             GROUP BY file_extension
--
--    Covering index for query 1: (timestamp_ns, change_type, risk_score)
--    Covering index for query 2: (timestamp_ns, file_extension)
-- ══════════════════════════════════════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_fim_stats_covering
    ON fim_events(timestamp_ns, change_type, risk_score);

CREATE INDEX IF NOT EXISTS idx_fim_extension_covering
    ON fim_events(timestamp_ns, file_extension)
    WHERE file_extension IS NOT NULL;

-- ══════════════════════════════════════════════════════════════════════
-- 3. get_observation_domain_stats
--    Query: SELECT domain, COUNT(*)
--           FROM observation_events WHERE timestamp_ns > ?
--           GROUP BY domain
--
--    Covering index on (timestamp_ns, domain) so the range scan + group
--    can use an index-only scan.
-- ══════════════════════════════════════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_observation_domain_ts_covering
    ON observation_events(timestamp_ns, domain);

-- ══════════════════════════════════════════════════════════════════════
-- 4. get_flow_stats
--    Query 1: SELECT COUNT(*), COUNT(DISTINCT dst_ip), SUM(bytes_tx),
--             SUM(bytes_rx), COUNT(DISTINCT geo_dst_country),
--             SUM(CASE threat_intel_match), SUM(CASE is_suspicious)
--             FROM flow_events WHERE timestamp_ns > ?
--    Query 2: SELECT protocol, COUNT(*)
--             FROM flow_events WHERE timestamp_ns > ?
--             GROUP BY protocol
--
--    Covering index for the aggregation query. Include the columns
--    needed to avoid table lookups.
-- ══════════════════════════════════════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_flow_stats_covering
    ON flow_events(timestamp_ns, dst_ip, bytes_tx, bytes_rx,
                   geo_dst_country, threat_intel_match, is_suspicious);

CREATE INDEX IF NOT EXISTS idx_flow_protocol_covering
    ON flow_events(timestamp_ns, protocol);

-- Covering indexes for Network Intelligence dashboard page
-- geo_stats: GROUP BY geo_dst_country
CREATE INDEX IF NOT EXISTS idx_flow_geo_country_covering
    ON flow_events(timestamp_ns, geo_dst_country, bytes_tx, bytes_rx);
-- geo_stats cities: GROUP BY geo_dst_country, geo_dst_city
CREATE INDEX IF NOT EXISTS idx_flow_geo_city_covering
    ON flow_events(timestamp_ns, geo_dst_city, geo_dst_country);
-- ASN breakdown: GROUP BY asn_dst_org
CREATE INDEX IF NOT EXISTS idx_flow_asn_covering
    ON flow_events(timestamp_ns, asn_dst_org, asn_dst_network_type, bytes_tx, bytes_rx);
-- geo_points: GROUP BY geo_dst_latitude, geo_dst_longitude
CREATE INDEX IF NOT EXISTS idx_flow_geopoints_covering
    ON flow_events(timestamp_ns, geo_dst_latitude, geo_dst_longitude, geo_dst_country,
                   geo_dst_city, bytes_tx, bytes_rx, asn_dst_org, threat_intel_match);
-- top_destinations: GROUP BY dst_ip
CREATE INDEX IF NOT EXISTS idx_flow_topdst_covering
    ON flow_events(timestamp_ns, dst_ip, dst_port, protocol, geo_dst_country, geo_dst_city,
                   asn_dst_org, asn_dst_network_type, bytes_tx, bytes_rx, threat_intel_match);
-- by_process: GROUP BY process_name
CREATE INDEX IF NOT EXISTS idx_flow_byprocess_covering
    ON flow_events(timestamp_ns, process_name, bytes_tx, bytes_rx, dst_ip);

-- ══════════════════════════════════════════════════════════════════════
-- 5. get_persistence_stats
--    Query 1: SELECT COUNT(*), SUM(CASE risk_score > 0.3)
--             FROM persistence_events WHERE timestamp_ns > ?
--    Query 2: SELECT mechanism, COUNT(*)
--             FROM persistence_events WHERE timestamp_ns > ?
--             GROUP BY mechanism
--    Query 3: SELECT change_type, COUNT(*)
--             FROM persistence_events WHERE timestamp_ns > ?
--             GROUP BY change_type
--
--    idx_posture_persistence already covers query 1.
--    Add covering indexes for queries 2 and 3.
-- ══════════════════════════════════════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_persistence_mechanism_covering
    ON persistence_events(timestamp_ns, mechanism);

CREATE INDEX IF NOT EXISTS idx_persistence_changetype_covering
    ON persistence_events(timestamp_ns, change_type);

-- Refresh query planner statistics after adding indexes
ANALYZE;
