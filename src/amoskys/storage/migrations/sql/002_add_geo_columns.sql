-- UP
-- A4.1/A4.2: Add GeoIP and ASN columns to flow_events and security_events.

ALTER TABLE flow_events ADD COLUMN geo_src_country TEXT;
ALTER TABLE flow_events ADD COLUMN geo_src_city TEXT;
ALTER TABLE flow_events ADD COLUMN geo_src_latitude REAL;
ALTER TABLE flow_events ADD COLUMN geo_src_longitude REAL;
ALTER TABLE flow_events ADD COLUMN geo_dst_country TEXT;
ALTER TABLE flow_events ADD COLUMN geo_dst_city TEXT;
ALTER TABLE flow_events ADD COLUMN geo_dst_latitude REAL;
ALTER TABLE flow_events ADD COLUMN geo_dst_longitude REAL;
ALTER TABLE flow_events ADD COLUMN asn_src_number INTEGER;
ALTER TABLE flow_events ADD COLUMN asn_src_org TEXT;
ALTER TABLE flow_events ADD COLUMN asn_src_network_type TEXT;
ALTER TABLE flow_events ADD COLUMN asn_dst_number INTEGER;
ALTER TABLE flow_events ADD COLUMN asn_dst_org TEXT;
ALTER TABLE flow_events ADD COLUMN asn_dst_network_type TEXT;

ALTER TABLE security_events ADD COLUMN geo_src_country TEXT;
ALTER TABLE security_events ADD COLUMN geo_src_city TEXT;
ALTER TABLE security_events ADD COLUMN geo_src_latitude REAL;
ALTER TABLE security_events ADD COLUMN geo_src_longitude REAL;
ALTER TABLE security_events ADD COLUMN asn_src_number INTEGER;
ALTER TABLE security_events ADD COLUMN asn_src_org TEXT;
ALTER TABLE security_events ADD COLUMN asn_src_network_type TEXT;

-- DOWN
-- SQLite < 3.35 cannot DROP COLUMN.
