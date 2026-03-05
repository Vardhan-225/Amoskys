-- UP
-- A4.4: Track enrichment pipeline status per security event.
-- Enables IGRIS to detect enrichment failures and SOMA to filter by enrichment quality.

ALTER TABLE security_events ADD COLUMN enrichment_status TEXT DEFAULT 'raw';

CREATE INDEX IF NOT EXISTS idx_security_enrichment ON security_events(enrichment_status);

-- DOWN
-- SQLite < 3.35 cannot DROP COLUMN.
