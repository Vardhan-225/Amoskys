-- Migration 014: Signals layer + Incident workflow extensions
--
-- Creates the signals table (intermediate object between detection and incident)
-- and extends the incidents table with workflow columns.
--
-- Signals are the "complement cascade recognition phase" — candidate incidents
-- that require triage before becoming full investigations.
--
-- Directive 3 of the Four-Directive Engine Plan.

-- ── Signals table ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signal_id TEXT UNIQUE NOT NULL,
    device_id TEXT NOT NULL,
    created_ns INTEGER NOT NULL,
    signal_type TEXT NOT NULL,           -- 'kill_chain', 'threshold', 'anomaly_burst', 'coherence', 'manual'
    trigger_summary TEXT NOT NULL,       -- human-readable: "3 MITRE phases on device X"
    contributing_event_ids TEXT NOT NULL, -- JSON array of security_event IDs
    risk_score REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- 'open', 'promoted', 'dismissed', 'expired'
    promoted_to_incident INTEGER,       -- incidents.id if promoted
    dismissed_by TEXT,
    dismissed_reason TEXT,
    updated_ns INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signals_device
    ON signals(device_id, created_ns DESC);
CREATE INDEX IF NOT EXISTS idx_signals_status
    ON signals(status, created_ns DESC);
CREATE INDEX IF NOT EXISTS idx_signals_type
    ON signals(signal_type, created_ns DESC);

-- ── Incident workflow extensions ─────────────────────────────────────────

-- Add workflow columns to existing incidents table (idempotent with IF NOT EXISTS pattern)
-- SQLite doesn't support IF NOT EXISTS on ALTER TABLE, so we use a safe approach

ALTER TABLE incidents ADD COLUMN signal_ids TEXT;
ALTER TABLE incidents ADD COLUMN assigned_to TEXT;
ALTER TABLE incidents ADD COLUMN investigation_notes TEXT;
ALTER TABLE incidents ADD COLUMN timeline_events TEXT;
ALTER TABLE incidents ADD COLUMN containment_actions TEXT;
ALTER TABLE incidents ADD COLUMN resolution_summary TEXT;
ALTER TABLE incidents ADD COLUMN sla_deadline_ns INTEGER;
ALTER TABLE incidents ADD COLUMN last_activity_ns INTEGER;
