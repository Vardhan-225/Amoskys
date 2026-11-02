-- WHY a verdict is what it is, kept next to the verdict.
--
-- The scorer already builds score_factors — a list of {name, contribution,
-- detail} recording every input that moved the number, including the one that
-- matters most:
--
--     {"name": "Independent Corroboration",
--      "detail": "Cap lifted — corroborated by: downloaded_and_untrusted,
--                 kernel_would_deny_on_download, novel_downloaded_binary ..."}
--
-- It was never persisted. On 2026-09-02 a live downloaded dropper produced the
-- first end-to-end MALICIOUS verdict on this machine (execute_to_exfil, pid
-- 14370, composite 0.70) and the stored row carried risk_score=0.7,
-- final_classification=malicious, and indicators='{}'. The number survived and
-- every reason for it was discarded at the moment of writing.
--
-- That is the wrong thing to lose. A malicious verdict is exactly the row
-- someone will be asked to defend — weeks later, to someone who was not there.
-- Without the factors the only available proof is indirect: "an uncorroborated
-- execute_to_exfil is capped at 0.40, this reads 0.70, therefore corroboration
-- must have fired." That reasoning is sound and it is not evidence — it asks a
-- reviewer to trust the gate math instead of showing them the witnesses.
--
-- TEXT holding JSON rather than typed columns: the factor list is heterogeneous
-- and its shape follows the scorer, which changes far more often than this
-- schema should.
--
-- NULL is meaningful and distinct from '[]'. NULL means this row predates the
-- column or was written by a path that does not score; '[]' means the scorer
-- ran and found nothing to say. Collapsing them would make "not recorded"
-- indistinguishable from "nothing contributed", and the second reads as an
-- explanation when it is an absence.
ALTER TABLE security_events ADD COLUMN score_factors TEXT;

-- Partial: the rows anyone reconstructs under pressure are the ones that
-- accused something, not the overwhelming majority that cleared it.
CREATE INDEX IF NOT EXISTS idx_security_events_scored_malicious
    ON security_events(timestamp_ns DESC)
    WHERE final_classification = 'malicious';
