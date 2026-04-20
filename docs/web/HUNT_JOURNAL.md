# AMOSKYS Web — Hunt Journal

**Purpose.** A living, append-only log of every red-team cycle we run.
Each cycle: what we attacked, what tools we used, what we found, what
Aegis caught, what Aegis missed, and what we learned. The whole point
of the offense+defense competition is this journal — the learning
loop that makes Argos stronger and makes Aegis smarter in lockstep.

**Discipline.**
- Every cycle is dated + targeted + scoped before it runs.
- Every finding is tagged: detected-by-Aegis, missed-by-Aegis, noisy.
- Every "missed" finding becomes an Aegis-sensor ticket.
- Every repro step is captured so anyone can re-run.
- Nothing in this document implies authorization to hit third-party
  targets. Stage-2 actions only against consented targets.

**Target profile we're calibrating against.** The lab — a production
WordPress install on `lab.amoskys.com` with Aegis v1.3 installed
(37 event types live, 9 strike rules). If something breaks Aegis
here, commercial WordPress sites will be just as exposed.

---

## Cycle log

### Cycle 001 — 2026-04-20 · Kali → lab.amoskys.com
**Operator:** Argos from Kali VM (ghostops@ghost-Spectre, ARM64)
**Target:** lab.amoskys.com (our own lab — consent via `AMOSKYS_CONSENT_DOMAIN`)
**Attacker IP seen by Aegis:** 38.2.43.171 (Mac public IP — Kali NATs through the host)
**Pipeline:** wpscan → nuclei (tag=wordpress) → nikto (tuning=234)

#### Setup
- Kali MCP server launched at `127.0.0.1:8445` on the VM.
- 6 `kali_*` MCP tools registered: wpscan, sqlmap, nikto, ffuf, nuclei,
  amass, hunt_journal.
- `AMOSKYS_CONSENT_DOMAIN=lab.amoskys.com` set on the server so every
  tool call against the lab is legally covered by standing consent.
- Before the run: whitelist cleared, transients flushed on the lab
  (Aegis state reset to cold).

#### Mid-run observation (5 min in)
Aegis is reacting aggressively:
| Signal | Count (last 5 min) |
|---|---|
| `aegis.capability.denied` | 155 |
| `aegis.block.enforced` (403s returned to wpscan) | 28 |
| `aegis.nonce.failed` | 6 |
| `aegis.query.event` | 99 |
| `aegis.options.updated` | 17 |

The scan is being partially blocked — 28 HTTP 403s returned to wpscan
already. Most likely our `priv_esc` strike rule tripped (threshold 3
capability-denied in 60s). That means: wpscan's unauth plugin-
enumeration hits `/wp-admin/*.php` files, each trips one
`capability.denied`, three in 60s blocks the IP for 10 min. This is
the defense working as designed AGAINST a real offensive scanner.

**Observation for Aegis team:** the block is too aggressive for a
consented pentest. In Stage-2 engagements the operator should be
able to scope a per-IP bypass without disabling the whole detection
chain. Action item: add a "pentest-mode" IP allow-list that suppresses
BLOCK but keeps emitting the events (we still want to see the coverage).

#### Tools run (results populate after scan completes)
_in progress — cycle driver is running, results will be appended_

---

## Findings-to-fix ledger

| # | Date | Finding | Detected-by-Aegis? | Fix (sensor to add) |
|---|---|---|---|---|
| | | | | |

## Bug-bounty candidates discovered

| # | Plugin/target | Class | Severity | Status |
|---|---|---|---|---|
| | | | | |

---

## Open questions

_Add things we don't know yet; close them as we learn._

