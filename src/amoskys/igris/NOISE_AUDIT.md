# IGRIS Noise Audit — April 2026

Status: diagnosis only. Code fixes not yet applied.

## The observed behavior

As of live fleet state at 2026-04-18 08:43 UTC:

- Brain cycle count: **3,605** (60.1h uptime, stable)
- Unresolved critical incidents: **328 and climbing**
- Recent signal pattern (last 10 min window):

  | Time (UTC) | Signal | dedup_key |
  |-|-|-|
  | 08:09 | FLEET_ANOMALY_EVENTS.FRESHNESS_S | `FRESHNESS_S:medium` |
  | 08:13 | THRESHOLD_FLEET.OFFLINE | `OFFLINE:medium` |
  | 08:13 | THRESHOLD_INCIDENTS.CRITICAL | `INCIDENTS.CRITICAL:critical` |
  | 08:23 | THRESHOLD_FLEET.OFFLINE | same key |
  | 08:23 | THRESHOLD_INCIDENTS.CRITICAL | same key |
  | 08:33 | (same pair) | |
  | 08:43 | (same pair) | |

  Pattern: **two signals firing on a perfect 600s cadence**, each creating a new incident, for at least the last 60 hours.

## Root cause: self-amplifying feedback loop

```
Benitha's MBP offline
       │
       ▼
  THRESHOLD_FLEET.OFFLINE fires (cooldown = 600s, so once per 10 min)
       │
       ▼
  (no incident created for this one — just an alert)

Unresolved incident count starts at N
       │
       ▼
  THRESHOLD_INCIDENTS.CRITICAL fires (cooldown = 600s)
       │
       ▼
  Creates a new incident → count becomes N+1
       │
       ▼
  10 min later: THRESHOLD_INCIDENTS.CRITICAL re-evaluates, sees count is higher,
  fires again, creates another incident → count becomes N+2
       │
       ▼
  Loop runs every 10 minutes forever.
  328 incidents today, ~1,050 by end of week if nothing changes.
```

The brain is **measuring its own output**. Every firing of THRESHOLD_INCIDENTS.CRITICAL adds one more unresolved incident, which guarantees the next firing will see a higher count. Cooldown can't save you here because every invocation IS legitimately different data — the count keeps climbing.

## Source locations

| Issue | File | Line |
|---|---|---|
| Cooldown constant | `src/amoskys/igris/supervisor.py` | `SIGNAL_COOLDOWN_S = 600` (line ~93) |
| Dedup key construction | `src/amoskys/igris/signals.py` | `_post_init_` (lines 59-67) |
| Cooldown gate logic | `src/amoskys/igris/supervisor.py` | `_observe_cycle` step 4 (lines 314-323) |
| No auto-resolve on condition clear | (nowhere — doesn't exist) | |

## Proposed fixes, in order of impact

### Fix 1 — exclude self-generated incidents from the count *(highest impact)*

The `incidents.critical` metric that feeds `THRESHOLD_INCIDENTS.CRITICAL` should filter out incidents whose `signal_type == 'THRESHOLD_INCIDENTS.CRITICAL'`. Otherwise the brain is measuring its own firing rate.

**Change surface**: wherever `incidents.critical` is computed in the metric collector. Probably one-line filter add.

**Expected outcome**: feedback loop breaks; `incidents.critical` reflects only real security incidents, not alert fatigue.

### Fix 2 — auto-resolve incidents when underlying condition clears

Incidents created from threshold signals should carry their `dedup_key` and be auto-resolved when:
- The threshold signal hasn't fired for N cooldown windows (underlying condition no longer true), AND
- No new evidence has been added to the incident.

Example: if Benitha's MBP comes back online, all `THRESHOLD_FLEET.OFFLINE` incidents should auto-close within one cooldown window.

**Change surface**: new `_sweep_resolved_incidents()` step in `_observe_cycle`, probably 30-50 lines.

**Expected outcome**: incident count naturally decays instead of monotonically growing.

### Fix 3 — exponential backoff on repeat suppression

Current: 600s cooldown, infinitely repeating. Proposed: 600s, 1800s, 3600s, 14400s, 86400s (cap at 24h). If the same dedup_key has fired N times in a row without resolution, the admin clearly already knows; stop telling them.

**Change surface**: `IgrisState.should_emit()` needs to track repeat count per dedup_key and apply escalating backoff.

**Expected outcome**: noisy persistent alerts (like an offline device that stays offline) fall silent after ~3 hours, come back loud only if conditions change.

### Fix 4 — dedup_key should distinguish "same problem re-observed" from "new problem of same class"

Current key: `{signal_type}:{metric_name}:{agent_id}`. For `THRESHOLD_INCIDENTS.CRITICAL` that's always `THRESHOLD_INCIDENTS.CRITICAL::fleet` — a single global key. So even if the critical incidents are completely different in nature, they dedup together. Fine for the amplification bug but lossy as a signal.

**Proposed v2 key**: include a content hash of the top-3 contributing incidents. Different underlying incidents = different dedup_key = both can fire.

**Change surface**: `IgrisSignal.__post_init__` plus whatever builds the raw signals.

**Expected outcome**: threshold signals fire once per distinct contributing incident set, not once per time window.

## Impact on the web pivot

This matters for AMOSKYS Web because:

1. **Aegis will emit 100-1000+ events per minute on a busy WP site.** The brain's incident-count threshold will pin at CRITICAL within an hour on ANY real customer, using the current logic.

2. **AMRDR is stubbed so we can't say "this rule is unreliable, deprioritize."** All signals weight 1.0. Which means "noisy threshold with feedback loop" is indistinguishable from "credible detection."

3. **The Argos Redemption Agent will ship synthetic attack events specifically to train IGRIS.** If the brain amplifies instead of dedups, Argos becomes a noise generator, not a label source.

**Recommendation**: Fix 1 is a ~1 hour change and directly unblocks the web pivot. Do it before enrolling lab.amoskys.com as fleet device #3. Fix 2 is a 1-day change, also before web enrollment. Fixes 3 and 4 can happen after.

## Reproducing the audit

```bash
# Pull current brain state
curl http://localhost:8444/resources/fleet/brain   # or via MCP ReadMcpResourceTool

# Count incidents by signal_type
sqlite3 /var/lib/amoskys/fleet.db "
  SELECT signal_type, COUNT(*) FROM fleet_incidents
  WHERE status='unresolved'
  GROUP BY signal_type ORDER BY 2 DESC;
"
```
