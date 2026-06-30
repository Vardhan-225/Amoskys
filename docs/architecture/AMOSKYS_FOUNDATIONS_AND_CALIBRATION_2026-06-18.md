# AMOSKYS — Foundations, the Calibration Build, and the Next Shape
**Date:** 2026-06-18 · **For:** Akash (founder) + future contributors · **Author:** Claude (builder)

> Read this first if you are new to AMOSKYS, or if you are about to change anything in the detection path. It is written as a story with the deep fundamentals underneath, grounded in the *actual* live system and the *actual* code. It also defines the **v0 baseline** — the numbers every future change must be measured against — so progress is provable, not felt.

---

## Part 0 — The story, explained simply

Imagine AMOSKYS is a **guard dog** for a house (your MacBook Air, device `b45045f5e1a0c15e`).

This dog has **incredible ears and eyes**. It hears every car on the street (500,000 network flows), every knock (69,000 DNS lookups), every footstep inside (200,000 process observations). It even writes down everything in a notebook that **can never be secretly edited** — every page is sealed with a wax stamp that links to the page before it (Ed25519 hash-chained signing). No other guard dog in the world keeps a notebook you can *prove* was never tampered with. That notebook is special.

But here is the problem we discovered this week. **The dog never learned who lives in the house.** So when the family comes home, it barks. When the mailman comes, it barks. When a burglar climbs through the window, it… also barks, exactly the same way. It barks at *everything* — which means barking tells you *nothing*. (In real numbers: **98.9% of everything the dog flags, it then quietly labels "probably fine."**)

Worse: the dog has a special nose for break-ins at the back door (persistence — how a burglar makes sure they can get back in tomorrow). But that nose's reports **never reach the dog's brain** (`persistence_events = 0`). So the one thing that *defines* a burglary — leaving a way back in — the dog cannot smell at all.

**This document is about teaching the dog who lives in the house, and then testing it with fake burglars to prove it learned.** That is the whole of detection. Everything else — the probes, the agents, the MITRE labels — is plumbing that carries the dog's senses to its brain. Good plumbing. But plumbing is not judgment.

---

## Part 1 — The fundamentals (with the code that proves each one)

### Fundamental 1 — Observability is *seeing*. Detection is *knowing*.

A camera that records a burglary is **observability**. A guard that *notices the burglary while it happens and shouts* is **detection**. They are different products. AMOSKYS today is an excellent observability/forensics system for the network surface — you could reconstruct an attack after the fact from the signed flows and DNS. It is not yet a detection system, because it cannot tell normal from novel.

The project's own identity notes say *"AMOSKYS = a network organism, not endpoint software."* That instinct is right. But an organism that **sees everything and knows nothing** is a camera, not an immune system. The job ahead is to grow the knowing.

### Fundamental 2 — Detection is fundamentally *"what is normal here?"*

Every real detection is **relative to a baseline**:
- *This process never made a network connection before* → now it does → suspicious.
- *This binary has never run on this host* → now it runs → suspicious.
- *This user never logs in at 3 a.m.* → now they do → suspicious.

Nothing is malicious in the absolute; it is malicious *relative to what is normal for this machine*. This is the single deepest idea in detection.

**The good news, discovered in the code:** AMOSKYS already has the *bones* of this.
- `src/amoskys/intel/scoring.py:582` — `class DeviceBaseline` with `LEARNING` and `DETECTION` modes. In `LEARNING` it records `known_actions`, `known_processes`, `known_suid_files`, `time_profile` (hour-of-day), `known_source_ips` (`scoring.py:601-643`). In `DETECTION` it scores how *known* an event is (`is_known_pattern`, `scoring.py:645`, weighting category/action frequency 40%, source-IP familiarity 20%, time-of-day 20%).
- `src/amoskys/intel/soma.py` — a "dual-hemisphere" memory: LEFT = frequency memory ("what's normal for THIS machine"), RIGHT = statistical z-score. It emits verdicts `familiar / learning / novel / anomalous` (`soma.py:121`) and tracks maturity `cold_start → learning → baseline → mature` at 100 unique patterns (`soma.py:162`).

**The bad news — why it doesn't work yet:** the baseline is **per-device, not per-entity**. It knows "this device has seen category=process_spawned before," which is true for almost everything, so almost everything scores as *known → legitimate*. It does **not** model "*this specific process* has never talked to *this specific destination*" — which is where attacks actually show up. The granularity is too coarse to separate a burglar from the mailman.

### Fundamental 3 — The "two risk numbers" bug (the precise reason judgment looks broken)

This is the sharpest, most fixable finding. There are **two different risk numbers** in the system and the system consumes the wrong one:

1. **The probe's raw `risk_score`** — hardcoded by the detector that fired. The DNS-beaconing probe stamps `0.9998` on *every* periodic DNS lookup, including Apple's and Google's.
2. **The scoring engine's verdict** — `scoring.py:1180-1202` computes `composite_score` from the geometric/temporal/behavioral baselines and derives `final_classification` (`malicious / suspicious / legitimate`). For those same Apple/Google lookups, it *correctly* concludes `legitimate`.

**The bug:** the row stored in `security_events` and consumed by the brain carries the **probe's raw `0.9998`**, while the scorer's wiser `legitimate` verdict is computed and then **ignored**. That is why, live, we see `risk_score=0.9998` sitting next to `final_classification='legitimate'` on the same event. The default itself is biased toward silence too — `scoring.py:993` sets `final_classification = "legitimate"` as the starting point.

So "the judgment is broken" is too harsh. The judgment is *computed correctly and then thrown away.* Re-wiring which number we trust is a surgical fix, not a rebuild.

### Fundamental 4 — Calibration needs a *teacher*, and we never hired one

`src/amoskys/intel/scoring.py:1211` — `def recalibrate(category, action, is_false_positive)`. It already exists. Feed it a false positive → it raises that pattern's threshold (`-0.02`); feed it a true positive → it lowers it (`+0.01`), and it forwards the outcome to `DynamicThresholds` (`scoring.py:1227`). Likewise `src/amoskys/intel/probe_calibration.py` is a Beta-Binomial precision tracker (`weight = α/(α+β)`, `risk_score *= weight`) designed to down-weight chronically-noisy probes.

**The machinery to learn from feedback is fully built. It has simply never been given a single labeled example.** No one ever told the system "*that* was an attack, *that* was benign." With no teacher, every probe keeps its benefit-of-the-doubt weight, every threshold stays put, and the noisy DNS-beaconing probe is treated as credible as a real C2 detector. **The teacher is the evaluation harness** — and that is the keystone of the whole build.

### Fundamental 5 — The notebook nobody else has (the moat)

`src/amoskys/agents/common/queue_adapter.py:27-71` — Ed25519 envelope signing with per-agent key resolution (`certs/agents/{agent}.ed25519`, shared fallback), producing `content_hash → sig → prev_sig` (a hash chain). Verified live this session: a sampled queue showed `sig` 89/89, `prev_sig` 87/89, `content_hash` 89/89. **Every observation is cryptographically provable from the moment of capture, in order, untampered.** CrowdStrike, SentinelOne, and Defender secure the *pipe* and trust the backend — they cannot *prove* an individual event. AMOSKYS can. Hold onto this; it is the wedge.

---

## Part 2 — The v0 baseline (measure everything against this)

These are the **current, measured facts** as of 2026-06-18. The purpose of writing them down is brutal and simple: **so that any future change can prove it helped.** A claim of "detection improved" is meaningless without these numbers to beat.

| Dimension | v0 metric (today) | Source |
|---|---|---|
| Tactics that would raise an alert | **0 of 12** | 15-agent adversarial coverage audit |
| Adversarially-confirmed detections | **0** (2 claims tested, both OVERSTATED) | coverage audit, Verify phase |
| Events self-classified "legitimate" | **98.9%** (~100% of high-risk band) | live `security_events` |
| `threat_intel_match` hit rate | **0 / 4,612** events | live `flow_events` + `security_events` |
| Persistence visibility at brain | **0** events (52 MB collected on-agent, 0 shipped) | live `fleet.db` + queue |
| Risk ↔ classification coupling | **decoupled** — probe raw risk stored, scorer verdict ignored | `scoring.py:1190-1202` |
| Host-surface exec capture (osascript/curl/python) | **0** captured in 7 days (polling, no ESF) | live `process_events` |
| Data coverage (eyes) | network = good; host/kernel = blind | coverage audit |
| Telemetry integrity | **signed at source** (`sig` 89/89), **stripped at rest** in fleet | `queue_adapter.py`; live `fleet.db` |
| Analyzer throughput | caught up, ms-scale steady-state cycles, 0 backlog rows | live analyzer log |
| Incident loop | **0 unresolved** (held 24h; was 21,513) | live `fleet.db` |

**How to use this table:** every PR that touches detection appends a row to a running `EVAL_RESULTS.md` with the same metrics on the same fixtures, so the delta is visible. Detection that cannot be measured does not count.

---

## Part 3 — The concrete build: adversary-first calibration + per-entity baselines + an evaluation harness

Designed adversary-first this time: we start from *what an attacker does*, define the *entity* and the *anomaly* that betrays it, and build the smallest mechanism that separates it from normal — then prove it with the harness.

### 3.1 — Per-entity baselines (extend, don't replace)

Generalize the existing `DeviceBaseline` (`scoring.py:582`) into an **`EntityBaseline`** keyed not by device but by the entity that actually matters for the technique:

| Entity key | Models the question | Catches |
|---|---|---|
| `process_name` → set of `dst_asn` | "has this process ever talked to this network?" | C2, exfil from a normally-offline process |
| `process_name` → set of child `exe` | "has this parent ever spawned this child?" | LOLBin abuse, ClickFix `Terminal → curl` |
| `dst_domain` → first-seen time + freq | "is this a brand-new domain for this host?" | phishing/C2 staging domains |
| `user` → login hour histogram | "does this user log in at this hour?" | account misuse, off-hours access |
| `exe` → first-seen + signing status | "has this binary ever run here?" | dropped payloads, trojanized installers |

Each baseline emits three calibrated signals already understood by the codebase: **novelty** (first-seen), **rarity** (frequency percentile), **deviation** (z-score vs the entity's own history — reuse SOMA's RIGHT hemisphere). The composite of these *replaces the probe's hardcoded `risk_score`* as the number we store and trust.

### 3.2 — Reconcile the two risk numbers (the surgical fix)

In the analyzer's per-event path (`analyzer_main.py`, after `scorer.score_event`), make the **scorer's verdict authoritative**:
```
final_risk = reconcile(probe_risk, composite_score, final_classification, entity_signals)
# rule: a 'legitimate' classification CAPS risk low; 'malicious' floors it high;
# the stored risk_score is final_risk, not the probe's raw stamp.
```
This single change converts the existing-but-ignored judgment into the consumed judgment. Expected effect on v0: the high-risk band stops being ~100% "legitimate."

### 3.3 — The evaluation harness (the teacher, and the moat seed)

A small, self-contained attack range that turns detection from a feeling into a number:

1. **Fixtures** — a labeled corpus: `benign/` (real captured normal events from this device) + `attack/` (synthetic-but-realistic events per technique: a `Terminal→curl|bash` ClickFix, a process's first connection to a fresh ASN, a new LaunchAgent, a keychain read). Each labeled `{technique, expect: detect|ignore}`.
2. **Runner** — replays each fixture through the *real* `ScoringEngine` + `EntityBaseline` and records the produced `final_classification` + `final_risk`.
3. **Scorecard** — computes, per technique and overall: **detection rate** (attacks that fired), **false-positive rate** (benign that fired), **precision/recall**. Writes a dated row to `EVAL_RESULTS.md`.
4. **The loop** — every miss/FP is fed to the *existing* `recalibrate()` (`scoring.py:1211`) and `probe_calibration` (Beta-Binomial). Re-run. Watch the scorecard move. **That is calibration with a teacher.**

**Why this is the moat (B):** every labeled fixture is proprietary data describing *what an attack looks like in cryptographically-signed telemetry* — a dataset no competitor can generate, because no competitor has signed telemetry to label. The harness is not just a test; it is the data factory.

---

## Part 4 — Making the "table stakes" defensible

Be ruthless: probe count (166), agent breadth, MITRE mapping, Sigma rules, "AI detection," the tiered architecture — **all table stakes; incumbents do every one better.** The detection engine today is broken. None of that is a moat. Defensibility comes from *recombining* assets into a position incumbents structurally won't take:

- **A — Tamper-evident evidence as the product (the wedge).** Stop competing on "did we catch it." Own "*can you prove what happened*." Markets where evidence integrity *is* the value: forensic/legal chain-of-custody, cyber-insurance claims, breach attribution, regulated industries. Backed by `queue_adapter.py` signing — which already exists. (To complete it, carry `sig`/`content_hash` into `fleet.db`, which currently strips them — see v0 baseline.)
- **B — Proprietary adversary-labeled dataset + AI-native eval loop (the compounding moat).** Built by §3.3. Every technique tested becomes proprietary calibration + training data on signed telemetry. It compounds; models and probe counts do not.
- **Velocity — AI-native deep-rebuild.** Real today (this session audited, re-architected, and adversarially self-tested a 38k-LOC system in days). Temporary — assume it commoditizes; use it to reach A and B first.

**The moat is the compound, not a feature:** *the only security org whose evidence is provable (A), sitting on the only adversary-labeled dataset of signed telemetry (B), reached faster than anyone notices the lane (velocity).* And it is credible — not a pitch deck — precisely because we now know, with adversarially-verified evidence, exactly where we are blind and why. A moat built on self-honesty is the only kind that holds.

---

## Part 5 — The shape AMOSKYS has taken, and the shape it becomes next

**Current shape — "The Sentinel that sees all and knows nothing."**
A superb signed nervous system; excellent network-surface eyes; a blind host surface; judgment that is computed correctly and then discarded; a teacher never hired. An *observability organism* wearing a detection costume. Honest, now, about both.

**Next shape — "The Immune System."**
The transformation is not more collection. It is three moves, in order:
1. **Re-wire judgment** (§3.2) — trust the verdict we already compute. *Cheapest, biggest single gain.*
2. **Grow per-entity memory** (§3.1) — learn who lives in the house, per process / destination / user.
3. **Hire the teacher** (§3.3) — the eval harness that measures, calibrates, and quietly becomes the moat.

An immune system does not see *more* than a camera. It *knows what is self and what is not*, it *acts*, and it *remembers what it learned* — and in our case, it can *prove every cell it ever saw*. That is the shape: from *sees-all/knows-nothing* to *sees-what-matters / proves-what-it-knows*.

> Build order for the next session: (1) reconcile risk (§3.2) + stand up the eval harness skeleton (§3.3) so we have a v0 scorecard, (2) ship the first `EntityBaseline` (process→ASN), (3) measure the delta against Part 2. Nothing counts until the scorecard moves.
