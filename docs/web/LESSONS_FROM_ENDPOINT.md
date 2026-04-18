# Lessons from the Endpoint Build

Things we learned building AMOSKYS for macOS — applied to AMOSKYS Web from
day one so we don't repeat the same mistakes.

This document is written in imperative voice: "do X from day one" or
"never do Y." Every item is grounded in a real issue observed in the
endpoint product.

---

## Lesson 1 — Noise suppression from day 1

**What went wrong on endpoint**: the IGRIS brain has a self-amplifying
feedback loop. `THRESHOLD_INCIDENTS.CRITICAL` fires every 600 seconds because
the metric it measures (`incidents.critical` count) includes incidents
created by itself. 328+ unresolved incidents today, growing linearly. See
[`src/amoskys/igris/NOISE_AUDIT.md`](../../src/amoskys/igris/NOISE_AUDIT.md).

**Rule for web**: the IGRIS-Web signal engine MUST filter self-generated
incidents out of any metric that feeds its own signals. No signal can
observe its own output. Enforce this in code, not just in documentation.

**Rule for web**: every signal type MUST have:
- a dedup window (no repeat within N seconds)
- a decay function (severity drops if no new evidence over M minutes)
- an auto-resolve path (incident closes when underlying condition clears)
- exponential backoff on persistent-condition repeats (don't alert forever
  about a device that's been offline for a week)

**Rule for web**: before IGRIS-Web ships to any customer, write a
load-generator test that runs 10,000 synthetic events through it over 24h
and asserts incident count stays bounded.

---

## Lesson 2 — Multi-tenant first

**What went wrong on endpoint**: the product is single-tenant by design
(internal org fleet). Any authenticated user can see any device's data.
There are no tenant barriers in the schema, the queries, or the middleware.

This is fine for an internal product. It is an existential bug for a
multi-tenant web SaaS.

**Rule for web**: every table with user-affected data has a `tenant_id`
column. Every query joins on `tenant_id` via Postgres row-level security,
not just application code. Application code MUST NEVER write a query that
could accidentally cross tenant boundaries.

**Rule for web**: before the first paying customer, write a test that:
1. Creates two tenants with known site counts
2. Runs every API endpoint as tenant A
3. Asserts tenant A never sees tenant B's data — not even in aggregate
4. Runs the test weekly in CI as a regression guard

**Rule for web**: when adding new tables or queries during development,
think "how does this interact with tenant boundaries?" before thinking
anything else. If the answer isn't immediately obvious, stop and design.

---

## Lesson 3 — AMRDR is a day-1 commitment

**What went wrong on endpoint**: `AMRDR` (adaptive reliability posterior)
is a `NoOpReliabilityTracker`. It's been stubbed since the beginning. The
marketing message claims self-calibrating sensors; the code does not
compute posteriors.

**Rule for web**: AMRDR-Web ships with real math from v1. Even crude math.
A basic Beta-Binomial posterior update after every labeled event is
sufficient to prove the concept. Sophistication comes later.

**Rule for web**: if AMRDR's math is temporarily disabled for any reason,
the marketing surface (docs, dashboard, reports) says so explicitly. No
silent stubs claimed as features.

**Rule for web**: the label flow (Argos finding → Aegis confirmation =
positive; no confirmation in 30 days = negative) is wired from the first
end-to-end test. This is the moat. Do not ship anything claiming
"self-calibrating" until the circle actually closes.

---

## Lesson 4 — Document reality, not aspiration

**What went wrong on endpoint**: `docs/Engineering/v2_architecture/BLUEPRINT.md`
is 400+ lines of aspirational architecture. Some of it matches the code; much
of it does not. The user explicitly flagged this as a problem: "Do not rely
on markdown files — they are not up to date."

**Rule for web**: every doc in `docs/web/` that describes code behavior has
a "reality-check" line at the top:

```markdown
<!-- Last code-verified: 2026-04-18. This doc MUST be re-verified when touching: {file list}. -->
```

**Rule for web**: pre-commit hook grep for docs that reference files touched
in the current PR. If a doc references a touched file but the doc hasn't
been edited in the PR, the PR is flagged (not blocked — reviewer decides).

**Rule for web**: quarterly "docs reality audit" — take every claim in
`docs/web/` and verify against live code or live system. File issues for
every drift.

**Rule for web**: when scope changes, the doc changes FIRST. Never code
without an updated doc. If the doc can't be written clearly, the design
isn't ready to code.

---

## Lesson 5 — Proof Spine is not optional

**What went right on endpoint**: every event is SHA-256 chain-linked.
Tamper-evident. This was the single most important early decision — it's
what makes AMOSKYS's evidence compliant-grade, and it's what differentiates
us from every other security vendor whose logs are mutable WP options or
internal databases.

**Rule for web**: Aegis's events are chain-linked (already implemented).
Argos's phase events are chain-linked. Ingest verifies the chain on arrival.
Dashboard exposes a "verify chain" button that re-runs verification on
demand.

**Rule for web**: if a chain break ever occurs in production, it's a
Pager-Duty-class incident. The whole point of the chain is that breaks are
impossible without tampering. If one happens, something is badly wrong and
we investigate before emitting the next event.

---

## Lesson 6 — Signal vocabulary is versioned and locked early

**What went wrong on endpoint**: new signal types were added ad-hoc as they
came up. Some are deeply typed (`SignalType` enum); others are stringly-
typed (`signal_type: str`). Metric keys have inconsistent casing
(`events.high_1h` vs `THRESHOLD_FLEET.OFFLINE`).

**Rule for web**: the web signal vocabulary is a single Python enum in
`src/amoskys/igris/web/signal_types.py`, added-to only via a proper
migration (add new enum member + write test + bump vocabulary version).

**Rule for web**: all event_type strings match a regex
`^(aegis|argos)\.[a-z_]+\.[a-z_]+$` enforced in the ingest API. New event
types require a schema registration step.

**Rule for web**: schema versioning is explicit. `schema_version: "1"` in
every envelope. When we bump to 2, both are accepted for 90 days minimum.
See [HANDOVER_PROTOCOL.md](./HANDOVER_PROTOCOL.md#schema-versioning).

---

## Lesson 7 — Tests mirror real data, not synthetic

**What went wrong on endpoint**: the endpoint test suite is large but
synthetic-heavy. Many tests construct an artificial TelemetryEvent and
assert a signal fires. They don't catch real-world false-positive flows
because the artificial events are too clean.

**Rule for web**: every signal type has at least one test that replays a
captured-from-lab real event sequence. The lab arena is the source of
truth. Synthetic tests complement, but don't replace, real-data tests.

**Rule for web**: capture Aegis event streams from lab.amoskys.com under
various attack scenarios. Store those captures as test fixtures. Add new
captures when new attacks are added to the arena.

---

## Lesson 8 — The dashboard tells the truth, not marketing

**What went wrong on endpoint**: the dashboard sometimes shows data that
makes the product look more polished than it is (e.g., "CRITICAL posture"
is prominently shown even when the critical count is driven by the
self-amplifying bug from Lesson 1).

**Rule for web**: the dashboard never lies about data quality. If AMRDR
posteriors are low-confidence for a site, the dashboard shows
"calibrating" not "protected." If an incident is suspected false-positive,
it's labeled as such.

**Rule for web**: every number shown on the dashboard has a tooltip
explaining what it measures. If we can't explain it in a tooltip, we
shouldn't be showing it.

---

## Lesson 9 — Don't ship passwords in scripts

**What went right on endpoint**: the repo has `.gitignore` entries for
`.env`, `certs/*.key`, etc. No secrets have leaked historically.

**Rule for web**: same discipline. `install-wordpress.sh` uses `${VAR:?must_set}`
env-var requires — never defaults to a hardcoded password.

**Rule for web**: credentials for lab infrastructure live in `docs/_local/`
(gitignored) or in `~/.claude/` memory. Any file containing real secrets is
either outside the repo or in a gitignored path.

**Rule for web**: if a contributor ever commits real credentials, treat it
as a security incident. Rotate immediately, even if the branch is deleted —
Git history is forever.

---

## Lesson 10 — Small working thing > large broken thing

**What went wrong on endpoint**: several subsystems were built with
ambitious scope and never quite finished. AMRDR is the best example. The
SomaBrain is another. These exist in code, are referenced in docs, and do
partial work in production, but none of them fully deliver what the name
implies.

**Rule for web**: each component ships at a known fidelity level. "Aegis
v0.1α" is honest about being alpha. "Argos v0.1 scaffold" names itself a
scaffold. "AMRDR-Web v0 — basic Beta-Binomial" says what it is. Version
numbers and clear-eyed naming prevent the "works on paper" trap.

**Rule for web**: if a component is incomplete, the dashboard, docs, and
CLI say so. An incomplete component that claims completeness is worse than
not shipping at all.

---

## The one rule that supersedes all of these

**If we're about to make the same mistake we made on endpoint, stop and
ask why.**

All ten of the above are specific instances. The general rule is: the
endpoint product is a source of learning, not a template. Web has different
requirements (multi-tenant, customer-facing, adversarial economics) and
deserves its own architectural decisions, informed by — but not constrained
by — endpoint's choices.

When in doubt, write the rule down before writing the code.
