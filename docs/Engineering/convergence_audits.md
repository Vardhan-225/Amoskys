# Convergence Audit Commands

Use these scripts to enforce architecture convergence without touching runtime code paths.

## 1) Agent Data-Quality Scorecard

```bash
python scripts/convergence/agent_quality_scorecard.py --platform darwin --json
```

What it checks:
- probe contract completeness (`requires_fields`, `requires_event_types`)
- field semantics coverage
- observation `_domain` to canonical router mapping
- likely drop points per probe and per agent

## 2) Dashboard/API Direct SQL Inventory

```bash
python scripts/convergence/dashboard_sql_inventory.py --json
```

What it checks:
- route handlers that use `store.db.execute` or `sqlite3.connect`
- telemetry table exposure by route function
- suggested `DashboardQueryService` methods for migration

CI mode:

```bash
python scripts/convergence/dashboard_sql_inventory.py --fail-on-findings
```

## 3) Training Gate Audit

```bash
python scripts/convergence/training_gate_audit.py --json
```

What it checks:
- SQL reads from `security_events` in ML code
- presence of `quality_state` and `training_exclude` filters

CI mode:

```bash
python scripts/convergence/training_gate_audit.py --fail-on-violation
```

## 4) MITRE Provenance Audit

```bash
python scripts/convergence/mitre_provenance_audit.py --db data/telemetry.db --json
```

What it checks:
- MITRE declared coverage (`mitre_techniques`)
- provenance completeness (`mitre_source`, `mitre_confidence`)
- explainability evidence (`mitre_evidence`)

CI threshold mode:

```bash
python scripts/convergence/mitre_provenance_audit.py --min-explainable-pct 95
```

## 5) Combined Conformance Gate

```bash
python scripts/convergence/ci_conformance.py --json
```

What it checks:
- forbidden `scan_all_probes()` use in agent code
- legacy schema references outside ingress boundary
- route-level direct SQL findings

CI mode:

```bash
python scripts/convergence/ci_conformance.py --strict
```
