# AMOSKYS Operations Runbook

## Purpose
This runbook defines one operational storyline for the current architecture (no migration assumptions):

1. Collect real telemetry through agents and WAL pipeline
2. Train SOMA on stored telemetry
3. Validate detection using red-team simulation scenarios
4. Score probe proof and contract health
5. Produce a positioning report with release gates

The objective is to keep all current refactors working in harmony with measurable outcomes.

## Primary Command
Run the full storyline:

```bash
python scripts/run_ops_storyline.py --clear-db --strict
```

Default safety controls in this command:

- collect step timeout: `--collect-timeout-seconds 900`
- queue drain budget: `--drain-max-events 5000`
- queue drain timeout: `--drain-timeout-seconds 90`

Outputs:

- `results/ops_storyline/ops_storyline_report.json`
- `results/ops_storyline/ops_storyline_report.md`
- `results/ops_storyline/collect.stdout.log`
- `results/ops_storyline/collect.stderr.log`
- `results/ops_storyline/coverage.stderr.log`

## What the storyline executes

1. `scripts/collect_and_store.py`
- Runs current macOS observatory collectors and probes.
- Routes events through WAL Processor (`enrichment -> scoring -> fusion -> storage`).

2. `SomaBrain.train_once()`
- Trains ML models from `data/telemetry.db`.
- Uses current safeguards (high-trust label policy, calibration, persisted artifacts).

3. Red-team suite (`amoskys.redteam.harness`)
- Runs all registered adversarial scenarios.
- Computes simulation metrics:
  - case pass rate
  - positive detection rate
  - benign false-positive rate
  - scenario reality score (L0-L3)

4. Coverage scorecard (`scripts/eoa/coverage_scorecard.py --json`)
- Captures probe proof and surface coverage.

5. Probe audit (`src/amoskys/observability/probe_audit.py`)
- Captures contract-health snapshot (`BROKEN`, `ERROR`, etc.).

## Gate policy (default)
The storyline gates are:

- `redteam_pass_rate >= 95%`
- `positive_detection_rate >= 95%`
- `benign_false_positive_rate <= 5%`
- `probe_proof_rate >= 80%`

Override thresholds if needed:

```bash
python scripts/run_ops_storyline.py \
  --min-redteam-pass 92 \
  --min-positive-detection 92 \
  --max-benign-fp 8 \
  --min-probe-proof 75
```

## Common run modes

Fast diagnostics (skip collection/training):

```bash
python scripts/run_ops_storyline.py --skip-collect --skip-train
```

Collection-only validation:

```bash
python scripts/run_ops_storyline.py \
  --skip-train --skip-redteam --skip-coverage --skip-audit
```

Train-only validation:

```bash
python scripts/run_ops_storyline.py --skip-collect --skip-redteam --skip-coverage --skip-audit
```

If collection appears slow due queue backlog, tune drain behavior:

```bash
python scripts/run_ops_storyline.py \
  --drain-max-events 1000 \
  --drain-timeout-seconds 30 \
  --collect-timeout-seconds 600
```

To bypass queue draining entirely for a clean probe-only pass:

```bash
python scripts/run_ops_storyline.py --skip-drain
```

## Interpretation guidance

If gates fail, check in this order:

1. `collect.stderr.log` for collector/probe runtime faults.
2. `soma.status` in JSON report:
- `completed`: training succeeded.
- `cold_start`: insufficient data/labels (pipeline is running but model is not yet fully trainable).
3. Red-team section for category-specific failures:
- positive misses => detection gaps
- benign failures or benign events > 0 => false-positive pressure
4. Probe audit counts:
- `broken > 0` or `error > 0` => contract/import drift blocking reliability

## Operational recommendation
Use this storyline report as the release gate while you keep full-context collection enabled.
After detection quality is stable, you can move to selective probe discovery and data-volume optimization without losing baseline confidence.
