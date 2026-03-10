# AMOSKYS Ops Storyline Report

- Generated at: `2026-03-08T07:49:21.752929+00:00`
- Overall gate: `FAIL`
- Positioning tier: `Foundational`

## Collection

- Collect success: `True`
- Collect elapsed seconds: `3.92`
- Collect timed out: `False`
- Queue drain mode: `skip`
- Queue drain max events: `5000`
- Queue drain timeout seconds: `90.0`

## Detection Simulation

- Scenario pass rate: `0%`
- Positive detection rate: `0%`
- Benign false-positive rate: `0%`
- Reality level average: `n/a`
- MITRE techniques covered in scenarios: `0`

## ML Training

- SOMA status: `unknown`
- Events seen by trainer: `n/a`
- Train elapsed seconds: `n/a`

## Coverage & Contracts

- Probe proof: `0%`
- Surface coverage: `0%`
- Probe audit broken/error: `0/0`

## Gate Checks

- `redteam_pass_rate`: `0.0` vs target `95.0` => `FAIL`
- `positive_detection_rate`: `0.0` vs target `95.0` => `FAIL`
- `benign_false_positive_rate`: `100.0` vs target `5.0` => `FAIL`
- `probe_proof_rate`: `0.0` vs target `80.0` => `FAIL`

## Notes

- This report measures current architecture behavior; no probe-discovery migration assumptions are used.
- Use this as the release gate for simulation readiness before architectural consolidation.

