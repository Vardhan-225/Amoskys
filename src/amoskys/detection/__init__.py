"""AMOSKYS Detection-as-Code Framework.

Provides Sigma and YARA rule evaluation against AMOSKYS telemetry events.
Rules are stored in `detection/rules/sigma/` and `detection/rules/yara/`
organized by MITRE ATT&CK tactic.

Components:
    SigmaEngine    — Evaluate Sigma YAML rules against TelemetryEvents
    YARAEngine     — YARA rule scanning for file/memory detection
    DetectionLifecycle — Rule lifecycle: create → test → deploy → tune → retire
"""
