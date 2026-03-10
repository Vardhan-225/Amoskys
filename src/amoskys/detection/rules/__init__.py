"""AMOSKYS Detection Rules — Sigma and YARA rule storage.

Directory structure:
    rules/
    ├── sigma/                  # Sigma YAML rules (log-based detection)
    │   ├── credential_access/
    │   ├── command_and_control/
    │   ├── defense_evasion/
    │   ├── discovery/
    │   ├── exfiltration/
    │   ├── execution/
    │   ├── impact/
    │   ├── initial_access/
    │   ├── persistence/
    │   ├── privilege_escalation/
    │   ├── collection/
    │   └── lateral_movement/
    └── yara/                   # YARA rules (file/memory pattern matching)
"""
