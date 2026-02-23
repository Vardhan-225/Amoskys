# Changelog

## v0.9.0-beta.1 (2026-02-23) — Nervous System Hardening Sprint

First beta release following a 5-week hardening sprint that transformed AMOSKYS
from prototype into a production-candidate security monitoring platform.

**4,188 tests | 9 canonical agents | 103 micro-probes | 24 correlation rules**

---

### Breaking Changes

Agent classes renamed to canonical names. Backward-compatibility shims are
provided for one release cycle and will be removed in v1.0.

| Old Name | New Canonical Name |
|---|---|
| `AuthGuardAgentV2` | `AuthGuardAgent` |
| `ProcAgentV3` | `ProcAgent` |
| `DNSAgentV2` | `DNSAgent` |
| `FIMAgentV2` | `FIMAgent` |
| `FlowAgentV2` | `FlowAgent` |
| `PersistenceGuardV2` | `PersistenceGuard` |
| `PeripheralAgentV2` | `PeripheralAgent` |
| `KernelAuditAgentV2` | `KernelAuditAgent` |
| `DeviceDiscoveryV2` | `DeviceDiscovery` |
| `ProtocolCollectorsV2` | `ProtocolCollectors` |

Old import paths (e.g. `from amoskys.agents.proc.proc_agent_v3 import ProcAgentV3`)
still work via shim modules. Migrate to canonical paths before v1.0.

---

### Phase A — Foundation Hardening (Weeks 1-4)

#### Security Fixes
- Rotated hardcoded credentials; environment-only credential injection
- Generated production-grade SECRET_KEY; removed dev-key fallback
- Migrated inline event handlers to external JS; enabled CSP nonces
- Authenticated health endpoints (`/v1/health/system`, `/v1/health/agents`)
- Restricted SocketIO CORS (was accepting any origin)
- Fixed SQL LIKE injection in hunt search endpoint
- Input validation on all agent constructors

#### Cryptographic Integrity
- BLAKE2b hash chain enforcement in EventBus.Publish()
- Per-device signature chain: `sig = BLAKE2b(prev_sig + event_bytes)`
- Chain verification on WAL batch read; corrupt entries quarantined
- Ed25519 envelope signing wired in queue layer
- ACK timing fix: OK response sent after confirmed WAL commit
- `scripts/audit_wal_chain.py` CLI for forensic chain verification

#### Delivery Guarantees
- Queue overflow telemetry: `dropped_events` counter + pre-loss alerts
- WAL auto-delete on exception disabled; failed entries moved to error table
- WAL batch processing capped at 500 to prevent resource exhaustion
- Dedup (`_seen`) calls in both Publish handlers
- EventBus handler connection reuse to prevent SQLite lock contention

#### Agent Framework
- Heartbeat emission in HardenedAgentBase (probe coverage, queue depth, CB state)
- Circuit breaker state transitions (CLOSED/OPEN/HALF_OPEN) now telemetrized
- DEGRADED probes tagged with visibility flags
- Null guards on all probe `shared_data` access
- Subprocess timeout protection on all OS calls
- Memory limits on filesystem scanners
- Canonical timestamp generator (`time.time_ns()`) across all agents

#### Schema & Storage
- `schema_version` field added to protobuf (UniversalEnvelope field 18)
- Schema migration framework with auto-migrate on startup
- SQLite pragmas: WAL mode, SYNCHRONOUS=FULL, foreign keys ON

---

### Phase B — Canonical Release Preparation (Week 5)

#### B5.1: Agent Name Canonicalization
- Renamed 10 agent files and classes to drop version suffixes
- Renamed 3 `run_agent_v2.py` files to `run_agent.py`
- Updated all `__init__.py`, `__main__.py`, and deployment configs
- Created backward-compatibility shim modules at old paths
- Updated 15+ test files with canonical import paths

#### B5.2: Dead Code Removal
- Deleted empty placeholder files (0-byte stubs)
- Removed orphan `agents/discovery/` directory
- Cleaned all `__pycache__` directories

#### B5.3: SQLite Test Isolation
- Added global `tmp_db_path` and `tmp_wal_path` pytest fixtures
- 13 new tests verifying per-test database isolation
- Concurrent write safety validated (4 threads x 50 inserts)

#### B5.4: Beta Tag
- Version bumped to `0.9.0-beta.1`
- CHANGELOG created
- Git tag `v0.9.0-beta.1`

---

### New Features
- Hash chain audit CLI (`scripts/audit_wal_chain.py`)
- Schema migration framework with `--dry-run` support
- Probe health telemetry (ACTIVE/DEGRADED/BROKEN status)
- Queue overflow alerts with `dropped_events` counter
- Circuit breaker telemetry for all state transitions

### Known Limitations
- EventBus Subscribe RPC returns UNIMPLEMENTED (deferred to v1.0)
- 10 gap probes not yet covered (Keychain, Credential, Memory, etc.)
- No GeoIP/ASN/threat intel enrichment pipeline
- Kill chain UI visualization deferred to v1.0
