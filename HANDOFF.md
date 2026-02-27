# AMOSKYS — External Drive Handoff

**Date:** 2026-02-27
**From:** Internal disk (`/Users/athanneeru/Downloads/GitHub/Amoskys`)
**To:** External drive (`/Volumes/Akash_Lab/Amoskys`)

---

## Quick Start

```bash
cd /Volumes/Akash_Lab/Amoskys
source amoskys-venv/bin/activate
# Launch all agents:
bash scripts/run_trinity_local.sh
# Or run the dashboard:
python -m flask --app web.app run --port 5050
```

---

## What's Ready

| Component       | Status | Location                                |
|-----------------|--------|-----------------------------------------|
| Git repo        | Synced | Same commit `5af165f`, same branch `main` |
| Source code      | Synced | All 80+ modified files transferred      |
| Data directory   | Real   | `data/` (not a symlink, 17 MB)          |
| Databases        | Intact | `amoskys.db`, `threat_intel.db`, `amoskys_auth.db` |
| WAL directory    | Intact | `data/wal/`                             |
| Virtual env      | Works  | `amoskys-venv/` (Python 3.13.5, 96 pkgs) |
| .env             | Intact | 82 lines, credentials included          |
| Tests            | Pass   | Verified: `test_dns_agent_v2.py` 18/18  |
| Remote           | Set    | `origin` → `github.com/Vardhan-225/Amoskys` |

---

## Uncommitted Work (112 files)

This is the Nervous System v2 sprint. All changes are staged/unstaged — **nothing has been committed yet**.

### Categories of changes:

**1. Agent Canonicalization (34 files)**
- All 10 agents refactored to canonical pattern (`__main__.py`, agent class, probes)
- Deleted: `kernel_audit/types.py`, `protocol_collectors/types.py` (replaced by `agent_types.py`)
- New: `device_discovery/__main__.py`, `protocol_collectors/__main__.py`, `kernel_audit/agent_types.py`, `protocol_collectors/agent_types.py`
- Updated: `common/cli.py`, `common/queue_adapter.py`

**2. Dashboard & Web (20 files)**
- New pages: `reliability.html`, `proof-spine.html`, `agent-monitor.html`
- Updated: `base.html`, `cortex.html`, `soc.html`, `agents.html`, all other templates
- API updates: `reliability.py`, `proofs.py`, `telemetry.py`, `database_manager.py`
- Route updates: `web/app/__init__.py`, `web/app/dashboard/__init__.py`

**3. Tests (20 files)**
- All unit tests updated for new agent imports
- Pipeline tests updated for WAL processor changes

**4. Config & Scripts (5 files)**
- `pyproject.toml` — dependency/entry-point updates
- `scripts/run_trinity_local.sh` — launch script adjustments
- `scripts/seed_dashboard_data.py` — dashboard seed data
- `scripts/dev_fullstack.sh` — new fullstack dev launcher

**5. Docs & Audit (6 files, untracked)**
- `AUDIT_QUICK_REFERENCE.md`, `AUDIT_SUMMARY.txt`, `README_AUDIT.md`, `TECHNICAL_AUDIT_REPORT.md`
- `agent_key_registry.json`
- `docs/hardening/` — 6 `.docx` audit documents

**6. Git housekeeping (staged)**
- `data/.gitkeep` + 12 ML pipeline files removed from tracking
- `.gitignore` updated to fully ignore `data/`

---

## Pending Tasks

1. **Commit the current work** — 112 files of agent canonicalization + dashboard updates
2. **Fix WAL checkpoint** — batch commits + retention policy in `wal_processor.py`
3. **Fix auth → onboarding → dashboard flow** — end-to-end login experience
4. **Audit dashboard pages** — visual usability across all 12+ pages
5. **SQL migration** — `004_add_security_collection_columns.sql` needs to be applied

---

## Directory Structure

```
/Volumes/Akash_Lab/Amoskys/
├── src/amoskys/
│   ├── agents/           # 10 agents (auth, dns, fim, flow, kernel_audit, ...)
│   │   └── common/       # Shared CLI, queue adapter
│   └── storage/          # WAL processor, migrations
├── web/app/              # Flask dashboard
│   ├── api/              # REST endpoints
│   ├── dashboard/        # Route blueprints
│   └── templates/dashboard/  # Jinja2 templates
├── tests/                # unit/, pipeline/, agents/
├── data/                 # Runtime data (gitignored)
│   ├── amoskys.db        # Main SQLite database
│   ├── wal/              # Write-ahead log
│   └── queue/            # Agent message queue
├── scripts/              # Launch & utility scripts
├── docs/                 # Hardening audit docs
├── amoskys-venv/         # Python 3.13.5 virtual env
├── .venv/                # Secondary venv (stale, 1.9 GB)
└── .env                  # Environment variables
```

---

## Key Commands

```bash
# Activate environment
source amoskys-venv/bin/activate

# Run all agents + WAL processor
bash scripts/run_trinity_local.sh

# Run dashboard only
python -m flask --app web.app run --port 5050

# Run single agent
python -m amoskys.agents.dns --interval 10 --no-heartbeat --log-level INFO

# Run all tests
python -m pytest tests/ -x -q

# Run unit tests only
python -m pytest tests/unit/ -x -q

# Check git status
git status --short | wc -l
```

---

## Differences from Internal Drive Copy

| Aspect | Internal (`~/Downloads/GitHub/Amoskys`) | External (`/Volumes/Akash_Lab/Amoskys`) |
|--------|----------------------------------------|----------------------------------------|
| `data/` | **Symlink** → `/Volumes/Akash_Lab/Amoskys_data` | **Real directory** |
| Disk | 1.3 GB free (93% full) | 1.5 TB free (18% used) |
| Agents | Stopped (were running) | Not started |
| Git state | Identical | Identical |

---

## Caution

- **Do NOT run agents on both copies simultaneously** — they share the same GitHub remote and would create conflicting WAL/DB state
- **The `.venv/` directory (1.9 GB) is a stale secondary venv** — `amoskys-venv/` is the active one. You can delete `.venv/` to save space
- **The `.env` file contains real credentials** — never commit it
- **The internal copy's `data/` is a symlink** — if the external drive is disconnected, agents on the internal copy will fail to write data
