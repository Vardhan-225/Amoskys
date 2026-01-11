# AMOSKYS Agent V2 - Deployment Template

This is the **canonical pattern** that works in production. Use this for all new agents.

## Proven Working Pattern (from KernelAuditGuardV2)

### 1. Directory Structure

```
/home/ubuntu/
├── amoskys-src/              # Source code (rsync'd from Mac)
│   └── amoskys/
│       └── agents/
│           └── <agent_name>/
│               ├── __init__.py
│               ├── <agent>_v2.py
│               ├── probes.py
│               ├── collector.py
│               └── types.py
│
├── amoskys-venv/             # Shared Python venv for all agents
│   └── bin/python3
│
├── <agent_dir>/              # Deployment package per agent
│   ├── run_agent_v2.py       # CLI entry point
│   ├── install.sh            # Installer
│   └── requirements-minimal.txt
│
└── /var/lib/amoskys/
    └── queues/
        └── <agent_name>/     # Queue directory per agent
            └── <agent>_queue.db  # SQLite WAL database
```

### 2. Systemd Service Template

**File:** `/etc/systemd/system/amoskys-<agent_name>.service`

```ini
[Unit]
Description=AMOSKYS <AgentName> v2 - <Plane> Threat Detection
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/<agent_dir>
Environment="PYTHONUNBUFFERED=1"

# Agent command - using shared venv
ExecStart=/home/ubuntu/amoskys-venv/bin/python3 \
  /home/ubuntu/<agent_dir>/run_agent_v2.py \
  --device-id=%H \
  --queue-path=/var/lib/amoskys/queues/<agent_name> \
  --collection-interval=5 \
  --metrics-interval=60

# Restart policy
Restart=on-failure
RestartSec=10
TimeoutStartSec=120

# Resource limits (tune per agent)
MemoryMax=512M
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

**Key Points:**
- ✅ Uses shared `/home/ubuntu/amoskys-venv/bin/python3`
- ✅ No complex security restrictions (add later after validation)
- ✅ Queue path is **directory** (script forms file path internally)
- ✅ `%H` expands to hostname for device-id

### 3. Run Agent Script Template

**File:** `deployments/<agent_dir>/run_agent_v2.py`

```python
#!/usr/bin/env python3
"""CLI entry point for <AgentName> Agent v2."""

import argparse
import logging
import os
import signal
import sys

# Add parent directory to Python path
_script_dir = os.path.dirname(os.path.abspath(__file__))
_possible_paths = [
    os.path.join(_script_dir, "../../src"),      # Local dev
    os.path.expanduser("~/amoskys-src"),          # Server deployment
]

for path in _possible_paths:
    if os.path.isdir(path):
        sys.path.insert(0, path)

from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.<agent_name>.<agent>_v2 import <Agent>V2

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="AMOSKYS <AgentName> v2 - <Plane> Threat Detection"
    )

    parser.add_argument(
        "--device-id",
        type=str,
        default=os.environ.get("AMOSKYS_DEVICE_ID", os.uname().nodename),
        help="Unique device identifier (default: hostname)",
    )

    parser.add_argument(
        "--queue-path",
        type=str,
        default="/var/lib/amoskys/queues/<agent_name>",
        help="Path to local queue directory",
    )

    parser.add_argument(
        "--collection-interval",
        type=float,
        default=5.0,
        help="Seconds between collection cycles (default: 5.0)",
    )

    parser.add_argument(
        "--metrics-interval",
        type=float,
        default=60.0,
        help="Seconds between metrics emissions (default: 60.0)",
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    return parser.parse_args()


def validate_environment(args):
    """Validate runtime environment."""
    # Check queue directory
    queue_dir = args.queue_path
    if not os.path.exists(queue_dir):
        logger.warning(f"Queue directory does not exist: {queue_dir}")
        logger.info(f"Creating directory: {queue_dir}")
        try:
            os.makedirs(queue_dir, mode=0o755, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create queue directory: {e}")
            return False

    if not os.access(queue_dir, os.W_OK):
        logger.error(f"Cannot write to queue directory: {queue_dir}")
        return False

    return True


def main():
    """Main entry point."""
    args = parse_args()

    # Configure logging
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    logger.info("=" * 70)
    logger.info("AMOSKYS <AgentName> v2")
    logger.info("=" * 70)
    logger.info(f"Device ID: {args.device_id}")
    logger.info(f"Queue Path: {args.queue_path}")
    logger.info(f"Collection Interval: {args.collection_interval}s")
    logger.info(f"Metrics Interval: {args.metrics_interval}s")
    logger.info("=" * 70)

    # Validate environment
    if not validate_environment(args):
        logger.error("Environment validation failed. Exiting.")
        return 1

    # Create queue adapter
    try:
        # CRITICAL: queue_path is a directory - form file path
        queue_db_path = os.path.join(args.queue_path, "<agent_name>_queue.db")
        queue_adapter = LocalQueueAdapter(
            queue_path=queue_db_path,           # File path, not directory
            agent_name="<agent_name>_v2",       # Required parameter
            device_id=args.device_id,
        )
        logger.info(f"Initialized queue adapter at {queue_db_path}")
    except Exception as e:
        logger.error(f"Failed to initialize queue adapter: {e}")
        return 1

    # Create agent
    try:
        agent = <Agent>V2(
            device_id=args.device_id,
            agent_name="<agent_name>_v2",
            collection_interval=args.collection_interval,
            queue_adapter=queue_adapter,
            metrics_interval=args.metrics_interval,
        )
        logger.info("Agent initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize agent: {e}", exc_info=True)
        return 1

    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        agent.is_running = False

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Run agent
    try:
        logger.info("Starting agent main loop...")
        agent.run()
        logger.info("Agent stopped gracefully")
        return 0
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Agent crashed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

**Critical Implementation Details:**

```python
# ✅ CORRECT: Form file path from directory
queue_db_path = os.path.join(args.queue_path, "kernel_audit_queue.db")
queue_adapter = LocalQueueAdapter(
    queue_path=queue_db_path,      # File path
    agent_name="kernel_audit_v2",  # Required!
    device_id=args.device_id,
)

# ❌ WRONG: Pass directory directly
queue_adapter = LocalQueueAdapter(
    queue_path="/var/lib/amoskys/queues/kernel_audit",  # Directory
    device_id=args.device_id,
)
# Error: missing required positional argument: 'agent_name'
```

### 4. Deployment Steps (Proven Working)

#### On Local Mac:

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# 1. Transfer source code
rsync -av -e "ssh -i ~/.ssh/amoskys-key.pem" \
  --exclude='.git' --exclude='__pycache__' \
  src/amoskys/ \
  ubuntu@3.147.175.238:~/amoskys-src/amoskys/

# 2. Transfer deployment package
rsync -av -e "ssh -i ~/.ssh/amoskys-key.pem" \
  deployments/<agent_dir>/ \
  ubuntu@3.147.175.238:~/<agent_dir>/
```

#### On Server:

```bash
# 3. Install in venv (one-time setup)
source ~/amoskys-venv/bin/activate
cd ~/amoskys-src
pip install -e .

# 4. Verify imports
python3 -c "from amoskys.agents.<agent_name> import <Agent>V2; print('OK')"

# 5. Create queue directory
sudo mkdir -p /var/lib/amoskys/queues/<agent_name>
sudo chown -R ubuntu:ubuntu /var/lib/amoskys

# 6. Install systemd service
sudo cp ~/<agent_dir>/amoskys-<agent_name>.service \
  /etc/systemd/system/amoskys-<agent_name>.service
sudo systemctl daemon-reload

# 7. Start and enable
sudo systemctl enable amoskys-<agent_name>
sudo systemctl start amoskys-<agent_name>

# 8. Verify
sudo systemctl status amoskys-<agent_name> --no-pager
sudo journalctl -u amoskys-<agent_name> -f
```

### 5. Validation Checklist

After deployment, verify:

```bash
# ✅ Service is running
systemctl is-active amoskys-<agent_name>
# Expected: active

# ✅ Probes are initialized
sudo journalctl -u amoskys-<agent_name> | grep "Registered.*probes"
# Expected: Registered X default <agent_name> probes

# ✅ Queue database created
ls -lh /var/lib/amoskys/queues/<agent_name>/
# Expected: <agent>_queue.db, *-shm, *-wal files

# ✅ No restart loops
sudo journalctl -u amoskys-<agent_name> -n 50
# Expected: No repeating errors

# ✅ Metrics after 60 seconds
sudo journalctl -u amoskys-<agent_name> | grep "emitted metrics"
# Expected: loops_started=X, success_rate=100%
```

### 6. Common Failure Modes (Fixed)

| Error | Root Cause | Fix |
|-------|-----------|-----|
| `status=203/EXEC` | Wrong ExecStart path or missing Python | Use full venv path: `/home/ubuntu/amoskys-venv/bin/python3` |
| `missing positional argument: 'agent_name'` | Old run_agent_v2.py out of sync | Add `agent_name="<agent>_v2"` to LocalQueueAdapter |
| `unable to open database file` | Directory doesn't exist or no write perms | `sudo chown -R ubuntu:ubuntu /var/lib/amoskys` |
| `No module named 'amoskys'` | PYTHONPATH issue | Use venv with `pip install -e .` |

### 7. Next Agents to Deploy (Using This Template)

1. **SNMPAgentV2** (6 probes)
   - Replace: `<agent_name>` → `snmp`
   - Replace: `<AgentName>` → `SNMP`
   - Replace: `<Plane>` → `Network Management Plane`

2. **ProtocolCollectorsV2** (10 probes)
   - Replace: `<agent_name>` → `protocol_collectors`
   - Replace: `<AgentName>` → `ProtocolCollectors`
   - Replace: `<Plane>` → `Protocol Plane`

3. **DeviceDiscoveryV2** (6 probes)
   - Replace: `<agent_name>` → `device_discovery`
   - Replace: `<AgentName>` → `DeviceDiscovery`
   - Replace: `<Plane>` → `Discovery Plane`

### 8. Future Hardening (After Validation)

Once agent is stable for 24-48 hours, add security restrictions:

```ini
# Add to [Service] section
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/amoskys/queues/<agent_name>
ReadOnlyPaths=/var/log /home/ubuntu/amoskys-src

PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Capability restrictions (if needed)
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_DAC_READ_SEARCH
```

Test after each addition:
```bash
sudo systemctl daemon-reload
sudo systemctl restart amoskys-<agent_name>
sudo systemctl status amoskys-<agent_name>
```

---

## Summary

**This pattern is proven to work:**
1. ✅ Shared venv at `/home/ubuntu/amoskys-venv`
2. ✅ Source at `~/amoskys-src/amoskys`
3. ✅ Queue directories at `/var/lib/amoskys/queues/<agent_name>`
4. ✅ SQLite file path formed in run_agent_v2.py
5. ✅ `agent_name` parameter passed to LocalQueueAdapter
6. ✅ Minimal security restrictions initially
7. ✅ Clear startup logging with probe counts

**Replication time per agent:** 20-30 minutes (including validation)

**Files to create per agent:**
- `deployments/<agent_dir>/run_agent_v2.py` (from template)
- `deployments/<agent_dir>/amoskys-<agent_name>.service` (from template)
- `deployments/<agent_dir>/requirements-minimal.txt` (copy from kernel_audit)

**Commands to run:**
```bash
# On Mac: transfer files
./deploy_to_server.sh  # (adapt for new agent)

# On server: install and start
source ~/amoskys-venv/bin/activate && cd ~/amoskys-src && pip install -e .
sudo cp ~/<agent_dir>/amoskys-<agent_name>.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now amoskys-<agent_name>
sudo journalctl -u amoskys-<agent_name> -f
```

---

**Status:** KernelAuditGuardV2 is **production-validated**. This template is ready for SNMP, ProtocolCollectors, and DeviceDiscovery.
