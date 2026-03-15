# AMOSKYS Agent Mesh — Implementation Files

## What This Is
Complete Python implementation of the Agent Mesh architecture:
- **17 agents communicating in real time** via a shared event bus
- **IGRIS Orchestrator** as the autonomous defense brain
- **11 action tools** for IGRIS to take defensive actions (kill processes, block IPs, quarantine binaries)
- **Confidence-gated execution** so IGRIS doesn't over-react

## File Structure

```
mesh/
├── __init__.py          # Package exports
├── events.py            # SecurityEvent dataclass + EventType enum + Severity enum
├── bus.py               # MeshBus: in-process pub/sub with SQLite persistence
├── mixin.py             # MeshMixin: drop-in for any BaseAgent subclass
├── actions.py           # ActionExecutor: 11 action tools with confidence gating
└── store.py             # MeshStore: forensic timeline queries

igris/
└── orchestrator.py      # IGRISOrchestrator: event loop + correlation + action dispatch
```

## Integration Steps

1. Copy `mesh/` to `src/amoskys/mesh/`
2. Copy `igris/orchestrator.py` to `src/amoskys/igris/orchestrator.py`
3. Add MeshMixin to your agent base classes
4. Initialize MeshBus at dashboard startup
5. Register the orchestrator

### Quick Start

```python
from amoskys.mesh import MeshBus, ActionExecutor, MeshStore, MeshMixin
from amoskys.igris.orchestrator import IGRISOrchestrator

# 1. Create the bus
bus = MeshBus(db_path="data/mesh_events.db")

# 2. Connect agents
MeshMixin.set_mesh_bus(bus)

# 3. Create the action executor
actions = ActionExecutor(mesh_bus=bus, dry_run=False)

# 4. Create the orchestrator
store = MeshStore(db_path="data/mesh_events.db")
orchestrator = IGRISOrchestrator(
    mesh_bus=bus,
    action_executor=actions,
    mesh_store=store,
    notification_callback=push_to_chat_widget,
)

# 5. Start autonomous defense
orchestrator.start()
```

## Zero New Dependencies
Pure Python + SQLite. No Node.js, no Redis, no ZeroMQ.

## Action Tiers
| Confidence | Actions Available |
|-----------|-------------------|
| Low (0.3+) | log, direct_watch, trigger_collection |
| Medium (0.5+) | above + promote_signal, add_threat_indicator |
| High (0.7+) | above + block_ip, block_domain, stop/start_agent |
| Critical (0.9+) | above + kill_process, quarantine_binary |
