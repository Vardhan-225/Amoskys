# AMOSKYS Codebase Cleanup & Architecture Audit

**Date:** 2025-12-27
**Goal:** FAANG-level quality, stability, and robustness

---

## Part 1: Codebase Cleanup

### Current State
- **93 markdown files** in root directory (massive clutter)
- Multiple redundant documentation files
- Session reports from October/November/December
- Duplicate guides and quick starts

### Essential Files to KEEP

#### Documentation (5 files):
1. **README.md** - Main project documentation
2. **MAC_LINUX_ARCHITECTURE_ASSESSMENT.md** - Current architecture (just created)
3. **SNMP_AGENT_TODO_FIX_REPORT.md** - Recent critical fix
4. **TODO_STATUS_UPDATE.md** - Current TODO status
5. **requirements.txt** - Python dependencies

#### Scripts (3 files):
1. **start_amoskys.sh** - Service startup
2. **stop_amoskys.sh** - Service shutdown
3. **quick_status.sh** - Health monitoring

#### Code Structure:
```
src/amoskys/
├── agents/          ✅ KEEP - Core agents
├── eventbus/        ✅ KEEP - Message routing
├── storage/         ✅ KEEP - WAL processor
├── proto/           ✅ KEEP - Protocol buffers
├── common/          ✅ KEEP - Shared utilities
├── config/          ✅ KEEP - Configuration
└── intelligence/    ⏳ REVIEW - ML features

web/
├── app/             ✅ KEEP - Dashboard
└── wsgi.py          ✅ KEEP - Entry point

data/
├── telemetry.db     ✅ KEEP - Main database
└── wal/             ✅ KEEP - WAL queue
```

### Files to ARCHIVE (88 files):

**Session Reports (20+ files):**
- SESSION_*.md
- *_COMPLETE.md
- *_FINAL.md
- PHASE_*_EXECUTION_REPORT.md

**Status Reports (15+ files):**
- STATUS_REPORT_*.md
- COMPLETE_STATUS_*.md
- *_VERIFICATION_REPORT.md

**Redundant Guides (25+ files):**
- *_QUICK_START.md
- *_GUIDE.md
- QUICKSTART.md
- ACTIVATION_*.md
- DASHBOARD_*.md

**Analysis Documents (10+ files):**
- ANALYSIS_*.md
- ISSUES_AND_*.md
- HONEST_*.md

**Obsolete Features (10+ files):**
- ML_PIPELINE_*.md
- MICROPROCESSOR_*.md
- NEURON_*.md

**Miscellaneous (8+ files):**
- *.txt files
- Old roadmaps
- Completion reports

### Cleanup Actions:
```bash
# Create archive directory
mkdir -p archive/2025-12-27-cleanup

# Move all non-essential files
mv SESSION_*.md archive/2025-12-27-cleanup/
mv *_COMPLETE.md archive/2025-12-27-cleanup/
mv PHASE_*.md archive/2025-12-27-cleanup/
mv ML_PIPELINE_*.md archive/2025-12-27-cleanup/
mv MICROPROCESSOR_*.md archive/2025-12-27-cleanup/
mv *_GUIDE.md archive/2025-12-27-cleanup/
mv QUICK*.md archive/2025-12-27-cleanup/
# ... (88 files total)

# Keep only essential 8 files in root
```

---

## Part 2: Architecture Audit - Data Pipeline

### Complete Data Flow Audit

```
DEVICE → AGENT → EVENTBUS → WAL → DATABASE → API → DASHBOARD
```

#### Stage 1: Device → Agent (Data Collection)

**Proc Agent (Process Monitoring):**
- ✅ Collection Method: `psutil.process_iter()`
- ✅ Frequency: Every 30 seconds
- ✅ Data Captured:
  - PID, PPID, executable path
  - User type (root, system, user)
  - CPU%, Memory%
  - Command line args
  - Create time
- ⚠️ **MISSING**:
  - Network connections per process
  - Open files/file descriptors
  - Parent-child process tree
  - Process state changes (new/exit events)
  - Environment variables
  - Working directory

**Peripheral Agent (Device Monitoring):**
- ✅ Collection Method: `system_profiler SPUSBDataType` (Mac)
- ✅ Frequency: Every 30 seconds
- ✅ Data Captured:
  - Vendor ID, Product ID
  - Device name, manufacturer
  - Serial number
  - Connection timestamp
  - Risk scoring
- ⚠️ **MISSING**:
  - Bluetooth devices
  - Thunderbolt devices
  - Network adapters (Ethernet, WiFi)
  - PCIe devices
  - Device disconnection events
  - Data transfer monitoring
  - HID keystroke detection (BadUSB)

**Mac Telemetry (Legacy):**
- ⚠️ Redundant with Proc Agent - consider removing

#### Stage 2: Agent → EventBus (Transport)

**Current Implementation:**
- ✅ Protocol: gRPC with mTLS
- ✅ Envelope: UniversalEnvelope (protobuf)
- ✅ Signing: Ed25519 signatures
- ✅ Deduplication: Idempotency keys
- ✅ Error Handling: Retry logic

**Potential Issues:**
- ⚠️ No backpressure monitoring
- ⚠️ No circuit breaker pattern
- ⚠️ No agent-side queue for offline resilience
- ⚠️ Certificate rotation not automated
- ⚠️ No health check heartbeats

#### Stage 3: EventBus → WAL (Message Routing)

**Current Implementation:**
- ✅ WAL Database: SQLite (flowagent.db)
- ✅ Write-ahead logging enabled
- ✅ Event persistence before processing

**Potential Issues:**
- ⚠️ No WAL size limits (could grow indefinitely)
- ⚠️ No compression
- ⚠️ No partitioning by time/agent
- ⚠️ Single WAL file (scalability limit)

#### Stage 4: WAL → Database (Processing)

**WAL Processor:**
- ✅ Batch Processing: 100 events per 5 seconds
- ✅ Process Classification: 6 categories
- ✅ Device ID: socket.gethostname()
- ✅ Timestamp conversion: nanoseconds → ISO datetime

**Potential Issues:**
- ⚠️ No schema validation
- ⚠️ No data enrichment (GeoIP, threat intel)
- ⚠️ No event correlation
- ⚠️ No anomaly detection at processing layer
- ⚠️ Classification rules hardcoded (not configurable)

#### Stage 5: Database → API (Data Access)

**Current APIs:**
- ✅ Process Telemetry: `/api/process-telemetry/*`
- ✅ Peripheral Telemetry: `/api/peripheral-telemetry/*`
- ✅ Database Manager: `/api/database-manager/*`
- ✅ Agent Status: `/dashboard/api/live/agents`

**Potential Issues:**
- ⚠️ No pagination on large queries
- ⚠️ No caching layer
- ⚠️ No rate limiting (except decorators)
- ⚠️ No API versioning
- ⚠️ No data aggregation endpoints
- ⚠️ No export functionality (CSV, JSON)

#### Stage 6: API → Dashboard (Visualization)

**Current Dashboards:**
- ✅ Cortex (Command Center)
- ✅ SOC Operations
- ✅ Agent Network
- ✅ Process Telemetry
- ✅ Peripheral Monitoring
- ✅ Database Manager
- ✅ System Health
- ✅ Neural Insights

**UI/UX Issues:**
- ⚠️ Inconsistent refresh rates (5s, 10s, 30s)
- ⚠️ No loading states on some pages
- ⚠️ Harsh color transitions (partially fixed)
- ⚠️ No keyboard shortcuts
- ⚠️ No dark/light mode toggle
- ⚠️ No data export buttons
- ⚠️ No time range selectors
- ⚠️ Charts not responsive on mobile
- ⚠️ No drill-down capabilities

---

## Part 3: Critical Issues Identified

### High Priority Issues

#### 1. Data Loss Risk
**Issue:** No agent-side queue for offline resilience
**Impact:** If EventBus is down, agents drop events
**Solution:** Implement local queue in each agent
```python
class AgentQueue:
    def __init__(self, max_size=10000):
        self.queue = deque(maxlen=max_size)

    def enqueue(self, event):
        self.queue.append(event)

    def flush_to_eventbus(self):
        while self.queue:
            try:
                publish(self.queue.popleft())
            except:
                break  # Stop on first failure
```

#### 2. WAL Growth Unbounded
**Issue:** WAL database can grow indefinitely
**Impact:** Disk space exhaustion
**Solution:** Add WAL rotation and cleanup
```python
def rotate_wal_if_needed():
    wal_size = os.path.getsize('data/wal/flowagent.db')
    if wal_size > 100 * 1024 * 1024:  # 100MB
        # Archive current WAL
        shutil.move('data/wal/flowagent.db',
                    f'data/wal/archive/flowagent-{timestamp}.db')
        # Create new WAL
        init_wal_database()
```

#### 3. Missing Process Metrics
**Issue:** Not collecting network connections, open files
**Impact:** Incomplete threat detection
**Solution:** Enhance proc_agent data collection
```python
def collect_enhanced_metrics(proc):
    return {
        'connections': proc.connections(),  # Network
        'open_files': proc.open_files(),    # File access
        'num_threads': proc.num_threads(),  # Threading
        'num_fds': proc.num_fds(),          # File descriptors
        'environ': proc.environ()           # Environment
    }
```

#### 4. No Real-time Alerting
**Issue:** Dashboard shows data but no alerts
**Impact:** Delayed threat response
**Solution:** Implement alert engine
```python
class AlertEngine:
    def check_rules(self, event):
        if event.user_type == 'root' and event.exe not in WHITELIST:
            self.send_alert('HIGH', 'Unauthorized root process')

        if event.connections and '0.0.0.0' in str(event.connections):
            self.send_alert('CRITICAL', 'Process listening on all interfaces')
```

#### 5. Peripheral Agent Mac-Only
**Issue:** Only works on macOS (system_profiler)
**Impact:** Not Linux-compatible
**Solution:** Platform abstraction layer
```python
class PeripheralScanner:
    def scan(self):
        if platform.system() == 'Darwin':
            return self._scan_mac()
        elif platform.system() == 'Linux':
            return self._scan_linux()

    def _scan_linux(self):
        # Parse /sys/bus/usb/devices/*
        pass
```

### Medium Priority Issues

#### 6. No Time-Series Analysis
**Issue:** Only showing latest data
**Impact:** Missing trend detection
**Solution:** Add time-series queries
```sql
SELECT
    datetime(timestamp_dt, 'unixepoch', 'start of hour') as hour,
    COUNT(*) as process_count,
    AVG(cpu_percent) as avg_cpu
FROM process_events
WHERE timestamp_dt > datetime('now', '-24 hours')
GROUP BY hour
ORDER BY hour;
```

#### 7. Dashboard Real-time Updates Inefficient
**Issue:** Polling every 5-30 seconds
**Impact:** High server load, delayed updates
**Solution:** WebSocket/Server-Sent Events
```python
@socketio.on('subscribe_agents')
def handle_subscription():
    while True:
        agent_data = get_live_agents()
        emit('agents_update', agent_data)
        time.sleep(1)
```

#### 8. No Data Export
**Issue:** Can't export data for analysis
**Impact:** Limited external tool integration
**Solution:** Add export endpoints
```python
@api_bp.route('/export/process-events')
def export_process_events():
    events = query_process_events()
    csv_data = convert_to_csv(events)
    return send_file(csv_data, 'events.csv')
```

---

## Part 4: Agent Design Review

### Proc Agent Design

**Current Architecture:**
```python
class ProcAgent:
    def collect():
        processes = psutil.process_iter()
        telemetry = create_telemetry(processes)
        publish_telemetry(telemetry)
```

**Improvements Needed:**
1. Add local queue for resilience
2. Collect enhanced metrics (connections, files)
3. Implement process tree tracking
4. Add configuration file support
5. Emit process lifecycle events (new, exit)

**Enhanced Design:**
```python
class ProcAgent:
    def __init__(self):
        self.queue = AgentQueue()
        self.process_cache = {}  # Track state
        self.config = load_config()

    def collect(self):
        current_pids = set()

        for proc in psutil.process_iter():
            pid = proc.pid
            current_pids.add(pid)

            # New process detected
            if pid not in self.process_cache:
                self.emit_event('PROCESS_START', proc)

            # Regular telemetry
            telemetry = self.create_enhanced_telemetry(proc)
            self.queue.enqueue(telemetry)

        # Detect exited processes
        for pid in self.process_cache.keys() - current_pids:
            self.emit_event('PROCESS_EXIT', pid)
            del self.process_cache[pid]

        # Flush queue
        self.queue.flush_to_eventbus()
```

### Peripheral Agent Design

**Current Architecture:**
```python
class PeripheralAgent:
    def scan():
        devices = system_profiler_parse()
        telemetry = create_telemetry(devices)
        publish_telemetry(telemetry)
```

**Improvements Needed:**
1. Platform abstraction (Mac/Linux)
2. Device connection/disconnection events
3. Risk scoring based on device behavior
4. Whitelist/blacklist management
5. Data transfer monitoring

**Enhanced Design:**
```python
class PeripheralAgent:
    def __init__(self):
        self.scanner = self._get_platform_scanner()
        self.device_cache = {}
        self.whitelist = load_whitelist()

    def _get_platform_scanner(self):
        if platform.system() == 'Darwin':
            return MacPeripheralScanner()
        elif platform.system() == 'Linux':
            return LinuxPeripheralScanner()

    def scan(self):
        current_devices = self.scanner.scan()

        for device in current_devices:
            device_id = device.serial_number

            # New device
            if device_id not in self.device_cache:
                risk = self.assess_risk(device)
                self.emit_event('DEVICE_CONNECTED', device, risk)

                if risk >= 8 and device_id not in self.whitelist:
                    self.send_alert('HIGH_RISK_DEVICE', device)

            self.device_cache[device_id] = device

        # Detect disconnections
        for device_id in set(self.device_cache.keys()) - set(d.serial_number for d in current_devices):
            self.emit_event('DEVICE_DISCONNECTED', device_id)
            del self.device_cache[device_id]
```

---

## Part 5: UI/UX Consistency Audit

### Current State

**Positive:**
- ✅ Consistent dark theme
- ✅ Neural/cyberpunk aesthetic
- ✅ Responsive grid layouts
- ✅ Real-time updates working

**Issues:**

#### Color Inconsistency
- Different shades of green for "online" status
- Inconsistent warning/error colors
- Chart colors clash with theme

#### Typography Inconsistency
- Different font sizes for same elements
- Inconsistent heading hierarchy
- Mixed use of bold/regular weights

#### Spacing Inconsistency
- Card padding varies (1rem, 1.5rem, 2rem)
- Margin between sections inconsistent
- Button spacing not uniform

#### Component Inconsistency
- Different button styles across pages
- Inconsistent table designs
- Mixed badge/pill styles

### UI/UX Improvement Plan

#### 1. Design System
Create `web/app/static/css/design-system.css`:
```css
/* Color System */
:root {
    /* Status Colors */
    --status-online: #5cb85c;
    --status-stopped: #d9534f;
    --status-warning: #f0ad4e;
    --status-incompatible: #999999;

    /* Functional Colors */
    --color-primary: #5cb85c;
    --color-secondary: #5bc0de;
    --color-danger: #d9534f;
    --color-warning: #f0ad4e;
    --color-info: #5bc0de;

    /* Background Colors */
    --bg-primary: #0a0e27;
    --bg-secondary: #1a1f3a;
    --bg-card: #141829;

    /* Text Colors */
    --text-primary: #ffffff;
    --text-secondary: #b8c5d6;
    --text-muted: #6c757d;

    /* Spacing Scale */
    --space-xs: 0.25rem;
    --space-sm: 0.5rem;
    --space-md: 1rem;
    --space-lg: 1.5rem;
    --space-xl: 2rem;
    --space-2xl: 3rem;

    /* Typography Scale */
    --font-xs: 0.75rem;
    --font-sm: 0.875rem;
    --font-md: 1rem;
    --font-lg: 1.25rem;
    --font-xl: 1.5rem;
    --font-2xl: 2rem;

    /* Border Radius */
    --radius-sm: 4px;
    --radius-md: 8px;
    --radius-lg: 12px;
}

/* Component Classes */
.btn-primary {
    background: var(--color-primary);
    color: white;
    padding: var(--space-sm) var(--space-lg);
    border-radius: var(--radius-md);
    font-size: var(--font-md);
}

.card {
    background: var(--bg-card);
    padding: var(--space-lg);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-lg);
}

.status-badge {
    padding: var(--space-xs) var(--space-md);
    border-radius: var(--radius-sm);
    font-size: var(--font-sm);
    font-weight: 600;
}

.status-online { background: var(--status-online); }
.status-stopped { background: var(--status-stopped); }
.status-warning { background: var(--status-warning); }
```

#### 2. Standardize Dashboard Layout
All dashboards should follow this structure:
```html
<div class="dashboard-container">
    <!-- Header -->
    <div class="dashboard-header">
        <h1 class="dashboard-title">{{ title }}</h1>
        <div class="dashboard-actions">
            <button class="btn-primary">Action</button>
        </div>
    </div>

    <!-- Metrics Row -->
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-value">{{ value }}</div>
            <div class="metric-label">{{ label }}</div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="content-grid">
        <div class="card">{{ content }}</div>
    </div>
</div>
```

#### 3. Loading States
Every data fetch should show loading:
```javascript
async function updateData() {
    showLoading();
    try {
        const data = await fetch(url);
        renderData(data);
    } finally {
        hideLoading();
    }
}
```

#### 4. Error Handling
Consistent error display:
```javascript
function showError(message) {
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}
```

---

## Part 6: OT Device Preparation

### Current Mac Foundation
- ✅ Agents collecting data
- ✅ EventBus routing messages
- ✅ Database storing events
- ✅ Dashboard displaying

### OT Device Considerations

**OT Devices Types:**
1. PLCs (Programmable Logic Controllers)
2. SCADA systems
3. Industrial sensors
4. RTUs (Remote Terminal Units)
5. HMIs (Human-Machine Interfaces)

**Collection Challenges:**
- Different protocols (Modbus, OPC UA, DNP3)
- Resource constraints (limited CPU/memory)
- Real-time requirements (< 100ms latency)
- Air-gapped networks (no internet)
- Legacy systems (old firmware)

**Adaptation Strategy:**
```
Current: Mac/Linux Agents → EventBus → Database
OT:      OT Gateway → EventBus → Database
         ↑
         Modbus/OPC/DNP3 Adapter
```

**OT Agent Design:**
```python
class OTAgent:
    def __init__(self, protocol='modbus'):
        self.adapter = self._get_protocol_adapter(protocol)
        self.queue = AgentQueue()

    def _get_protocol_adapter(self, protocol):
        if protocol == 'modbus':
            return ModbusAdapter()
        elif protocol == 'opcua':
            return OPCUAAdapter()
        elif protocol == 'dnp3':
            return DNP3Adapter()

    def collect(self):
        # Read from PLC/SCADA
        data = self.adapter.read()

        # Convert to UniversalTelemetry
        telemetry = self.convert_to_telemetry(data)

        # Publish
        self.queue.enqueue(telemetry)
        self.queue.flush_to_eventbus()
```

---

## Part 7: Action Items

### Immediate (Today):
1. ✅ Archive 88 non-essential markdown files
2. ✅ Remove redundant scripts
3. ✅ Update README.md with current architecture
4. ✅ Create design system CSS file

### Short-term (This Week):
1. ⏳ Implement agent-side queue for resilience
2. ⏳ Add WAL rotation and cleanup
3. ⏳ Enhance proc_agent with missing metrics
4. ⏳ Fix UI/UX inconsistencies

### Medium-term (Next 2 Weeks):
1. ⏳ Implement real-time alerting engine
2. ⏳ Add Linux support to peripheral_agent
3. ⏳ Create data export functionality
4. ⏳ Optimize dashboard performance

### Long-term (Next Month):
1. ⏳ OT device adapter framework
2. ⏳ Time-series analysis features
3. ⏳ Advanced threat detection
4. ⏳ Production hardening

---

**Audit Completed:** 2025-12-27
**Next Action:** Execute cleanup and implement critical fixes
