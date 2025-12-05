# AMOSKYS for Security Analysts - Quick Start Guide

**Role**: Security Analyst / SOC Operator  
**Goal**: Monitor Mac/Linux/Windows endpoints for threats and anomalies  
**Time to First Dashboard**: <2 minutes

---

## 🚀 QUICK START (5 Minutes)

### Step 1: Access the Dashboard
```
URL: http://127.0.0.1:5000/dashboard
Expected: Cortex Command Center loads in ~1.5 seconds
```

### Step 2: Understand What You're Looking At
```
Cortex Dashboard shows:
├─ Threat Score (top-left metric)
├─ Active Agents (count + health)
├─ Recent Threats (last 24h)
├─ System Performance (CPU, Memory, Disk charts)
└─ System Health Score
```

### Step 3: Navigate to Other Dashboards
```
Use menu or direct URLs:
- /dashboard/cortex     → System overview
- /dashboard/processes  → Deep process visibility
- /dashboard/system     → Resource monitoring
- /dashboard/soc        → Threat timeline
- /dashboard/agents     → Agent management
- /dashboard/neural     → ML insights (beta)
```

---

## 📊 DASHBOARD-BY-DASHBOARD GUIDE

### Dashboard 1: CORTEX COMMAND CENTER
**What it is**: Your main operational view  
**Refresh Rate**: Auto-updates every 5 seconds  
**Time to understand**: <2 minutes

#### What You Can Do:
```
✅ See real-time system metrics
✅ Monitor agent health
✅ Check threat status
✅ Understand system capacity

❌ (Coming soon) Drill down into specific events
❌ (Coming soon) Create alerts
❌ (Coming soon) Acknowledge threats
```

#### What to Monitor:
```
🔴 Threat Score → Indicates risk level
  - 0-20: Safe
  - 21-50: Warning
  - 51-100: Critical

🟢 Agent Health → Shows agent connectivity
  - Green: All agents online
  - Yellow: Some agents offline
  - Red: Critical agent down

💻 System Metrics → Resource availability
  - CPU >80%: Performance degradation risk
  - Memory >90%: OOM risk
  - Disk >95%: Storage risk
```

---

### Dashboard 2: PROCESS TELEMETRY
**What it is**: Deep visibility into process activity  
**Refresh Rate**: Auto-updates every 5 seconds  
**Time to understand**: <3 minutes  
**Value**: Find suspicious processes, understand running software

#### What You'll See:
```
📈 Total ProcessEvents: 491,502+ (7.2 hours of data)
🔢 Unique PIDs: 3,766 (processes)
📦 Unique Executables: 663 (different binaries)

Distribution:
├─ User Type:
│  ├─ Root: 103K processes (21%)
│  ├─ System: 64K processes (13%)
│  └─ User: 323K processes (66%)
│
└─ Process Class:
   ├─ System: 262K (53%)
   ├─ Daemon: 140K (29%)
   ├─ Application: 52K (11%)
   ├─ Third-party: 2.8K (1%)
   └─ Other: 32K (7%)

Top Processes:
1. distnoted (17,040x)
2. Chrome WebContent (11,980x)
3. Chrome Helper (10,246x)
4. zsh (8,567x)
5. cfprefsd (6,454x)
```

#### How to Use It:
```
SCENARIO 1: Find suspicious process
  Q: What process is using CPU?
  A: Check "Top Executables" - normal = system processes
  
SCENARIO 2: Understand process breakdown
  Q: Are there too many root processes?
  A: Check user distribution - 21% root is normal for Mac
  
SCENARIO 3: Find anomalous executable
  Q: Do I see unexpected binaries?
  A: Compare with "Top Executables" list
```

#### Key Insights:
```
✅ System (53%) is primary → Normal for OS
✅ Daemon (29%) is high → Normal for always-running services
✅ User (66%) processes → Your applications
⚠️  If third-party >20% → Possible malware-like behavior
⚠️  If "Other" >50% → Possible unknown executables
```

---

### Dashboard 3: SYSTEM HEALTH
**What it is**: Real-time system resource monitoring  
**Refresh Rate**: Auto-updates every 5 seconds  
**Time to understand**: <2 minutes  
**Value**: Detect resource exhaustion, performance issues

#### What You'll See:
```
💻 CPU Usage: X%
   - Green: <50%
   - Yellow: 50-80%
   - Red: >80%

🧠 Memory Usage: X%
   - Green: <70%
   - Yellow: 70-85%
   - Red: >85%

💾 Disk Usage: X%
   - Green: <70%
   - Yellow: 70-90%
   - Red: >90%

🌐 Network Traffic:
   - Bytes Received: X GB
   - Bytes Sent: Y GB
   - Packets: Z count
```

#### How to Use It:
```
SCENARIO 1: Check if system is healthy
  Q: Is the system under stress?
  A: Look at CPU/Memory charts - all green = healthy
  
SCENARIO 2: Diagnose slowness
  Q: Why is Mac slow?
  A: Check CPU and Memory - if high, something's using resources
  
SCENARIO 3: Monitor disk space
  Q: Do I have enough disk?
  A: Check Disk chart - if >90%, cleanup needed
```

---

### Dashboard 4: SOC OPERATIONS
**What it is**: Threat monitoring and incident management  
**Refresh Rate**: Real-time (when events happen)  
**Time to understand**: <3 minutes  
**Value**: Track security events, manage incidents

#### What You'll See:
```
📋 Threat List
   ├─ Event Type (e.g., "Suspicious Process", "Port Scan")
   ├─ Severity (Low/Medium/High/Critical)
   ├─ Source (IP or agent ID)
   ├─ Timestamp
   └─ Details

🎯 Threat Timeline
   ├─ Incidents over time
   ├─ Severity distribution
   └─ Trend analysis

📊 Metrics
   ├─ Total events (24h)
   ├─ Critical events
   ├─ Top threat types
   └─ Affected systems
```

#### How to Use It:
```
SCENARIO 1: What happened in the last hour?
  A: Look at threat timeline - see all incidents
  
SCENARIO 2: Are there critical threats?
  A: Filter by severity = Critical
  
SCENARIO 3: Where is the threat coming from?
  A: Check source IP/agent - correlate with system
  
SCENARIO 4: What's the threat pattern?
  A: Look at timeline - see if clustered or distributed
```

**Current Status**: Empty (no threat events yet)  
**Why**: This Mac hasn't generated threat events  
**When filled**: After adding Linux/Windows agents or ML detection

---

### Dashboard 5: AGENT MANAGEMENT
**What it is**: Monitor and manage distributed agents  
**Refresh Rate**: Auto-updates every 5 seconds  
**Time to understand**: <2 minutes  
**Value**: See which endpoints are protected

#### What You'll See:
```
🤖 Agent List
   ├─ Agent ID (e.g., "mac-01", "linux-prod-01")
   ├─ Hostname (e.g., "MyMac.local")
   ├─ Status (Online/Offline/Error)
   ├─ Last Heartbeat
   ├─ Version
   ├─ Platform (Mac/Linux/Windows)
   └─ CPU/Memory Usage

📊 Agent Health Summary
   ├─ Total Agents: X
   ├─ Online: Y (Y% healthy)
   ├─ Offline: Z
   └─ Errors: W
```

#### How to Use It:
```
SCENARIO 1: Which endpoints am I protecting?
  A: See agent list - shows all connected endpoints
  
SCENARIO 2: Is agent X still running?
  A: Check status - if offline, investigate
  
SCENARIO 3: How long since agent checked in?
  A: Check "Last Heartbeat" - should be <5 minutes
  
SCENARIO 4: Agent consuming too much CPU?
  A: Check "CPU/Memory Usage" - adjust settings if high
```

**Current Status**: Empty (no agents running)  
**Why**: Only FlowAgent on this Mac (doesn't appear in registry)  
**Future**: Will show all agent endpoints once running

---

### Dashboard 6: NEURAL INSIGHTS (Beta)
**What it is**: ML-based anomaly detection and insights  
**Status**: Infrastructure ready, ML models in development  
**Time to understand**: <3 minutes (when ready)  
**Value**: Automated threat detection, behavioral analysis

#### What You'll See (When Ready):
```
🧠 ML Model Status
   ├─ Training Status (Learning, Ready, Error)
   ├─ Confidence Score (0-100%)
   └─ Last Training Date

📊 Anomaly Detection
   ├─ Anomaly Score (0-100)
   ├─ Type (Process, Network, System)
   ├─ Confidence
   └─ Action Recommended

🎯 Behavioral Analysis
   ├─ Baseline Process Behavior
   ├─ Deviations Detected
   ├─ Risk Assessment
   └─ Recommended Actions
```

#### How to Use It (When Ready):
```
SCENARIO 1: Is this behavior normal?
  A: ML model compares against baseline - red flag if anomalous
  
SCENARIO 2: Should I investigate X?
  A: Check anomaly score - >80% = definitely investigate
  
SCENARIO 3: What's the threat?
  A: ML provides recommendation - process block, alert, etc.
```

**Current Status**: Coming in Phase 2.5  
**ETA**: January 2026  

---

## 🎯 ANALYST WORKFLOWS

### Workflow 1: Morning Briefing (10 minutes)
```
1. Open Cortex Dashboard
   → Check threat score (should be <20 for normal)
   → Check agent health (all green?)
   → Check system metrics (any resources low?)
   
2. Switch to SOC Dashboard
   → Any critical events overnight?
   → Any trends?
   
3. Check Agents
   → All endpoints online?
   → Any agents offline?
   
4. Review Process Telemetry
   → Any unusual executables?
   → Anything suspicious in top processes?
```

### Workflow 2: Incident Response (varies)
```
1. DETECT: Alert fires or you notice anomaly
   → Cortex shows high threat score
   → SOC dashboard shows suspicious event
   
2. INVESTIGATE:
   → Click threat event → drill down
   → Check Process Telemetry for related activity
   → Check System Health at time of incident
   → Check Agent status (was endpoint affected?)
   
3. ANALYZE:
   → Correlate events (what happened before/after?)
   → Check behavioral baseline (ML insights)
   → Determine impact
   
4. RESPOND:
   → Document incident (in external ticket system)
   → Block/quarantine if needed
   → Notify stakeholders
   
5. REVIEW:
   → Why wasn't this caught earlier?
   → Add alert rule to prevent recurrence
```

### Workflow 3: Regular Monitoring (continuous)
```
1. Auto-refresh every 5 seconds
   → Passively monitor dashboards
   → Glance at Cortex for threat score
   
2. Alert on unusual activity
   → (Coming Phase 2) Set thresholds
   → Get notifications on anomalies
   
3. Weekly review
   → Check trends in Process Telemetry
   → Review incident patterns
   → Optimize agent configurations
```

---

## ⚡ QUICK REFERENCE: WHAT MEANS WHAT

### Color Coding
```
🟢 Green    = All good, no action needed
🟡 Yellow   = Warning, monitor closely
🔴 Red      = Critical, action needed now
⚪ Gray     = Offline, waiting for data
```

### Severity Levels
```
🟦 Low       = Informational, monitor
🟨 Medium    = Review, may need action
🟥 High      = Investigate immediately
⚫ Critical  = Incident, escalate
```

### Health Indicators
```
Threat Score:
  0-20  = Safe
  21-50 = Alert
  51-100= Danger

System Health:
  CPU <70% = Good
  Memory <70% = Good
  Disk <70% = Good

Agent Status:
  Online = Connected and reporting
  Offline = Not communicating (check agent)
  Error = Problem detected (check logs)
```

---

## 🔍 HOW TO FIND THINGS

### Find a Specific Process
```
1. Go to Process Telemetry
2. Look at "Top Executables" list
3. OR check "Live Process Stream" (paginated)
4. Future: Use search when implemented
```

### Find Security Events
```
1. Go to SOC Dashboard
2. Check Threat Timeline
3. Look at event list
4. Click for details
5. Future: Filter by severity, type, source
```

### Check If Agent Is Online
```
1. Go to Agent Management
2. Look for agent in list
3. Check status (Online/Offline)
4. Check "Last Heartbeat" time
5. If offline >5min: investigate agent
```

### Verify System Is Healthy
```
1. Go to System Health
2. Check CPU, Memory, Disk metrics
3. All should be <70% for healthy
4. If any >90%: investigate what's using resources
5. Use Process Telemetry to find the process
```

---

## 🚨 COMMON ISSUES & FIXES

### Issue: Dashboard shows "no data"
```
Likely Cause: Endpoint not connected or no events
Solution:
  1. Check Agents dashboard - is endpoint online?
  2. If offline: Restart agent
  3. If online: Wait 5 minutes for data collection
  4. Check browser console (F12) for errors
```

### Issue: Charts not updating
```
Likely Cause: Network issue or API down
Solution:
  1. Refresh page (F5 or Cmd+R)
  2. Check network tab (F12 → Network)
  3. Look for failed requests
  4. Check if Flask is running: curl http://127.0.0.1:5000/dashboard
```

### Issue: Process Telemetry shows old data
```
Likely Cause: Data is from collection period (7.2 hours ago)
Solution:
  1. This is normal - data is historical
  2. Live data will update as new events arrive
  3. Check timestamp at top of metrics
```

### Issue: Agent shows offline
```
Likely Cause: Agent crashed or stopped
Solution:
  1. Check agent logs: tail -50 logs/agent.log
  2. Restart agent: pkill -f amoskys-agent && make run-agent
  3. Wait 30 seconds for reconnection
  4. Check "Last Heartbeat" updates
```

---

## 📱 MOBILE ACCESS

### Access from Mobile Device
```
On same WiFi as Flask server:
1. Find your computer's IP: ifconfig | grep inet
   (look for 192.168.x.x or 10.x.x.x)
2. Open mobile browser: http://[IP]:5000/dashboard
3. Dashboard is responsive - works on mobile!
```

### Limitations on Mobile
```
✅ Can view all dashboards
✅ Can see charts on mobile
✅ Auto-refresh works
❌ Some text may be small
❌ Tables may need scrolling
💡 Recommendation: Use tablet for better UX
```

---

## 🔐 SECURITY BEST PRACTICES

### Access Control (When Auth Implemented)
```
1. Never share login credentials
2. Use strong passwords (Phase 2)
3. Enable MFA when available (Phase 2)
4. Log out when leaving machine
5. Report suspicious access attempts
```

### Threat Assessment
```
1. Don't trust single indicators - correlate
2. Check timestamp - when did it happen?
3. Check context - what was running before/after?
4. Verify with multiple dashboards
5. Document findings before acting
```

### Incident Handling
```
1. Isolate affected system if critical
2. Preserve evidence (don't restart)
3. Contact security team
4. Document timeline
5. Review after resolution
```

---

## 📞 GETTING HELP

### Common Questions

**Q: Can I see historical data?**
```
A: Currently showing last 7.2 hours (process)
   Phase 2: Will have 30-day history
```

**Q: Can I set alerts?**
```
A: Not yet - Phase 2 feature
   Workaround: Manually monitor dashboards
```

**Q: Can I export reports?**
```
A: Not yet - Phase 2 feature
   Workaround: Screenshot dashboards
```

**Q: How often does data refresh?**
```
A: Every 5 seconds automatically
   Faster: Click refresh button (when added)
```

**Q: Can I correlate events across endpoints?**
```
A: Phase 2 - currently single endpoint
   Workaround: Use agent IDs when available
```

### Escalation Path
```
For bugs:        Report to dev team with screenshots
For feature requests: Priority based on analyst feedback
For security issues:  Report immediately to security team
For performance:      Check Flask logs and share details
```

---

## ✨ KEY TAKEAWAYS

1. **Cortex Dashboard**: Your main control panel - check it first
2. **Process Telemetry**: Deep visibility into what's running
3. **System Health**: Understand resource utilization
4. **SOC Dashboard**: Track security events (coming soon)
5. **Agent Management**: See your protected endpoints
6. **Neural Insights**: ML-powered anomaly detection (coming soon)

---

**Ready to start?** Open http://127.0.0.1:5000/dashboard now!

---

**Document Version**: 1.0  
**Last Updated**: December 4, 2025  
**Audience**: Security Analysts, SOC Operators, System Administrators

