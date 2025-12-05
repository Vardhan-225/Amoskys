# AMOSKYS Production Hardening Checklist

**Status**: Phase 1.5 Implementation  
**Date**: December 4, 2025  
**Target**: Production-ready security intelligence platform

---

## Phase 1.5: Critical Enhancements (IN PROGRESS)

### ✅ COMPLETED: Error Handling & Data Freshness (Cortex Dashboard)

**What Was Done**:
- Added error boundary UI with retry buttons
- Implemented data freshness indicators ("Last updated: Xs ago")
- Added failure counting (max 3 retries before showing error)
- Color-coded timestamp display (green = fresh, yellow = stale, red = error)
- Better exception handling with try-catch blocks

**Files Modified**:
- `web/app/templates/dashboard/cortex.html`

**Implementation Details**:
```javascript
// New Error Display
showErrorState(containerId, message, retryFn) {
    // Displays red error box with retry button
}

// Data Freshness Tracking
lastUpdateTime = { metrics: null, threats: null, agents: null }
getTimeSinceUpdate(updateType)     // Returns "5s ago", "1m ago", etc.
updateTimestampDisplay(elementId)  // Shows color-coded freshness

// Failure Counting
failureCount = { metrics: 0, threats: 0, agents: 0 }
maxRetries = 3                      // Show error after 3 consecutive failures
```

**Test Result**: ✅ **VERIFIED WORKING**
- Error messages now display with retry button
- Timestamps update every 5 seconds
- Color transitions from green → yellow → red as data ages

---

### ⏳ IN PROGRESS: Rate Limiting (API Gateway)

**What To Do**:
- Implement per-IP rate limiting (100 req/min)
- Prevent API abuse from malicious clients
- Log rate limit violations
- Return 429 (Too Many Requests) when limit exceeded

**Implementation Plan**:
```python
# File: web/app/api/rate_limiter.py (NEW)
from flask import request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import collections

class RateLimiter:
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = collections.defaultdict(list)  # IP -> [timestamps]
    
    def is_allowed(self, ip_address):
        """Check if IP is within rate limit"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        # Clean old requests
        self.requests[ip_address] = [
            ts for ts in self.requests[ip_address] 
            if ts > cutoff
        ]
        
        # Check limit
        if len(self.requests[ip_address]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[ip_address].append(now)
        return True
    
    def get_remaining(self, ip_address):
        """Get remaining requests for IP"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        count = len([ts for ts in self.requests[ip_address] if ts > cutoff])
        return max(0, self.max_requests - count)

# Global rate limiter instance
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)

def require_rate_limit(f):
    """Decorator to enforce rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        
        if not rate_limiter.is_allowed(ip):
            remaining = rate_limiter.get_remaining(ip)
            return jsonify({
                'error': 'Rate limit exceeded',
                'max_requests': 100,
                'window_seconds': 60,
                'retry_after': 60,
                'requests_remaining': remaining
            }), 429
        
        return f(*args, **kwargs)
    return decorated_function
```

**Where To Apply**:
```python
# File: web/app/api/__init__.py
from .rate_limiter import require_rate_limit

# Apply to all API endpoints
@api_bp.route('/events/submit', methods=['POST'])
@require_rate_limit
def submit_event():
    ...

@api_bp.route('/events/list', methods=['GET'])
@require_rate_limit
def list_events():
    ...
```

**Status**: ⏳ **READY TO IMPLEMENT**

---

### ⏳ PENDING: Memory Leak Fixes (JavaScript)

**What To Do**:
- Add proper cleanup for setInterval timers on page navigation
- Implement lifecycle management in JavaScript classes
- Prevent memory growth over long sessions

**Current Issue**:
```javascript
// PROBLEM: Timer keeps running even after navigation
this.updateTimer = setInterval(() => this.updateAll(), 5000);
// When user navigates away, timer continues in background
```

**Solution**:
```javascript
// GOOD: Timer is properly cleaned up
class Dashboard {
    constructor() {
        this.updateTimer = null;
    }
    
    startUpdates() {
        this.updateTimer = setInterval(() => this.updateAll(), 5000);
        // Cleanup on page unload
        window.addEventListener('beforeunload', () => this.cleanup());
        // Cleanup on SPA navigation (if using routing)
        window.addEventListener('popstate', () => this.cleanup());
    }
    
    cleanup() {
        if (this.updateTimer) {
            clearInterval(this.updateTimer);
            this.updateTimer = null;
        }
        // Remove event listeners
        window.removeEventListener('beforeunload', () => this.cleanup());
        window.removeEventListener('popstate', () => this.cleanup());
    }
}
```

**Files To Update**:
- `web/app/templates/dashboard/cortex.html`
- `web/app/templates/dashboard/soc.html`
- `web/app/templates/dashboard/processes.html`
- `web/app/templates/dashboard/agents.html`
- `web/app/templates/dashboard/system.html`

**Status**: ⏳ **READY TO IMPLEMENT**

---

### ⏳ PENDING: Search & Filter (SOC Dashboard)

**What To Do**:
- Add basic threat search by type/severity
- Filter threats by date range
- Filter by agent_id
- Save filter preferences

**Implementation Example**:
```python
# File: web/app/api/events.py
@events_bp.route('/search', methods=['GET'])
@require_rate_limit
def search_events():
    """
    Search events with filters
    Query parameters:
      - event_type: str (malware_detection, anomaly_detected, etc.)
      - severity: str (low, medium, high, critical)
      - agent_id: str
      - after: timestamp (RFC3339)
      - before: timestamp (RFC3339)
      - limit: int (default: 50, max: 1000)
    """
    event_type = request.args.get('event_type')
    severity = request.args.get('severity')
    agent_id = request.args.get('agent_id')
    after = request.args.get('after')
    before = request.args.get('before')
    limit = min(int(request.args.get('limit', 50)), 1000)
    
    # Filter EVENT_STORE
    results = EVENT_STORE
    
    if event_type:
        results = [e for e in results if e['event_type'] == event_type]
    if severity:
        results = [e for e in results if e['severity'] == severity]
    if agent_id:
        results = [e for e in results if e['agent_id'] == agent_id]
    
    # Date range filtering
    if after:
        results = [e for e in results if e['timestamp'] > after]
    if before:
        results = [e for e in results if e['timestamp'] < before]
    
    # Sort by timestamp (newest first)
    results = sorted(results, key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        'status': 'success',
        'results': results[:limit],
        'count': len(results),
        'query': {
            'event_type': event_type,
            'severity': severity,
            'agent_id': agent_id
        }
    })
```

**Frontend Example**:
```html
<!-- Search/Filter Panel in SOC Dashboard -->
<div class="search-panel">
    <input type="text" id="search-type" placeholder="Event type...">
    <select id="filter-severity">
        <option value="">All Severities</option>
        <option value="low">Low</option>
        <option value="medium">Medium</option>
        <option value="high">High</option>
        <option value="critical">Critical</option>
    </select>
    <input type="date" id="filter-after" placeholder="From date">
    <input type="date" id="filter-before" placeholder="To date">
    <button onclick="applyFilters()">Search</button>
</div>
```

**Status**: ⏳ **DESIGN READY, AWAITING IMPLEMENTATION**

---

## Phase 2.0: Multi-Agent Support (SCHEDULED)

### Agent Auto-Registration
```python
# POST /api/agents/register
{
    "agent_id": "flowagent-002-linux",
    "hostname": "production-01.internal",
    "platform": "linux",
    "capabilities": ["process_telemetry", "network_capture", "file_monitoring"],
    "version": "1.0.0"
}
```

### Multi-Agent Threat Aggregation
```
Endpoint: GET /dashboard/api/live/threats?source=all
Response: Threats from all agents in unified view
Sorting: By severity (critical first), then timestamp
```

### Database Migration
```
Current: EVENT_STORE (in-memory Python list)
Future: PostgreSQL with proper indexing
Indexes needed:
  - timestamp (range queries)
  - severity (filtering)
  - agent_id (agent-specific views)
  - event_type (type filtering)
```

---

## Phase 2.5: Intelligence (SCHEDULED)

### Anomaly Detection
- Behavioral baselining per process
- Deviation scoring
- Threshold alerting

### ML Integration
- Threat prediction models
- Cross-endpoint correlation
- Automated response rules

### External Integrations
- SIEM connectors (Splunk, ELK)
- EDR platform integration (CrowdStrike, MS Defender)
- Ticket system automation (Jira, ServiceNow)

---

## Production Readiness Scorecard

| Component | Status | Priority | Owner | ETA |
|-----------|--------|----------|-------|-----|
| Error Boundaries | ✅ DONE | P0 | Agent | Dec 4 |
| Data Freshness | ✅ DONE | P0 | Agent | Dec 4 |
| Rate Limiting | ⏳ TODO | P1 | Agent | Dec 5 |
| Memory Leak Fixes | ⏳ TODO | P1 | Agent | Dec 5 |
| Search/Filter | ⏳ TODO | P2 | Agent | Dec 6 |
| Multi-Agent Support | ⏳ TODO | P2 | Agent | Dec 10 |
| DB Migration | ⏳ TODO | P2 | Agent | Dec 15 |
| ML Integration | ⏳ TODO | P2 | Agent | Dec 20 |

---

## Critical Tests Required

### Before Going to Production

**Test 1: Error Scenario Handling**
```bash
# Simulate API failure
Kill Flask server
# Dashboard should show error message with retry button
# Analyst should see: "Error loading metrics. Retry?"
```

**Test 2: Rate Limiting**
```bash
# Send 150 requests in 10 seconds
for i in {1..150}; do
  curl http://127.0.0.1:5000/api/events/submit &
done
# After 100 requests, should get 429 (Too Many Requests)
```

**Test 3: Memory Stability**
```bash
# Run dashboard for 8 hours
# Monitor memory: should stay stable (~150MB)
# Navigate between pages 100x
# Memory should not grow unbounded
```

**Test 4: Data Freshness**
```bash
# Open dashboard
# Verify: "Last updated: 5s ago"
# Wait 10 seconds
# Verify: "Last updated: 10s ago" (timestamp updates)
# Verify: Color changes from green → yellow
```

---

## Implementation Order (Recommended)

### Day 1 (Dec 5)
```
Morning:   Implement rate limiting
Afternoon: Test rate limiting under load
Evening:   Memory leak fix for all dashboards
```

### Day 2 (Dec 6)
```
Morning:   Implement search/filter API
Afternoon: Add search UI to SOC dashboard
Evening:   Integration testing
```

### Day 3-5 (Dec 7-9)
```
Multi-agent support design
Database schema design
Agent registration endpoint
```

### Day 6+ (Dec 10+)
```
ML pipeline integration
External SIEM connectors
Incident management workflow
```

---

## Notes for Implementers

### Security Considerations
- **Rate Limiting**: Must be enforced on all public APIs
- **Input Validation**: All search parameters must be sanitized
- **Error Messages**: Never expose internal stack traces to clients
- **Logging**: All rate limit violations and errors should be logged

### Performance Considerations
- **Database Indexes**: Add before storing more than 1M events
- **Query Optimization**: Use pagination (limit/offset) for large result sets
- **Caching**: Cache frequent queries (threat timeline, top processes)
- **Connection Pooling**: PostgreSQL connection pool for multi-agent deployments

### Monitoring Considerations
- **Health Checks**: `/health` endpoint that returns system status
- **Metrics**: Track API response times, error rates, rate limit violations
- **Alerting**: Alert if API latency > 1s or error rate > 5%
- **Logs**: Structure logs for ELK ingestion

---

## Rollback Plan

If production issues occur:

**Issue: High error rate after deployment**
```bash
# Rollback to previous version
git checkout HEAD~1
# Restart Flask server
# Verify dashboards work again
```

**Issue: Rate limiter causing legitimate traffic to fail**
```bash
# Increase limit temporarily
# Edit max_requests: 100 → 500
# Restart Flask server
```

**Issue: Memory leak not fixed**
```bash
# Restart Flask server nightly (temporary)
# Add monitoring to detect memory growth
# Schedule deeper investigation
```

---

## Post-Production Monitoring

### Metrics to Track
- API response time (p50, p95, p99)
- Error rate (5xx responses)
- Rate limit hit rate (429 responses)
- Dashboard load time
- Browser memory usage
- Data freshness (how often updates fail)

### Alerts to Configure
- API latency > 1 second → Page Engineering Team
- Error rate > 5% → Page SOC Team
- Memory usage > 500MB → Page DevOps Team
- Data updates failing > 3x → Page Ops Team

### Dashboard to Create
- Real-time platform health monitor
- API performance metrics
- Error rate trends
- Rate limit statistics
- User activity audit log

---

**Document Status**: ✅ **COMPLETE**  
**Next Action**: Implement rate limiting (highest priority)  
**Estimated Time to Production**: 3-5 days with all Phase 1.5 enhancements
