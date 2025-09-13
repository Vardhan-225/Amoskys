# Amoskys Backpressure & Incident Response Runbook

## Quick Reference

### 🚨 Emergency Response
```bash
# Check system health immediately
make curl-health        # Agent and EventBus health status
make curl-metrics       # Current performance metrics
make logs-eventbus      # EventBus logs for errors
make logs-agent         # Agent logs for WAL issues
```

### 📊 Critical Metrics to Monitor
```
infraspectre_eventbus_inflight_messages     # Current queue depth
infraspectre_agent_wal_events_queued       # Agent WAL backlog
infraspectre_eventbus_overload_mode        # Backpressure engaged
infraspectre_agent_wal_events_dropped_total # Data loss indicator
```

## Backpressure System Overview

### Architecture
```
Agent WAL → EventBus Queue → Processing Pipeline
     ↓           ↓                    ↓
   [WAL Full] [Queue Full]      [Slow Processing]
     ↓           ↓                    ↓
  Drop Oldest  Reject New        Signal Backpressure
```

### Backpressure Flow
```
1. EventBus Queue Fills → Overload Mode Activated
2. EventBus Signals Backpressure → Agent Reduces Send Rate
3. Agent WAL Fills → Older Events Dropped (LRU)
4. Monitoring Alerts → Human Intervention Required
```

## Incident Severity Levels

### 🟢 **Level 0: Normal Operation**
```
Metrics:
- infraspectre_eventbus_inflight_messages < 50
- infraspectre_agent_wal_events_queued < 100
- infraspectre_eventbus_overload_mode = 0
- No dropped events
```

**Action**: Continue monitoring

### 🟡 **Level 1: Elevated Queue Depth**
```
Metrics:
- infraspectre_eventbus_inflight_messages: 50-100
- infraspectre_agent_wal_events_queued: 100-500
- System still processing normally
```

**Actions**:
1. Increase monitoring frequency
2. Check processing pipeline performance
3. Verify no resource constraints

### 🟠 **Level 2: Backpressure Engaged**
```
Metrics:
- infraspectre_eventbus_inflight_messages > 100
- infraspectre_eventbus_overload_mode = 1
- Agent send rates reduced
```

**Actions**:
1. **Immediate**: Verify backpressure is working correctly
2. **Investigate**: Root cause of processing slowdown
3. **Monitor**: WAL queue depths on all agents
4. **Escalate**: If condition persists > 5 minutes

### 🔴 **Level 3: Data Loss Risk**
```
Metrics:
- infraspectre_agent_wal_events_queued > 1000
- infraspectre_agent_wal_events_dropped_total > 0
- Multiple agents showing high WAL depth
```

**Actions**:
1. **Immediate**: Execute emergency response procedures
2. **Investigate**: EventBus processing bottleneck
3. **Mitigate**: Scale EventBus horizontally if possible
4. **Document**: All dropped events for analysis

### 🚨 **Level 4: System Overload**
```
Metrics:
- Multiple agents dropping events
- EventBus queue depth > 500
- Processing pipeline stalled
```

**Actions**:
1. **Emergency**: Consider temporary agent shutdown
2. **Escalate**: Page on-call engineer immediately
3. **Document**: System state for post-incident analysis
4. **Communicate**: Notify stakeholders of potential data loss

## Diagnostic Procedures

### 1. **Quick Health Check**
```bash
#!/bin/bash
# Quick system health assessment

echo "=== Amoskys Health Check ==="
echo "Timestamp: $(date)"
echo

# Check service health
echo "🏥 Service Health:"
curl -s http://localhost:8080/health | jq '.'  # EventBus
curl -s http://localhost:8081/health | jq '.'  # Agent

echo
echo "📊 Key Metrics:"
# EventBus metrics
echo "EventBus Queue Depth:"
curl -s http://localhost:9100/metrics | grep infraspectre_eventbus_inflight_messages

echo "EventBus Overload Mode:"
curl -s http://localhost:9100/metrics | grep infraspectre_eventbus_overload_mode

# Agent metrics
echo "Agent WAL Queue:"
curl -s http://localhost:9101/metrics | grep infraspectre_agent_wal_events_queued

echo "Agent Dropped Events:"
curl -s http://localhost:9101/metrics | grep infraspectre_agent_wal_events_dropped_total
```

### 2. **Detailed Performance Analysis**
```bash
#!/bin/bash
# Comprehensive performance analysis

echo "=== Performance Analysis ==="

# EventBus performance
echo "📈 EventBus Throughput:"
curl -s http://localhost:9100/metrics | grep -E "(messages_received_total|messages_processed_total)"

# Agent performance
echo "📈 Agent Throughput:"
curl -s http://localhost:9101/metrics | grep -E "(messages_sent_total|wal_events_processed_total)"

# System resources
echo "💾 System Resources:"
echo "Memory Usage:"
ps aux | grep -E "(infraspectre-eventbus|infraspectre-agent)" | awk '{print $1, $2, $3, $4, $11}'

echo "File Descriptors:"
lsof | grep -E "(infraspectre|50051|9100|9101)" | wc -l

echo "Network Connections:"
netstat -an | grep -E "(50051|9100|9101)" | wc -l
```

### 3. **WAL Analysis**
```bash
#!/bin/bash
# WAL database analysis

WAL_DB="${IS_WAL_PATH:-data/wal/flowagent.db}"

if [ -f "$WAL_DB" ]; then
    echo "=== WAL Database Analysis ==="
    echo "Database: $WAL_DB"
    echo "Size: $(du -h $WAL_DB | cut -f1)"
    
    echo "📊 WAL Statistics:"
    sqlite3 "$WAL_DB" "SELECT COUNT(*) as total_events FROM events;"
    sqlite3 "$WAL_DB" "SELECT COUNT(*) as pending_events FROM events WHERE processed = 0;"
    sqlite3 "$WAL_DB" "SELECT MIN(created_at), MAX(created_at) FROM events;"
    
    echo "🔍 Recent Events:"
    sqlite3 "$WAL_DB" "SELECT created_at, processed, retry_count FROM events ORDER BY created_at DESC LIMIT 10;"
else
    echo "❌ WAL database not found: $WAL_DB"
fi
```

## Troubleshooting Procedures

### EventBus Queue Buildup

#### **Symptom**: EventBus inflight messages > 100
```bash
# Diagnostic steps
echo "=== EventBus Queue Buildup Analysis ==="

# 1. Check EventBus processing rate
echo "Processing Rate:"
curl -s http://localhost:9100/metrics | grep infraspectre_eventbus_messages_processed_total

# 2. Check for processing errors
echo "Processing Errors:"
curl -s http://localhost:9100/metrics | grep infraspectre_eventbus_messages_failed_total

# 3. Check EventBus resource usage
echo "EventBus Resources:"
ps aux | grep infraspectre-eventbus

# 4. Check network connectivity
echo "Network Status:"
netstat -an | grep 50051
```

#### **Common Causes & Solutions**:

##### 1. **Processing Pipeline Bottleneck**
```bash
# Symptoms: High CPU usage, slow processing rate
# Investigation:
top -p $(pgrep infraspectre-eventbus)

# Solutions:
# - Scale EventBus horizontally
# - Optimize processing logic
# - Increase EventBus resources
```

##### 2. **Database Contention**
```bash
# Symptoms: High I/O wait, slow database operations
# Investigation:
iostat -x 1 5

# Solutions:
# - Optimize database queries
# - Consider database tuning
# - Check disk space and performance
```

##### 3. **Network Saturation**
```bash
# Symptoms: High network utilization, connection timeouts
# Investigation:
iftop -i eth0

# Solutions:
# - Check network bandwidth limits
# - Implement connection pooling
# - Consider load balancing
```

### Agent WAL Buildup

#### **Symptom**: Agent WAL events queued > 500
```bash
# Diagnostic steps
echo "=== Agent WAL Buildup Analysis ==="

# 1. Check agent send rate
echo "Agent Send Rate:"
curl -s http://localhost:9101/metrics | grep infraspectre_agent_messages_sent_total

# 2. Check connection to EventBus
echo "EventBus Connectivity:"
grpcurl -insecure -cert certs/agent.crt -key certs/agent.key \
  localhost:50051 infraspectre.EventBusService/Health

# 3. Check WAL processing
echo "WAL Processing:"
curl -s http://localhost:9101/metrics | grep infraspectre_agent_wal_events_processed_total

# 4. Analyze WAL database
sqlite3 data/wal/flowagent.db "SELECT COUNT(*) FROM events WHERE processed = 0;"
```

#### **Common Causes & Solutions**:

##### 1. **EventBus Connectivity Issues**
```bash
# Symptoms: Connection timeouts, gRPC errors
# Investigation:
tcpdump -i any port 50051

# Solutions:
# - Check EventBus health
# - Verify certificate validity
# - Check network connectivity
# - Review firewall rules
```

##### 2. **EventBus Backpressure**
```bash
# Symptoms: Backpressure signals from EventBus
# Investigation:
curl -s http://localhost:9100/metrics | grep overload_mode

# Solutions:
# - Wait for EventBus recovery
# - Scale EventBus if needed
# - Implement traffic shaping
```

##### 3. **Agent Resource Constraints**
```bash
# Symptoms: High memory/CPU usage, slow WAL processing
# Investigation:
ps aux | grep infraspectre-agent
df -h data/wal/

# Solutions:
# - Increase agent resources
# - Check disk space
# - Optimize WAL processing
```

## Recovery Procedures

### Graceful Recovery from Backpressure

#### **Step 1: Verify Backpressure Mechanism**
```bash
# Confirm backpressure is working
echo "Checking backpressure status..."
curl -s http://localhost:9100/metrics | grep infraspectre_eventbus_overload_mode

# Should show overload_mode = 1 during backpressure
```

#### **Step 2: Monitor Queue Reduction**
```bash
# Monitor queue depth reduction
watch -n 5 'curl -s http://localhost:9100/metrics | grep inflight_messages'

# Queue should gradually decrease
```

#### **Step 3: Verify Agent Adaptation**
```bash
# Check agent send rate reduction
curl -s http://localhost:9101/metrics | grep messages_sent_total

# Send rate should be lower during backpressure
```

#### **Step 4: Confirm Normal Operation**
```bash
# Wait for metrics to return to normal
# infraspectre_eventbus_overload_mode = 0
# infraspectre_eventbus_inflight_messages < 50
```

### Emergency Recovery Procedures

#### **Emergency: Stop Agent Data Collection**
```bash
# If data loss is imminent, temporarily stop agents
echo "🚨 EMERGENCY: Stopping agent data collection"

# Option 1: Graceful shutdown
pkill -TERM infraspectre-agent

# Option 2: Immediate stop (if graceful fails)
pkill -KILL infraspectre-agent

# Document the action
echo "$(date): Emergency agent shutdown - see incident log" >> /var/log/infraspectre/incidents.log
```

#### **Emergency: EventBus Restart**
```bash
# If EventBus is completely stalled
echo "🚨 EMERGENCY: Restarting EventBus"

# 1. Save current state
curl -s http://localhost:9100/metrics > /tmp/eventbus_metrics_before_restart.txt

# 2. Graceful shutdown
pkill -TERM infraspectre-eventbus

# 3. Wait for shutdown
sleep 10

# 4. Force kill if needed
pkill -KILL infraspectre-eventbus

# 5. Restart service
systemctl start infraspectre-eventbus
# OR: make run-eventbus

# 6. Verify recovery
sleep 30
curl http://localhost:8080/health
```

### Data Recovery Procedures

#### **Recover Lost Events from WAL**
```bash
#!/bin/bash
# Attempt to recover events from agent WAL after outage

WAL_DB="${IS_WAL_PATH:-data/wal/flowagent.db}"

echo "=== WAL Data Recovery ==="
echo "Analyzing WAL database: $WAL_DB"

# Count unprocessed events
UNPROCESSED=$(sqlite3 "$WAL_DB" "SELECT COUNT(*) FROM events WHERE processed = 0;")
echo "Unprocessed events: $UNPROCESSED"

if [ "$UNPROCESSED" -gt 0 ]; then
    echo "📤 Attempting to reprocess WAL events..."
    
    # Restart agent to trigger WAL replay
    systemctl restart infraspectre-agent
    
    # Monitor replay progress
    echo "Monitoring WAL replay progress..."
    watch -n 5 "sqlite3 $WAL_DB 'SELECT COUNT(*) FROM events WHERE processed = 0;'"
else
    echo "✅ No unprocessed events found"
fi
```

## Performance Tuning

### EventBus Tuning

#### **Increase Queue Capacity**
```yaml
# config/infraspectre.yaml
eventbus:
  max_inflight: 200      # Increase from default 100
  hard_max: 1000         # Increase from default 500
  overload_mode: false   # Disable during high-volume periods (caution!)
```

#### **Optimize Processing Threads**
```python
# Increase EventBus worker threads
server = grpc.server(ThreadPoolExecutor(max_workers=20))  # Default: 10
```

### Agent Tuning

#### **WAL Configuration**
```yaml
# config/infraspectre.yaml
agent:
  send_rate: 100         # Limit events/second to reduce load
  retry_max: 3           # Reduce retries to fail faster
  retry_timeout: 0.5     # Reduce timeout for faster failure detection

storage:
  max_wal_bytes: 419430400  # Increase WAL size (400MB)
```

#### **Batch Processing**
```python
# Process WAL events in batches
BATCH_SIZE = 50  # Increase from default
events = wal.get_pending_events(limit=BATCH_SIZE)
```

## Monitoring and Alerting

### Critical Alerts

#### **Prometheus Alert Rules**
```yaml
# deploy/observability/alerts.yml
groups:
- name: infraspectre_backpressure
  rules:
  
  # Level 2: Backpressure Engaged
  - alert: AmoskysBackpressureEngaged
    expr: infraspectre_eventbus_overload_mode == 1
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "Amoskys EventBus backpressure engaged"
      description: "EventBus queue depth triggered backpressure mode"

  # Level 3: High WAL Queue
  - alert: AmoskysHighWALQueue
    expr: infraspectre_agent_wal_events_queued > 1000
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Amoskys Agent WAL queue very high"
      description: "Agent WAL queue at {{ $value }} events, data loss risk"

  # Level 4: Data Loss
  - alert: AmoskysDataLoss
    expr: increase(infraspectre_agent_wal_events_dropped_total[5m]) > 0
    labels:
      severity: critical
    annotations:
      summary: "Amoskys data loss detected"
      description: "{{ $value }} events dropped in last 5 minutes"
```

#### **Custom Monitoring Script**
```bash
#!/bin/bash
# Continuous monitoring with automatic alerting

ALERT_WEBHOOK="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

while true; do
    # Get current metrics
    QUEUE_DEPTH=$(curl -s http://localhost:9100/metrics | grep infraspectre_eventbus_inflight_messages | awk '{print $2}')
    WAL_QUEUE=$(curl -s http://localhost:9101/metrics | grep infraspectre_agent_wal_events_queued | awk '{print $2}')
    OVERLOAD=$(curl -s http://localhost:9100/metrics | grep infraspectre_eventbus_overload_mode | awk '{print $2}')
    
    # Check for concerning conditions
    if [ "$QUEUE_DEPTH" -gt 200 ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data '{"text":"🚨 Amoskys EventBus queue very high: '$QUEUE_DEPTH'"}' \
            "$ALERT_WEBHOOK"
    fi
    
    if [ "$WAL_QUEUE" -gt 1000 ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data '{"text":"⚠️ Amoskys Agent WAL queue high: '$WAL_QUEUE'"}' \
            "$ALERT_WEBHOOK"
    fi
    
    sleep 60
done
```

## Incident Response Checklist

### 🟡 **Level 1-2 Response**
- [ ] Check current metrics and trends
- [ ] Verify system health endpoints
- [ ] Review recent log entries
- [ ] Confirm backpressure mechanism working
- [ ] Document incident start time
- [ ] Increase monitoring frequency

### 🔴 **Level 3-4 Response**
- [ ] Execute emergency diagnostic procedures
- [ ] Page on-call engineer if off-hours
- [ ] Document all current metric values
- [ ] Consider scaling EventBus horizontally
- [ ] Prepare for potential agent shutdown
- [ ] Notify stakeholders of potential impact
- [ ] Begin incident communication process

### 📊 **Post-Incident**
- [ ] Document timeline of events
- [ ] Analyze root cause
- [ ] Review metric trends leading to incident
- [ ] Update monitoring thresholds if needed
- [ ] Implement preventive measures
- [ ] Share lessons learned with team
- [ ] Update runbook based on experience

## Contact Information

### 🚨 **Emergency Contacts**
- **On-Call Engineer**: [Your on-call rotation]
- **Infrastructure Team**: [Team contact]
- **Security Team**: [Security contact if data loss]

### 📞 **Escalation Path**
1. **Level 1-2**: Monitor and document
2. **Level 3**: Page on-call engineer
3. **Level 4**: Page infrastructure manager
4. **Data Loss**: Notify security team

This runbook provides comprehensive procedures for managing backpressure situations and ensuring system reliability under load.
