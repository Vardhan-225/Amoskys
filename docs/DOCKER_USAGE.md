# InfraSpectre Docker Usage Guide

## Overview

InfraSpectre is designed as a **cloud-native, container-first** architecture. This guide covers Docker integration, container orchestration, and production deployment strategies.

## Container Architecture

### Multi-Service Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                 InfraSpectre Container Stack                │
├─────────────────┬─────────────────┬─────────────────────────┤
│  EventBus       │  FlowAgent      │  Observability Stack    │
│  Container      │  Container      │  (Prometheus/Grafana)   │
│                 │                 │                         │
│  ┌────────────┐ │ ┌─────────────┐ │ ┌─────────────────────┐ │
│  │ gRPC Server│ │ │ Network     │ │ │ Prometheus          │ │
│  │ mTLS       │ │ │ Collector   │ │ │ ┌─────────────────┐ │ │
│  │ Metrics    │ │ │ WAL Storage │ │ │ │ Grafana         │ │ │
│  │ Health     │ │ │ Ed25519     │ │ │ │ AlertManager    │ │ │
│  └────────────┘ │ └─────────────┘ │ │ └─────────────────┘ │ │
└─────────────────┴─────────────────┴─────────────────────────┘
```

## Docker Images

### EventBus Container (`infraspectre/eventbus`)

#### Dockerfile Analysis
```dockerfile
FROM python:3.11-slim

# Security: Create non-root user
RUN useradd -r -u 10001 -s /usr/sbin/nologin infraspectre

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependencies and install
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/
COPY infraspectre-eventbus /app/infraspectre-eventbus

# Security: Make executable and set ownership
RUN chmod +x /app/infraspectre-eventbus

# Expose ports
EXPOSE 50051 9100 8080

# Security: Run as non-root user
USER infraspectre:infraspectre

# Set runtime environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

# Start EventBus server
CMD ["/app/infraspectre-eventbus"]
```

#### Image Layers
```bash
# View image layers
docker history infraspectre/eventbus

# Expected output:
# Layer 1: python:3.11-slim base (150MB)
# Layer 2: System packages (5MB)
# Layer 3: Python dependencies (50MB)
# Layer 4: Application code (5MB)
# Total: ~210MB
```

### FlowAgent Container (`infraspectre/agent`)

#### Dockerfile Analysis
```dockerfile
FROM python:3.11-slim

# Security: Create non-root user with different UID
RUN useradd -r -u 10002 -s /usr/sbin/nologin infraspectre

# Install system dependencies (including SQLite)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates sqlite3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependencies and install
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/
COPY infraspectre-agent /app/infraspectre-agent

# Security: Make executable
RUN chmod +x /app/infraspectre-agent

# Mount points for persistent data
VOLUME ["/certs", "/wal"]

# Expose ports
EXPOSE 9101 8081

# Security: Run as non-root user
USER infraspectre:infraspectre

# Set runtime environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src
ENV IS_WAL_PATH=/wal/wal.db
ENV IS_CERT_DIR=/certs

# Start FlowAgent
CMD ["/app/infraspectre-agent"]
```

## Docker Compose Configuration

### Development Environment
```yaml
# deploy/docker-compose.dev.yml
version: '3.8'

services:
  eventbus:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.eventbus
    container_name: infraspectre-eventbus
    ports:
      - "50051:50051"  # gRPC API
      - "9100:9100"    # Prometheus metrics
      - "8080:8080"    # Health checks
    volumes:
      - ../certs:/certs:ro
      - ../config:/config:ro
    environment:
      - PYTHONUNBUFFERED=1
      - IS_CONFIG_PATH=/config/infraspectre.yaml
      - IS_CERT_DIR=/certs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    networks:
      - infraspectre

  agent:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.agent
    container_name: infraspectre-agent
    ports:
      - "9101:9101"    # Prometheus metrics
      - "8081:8081"    # Health checks
    volumes:
      - ../certs:/certs:ro
      - ../config:/config:ro
      - agent_wal:/wal
    environment:
      - PYTHONUNBUFFERED=1
      - IS_CONFIG_PATH=/config/infraspectre.yaml
      - IS_CERT_DIR=/certs
      - IS_WAL_PATH=/wal/flowagent.db
      - BUS_ADDRESS=eventbus:50051
    depends_on:
      eventbus:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    networks:
      - infraspectre

  prometheus:
    image: prom/prometheus:v2.45.0
    container_name: infraspectre-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./observability/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./observability/alerts.yml:/etc/prometheus/alerts.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    networks:
      - infraspectre

  grafana:
    image: grafana/grafana:10.0.0
    container_name: infraspectre-grafana
    ports:
      - "3000:3000"
    volumes:
      - ./observability/grafana_infraspectre.json:/var/lib/grafana/dashboards/infraspectre.json:ro
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=infraspectre
      - GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/infraspectre.json
    networks:
      - infraspectre

volumes:
  agent_wal:
    driver: local
  prometheus_data:
    driver: local
  grafana_data:
    driver: local

networks:
  infraspectre:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Production Environment
```yaml
# deploy/docker-compose.prod.yml
version: '3.8'

services:
  eventbus:
    image: infraspectre/eventbus:latest
    deploy:
      replicas: 2
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
    ports:
      - "50051:50051"
    volumes:
      - /etc/infraspectre/certs:/certs:ro
      - /etc/infraspectre/config:/config:ro
    environment:
      - PYTHONUNBUFFERED=1
      - IS_CONFIG_PATH=/config/infraspectre.yaml
      - IS_CERT_DIR=/certs
      - IS_LOG_LEVEL=INFO
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    networks:
      - infraspectre

  agent:
    image: infraspectre/agent:latest
    deploy:
      mode: global  # One agent per node
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 5
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'
    volumes:
      - /etc/infraspectre/certs:/certs:ro
      - /etc/infraspectre/config:/config:ro
      - /var/lib/infraspectre/wal:/wal
    environment:
      - PYTHONUNBUFFERED=1
      - IS_CONFIG_PATH=/config/infraspectre.yaml
      - IS_CERT_DIR=/certs
      - IS_WAL_PATH=/wal/flowagent.db
      - BUS_ADDRESS=eventbus:50051
      - IS_LOG_LEVEL=INFO
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    networks:
      - infraspectre

networks:
  infraspectre:
    driver: overlay
    attachable: true
```

## Container Operations

### Building Images

#### Development Build
```bash
# Build development images
make build-docker

# Equivalent to:
docker build -f deploy/Dockerfile.eventbus -t infraspectre/eventbus:dev .
docker build -f deploy/Dockerfile.agent -t infraspectre/agent:dev .
```

#### Production Build
```bash
# Build production images with version tags
VERSION=$(git describe --tags --always)
docker build -f deploy/Dockerfile.eventbus -t infraspectre/eventbus:${VERSION} .
docker build -f deploy/Dockerfile.agent -t infraspectre/agent:${VERSION} .

# Tag as latest
docker tag infraspectre/eventbus:${VERSION} infraspectre/eventbus:latest
docker tag infraspectre/agent:${VERSION} infraspectre/agent:latest
```

#### Multi-Architecture Build
```bash
# Build for multiple architectures
docker buildx create --name infraspectre-builder --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -f deploy/Dockerfile.eventbus \
  -t infraspectre/eventbus:latest \
  --push .
```

### Running Containers

#### Single Container
```bash
# Run EventBus container
docker run -d \
  --name infraspectre-eventbus \
  -p 50051:50051 \
  -p 9100:9100 \
  -p 8080:8080 \
  -v $(pwd)/certs:/certs:ro \
  -v $(pwd)/config:/config:ro \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp \
  infraspectre/eventbus:latest

# Run Agent container
docker run -d \
  --name infraspectre-agent \
  -p 9101:9101 \
  -p 8081:8081 \
  -v $(pwd)/certs:/certs:ro \
  -v $(pwd)/config:/config:ro \
  -v infraspectre_wal:/wal \
  -e BUS_ADDRESS=host.docker.internal:50051 \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp \
  infraspectre/agent:latest
```

#### Docker Compose
```bash
# Development environment
cd deploy
docker-compose -f docker-compose.dev.yml up -d

# Production environment
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose logs -f eventbus
docker-compose logs -f agent

# Scale services
docker-compose -f docker-compose.prod.yml up -d --scale agent=3
```

## Prometheus Integration

### Metrics Collection Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   EventBus      │    │   FlowAgent     │    │   Prometheus    │
│   :9100/metrics │ <- │   :9101/metrics │ <- │   :9090         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                               ┌─────────────────┐
                                               │   Grafana       │
                                               │   :3000         │
                                               └─────────────────┘
```

### Prometheus Configuration
```yaml
# deploy/observability/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alerts.yml"
  - "records.yml"

scrape_configs:
  - job_name: 'infraspectre-eventbus'
    static_configs:
      - targets: ['eventbus:9100']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'infraspectre-agent'
    static_configs:
      - targets: ['agent:9101']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

### Custom Metrics Exposed

#### EventBus Metrics
```python
# EventBus metrics
infraspectre_eventbus_messages_received_total{source_agent="agent-001"} 1234
infraspectre_eventbus_messages_processed_total{source_agent="agent-001"} 1230
infraspectre_eventbus_messages_failed_total{source_agent="agent-001"} 4
infraspectre_eventbus_inflight_messages 45
infraspectre_eventbus_connections_active 3
infraspectre_eventbus_auth_failures_total{agent="agent-002"} 2
```

#### Agent Metrics
```python
# Agent metrics
infraspectre_agent_messages_sent_total{destination="eventbus"} 1234
infraspectre_agent_wal_events_queued 12
infraspectre_agent_wal_events_processed_total 1222
infraspectre_agent_network_bytes_captured_total 567890123
infraspectre_agent_health_check_duration_seconds 0.045
```

### Grafana Dashboards

#### InfraSpectre System Overview
```json
{
  "dashboard": {
    "title": "InfraSpectre System Overview",
    "panels": [
      {
        "title": "Message Throughput",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(infraspectre_eventbus_messages_received_total[5m])",
            "legendFormat": "Messages/sec"
          }
        ]
      },
      {
        "title": "System Health",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=~\"infraspectre-.*\"}",
            "legendFormat": "{{job}}"
          }
        ]
      },
      {
        "title": "WAL Queue Depth",
        "type": "graph",
        "targets": [
          {
            "expr": "infraspectre_agent_wal_events_queued",
            "legendFormat": "{{instance}}"
          }
        ]
      }
    ]
  }
}
```

## Container Security

### Security Best Practices

#### Runtime Security
```bash
# Security-hardened container execution
docker run \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --read-only \
  --tmpfs /tmp \
  --user 10001:10001 \
  --security-opt seccomp=seccomp-python-net.json \
  infraspectre/eventbus:latest
```

#### SecComp Profile
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "socket", "connect", "accept", "bind", "listen",
        "getsockname", "getpeername", "setsockopt", "getsockopt"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### Container Scanning

#### Vulnerability Scanning
```bash
# Scan images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image infraspectre/eventbus:latest

# Expected output:
# Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```

#### Image Signing
```bash
# Sign container images (production)
export COSIGN_PRIVATE_KEY=/path/to/cosign.key
cosign sign --key cosign.key infraspectre/eventbus:latest
cosign sign --key cosign.key infraspectre/agent:latest

# Verify signatures
cosign verify --key cosign.pub infraspectre/eventbus:latest
```

## Kubernetes Deployment

### EventBus Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: infraspectre-eventbus
  namespace: infraspectre
spec:
  replicas: 2
  selector:
    matchLabels:
      app: infraspectre-eventbus
  template:
    metadata:
      labels:
        app: infraspectre-eventbus
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
      - name: eventbus
        image: infraspectre/eventbus:latest
        ports:
        - containerPort: 50051
          name: grpc
        - containerPort: 9100
          name: metrics
        - containerPort: 8080
          name: health
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
        - name: config
          mountPath: /config
          readOnly: true
        - name: tmp
          mountPath: /tmp
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: certs
        secret:
          secretName: infraspectre-certs
      - name: config
        configMap:
          name: infraspectre-config
      - name: tmp
        emptyDir: {}
```

### Agent DaemonSet
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: infraspectre-agent
  namespace: infraspectre
spec:
  selector:
    matchLabels:
      app: infraspectre-agent
  template:
    metadata:
      labels:
        app: infraspectre-agent
    spec:
      hostNetwork: true  # For network monitoring
      securityContext:
        runAsNonRoot: true
        runAsUser: 10002
        fsGroup: 10002
      containers:
      - name: agent
        image: infraspectre/agent:latest
        ports:
        - containerPort: 9101
          name: metrics
        - containerPort: 8081
          name: health
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
            add: ["NET_RAW", "NET_ADMIN"]  # For packet capture
        volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
        - name: config
          mountPath: /config
          readOnly: true
        - name: wal
          mountPath: /wal
        - name: tmp
          mountPath: /tmp
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: BUS_ADDRESS
          value: "infraspectre-eventbus:50051"
      volumes:
      - name: certs
        secret:
          secretName: infraspectre-certs
      - name: config
        configMap:
          name: infraspectre-config
      - name: wal
        hostPath:
          path: /var/lib/infraspectre/wal
          type: DirectoryOrCreate
      - name: tmp
        emptyDir: {}
```

## Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check container logs
docker logs infraspectre-eventbus

# Common issues:
# 1. Certificate permission errors
# 2. Port binding conflicts
# 3. Configuration file missing
# 4. Network connectivity issues
```

#### Performance Issues
```bash
# Monitor container resources
docker stats infraspectre-eventbus infraspectre-agent

# Check metrics
curl http://localhost:9100/metrics | grep infraspectre
curl http://localhost:9101/metrics | grep infraspectre
```

#### Network Connectivity
```bash
# Test gRPC connectivity
grpcurl -insecure -cert certs/agent.crt -key certs/agent.key \
  localhost:50051 infraspectre.EventBusService/Health

# Test from inside container
docker exec -it infraspectre-agent \
  curl -f http://localhost:8081/health
```

### Debugging Commands
```bash
# Enter container for debugging
docker exec -it infraspectre-eventbus /bin/bash

# View container configuration
docker inspect infraspectre-eventbus

# Monitor container events
docker events --filter container=infraspectre-eventbus

# Analyze image layers
docker history infraspectre/eventbus:latest
```

## Performance Optimization

### Container Tuning

#### Memory Optimization
```bash
# Limit memory usage
docker run --memory=512m --memory-swap=512m infraspectre/eventbus

# Monitor memory usage
docker stats --format "table {{.Container}}\t{{.MemUsage}}\t{{.MemPerc}}"
```

#### CPU Optimization
```bash
# Limit CPU usage
docker run --cpus="0.5" infraspectre/eventbus

# Use CPU affinity
docker run --cpuset-cpus="0,1" infraspectre/eventbus
```

### Image Optimization

#### Multi-Stage Build
```dockerfile
# Build stage
FROM python:3.11-slim as builder
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# Production stage
FROM python:3.11-slim
COPY --from=builder /root/.local /root/.local
COPY src/ /app/src/
```

#### Image Size Reduction
```bash
# Remove development dependencies
pip install --no-dev -r requirements.txt

# Use Alpine base image (if compatible)
FROM python:3.11-alpine

# Clean package cache
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
```

This comprehensive Docker guide enables efficient container deployment and management of InfraSpectre in any environment.
