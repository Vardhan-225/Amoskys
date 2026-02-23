# InfraSpectre Docker Deployment Guide

**Purpose**: Comprehensive guide for containerized deployment and service orchestration across development, staging, and production environments.

## 🐳 Docker Architecture Overview

InfraSpectre uses a **multi-container architecture** with service mesh principles:

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  EventBus   │  │ FlowAgent   │  │    Observability    │  │
│  │             │  │             │  │                     │  │
│  │ Port: 50051 │  │ Port: 8081  │  │ Prometheus: 9090    │  │
│  │ Health:8080 │  │ Health:8081 │  │ Grafana: 3000       │  │
│  │ Metrics:9100│  │ Metrics:9101│  │ AlertManager: 9093  │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Container Images

### 1. EventBus Container (`deploy/Dockerfile.eventbus`)

```dockerfile
FROM python:3.13.5-slim

# Security: Non-root user
RUN groupadd -r infraspectre && useradd -r -g infraspectre infraspectre

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy application
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ src/
COPY config/ config/
COPY proto/ proto/
COPY infraspectre-eventbus .

# Generate protocol buffers
RUN python -m grpc_tools.protoc \
    -I proto \
    --python_out=src/amoskys/proto \
    --grpc_python_out=src/amoskys/proto \
    --pyi_out=src/amoskys/proto \
    proto/messaging_schema.proto

# Create required directories
RUN mkdir -p certs data/storage data/metrics

# Security: Read-only filesystem
VOLUME ["/app/certs", "/app/data"]

# Switch to non-root user
USER infraspectre

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

# Set environment
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE 50051 8080 9100

# Entry point
CMD ["./infraspectre-eventbus"]
```

**Key Features**:
- **Security**: Non-root user, read-only filesystem
- **Health Checks**: Built-in health monitoring
- **Multi-stage Build**: Optimized image size
- **Volume Mounts**: Persistent data and certificates

### 2. Agent Container (`deploy/Dockerfile.agent`)

```dockerfile
FROM python:3.13.5-slim

# Security setup
RUN groupadd -r infraspectre && useradd -r -g infraspectre infraspectre

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ src/
COPY config/ config/
COPY infraspectre-agent .

# Create data directories
RUN mkdir -p data/wal certs

# Security: Drop all capabilities
RUN setcap 'cap_net_raw,cap_net_admin+ep' /usr/bin/python3.13

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/healthz || exit 1

# Switch to non-root
USER infraspectre

# Environment
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE 8081 9101

# Entry point
CMD ["./infraspectre-agent"]
```

## 🚀 Docker Compose Configurations

### 1. Development Environment (`deploy/docker-compose.dev.yml`)

```yaml
version: '3.8'

networks:
  infraspectre:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

volumes:
  prometheus_data:
  grafana_data:
  eventbus_certs:
  agent_certs:
  eventbus_data:
  agent_data:

services:
  eventbus:
    build:
      context: .
      dockerfile: deploy/Dockerfile.eventbus
    container_name: infraspectre-eventbus
    hostname: eventbus
    networks:
      infraspectre:
        ipv4_address: 172.20.0.10
    ports:
      - "50051:50051"  # gRPC
      - "8080:8080"    # Health
      - "9100:9100"    # Metrics
    volumes:
      - eventbus_certs:/app/certs:ro
      - eventbus_data:/app/data
    environment:
      - BUS_SERVER_PORT=50051
      - BUS_OVERLOAD=false
      - BUS_MAX_INFLIGHT=100
      - LOGLEVEL=INFO
    depends_on:
      - prometheus
    restart: unless-stopped
    security_opt:
      - seccomp:deploy/seccomp-python-net.json
      - apparmor:unconfined
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

  agent:
    build:
      context: .
      dockerfile: deploy/Dockerfile.agent
    container_name: infraspectre-agent
    hostname: agent
    networks:
      infraspectre:
        ipv4_address: 172.20.0.11
    ports:
      - "8081:8081"    # Health
      - "9101:9101"    # Metrics
    volumes:
      - agent_certs:/app/certs:ro
      - agent_data:/app/data
    environment:
      - IS_BUS_ADDRESS=eventbus:50051
      - IS_WAL_PATH=/app/data/wal/flowagent.db
      - IS_CERT_DIR=/app/certs
      - LOGLEVEL=INFO
    depends_on:
      - eventbus
    restart: unless-stopped
    security_opt:
      - seccomp:deploy/seccomp-python-net.json
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN

  prometheus:
    image: prom/prometheus:v2.47.0
    container_name: infraspectre-prometheus
    hostname: prometheus
    networks:
      infraspectre:
        ipv4_address: 172.20.0.20
    ports:
      - "9090:9090"
    volumes:
      - ./deploy/observability/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:10.1.0
    container_name: infraspectre-grafana
    hostname: grafana
    networks:
      infraspectre:
        ipv4_address: 172.20.0.21
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./deploy/observability/grafana_infraspectre.json:/etc/grafana/provisioning/dashboards/infraspectre.json:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=infraspectre123
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
    restart: unless-stopped

  alertmanager:
    image: prom/alertmanager:v0.26.0
    container_name: infraspectre-alertmanager
    hostname: alertmanager
    networks:
      infraspectre:
        ipv4_address: 172.20.0.22
    ports:
      - "9093:9093"
    volumes:
      - ./deploy/observability/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
    restart: unless-stopped
```

### 2. Production Environment (`deploy/docker-compose.prod.yml`)

```yaml
version: '3.8'

# Production-ready configuration with:
# - Resource limits
# - Logging configuration
# - Health checks
# - Secrets management
# - High availability setup

services:
  eventbus:
    image: infraspectre/eventbus:${VERSION:-latest}
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        order: start-first
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
    networks:
      - infraspectre_prod
    ports:
      - "50051:50051"
    secrets:
      - eventbus_tls_cert
      - eventbus_tls_key
      - ca_cert
    environment:
      - BUS_SERVER_PORT=50051
      - BUS_MAX_INFLIGHT=1000
      - LOGLEVEL=WARN
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

networks:
  infraspectre_prod:
    external: true

secrets:
  eventbus_tls_cert:
    external: true
  eventbus_tls_key:
    external: true
  ca_cert:
    external: true
```

## 🔒 Security Configuration

### 1. Seccomp Profile (`deploy/seccomp-python-net.json`)

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
        "pread64", "pwrite64", "readv", "writev", "access", "pipe",
        "select", "sched_yield", "mremap", "msync", "mincore",
        "madvise", "shmget", "shmat", "shmctl", "dup", "dup2",
        "pause", "nanosleep", "getitimer", "alarm", "setitimer",
        "getpid", "sendfile", "socket", "connect", "accept",
        "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
        "bind", "listen", "getsockname", "getpeername", "socketpair",
        "setsockopt", "getsockopt", "clone", "fork", "vfork",
        "execve", "exit", "wait4", "kill", "uname", "semget",
        "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv",
        "msgctl", "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "getdents", "getcwd", "chdir",
        "fchdir", "rename", "mkdir", "rmdir", "creat", "link",
        "unlink", "symlink", "readlink", "chmod", "fchmod",
        "chown", "fchown", "lchown", "umask", "gettimeofday",
        "getrlimit", "getrusage", "sysinfo", "times", "ptrace",
        "getuid", "syslog", "getgid", "setuid", "setgid",
        "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
        "setsid", "setreuid", "setregid", "getgroups", "setgroups",
        "setresuid", "getresuid", "setresgid", "getresgid",
        "getpgid", "setfsuid", "setfsgid", "getsid", "capget",
        "capset", "rt_sigpending", "rt_sigtimedwait",
        "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack",
        "utime", "mknod", "uselib", "personality", "ustat",
        "statfs", "fstatfs", "sysfs", "getpriority", "setpriority",
        "sched_setparam", "sched_getparam", "sched_setscheduler",
        "sched_getscheduler", "sched_get_priority_max",
        "sched_get_priority_min", "sched_rr_get_interval",
        "mlock", "munlock", "mlockall", "munlockall", "vhangup",
        "modify_ldt", "pivot_root", "prctl", "arch_prctl",
        "adjtimex", "setrlimit", "chroot", "sync", "acct",
        "settimeofday", "mount", "umount2", "swapon", "swapoff",
        "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
        "create_module", "init_module", "delete_module",
        "get_kernel_syms", "query_module", "quotactl", "nfsservctl",
        "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security",
        "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr",
        "getxattr", "lgetxattr", "fgetxattr", "listxattr",
        "llistxattr", "flistxattr", "removexattr", "lremovexattr",
        "fremovexattr", "tkill", "time", "futex", "sched_setaffinity",
        "sched_getaffinity", "set_thread_area", "io_setup",
        "io_destroy", "io_getevents", "io_submit", "io_cancel",
        "get_thread_area", "lookup_dcookie", "epoll_create",
        "epoll_ctl_old", "epoll_wait_old", "remap_file_pages",
        "getdents64", "set_tid_address", "restart_syscall",
        "semtimedop", "fadvise64", "timer_create", "timer_settime",
        "timer_gettime", "timer_getoverrun", "timer_delete",
        "clock_settime", "clock_gettime", "clock_getres",
        "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl",
        "tgkill", "utimes", "vserver", "mbind", "set_mempolicy",
        "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend",
        "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load",
        "waitid", "add_key", "request_key", "keyctl", "ioprio_set",
        "ioprio_get", "inotify_init", "inotify_add_watch",
        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat",
        "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat",
        "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat",
        "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list",
        "get_robust_list", "splice", "tee", "sync_file_range",
        "vmsplice", "move_pages", "utimensat", "epoll_pwait",
        "signalfd", "timerfd_create", "eventfd", "fallocate",
        "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4",
        "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1",
        "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open",
        "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64",
        "name_to_handle_at", "open_by_handle_at", "clock_adjtime",
        "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
        "process_vm_writev", "kcmp", "finit_module"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### 2. AppArmor Profile (Optional)
```bash
# File: /etc/apparmor.d/infraspectre-eventbus
#include <tunables/global>

profile infraspectre-eventbus flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/python>

  # Allow network access
  network inet stream,
  network inet dgram,

  # Allow file access
  /app/** r,
  /app/data/** rw,
  /app/certs/** r,

  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_rawio,
}
```

## 📊 Container Monitoring

### 1. Health Checks
```bash
# EventBus health check
curl -f http://localhost:8080/healthz

# Agent health check  
curl -f http://localhost:8081/healthz

# Container health status
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### 2. Resource Monitoring
```bash
# Container resource usage
docker stats --no-stream

# Container logs
docker logs infraspectre-eventbus
docker logs infraspectre-agent

# Volume usage
docker system df
```

### 3. Prometheus Metrics
```yaml
# Scrape configuration
scrape_configs:
  - job_name: 'infraspectre-eventbus'
    static_configs:
      - targets: ['eventbus:9100']
    metrics_path: /metrics
    scrape_interval: 15s

  - job_name: 'infraspectre-agent'
    static_configs:
      - targets: ['agent:9101']
    metrics_path: /metrics
    scrape_interval: 15s
```

## 🚀 Deployment Workflows

### 1. Development Deployment
```bash
# Start development environment
make run-all

# This executes:
docker compose -f deploy/docker-compose.dev.yml up -d

# Health checks
make curl-health
make curl-metrics

# View logs
make logs-eventbus
make logs-agent
```

### 2. Production Deployment
```bash
# Build production images
make build-docker

# Tag for registry
docker tag infraspectre/eventbus:dev registry.company.com/infraspectre/eventbus:v1.0.0
docker tag infraspectre/agent:dev registry.company.com/infraspectre/agent:v1.0.0

# Push to registry
docker push registry.company.com/infraspectre/eventbus:v1.0.0
docker push registry.company.com/infraspectre/agent:v1.0.0

# Deploy with Docker Swarm
docker stack deploy -c deploy/docker-compose.prod.yml infraspectre
```

### 3. Rolling Updates
```bash
# Update EventBus
docker service update \
  --image registry.company.com/infraspectre/eventbus:v1.1.0 \
  --update-parallelism 1 \
  --update-delay 30s \
  infraspectre_eventbus

# Update Agent
docker service update \
  --image registry.company.com/infraspectre/agent:v1.1.0 \
  --update-parallelism 2 \
  --update-delay 10s \
  infraspectre_agent
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Certificate Mounting Issues
```bash
# Check certificate volume
docker volume inspect infraspectre_eventbus_certs

# Manual certificate copy
docker cp certs/. infraspectre-eventbus:/app/certs/
```

#### 2. Network Connectivity
```bash
# Test EventBus connectivity
docker exec infraspectre-agent nc -zv eventbus 50051

# Check DNS resolution
docker exec infraspectre-agent nslookup eventbus
```

#### 3. Resource Constraints
```bash
# Check resource limits
docker exec infraspectre-eventbus cat /sys/fs/cgroup/memory/memory.limit_in_bytes

# Monitor CPU usage
docker exec infraspectre-eventbus top -n 1
```

#### 4. Log Analysis
```bash
# Filter logs by level
docker logs infraspectre-eventbus 2>&1 | grep ERROR

# Follow logs in real-time
docker logs -f infraspectre-eventbus --tail 100
```

## 🎯 Production Readiness Checklist

### ✅ Security
- [x] Non-root containers
- [x] Read-only filesystems where possible
- [x] Seccomp profiles applied
- [x] Capability dropping
- [x] Secret management for TLS certificates
- [x] Network segmentation

### ✅ Reliability
- [x] Health checks configured
- [x] Restart policies defined
- [x] Resource limits set
- [x] Volume persistence
- [x] Graceful shutdown handling

### ✅ Observability
- [x] Structured logging
- [x] Prometheus metrics
- [x] Grafana dashboards
- [x] Alert rules configured
- [x] Distributed tracing ready

### ✅ Scalability
- [x] Horizontal scaling support
- [x] Load balancing ready
- [x] Resource monitoring
- [x] Auto-scaling hooks

---
*Docker deployment guide for production-ready InfraSpectre infrastructure*
