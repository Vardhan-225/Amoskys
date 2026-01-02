# AMOSKYS Gunicorn Configuration
# Production WSGI server configuration for NGINX deployment

import multiprocessing
import os

# Server socket
bind = "127.0.0.1:8000"
backlog = 2048

# Worker processes
worker_count = multiprocessing.cpu_count() * 2 + 1
# Cap at 4 workers for local development to prevent resource exhaustion
workers = (
    min(worker_count, 4)
    if os.getenv("FLASK_DEBUG", "False").lower() == "true"
    else worker_count
)
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests, to help control memory leaks
max_requests = 1000
max_requests_jitter = 50

# Load application code before the worker processes are forked
preload_app = True

# Server mechanics
daemon = False
pidfile = "/tmp/amoskys-web.pid"
user = None
group = None
tmp_upload_dir = None

# Logging
accesslog = "/var/log/amoskys/web-access.log"
errorlog = "/var/log/amoskys/web-error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Development logging (when running locally)
import os

if os.getenv("FLASK_DEBUG", "False").lower() == "true":
    accesslog = "-"  # stdout
    errorlog = "-"  # stderr

# Process naming
proc_name = "amoskys-web"


# Server hooks
def on_starting(server):
    server.log.info("🧠🛡️ AMOSKYS Web Interface Starting...")


def on_reload(server):
    server.log.info("🔄 AMOSKYS Web Interface Reloading...")


def worker_int(worker):
    worker.log.info("🔧 AMOSKYS Worker received INT or QUIT signal")


def pre_fork(server, worker):
    server.log.info(f"🚀 AMOSKYS Worker spawned (pid: {worker.pid})")


def post_fork(server, worker):
    server.log.info(f"✅ AMOSKYS Worker ready (pid: {worker.pid})")


def worker_abort(worker):
    worker.log.info(f"❌ AMOSKYS Worker aborted (pid: {worker.pid})")
