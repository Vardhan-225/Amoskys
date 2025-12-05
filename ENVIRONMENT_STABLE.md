# ✅ AMOSKYS Environment - Stable & Robust Setup

## 🎯 What's Been Implemented

The AMOSKYS environment has been made **stable and robust** with comprehensive automation and validation.

---

## 🚀 Quick Start (Copy-Paste Ready)

### 1️⃣ Setup Environment
```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys
make env
```

### 2️⃣ Activate Environment
```bash
source .venv/bin/activate
```

### 3️⃣ Start Dashboard
```bash
make run-dashboard
```

### 4️⃣ Access Dashboard
Open in browser: **http://127.0.0.1:5000/dashboard/cortex**

---

## ✨ New Features

### 1. **Robust Environment Management**
- ✅ `make env` - One command to set up everything
- ✅ `make check-env` - Verify environment is activated
- ✅ `make validate` - Comprehensive validation checks
- ✅ Automatic dependency installation
- ✅ Directory creation and setup

### 2. **Automated Validation**
- ✅ Python version checking (requires 3.9+)
- ✅ Package installation verification
- ✅ Application structure validation
- ✅ Database connectivity checks
- ✅ Port availability detection

### 3. **Environment Activation Checks**
```bash
make run-dashboard
# If environment not activated, shows:
# ❌ Virtual environment not activated!
#    Activate with: source .venv/bin/activate
```

### 4. **Single-Port Server Management**
- ✅ Always runs on port 5000
- ✅ Automatically kills duplicate instances
- ✅ PID tracking in `logs/flask.pid`
- ✅ Health checks before confirming startup

### 5. **Helper Scripts**
- `start_amoskys.sh` - Automated dashboard startup
- `stop_amoskys.sh` - Clean shutdown
- `scripts/check_env.sh` - Comprehensive environment validation
- `scripts/activate_check.sh` - Quick activation check

---

## 📋 Environment Commands Reference

### Setup & Validation
| Command | Description | Requires Activation |
|---------|-------------|---------------------|
| `make env` | Create and configure environment | ❌ No |
| `make check-env` | Verify environment is activated | ✅ Yes |
| `make validate` | Validate installation | ❌ No |
| `make env-info` | Show environment details | ❌ No |

### Dashboard Management
| Command | Description | Requires Activation |
|---------|-------------|---------------------|
| `make run-dashboard` | Start dashboard | ✅ Yes |
| `make stop-dashboard` | Stop dashboard | ❌ No |
| `make restart-dashboard` | Restart dashboard | ✅ Yes |
| `make status` | Show dashboard status | ❌ No |
| `make logs-dashboard` | View dashboard logs | ❌ No |

### Development
| Command | Description | Requires Activation |
|---------|-------------|---------------------|
| `make test` | Run tests | ✅ Yes |
| `make shell` | Interactive shell with environment | ❌ No (auto-activates) |
| `make fmt` | Format code | ✅ Yes |
| `make lint` | Lint code | ✅ Yes |

---

## 🔧 What Happens Behind the Scenes

### `make env` Process
1. **Python Version Check** - Ensures Python 3.9+
2. **Virtual Environment Creation** - Creates `.venv/`
3. **Pip Upgrade** - Upgrades to latest pip
4. **Dependency Installation** - Installs from `requirements.txt`
5. **Directory Creation** - Creates `logs/`, `data/`, `backups/`
6. **Protobuf Generation** - Generates protocol buffer schemas
7. **Validation** - Confirms everything installed correctly

### `make run-dashboard` Process
1. **Environment Check** - Verifies activation
2. **Port Check** - Ensures port 5000 is available
3. **Cleanup** - Kills any existing Flask instances
4. **Startup** - Launches Flask with proper PYTHONPATH
5. **Health Check** - Waits for server to respond
6. **PID Tracking** - Saves PID to `logs/flask.pid`

---

## ✅ Validation & Error Handling

### Environment Validation (`make validate`)
```bash
$ make validate

🔍 Validating AMOSKYS installation...

[1/5] Python Environment
  Python: 3.9.6
  Location: /Users/athanneeru/Downloads/GitHub/Amoskys/.venv/bin/python
  ✓

[2/5] Critical Dependencies
  ✓ Flask: 3.1.0
  ✓ psutil: 6.1.1
  ✓ Flask-SocketIO: 5.3.6
  ✓

[3/5] Application Structure
  ✓ web/wsgi.py
  ✓ web/app/
  ✓ src/amoskys/
  ✓

[4/5] Data Directories
  ✓ logs/
  ✓ data/
  ✓

[5/5] Database
  ✓ flowagent.db (15 MB, 491,501 rows)
  ✓

✓ Validation complete!
```

### Environment Activation Check (`make check-env`)
```bash
# When activated:
$ make check-env
✅ Virtual environment active: /Users/athanneeru/Downloads/GitHub/Amoskys/.venv

# When NOT activated:
$ make check-env
❌ Virtual environment not activated!
   Activate with: source .venv/bin/activate
   Or run with: make shell
```

---

## 🚨 Error Prevention

### 1. **Duplicate Server Prevention**
The startup script automatically:
- Checks for existing Flask process on port 5000
- Kills duplicate instances before starting
- Validates PID file
- Ensures single-instance operation

### 2. **Dependency Validation**
Before running:
- Checks all critical packages are installed
- Verifies correct versions
- Reports missing dependencies clearly

### 3. **Environment Activation Enforcement**
Commands that require activation will:
- Check for `$VIRTUAL_ENV` variable
- Show clear activation instructions
- Prevent execution without proper environment

### 4. **Port Conflict Resolution**
- Automatically detects port 5000 usage
- Terminates conflicting processes
- Validates port is listening after startup

---

## 📊 Files Updated

### Configuration Files
- ✅ `requirements.txt` - Updated psutil to 6.1.1
- ✅ `Makefile` - Added dashboard management targets
- ✅ `start_amoskys.sh` - Comprehensive startup script
- ✅ `stop_amoskys.sh` - Clean shutdown script

### Documentation
- ✅ `ENV_SETUP.md` - Complete environment setup guide
- ✅ `DASHBOARD_ACCESS.md` - Dashboard access guide
- ✅ `ENVIRONMENT_STABLE.md` - This file

### Helper Scripts
- ✅ `scripts/check_env.sh` - Comprehensive validation
- ✅ `scripts/activate_check.sh` - Quick activation check

---

## 🎓 Common Workflows

### First Time Setup
```bash
# 1. Clone repository (if not already done)
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# 2. Set up environment
make env

# 3. Activate
source .venv/bin/activate

# 4. Validate
make validate

# 5. Start dashboard
make run-dashboard
```

### Daily Development
```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Start dashboard
make run-dashboard

# ... do your work ...

# 3. Stop when done
make stop-dashboard
```

### After Pulling Updates
```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Update dependencies
make install-deps

# 3. Regenerate protobuf (if changed)
make proto

# 4. Restart dashboard
make restart-dashboard
```

### Troubleshooting
```bash
# Check environment status
make check-env

# Validate installation
make validate

# View logs
make logs-dashboard

# Check dashboard status
make status

# Clean restart
make stop-dashboard && make run-dashboard
```

---

## 🔍 Troubleshooting Guide

### Issue: "Virtual environment not activated"
```bash
# Solution:
source .venv/bin/activate

# Verify:
make check-env
```

### Issue: "Port 5000 already in use"
```bash
# Solution:
make stop-dashboard

# Or force kill:
lsof -ti :5000 | xargs kill -9

# Then restart:
make run-dashboard
```

### Issue: "ModuleNotFoundError"
```bash
# Solution:
source .venv/bin/activate
make install-deps
make validate
```

### Issue: "Dashboard not responding"
```bash
# Check status:
make status

# View logs:
make logs-dashboard

# Restart:
make restart-dashboard
```

---

## 📦 Dependency Management

### Current Versions (Stable)
- Flask: 3.1.0
- psutil: 6.1.1 ⬆️ (updated from 5.9.0)
- Flask-SocketIO: 5.3.6
- protobuf: 5.28.2
- grpcio: 1.66.2

### Update Single Package
```bash
source .venv/bin/activate
pip install --upgrade package-name
pip freeze > requirements.txt
```

### Update All Packages
```bash
source .venv/bin/activate
make upgrade-deps  # If available
# or
pip install --upgrade -r requirements.txt
```

---

## 🎯 Next Steps

Now that the environment is stable and robust:

1. **Start Dashboard**
   ```bash
   source .venv/bin/activate
   make run-dashboard
   ```

2. **Access Dashboards**
   - Cortex Center: http://127.0.0.1:5000/dashboard/cortex
   - System Monitor: http://127.0.0.1:5000/dashboard/system
   - Process Telemetry: http://127.0.0.1:5000/dashboard/processes

3. **Deploy Agents**
   - Start process monitoring agents
   - Configure SNMP agents
   - Enable real-time telemetry

4. **Customize**
   - Configure alert thresholds
   - Set up integrations
   - Customize dashboards

---

## ✨ Key Improvements Summary

1. ✅ **One-Command Setup** - `make env` does everything
2. ✅ **Activation Enforcement** - Clear errors if not activated
3. ✅ **Comprehensive Validation** - Multi-level checks
4. ✅ **Single-Port Operation** - No duplicate servers
5. ✅ **Updated Dependencies** - psutil 6.1.1
6. ✅ **Helper Scripts** - Automated startup/shutdown
7. ✅ **Clear Documentation** - Step-by-step guides
8. ✅ **Error Prevention** - Proactive checks
9. ✅ **Status Monitoring** - Easy to check what's running
10. ✅ **Log Management** - Centralized logging

---

**Status**: ✅ **STABLE & PRODUCTION-READY**

**Dashboard URL**: http://127.0.0.1:5000/dashboard/cortex

**Last Updated**: 2025-12-04
**Version**: AMOSKYS Neural Security Platform v2.4
