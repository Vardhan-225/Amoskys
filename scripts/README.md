# AMOSKYS Scripts

Automation scripts and utilities for the AMOSKYS platform.

## Directory Structure

### [`bin/`](bin/)
Executable launcher scripts for AMOSKYS components.

- `amoskys-agent` - Flow agent launcher
- `amoskys-eventbus` - EventBus server launcher
- `amoskys-snmp-agent` - SNMP agent launcher

### [`tools/`](tools/)
Development and testing utilities.

- `generate_mac_telemetry.py` - Generate test telemetry data
- `run_dashboard.py` - Dashboard development server
- Additional diagnostic tools

### [`deploy/`](deploy/) (if exists)
Deployment automation scripts.

## Usage

Most scripts can be run directly from the project root using the operational scripts:
- `./start_amoskys.sh` - Start all services
- `./stop_amoskys.sh` - Stop all services
- `./quick_status.sh` - Check system health
