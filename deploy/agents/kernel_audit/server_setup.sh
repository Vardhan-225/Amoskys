#!/bin/bash
# =============================================================================
# AMOSKYS KernelAudit Server Setup Script
# Run this on the production server after transferring files
# =============================================================================

set -e  # Exit on error

echo "=============================================="
echo "AMOSKYS KernelAudit Production Server Setup"
echo "=============================================="

# Check we're on the right server
echo ""
echo "📍 Server: $(hostname)"
echo "📍 IP: $(hostname -I | awk '{print $1}')"
echo "📍 OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo ""

# Step 1: Install Python dependencies
echo "🔧 Step 1: Installing Python dependencies..."
sudo apt install -y python3-pip python3-dev python3-venv python3-full

# Step 2: Create virtual environment and install packages
echo "🔧 Step 2: Creating virtual environment and installing packages..."
cd ~

# Create venv if it doesn't exist
if [ ! -d ~/amoskys-venv ]; then
    python3 -m venv ~/amoskys-venv
    echo "   Created virtual environment: ~/amoskys-venv"
fi

# Activate venv and install packages
source ~/amoskys-venv/bin/activate

# Use minimal requirements for KernelAudit (no TensorFlow/ML deps)
if [ -f ~/kernel_audit/requirements-minimal.txt ]; then
    echo "   Using minimal requirements (no heavy ML dependencies)..."
    pip install --upgrade pip
    pip install -r ~/kernel_audit/requirements-minimal.txt
elif [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    echo "   requirements.txt not found, installing minimal deps..."
    pip install protobuf psutil pydantic python-dotenv prometheus_client
fi

# Step 3: Install AMOSKYS source
echo "🔧 Step 3: Setting up AMOSKYS source..."
if [ -d ~/amoskys-src/amoskys ]; then
    echo "   Found amoskys-src, installing in venv..."
    # Install as editable package in venv
    cd ~/amoskys-src
    pip install -e . 2>/dev/null || pip install .
    cd ~
else
    echo "   ⚠️  amoskys-src not found. Please transfer with rsync first."
    exit 1
fi

# Step 4: Verify Python imports work
echo "🔧 Step 4: Verifying Python imports..."
~/amoskys-venv/bin/python3 -c "
from amoskys.agents.kernel_audit import KernelAuditAgentV2
print('   ✅ KernelAuditAgentV2 import successful')
"

# Step 5: Verify auditd is running
echo "🔧 Step 5: Checking auditd status..."
if systemctl is-active --quiet auditd; then
    echo "   ✅ auditd is running"
else
    echo "   ⚠️  auditd not running, starting..."
    sudo systemctl enable --now auditd
fi

# Step 6: Run the main install script
echo "🔧 Step 6: Running KernelAudit installer..."
cd ~/kernel_audit
chmod +x install.sh smoke_test.sh run_agent_v2.py

# Run installer with device ID
DEVICE_ID=$(hostname)
echo "   Device ID: $DEVICE_ID"
sudo ./install.sh --device-id="$DEVICE_ID"

# Step 7: Verify service is running
echo ""
echo "🔧 Step 7: Verifying service status..."
sleep 3
if systemctl is-active --quiet amoskys-kernel-audit; then
    echo "   ✅ amoskys-kernel-audit service is RUNNING"
else
    echo "   ⚠️  Service not running. Check logs:"
    sudo journalctl -u amoskys-kernel-audit -n 20 --no-pager
    exit 1
fi

# Step 8: Run smoke tests
echo ""
echo "🔧 Step 8: Running smoke tests..."
sudo ./smoke_test.sh

# Final status
echo ""
echo "=============================================="
echo "✅ AMOSKYS KernelAudit Deployment Complete!"
echo "=============================================="
echo ""
echo "📊 Monitor with:"
echo "   sudo journalctl -u amoskys-kernel-audit -f"
echo ""
echo "📈 Check metrics after 5 minutes:"
echo "   sudo journalctl -u amoskys-kernel-audit | grep 'emitted metrics'"
echo ""
echo "🔍 Service status:"
sudo systemctl status amoskys-kernel-audit --no-pager
