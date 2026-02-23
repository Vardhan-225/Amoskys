#!/bin/bash

################################################################################
# Amoskys Installation & Setup Script
#
# This script automates the setup of a complete Amoskys environment including:
#   - Python virtual environment creation
#   - Dependency installation
#   - Directory structure setup
#   - TLS certificate generation
#   - Ed25519 keypair generation
#   - Configuration file setup
#
# Security Notes:
#   - TLS certificates are self-signed (suitable for development)
#   - Production deployments should use proper CA-signed certificates
#   - Private keys are stored with restricted permissions (0600)
#   - Ed25519 keys are generated with cryptography library
#
# Usage:
#   ./scripts/install_amoskys.sh [--dev] [--skip-certs]
#
# Options:
#   --dev            Install development dependencies (pytest, black, etc)
#   --skip-certs     Skip TLS/Ed25519 certificate generation
#
################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="${PROJECT_ROOT}/.venv"
CERTS_DIR="${PROJECT_ROOT}/certs"
DATA_DIR="${PROJECT_ROOT}/data"
CONFIG_DIR="${PROJECT_ROOT}/config"
LOGS_DIR="${PROJECT_ROOT}/logs"

# Flags
INSTALL_DEV=false
SKIP_CERTS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --dev)
      INSTALL_DEV=true
      shift
      ;;
    --skip-certs)
      SKIP_CERTS=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Helper functions
print_header() {
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_step() {
  echo -e "${GREEN}➜${NC} $1"
}

print_error() {
  echo -e "${RED}✗${NC} $1" >&2
}

print_warning() {
  echo -e "${YELLOW}⚠${NC} $1"
}

check_command() {
  if ! command -v "$1" &> /dev/null; then
    print_error "$1 is not installed. Please install it before running this script."
    exit 1
  fi
}

# Verify prerequisites
print_header "Checking Prerequisites"

check_command python3
check_command pip3
check_command git

python_version=$(python3 --version 2>&1 | awk '{print $2}')
print_step "Found Python $python_version"

# Check Python version (3.11+)
required_version="3.11"
if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)"; then
  print_error "Python 3.11+ is required (found $python_version)"
  exit 1
fi

# Create virtual environment
print_header "Setting Up Python Virtual Environment"

if [ -d "$VENV_DIR" ]; then
  print_warning "Virtual environment already exists at $VENV_DIR"
  print_step "Activating existing virtual environment..."
else
  print_step "Creating virtual environment at $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"
print_step "Virtual environment activated"

# Upgrade pip, setuptools, wheel
print_step "Upgrading pip, setuptools, and wheel..."
pip install --quiet --upgrade pip setuptools wheel

# Install dependencies
print_header "Installing Dependencies"

print_step "Installing core dependencies from pyproject.toml..."
cd "$PROJECT_ROOT"

if [ "$INSTALL_DEV" = true ]; then
  print_step "Installing development dependencies (--dev flag)..."
  pip install -e ".[dev]"
else
  pip install -e "."
fi

print_step "Dependencies installed successfully"

# Create directory structure
print_header "Creating Directory Structure"

for dir in "$CERTS_DIR" "$DATA_DIR/wal" "$DATA_DIR/storage" "$DATA_DIR/metrics" "$CONFIG_DIR" "$LOGS_DIR"; do
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
    print_step "Created directory: $dir"
  else
    print_warning "Directory already exists: $dir"
  fi
done

# Generate TLS certificates
if [ "$SKIP_CERTS" != true ]; then
  print_header "Generating TLS Certificates"

  # Check if certificates already exist
  if [ -f "$CERTS_DIR/server.crt" ] && [ -f "$CERTS_DIR/server.key" ]; then
    print_warning "TLS certificates already exist at $CERTS_DIR"
  else
    print_step "Generating self-signed TLS certificates..."

    # Generate CA private key
    openssl genrsa -out "$CERTS_DIR/ca.key" 2048 2>/dev/null
    print_step "Generated CA private key"

    # Generate CA certificate
    openssl req -new -x509 -days 365 -key "$CERTS_DIR/ca.key" -out "$CERTS_DIR/ca.crt" \
      -subj "/CN=amoskys-ca/O=Amoskys/C=US" 2>/dev/null
    print_step "Generated CA certificate (valid for 365 days)"

    # Generate server private key
    openssl genrsa -out "$CERTS_DIR/server.key" 2048 2>/dev/null
    chmod 600 "$CERTS_DIR/server.key"
    print_step "Generated server private key (permissions: 0600)"

    # Generate server CSR
    openssl req -new -key "$CERTS_DIR/server.key" -out "$CERTS_DIR/server.csr" \
      -subj "/CN=amoskys-eventbus/O=Amoskys/C=US" 2>/dev/null

    # Sign server certificate with CA
    openssl x509 -req -in "$CERTS_DIR/server.csr" -CA "$CERTS_DIR/ca.crt" \
      -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/server.crt" \
      -days 365 2>/dev/null
    print_step "Generated server certificate (valid for 365 days)"

    # Generate agent private key
    openssl genrsa -out "$CERTS_DIR/agent.key" 2048 2>/dev/null
    chmod 600 "$CERTS_DIR/agent.key"
    print_step "Generated agent private key (permissions: 0600)"

    # Generate agent CSR
    openssl req -new -key "$CERTS_DIR/agent.key" -out "$CERTS_DIR/agent.csr" \
      -subj "/CN=amoskys-agent/O=Amoskys/C=US" 2>/dev/null

    # Sign agent certificate with CA
    openssl x509 -req -in "$CERTS_DIR/agent.csr" -CA "$CERTS_DIR/ca.crt" \
      -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/agent.crt" \
      -days 365 2>/dev/null
    print_step "Generated agent certificate (valid for 365 days)"

    # Clean up CSR files
    rm -f "$CERTS_DIR/server.csr" "$CERTS_DIR/agent.csr" "$CERTS_DIR/ca.srl"
  fi
fi

# Generate Ed25519 keypair for agent signing
print_header "Generating Ed25519 Keypair for Agent Signing"

if [ -f "$CERTS_DIR/agent.ed25519" ] && [ -f "$CERTS_DIR/agent.ed25519.pub" ]; then
  print_warning "Ed25519 keypair already exists at $CERTS_DIR"
else
  print_step "Generating Ed25519 keypair for message signing..."

  python3 << 'EOF'
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate Ed25519 keypair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Get cert directory
cert_dir = Path("certs")

# Save private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
private_path = cert_dir / "agent.ed25519"
private_path.write_bytes(private_pem)
os.chmod(private_path, 0o600)
print(f"✓ Wrote private key to {private_path} (permissions: 0600)")

# Save public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_path = cert_dir / "agent.ed25519.pub"
public_path.write_bytes(public_pem)
print(f"✓ Wrote public key to {public_path}")
EOF

fi

# Setup configuration file
print_header "Setting Up Configuration Files"

# Create amoskys.yaml from template if not exists
if [ ! -f "$PROJECT_ROOT/amoskys.yaml" ]; then
  print_step "Creating amoskys.yaml from template..."
  cp "$PROJECT_ROOT/amoskys.yaml" "$PROJECT_ROOT/amoskys.yaml.bak" 2>/dev/null || true
  print_step "Configuration file created at $PROJECT_ROOT/amoskys.yaml"
else
  print_warning "amoskys.yaml already exists at $PROJECT_ROOT/amoskys.yaml"
fi

# Create example .env file with guidance
print_step "Creating example environment configuration..."
cat > "$PROJECT_ROOT/.env.amoskys.example" << 'EOF'
# Amoskys Environment Configuration
# Copy this file to .env and update values for your deployment

# ─── Critical: Must be set in production ───
# Generate a strong key for production:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
AMOSKYS_SECRET_KEY=""

# ─── EventBus Configuration ───
BUS_HOST=0.0.0.0
BUS_SERVER_PORT=50051
BUS_OVERLOAD=false
BUS_MAX_INFLIGHT=100
BUS_HARD_MAX=500

# Deduplication settings
BUS_DEDUPE_TTL_SEC=300
BUS_DEDUPE_MAX=50000

# Maximum envelope size (10MB default)
BUS_MAX_ENV_BYTES=10485760

# Require signatures for all envelopes (set to true in production)
BUS_REQUIRE_SIGNATURES=false

# ─── Agent Configuration ───
IS_BUS_ADDRESS=localhost:50051
IS_WAL_PATH=data/wal/flowagent.db
IS_MAX_ENV_BYTES=131072
IS_SEND_RATE=0
IS_RETRY_MAX=6
IS_RETRY_TIMEOUT=1.0

# ─── Storage Configuration ───
IS_DATA_DIR=data
IS_WAL_DIR=data/wal
IS_STORAGE_DIR=data/storage
IS_MAX_WAL_BYTES=209715200

# ─── Logging ───
LOGLEVEL=INFO

# ─── Optional: EventBus mTLS configuration ───
EVENTBUS_REQUIRE_CLIENT_AUTH=false
EOF
print_step "Created .env.amoskys.example for reference"

# Setup trust map
if [ ! -f "$CONFIG_DIR/trust_map.yaml" ]; then
  print_step "Creating example trust_map.yaml..."
  cat > "$CONFIG_DIR/trust_map.yaml" << 'EOF'
# Amoskys Trust Map - Agent Authorization Configuration
#
# This file lists authorized agents and their Ed25519 public keys.
# The EventBus uses this to verify agent signatures and enforce authorization.
#
# Format:
#   agents:
#     <agent-cn>: <path-to-ed25519-public-key>
#
# The agent-cn should match the Common Name (CN) in the agent's client certificate.

agents:
  # Example:
  # amoskys-agent-1: certs/agent1.ed25519.pub
  # amoskys-agent-2: certs/agent2.ed25519.pub
EOF
  print_step "Created trust_map.yaml at $CONFIG_DIR/trust_map.yaml"
else
  print_warning "trust_map.yaml already exists at $CONFIG_DIR/trust_map.yaml"
fi

# Verify installation
print_header "Verifying Installation"

# Check Python imports
print_step "Verifying Python imports..."
python3 << 'EOF'
try:
    import grpc
    import yaml
    import pydantic
    import cryptography
    from amoskys.config import get_config
    print("✓ All core dependencies imported successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")
    exit(1)
EOF

# Check directory structure
print_step "Verifying directory structure..."
for dir in "$CERTS_DIR" "$DATA_DIR" "$CONFIG_DIR" "$LOGS_DIR"; do
  if [ -d "$dir" ]; then
    echo "✓ $dir exists"
  else
    print_error "$dir does not exist"
    exit 1
  fi
done

# Check certificate files
if [ "$SKIP_CERTS" != true ]; then
  print_step "Verifying TLS certificates..."
  for file in server.crt server.key ca.crt agent.ed25519 agent.ed25519.pub; do
    if [ -f "$CERTS_DIR/$file" ]; then
      echo "✓ $CERTS_DIR/$file exists"
    else
      print_warning "$CERTS_DIR/$file not found"
    fi
  done
fi

# Display summary
print_header "Installation Complete!"

echo ""
echo "Next Steps:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Activate the virtual environment:"
echo "   source $VENV_DIR/bin/activate"
echo ""
echo "2. Set up environment variables (CRITICAL):"
echo "   - Copy .env.amoskys.example to .env.amoskys"
echo "   - Generate a strong secret key for AMOSKYS_SECRET_KEY:"
echo "     python3 -c \"import secrets; print(secrets.token_hex(32))\""
echo "   - Update AMOSKYS_SECRET_KEY in your environment"
echo ""
echo "3. Verify the configuration:"
echo "   python3 -m amoskys.config --validate"
echo ""
echo "4. Start the EventBus server:"
echo "   amoskys-eventbus"
echo ""
echo "5. In another terminal, test with an agent:"
echo "   amoskys-flow"
echo ""
echo "Security Notes:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "• TLS certificates are self-signed (development only)"
echo "• Production deployments require CA-signed certificates"
echo "• All secrets must be in environment variables, never in config files"
echo "• Private key files have restricted permissions (0600)"
echo "• Ed25519 keys are used for message signing and verification"
echo ""
echo "Documentation: https://github.com/Vardhan-225/Amoskys"
echo ""
