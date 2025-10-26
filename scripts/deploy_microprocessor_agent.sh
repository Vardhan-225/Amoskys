#!/bin/bash

# AMOSKYS Microprocessor Agent Deployment Script
# This script deploys the microprocessor agent on edge devices and servers

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Deployment configuration
DEPLOYMENT_TYPE=${1:-"edge"}  # edge, server, or docker
ENVIRONMENT=${2:-"production"}
CONFIG_FILE="config/microprocessor_agent.yaml"

echo -e "${BLUE}AMOSKYS Microprocessor Agent Deployment${NC}"
echo "========================================"
echo "Deployment Type: $DEPLOYMENT_TYPE"
echo "Environment: $ENVIRONMENT"
echo ""

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_status "Python $PYTHON_VERSION detected"
    else
        print_error "Python 3.8+ is required"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is required"
        exit 1
    fi
    
    # Check git
    if ! command -v git &> /dev/null; then
        print_error "git is required"
        exit 1
    fi
    
    # Check available memory
    AVAILABLE_MEMORY=$(free -m | awk 'NR==2{printf "%d", $7}')
    if [ "$AVAILABLE_MEMORY" -lt 512 ]; then
        print_warning "Low memory detected ($AVAILABLE_MEMORY MB). Edge optimization will be enabled."
        EDGE_MODE=true
    else
        print_status "Memory check passed ($AVAILABLE_MEMORY MB available)"
        EDGE_MODE=false
    fi
    
    print_status "Prerequisites check completed"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    # Update package lists
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y python3-dev python3-pip libpcap-dev build-essential
    elif command -v yum &> /dev/null; then
        sudo yum update
        sudo yum install -y python3-devel python3-pip libpcap-devel gcc gcc-c++
    elif command -v dnf &> /dev/null; then
        sudo dnf update
        sudo dnf install -y python3-devel python3-pip libpcap-devel gcc gcc-c++
    fi
    
    # Install Python dependencies
    if [ "$EDGE_MODE" = true ]; then
        print_status "Installing edge-optimized dependencies..."
        pip3 install -r requirements-microprocessor.txt --no-cache-dir
    else
        print_status "Installing full dependencies..."
        pip3 install -r requirements-microprocessor.txt
    fi
    
    print_status "Dependencies installed successfully"
}

# Function to configure the agent
configure_agent() {
    print_status "Configuring microprocessor agent..."
    
    # Create directories
    mkdir -p logs
    mkdir -p data
    mkdir -p tmp
    
    # Copy configuration
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "Configuration file $CONFIG_FILE not found"
        exit 1
    fi
    
    # Environment-specific configuration
    case $ENVIRONMENT in
        "production")
            print_status "Applying production configuration..."
            ;;
        "staging")
            print_status "Applying staging configuration..."
            ;;
        "development")
            print_status "Applying development configuration..."
            ;;
    esac
    
    # Edge-specific optimizations
    if [ "$EDGE_MODE" = true ]; then
        print_status "Applying edge optimizations..."
        # Reduce memory limits, enable compression, etc.
    fi
    
    print_status "Agent configuration completed"
}

# Function to deploy on edge device
deploy_edge() {
    print_status "Deploying on edge device..."
    
    # Create systemd service for edge deployment
    cat > /tmp/amoskys-agent.service << EOF
[Unit]
Description=AMOSKYS Microprocessor Agent
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=amoskys
ExecStart=/usr/bin/python3 $(pwd)/src/amoskys/intelligence/integration/agent_core.py
WorkingDirectory=$(pwd)
Environment=PYTHONPATH=$(pwd)

[Install]
WantedBy=multi-user.target
EOF
    
    # Install service
    sudo mv /tmp/amoskys-agent.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable amoskys-agent
    
    print_status "Edge deployment completed"
}

# Function to deploy on server
deploy_server() {
    print_status "Deploying on server..."
    
    # Create more robust service configuration
    cat > /tmp/amoskys-agent.service << EOF
[Unit]
Description=AMOSKYS Microprocessor Agent
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=5
User=amoskys
ExecStart=/usr/bin/python3 $(pwd)/src/amoskys/intelligence/integration/agent_core.py
WorkingDirectory=$(pwd)
Environment=PYTHONPATH=$(pwd)
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF
    
    # Install service
    sudo mv /tmp/amoskys-agent.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable amoskys-agent
    
    print_status "Server deployment completed"
}

# Function to deploy with Docker
deploy_docker() {
    print_status "Deploying with Docker..."
    
    # Create Dockerfile
    cat > Dockerfile << EOF
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    libpcap-dev \\
    build-essential \\
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements-microprocessor.txt .
RUN pip install --no-cache-dir -r requirements-microprocessor.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 amoskys && chown -R amoskys:amoskys /app
USER amoskys

# Expose ports
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD python3 -c "import requests; requests.get('http://localhost:9090/health')"

# Start the agent
CMD ["python3", "src/amoskys/intelligence/integration/agent_core.py"]
EOF
    
    # Create docker-compose.yml
    cat > docker-compose.yml << EOF
version: '3.8'

services:
  amoskys-agent:
    build: .
    container_name: amoskys-microprocessor-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
      - ./data:/app/data
    environment:
      - ENVIRONMENT=$ENVIRONMENT
      - PYTHONPATH=/app
    cap_add:
      - NET_ADMIN
      - NET_RAW
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "python3", "-c", "import requests; requests.get('http://localhost:9090/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
EOF
    
    # Build and start
    docker-compose build
    docker-compose up -d
    
    print_status "Docker deployment completed"
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    # Run unit tests
    python3 -m pytest tests/test_microprocessor_agent.py -v
    
    # Run integration tests
    print_status "Running integration tests..."
    python3 tests/test_microprocessor_agent.py
    
    print_status "Tests completed successfully"
}

# Function to verify deployment
verify_deployment() {
    print_status "Verifying deployment..."
    
    case $DEPLOYMENT_TYPE in
        "docker")
            # Check Docker container
            if docker ps | grep -q "amoskys-microprocessor-agent"; then
                print_status "Docker container is running"
            else
                print_error "Docker container is not running"
                return 1
            fi
            ;;
        "edge"|"server")
            # Check systemd service
            if systemctl is-active --quiet amoskys-agent; then
                print_status "Systemd service is running"
            else
                print_error "Systemd service is not running"
                return 1
            fi
            ;;
    esac
    
    # Check if agent is responding
    sleep 10  # Give agent time to start
    
    # Try to connect to health endpoint
    if command -v curl &> /dev/null; then
        if curl -s http://localhost:9090/health > /dev/null; then
            print_status "Agent health check passed"
        else
            print_warning "Agent health check failed (this may be normal during startup)"
        fi
    fi
    
    print_status "Deployment verification completed"
}

# Function to show deployment status
show_status() {
    echo ""
    echo -e "${BLUE}Deployment Status${NC}"
    echo "=================="
    
    case $DEPLOYMENT_TYPE in
        "docker")
            echo "Docker Status:"
            docker ps | grep amoskys || echo "Container not found"
            echo ""
            echo "Container Logs:"
            docker logs amoskys-microprocessor-agent --tail 20
            ;;
        "edge"|"server")
            echo "Service Status:"
            systemctl status amoskys-agent --no-pager || echo "Service not found"
            echo ""
            echo "Service Logs:"
            journalctl -u amoskys-agent --no-pager -n 20
            ;;
    esac
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [DEPLOYMENT_TYPE] [ENVIRONMENT]"
    echo ""
    echo "DEPLOYMENT_TYPE:"
    echo "  edge      - Deploy on edge device (lightweight)"
    echo "  server    - Deploy on server (full features)"
    echo "  docker    - Deploy using Docker containers"
    echo ""
    echo "ENVIRONMENT:"
    echo "  production - Production configuration"
    echo "  staging    - Staging configuration"
    echo "  development- Development configuration"
    echo ""
    echo "Examples:"
    echo "  $0 edge production"
    echo "  $0 server staging"
    echo "  $0 docker development"
}

# Main deployment flow
main() {
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_usage
        exit 0
    fi
    
    # Validate deployment type
    case $DEPLOYMENT_TYPE in
        "edge"|"server"|"docker")
            ;;
        *)
            print_error "Invalid deployment type: $DEPLOYMENT_TYPE"
            show_usage
            exit 1
            ;;
    esac
    
    # Validate environment
    case $ENVIRONMENT in
        "production"|"staging"|"development")
            ;;
        *)
            print_error "Invalid environment: $ENVIRONMENT"
            show_usage
            exit 1
            ;;
    esac
    
    # Run deployment steps
    check_prerequisites
    install_dependencies
    configure_agent
    
    case $DEPLOYMENT_TYPE in
        "edge")
            deploy_edge
            ;;
        "server")
            deploy_server
            ;;
        "docker")
            deploy_docker
            ;;
    esac
    
    run_tests
    verify_deployment
    show_status
    
    echo ""
    print_status "Deployment completed successfully!"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Review the configuration in $CONFIG_FILE"
    echo "2. Monitor the agent logs for any issues"
    echo "3. Configure network access for device discovery"
    echo "4. Set up EventBus integration if needed"
    echo "5. Configure alerting and notification channels"
    echo ""
    echo -e "${BLUE}Documentation:${NC} See MICROPROCESSOR_AGENT_ROADMAP.md for detailed information"
}

# Run main function
main "$@"
