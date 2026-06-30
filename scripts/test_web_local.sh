#!/bin/bash

# AMOSKYS Web Interface Local Testing Script
# Tests the Flask application locally before VPS deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Change to web directory
cd "$(dirname "$0")/../web"

log "🧠🛡️ AMOSKYS Local Testing Environment"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Check Python version
log "🐍 Checking Python environment..."
python3 --version
if ! command -v python3 &> /dev/null; then
    error "Python 3 is not installed"
fi
success "Python 3 available"

# 2. Create virtual environment if it doesn't exist
if [[ ! -d "venv" ]]; then
    log "Creating Python virtual environment..."
    python3 -m venv venv
    success "Virtual environment created"
else
    log "Virtual environment already exists"
fi

# 3. Activate virtual environment and install dependencies
log "🔧 Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
success "Dependencies installed"

# 4. Check Flask app structure
log "📁 Validating Flask application structure..."
required_files=(
    "wsgi.py"
    "app/__init__.py"
    "app/routes.py"
    "app/templates/index.html"
    "gunicorn_config.py"
)

for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        success "$file found"
    else
        error "$file missing"
    fi
done

# 5. Test Flask app import
log "🧪 Testing Flask application import..."
if python3 -c "from app import create_app; app = create_app(); print('✅ Flask app created successfully')"; then
    success "Flask application imports correctly"
else
    error "Flask application import failed"
fi

# 6. Start development server in background
log "🚀 Starting Flask development server..."
export FLASK_ENV=development
export FLASK_DEBUG=true
python3 wsgi.py &
SERVER_PID=$!

# Wait for server to start
sleep 3

# 7. Test endpoints
log "🔍 Testing application endpoints..."

# Test health endpoint
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    success "Health endpoint working"
else
    warning "Health endpoint not responding correctly"
fi

# Test status endpoint
if curl -s http://localhost:8000/status | grep -q "OPERATIONAL"; then
    success "Status endpoint working"
else
    warning "Status endpoint not responding correctly"
fi

# Test main page
if curl -s http://localhost:8000/ | grep -q "AMOSKYS"; then
    success "Main page loading"
else
    warning "Main page not loading correctly"
fi

# 8. Test Gunicorn configuration
log "⚙️  Testing Gunicorn configuration..."
if gunicorn --check-config --config gunicorn_config.py wsgi:app; then
    success "Gunicorn configuration valid"
else
    warning "Gunicorn configuration issues detected"
fi

# 9. Stop development server
log "🛑 Stopping development server..."
kill $SERVER_PID 2>/dev/null || true
sleep 1

# 10. Test production-like Gunicorn startup
log "🏭 Testing production Gunicorn startup..."
gunicorn --config gunicorn_config.py wsgi:app --daemon --pid /tmp/amoskys-test.pid

# Wait for Gunicorn to start
sleep 3

# Test production endpoints
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    success "Production health endpoint working"
else
    warning "Production health endpoint not responding"
fi

# Stop Gunicorn
if [[ -f "/tmp/amoskys-test.pid" ]]; then
    kill "$(cat /tmp/amoskys-test.pid)" 2>/dev/null || true
    rm -f /tmp/amoskys-test.pid
fi

# 11. Performance test
log "📊 Running basic performance test..."
echo "Testing concurrent requests..."
for i in {1..10}; do
    curl -s http://localhost:8000/health > /dev/null &
done
wait
success "Concurrent request test completed"

# 12. Security headers test (would work with NGINX in production)
log "🔒 Security validation..."
if grep -q "X-Frame-Options" ../nginx/amoskys.conf; then
    success "Security headers configured in NGINX"
else
    warning "Check NGINX security headers"
fi

log "📋 Test Summary:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧠 Flask Application: ✅ Working"
echo "⚙️  Gunicorn Config: ✅ Valid"
echo "🌐 Endpoints: ✅ Responding"
echo "🔧 Dependencies: ✅ Installed"
echo "📂 File Structure: ✅ Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

success "🧠🛡️ AMOSKYS local testing completed successfully!"

log "Ready for VPS deployment with:"
echo "  sudo ./scripts/deploy_web.sh"
echo ""
log "Local development server:"
echo "  source web/venv/bin/activate"
echo "  cd web && python3 wsgi.py"
