#!/bin/bash
set -e

echo "🐳 Docker Entrypoint: Starting My Network Scanner..."

# Create necessary directories
mkdir -p /app/data /app/config /app/logs

# Set proper permissions
chown -R scanner:scanner /app/data /app/config /app/logs 2>/dev/null || true

# Check if we're in Docker environment
if [ -f /.dockerenv ]; then
    echo "✅ Docker environment confirmed"
    export container=docker
else
    echo "⚠️  Not in standard Docker environment"
fi

# Check network capabilities
echo "🔍 Checking network capabilities..."

# Test if we can access network interfaces
if python3 -c "from network_utils import get_network_interfaces; print(f'Found {len(get_network_interfaces())} network interfaces')" 2>/dev/null; then
    echo "✅ Network interface detection working"
else
    echo "⚠️  Network interface detection may have issues"
fi

# Test if nmap is available
if command -v nmap >/dev/null 2>&1; then
    echo "✅ nmap is available"
    # Test nmap with a simple command
    if timeout 5 nmap -V >/dev/null 2>&1; then
        echo "✅ nmap is functional"
    else
        echo "⚠️  nmap may have permission issues"
    fi
else
    echo "❌ nmap is not available"
fi

# Test network connectivity
echo "🌐 Testing network connectivity..."
if timeout 3 ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ External network connectivity OK"
else
    echo "⚠️  External network connectivity may be limited"
fi

# Show environment info
echo "📋 Environment Information:"
echo "  - FLASK_ENV: ${FLASK_ENV:-development}"
echo "  - FLASK_PORT: ${FLASK_PORT:-5883}"
echo "  - User: $(whoami)"
echo "  - Working Directory: $(pwd)"
echo "  - Python Version: $(python3 --version)"

# Start the application
echo "🚀 Starting application..."
exec "$@"