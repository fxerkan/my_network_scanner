#!/bin/bash

# My Network Scanner (MyNeS) Setup Script
# This script sets up the application for first-time use

echo "🔧 Setting up My Network Scanner (MyNeS)..."
echo "==========================================="

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p config data logs static templates

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv .venv

# Activate virtual environment
echo "📦 Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

# Create example configuration files
echo "⚙️  Creating configuration files..."

# Create config.json if it doesn't exist
if [ ! -f "config/config.json" ]; then
    echo "📄 Creating default config.json..."
    cat > config/config.json << 'EOF'
{
  "app": {
    "name": "My Network Scanner (MyNeS)",
    "version": "1.0.1",
    "port": 5003,
    "host": "0.0.0.0",
    "debug": false
  },
  "scanner": {
    "timeout": 30,
    "max_threads": 5,
    "default_ports": [21, 22, 23, 53, 80, 443, 993, 995, 8080, 8443]
  },
  "oui": {
    "update_interval_days": 7,
    "sources": [
      "http://standards-oui.ieee.org/oui/oui.csv",
      "http://standards-oui.ieee.org/oui28/mam.csv",
      "http://standards-oui.ieee.org/oui36/oui36.csv"
    ]
  },
  "security": {
    "encryption_iterations": 100000,
    "credential_timeout": 3600
  }
}
EOF
fi

# Create device_types.json if it doesn't exist
if [ ! -f "config/device_types.json" ]; then
    echo "📄 Creating default device_types.json..."
    cat > config/device_types.json << 'EOF'
{
  "device_types": {
    "router": {
      "patterns": ["router", "gateway", "openwrt", "tplink", "linksys", "netgear", "asus"],
      "vendor_patterns": ["TP-Link", "Linksys", "NETGEAR", "ASUS", "D-Link"],
      "ports": [80, 443, 8080, 8443, 23, 22]
    },
    "raspberry_pi": {
      "patterns": ["raspberrypi", "raspberry", "rpi"],
      "vendor_patterns": ["Raspberry Pi Foundation"],
      "ports": [22, 80, 443, 5000, 8080]
    },
    "printer": {
      "patterns": ["printer", "print", "hp", "canon", "epson"],
      "vendor_patterns": ["Hewlett Packard", "Canon", "Epson"],
      "ports": [631, 9100, 515, 80, 443]
    },
    "camera": {
      "patterns": ["camera", "cam", "ipcam", "webcam"],
      "vendor_patterns": ["Hikvision", "Dahua", "Axis"],
      "ports": [80, 443, 554, 8080, 8554]
    }
  }
}
EOF
fi

# Set proper permissions
echo "🔒 Setting file permissions..."
chmod +x start.sh
chmod +x setup.sh
chmod 755 config data logs

# Check dependencies
echo "🔍 Checking system dependencies..."

# Check for nmap
if ! command -v nmap &> /dev/null; then
    echo "⚠️  Warning: nmap is not installed."
    echo "Please install nmap for network scanning:"
    echo "  macOS: brew install nmap"
    echo "  Ubuntu/Debian: sudo apt-get install nmap"
    echo "  CentOS/RHEL: sudo yum install nmap"
fi

# Check for Docker (optional)
if ! command -v docker &> /dev/null; then
    echo "ℹ️  Info: Docker is not installed (optional feature)."
    echo "Install Docker for container detection features."
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Copy .env.example to .env and configure your settings"
echo "2. Run './start.sh' to start the application"
echo "3. Open http://localhost:5003 in your browser"
echo ""
echo "For security features, set your master password:"
echo "export LAN_SCANNER_PASSWORD='your_secure_password'"