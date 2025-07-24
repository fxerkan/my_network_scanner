#!/usr/bin/env python3
"""
Docker Health Check Script for My Network Scanner
This script verifies that the application is running correctly in Docker
"""

import sys
import requests
import socket
import os
import time
from network_utils import is_docker_environment, get_network_interfaces

def check_port_binding(port=5883):
    """Check if Flask app is binding to the correct port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    except:
        return False

def check_flask_app(port=5883):
    """Check if Flask app is responding"""
    try:
        response = requests.get(f'http://127.0.0.1:{port}/api/version', timeout=5)
        return response.status_code == 200
    except:
        return False

def check_network_interfaces():
    """Check if network interfaces are available"""
    try:
        interfaces = get_network_interfaces()
        return len(interfaces) > 0
    except:
        return False

def main():
    """Main health check function"""
    port = int(os.environ.get('FLASK_PORT', 5883))
    
    print(f"🏥 Docker Health Check Starting...")
    print(f"🔍 Checking port {port}...")
    
    # Check if we're in Docker
    if is_docker_environment():
        print("🐳 Docker environment confirmed")
    else:
        print("⚠️  Not in Docker environment")
    
    # Check port binding
    if check_port_binding(port):
        print(f"✅ Port {port} is bound and listening")
    else:
        print(f"❌ Port {port} is not accessible")
        return 1
    
    # Check Flask app response
    if check_flask_app(port):
        print("✅ Flask application is responding")
    else:
        print("❌ Flask application is not responding")
        return 1
    
    # Check network interfaces
    if check_network_interfaces():
        print("✅ Network interfaces are available")
    else:
        print("⚠️  Network interfaces may not be available")
    
    print("🎉 Health check passed!")
    return 0

if __name__ == '__main__':
    sys.exit(main())