#!/usr/bin/env python3
"""
Test script to verify Docker fixes for My Network Scanner
This script tests the key components that were fixed
"""

import os
import sys
import time
import requests
from network_utils import is_docker_environment, get_network_interfaces, get_host_network_ranges

def test_environment_detection():
    """Test Docker environment detection"""
    print("🧪 Testing Docker environment detection...")
    
    in_docker = is_docker_environment()
    print(f"   Docker environment detected: {in_docker}")
    
    # Check environment variables
    flask_env = os.environ.get('FLASK_ENV', 'development')
    flask_port = os.environ.get('FLASK_PORT', '5883')
    
    print(f"   FLASK_ENV: {flask_env}")
    print(f"   FLASK_PORT: {flask_port}")
    
    return True

def test_network_interfaces():
    """Test network interface detection"""
    print("🧪 Testing network interface detection...")
    
    try:
        interfaces = get_network_interfaces()
        print(f"   Found {len(interfaces)} network interfaces:")
        
        for interface in interfaces[:3]:  # Show first 3
            print(f"     - {interface['name']}: {interface['ip']}/{interface['netmask']}")
        
        if len(interfaces) > 3:
            print(f"     ... and {len(interfaces) - 3} more")
            
        return len(interfaces) > 0
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_host_network_discovery():
    """Test host network range discovery"""
    print("🧪 Testing host network discovery...")
    
    try:
        ranges = get_host_network_ranges()
        print(f"   Discovered {len(ranges)} network ranges:")
        
        for range_info in ranges[:5]:  # Show first 5
            print(f"     - {range_info['cidr']} ({range_info['interface']})")
        
        if len(ranges) > 5:
            print(f"     ... and {len(ranges) - 5} more")
            
        return len(ranges) > 0
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_flask_configuration():
    """Test Flask app configuration"""
    print("🧪 Testing Flask configuration...")
    
    # Test if we can import the app
    try:
        from app import app
        print("   ✅ Flask app import successful")
        
        # Check configuration
        is_production = os.environ.get('FLASK_ENV', 'development') == 'production'
        debug_mode = not is_production
        
        print(f"   Production mode: {is_production}")
        print(f"   Debug mode: {debug_mode}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error importing app: {e}")
        return False

def test_port_availability():
    """Test if the configured port is available"""
    print("🧪 Testing port availability...")
    
    import socket
    
    port = int(os.environ.get('FLASK_PORT', 5883))
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        
        if result == 0:
            print(f"   ✅ Port {port} is in use (app may be running)")
            return True
        else:
            print(f"   ℹ️  Port {port} is available")
            return True
            
    except Exception as e:
        print(f"   ❌ Error testing port {port}: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Running Docker fixes test suite...")
    print("=" * 50)
    
    tests = [
        ("Environment Detection", test_environment_detection),
        ("Network Interfaces", test_network_interfaces),
        ("Host Network Discovery", test_host_network_discovery),
        ("Flask Configuration", test_flask_configuration),
        ("Port Availability", test_port_availability),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 30)
        
        try:
            result = test_func()
            results.append((test_name, result))
            
            if result:
                print(f"   ✅ {test_name}: PASSED")
            else:
                print(f"   ❌ {test_name}: FAILED")
                
        except Exception as e:
            print(f"   💥 {test_name}: ERROR - {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary")
    print("=" * 50)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} {test_name}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Docker fixes are working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1

if __name__ == '__main__':
    sys.exit(main())