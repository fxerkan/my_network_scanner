#!/usr/bin/env python3
"""
Network utilities with fallback support for Docker environments
Provides network interface detection with or without netifaces
"""

import psutil
import socket
import ipaddress
import os

# Try to import netifaces, fall back to psutil if not available
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    netifaces = None

def get_network_interfaces():
    """Get network interfaces using available library"""
    interfaces = []
    
    if HAS_NETIFACES:
        return _get_interfaces_netifaces()
    else:
        return _get_interfaces_psutil()

def _get_interfaces_netifaces():
    """Get interfaces using netifaces library"""
    interfaces = []
    try:
        for interface in netifaces.interfaces():
            if interface == 'lo' or interface.startswith('lo'):
                continue
                
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get('addr')
                    netmask = addr.get('netmask')
                    if ip and netmask and not ip.startswith('127.'):
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            interfaces.append({
                                'name': interface,
                                'ip': ip,
                                'netmask': netmask,
                                'network': str(network),
                                'cidr': str(network)
                            })
                        except:
                            continue
    except Exception as e:
        print(f"Error getting interfaces with netifaces: {e}")
    
    return interfaces

def _get_interfaces_psutil():
    """Get interfaces using psutil library"""
    interfaces = []
    try:
        # Get network interfaces using psutil
        for interface_name, interface_addresses in psutil.net_if_addrs().items():
            if interface_name == 'lo' or interface_name.startswith('lo'):
                continue
                
            for address in interface_addresses:
                if address.family == socket.AF_INET:  # IPv4
                    ip = address.address
                    netmask = address.netmask
                    
                    if ip and netmask and not ip.startswith('127.'):
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            interfaces.append({
                                'name': interface_name,
                                'ip': ip,
                                'netmask': netmask,
                                'network': str(network),
                                'cidr': str(network)
                            })
                        except:
                            continue
                            
    except Exception as e:
        print(f"Error getting interfaces with psutil: {e}")
    
    return interfaces

def get_default_gateway():
    """Get default gateway using available method"""
    if HAS_NETIFACES:
        return _get_gateway_netifaces()
    else:
        return _get_gateway_psutil()

def _get_gateway_netifaces():
    """Get default gateway using netifaces"""
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][0]
    except:
        pass
    return None

def _get_gateway_psutil():
    """Get default gateway using psutil and system commands"""
    try:
        import subprocess
        import platform
        
        system = platform.system().lower()
        if system == 'linux':
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'default via' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'via' and i + 1 < len(parts):
                                return parts[i + 1]
        elif system == 'darwin':  # macOS
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'gateway:' in line:
                        return line.split(':')[1].strip()
    except:
        pass
    
    # Fallback: try to detect gateway by analyzing interfaces
    try:
        interfaces = get_network_interfaces()
        for interface in interfaces:
            # Common gateway patterns
            ip_parts = interface['ip'].split('.')
            if len(ip_parts) == 4:
                # Try .1 as gateway (most common)
                gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                return gateway
    except:
        pass
    
    return None

def get_local_ip_ranges():
    """Get local IP ranges for scanning"""
    ranges = []
    interfaces = get_network_interfaces()
    
    for interface in interfaces:
        try:
            network = ipaddress.IPv4Network(interface['cidr'])
            ranges.append({
                'interface': interface['name'],
                'network': str(network),
                'cidr': interface['cidr'],
                'ip': interface['ip']
            })
        except:
            continue
    
    return ranges

def is_docker_environment():
    """Check if running in Docker container"""
    try:
        # Check multiple indicators for Docker environment
        # 1. Check cgroup
        with open('/proc/1/cgroup', 'r') as f:
            cgroup_content = f.read()
            if 'docker' in cgroup_content or 'containerd' in cgroup_content:
                return True
        
        # 2. Check for .dockerenv file
        if os.path.exists('/.dockerenv'):
            return True
            
        # 3. Check environment variables
        if os.environ.get('container') == 'docker':
            return True
            
        # 4. Check hostname patterns (Docker often uses random hostnames)
        import socket
        hostname = socket.gethostname()
        if len(hostname) == 12 and all(c in '0123456789abcdef' for c in hostname):
            return True
            
    except:
        pass
        
    return False

def get_docker_networks():
    """Get Docker network information if in Docker environment"""
    if not is_docker_environment():
        return []
    
    networks = []
    try:
        # In Docker, we can still get host network interfaces
        interfaces = get_network_interfaces()
        for interface in interfaces:
            if 'docker' in interface['name'] or 'br-' in interface['name']:
                networks.append(interface)
    except:
        pass
    
    return networks

def get_host_network_ranges():
    """Get host network ranges even from Docker container"""
    ranges = []
    
    if is_docker_environment():
        # If in Docker, try to detect host networks through gateway analysis
        try:
            import subprocess
            
            print("🐳 Docker environment detected, attempting to discover host networks...")
            
            # Try to get host network via default gateway
            gateway = get_default_gateway()
            if gateway:
                print(f"🌐 Default gateway detected: {gateway}")
                # Assume host is on common networks based on gateway
                gateway_parts = gateway.split('.')
                if len(gateway_parts) == 4:
                    # Common network patterns
                    host_networks = [
                        f"{gateway_parts[0]}.{gateway_parts[1]}.{gateway_parts[2]}.0/24",  # Most common
                        f"{gateway_parts[0]}.{gateway_parts[1]}.0.0/16",  # Larger network
                    ]
                    
                    for network in host_networks:
                        try:
                            net = ipaddress.IPv4Network(network)
                            ranges.append({
                                'interface': 'host-bridge',
                                'network': str(net),
                                'cidr': network,
                                'ip': gateway,
                                'is_host_network': True
                            })
                            print(f"📡 Added host network range: {network}")
                        except:
                            continue
            
            # Try to get Docker bridge network information
            try:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'docker' in line or 'br-' in line:
                            print(f"🔍 Docker network route found: {line}")
            except:
                pass
            
            # Also try to detect networks through environment or common ranges
            # Add common private network ranges if in Docker
            common_ranges = [
                '192.168.1.0/24',
                '192.168.0.0/24', 
                '10.0.0.0/24',
                '172.16.0.0/24',
                '172.17.0.0/16',  # Default Docker bridge network
                '172.18.0.0/16',  # Common Docker custom networks
                '172.19.0.0/16',
                '172.20.0.0/16'
            ]
            
            for network in common_ranges:
                try:
                    net = ipaddress.IPv4Network(network)
                    ranges.append({
                        'interface': 'host-common',
                        'network': str(net),
                        'cidr': network,
                        'ip': str(net.network_address + 1),  # Assume gateway is .1
                        'is_host_network': True,
                        'is_common_range': True
                    })
                except:
                    continue
                    
        except Exception as e:
            print(f"❌ Error detecting host networks: {e}")
    
    # Add local interfaces too
    local_ranges = get_local_ip_ranges()
    ranges.extend(local_ranges)
    
    print(f"📊 Total network ranges discovered: {len(ranges)}")
    for range_info in ranges:
        print(f"  - {range_info['cidr']} ({range_info['interface']})")
    
    return ranges