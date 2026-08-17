#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Docker Network Manager
Docker container'ları ve network'leri tespit etme modülü
"""

import json
import subprocess
import socket
import os
import http.client
from datetime import datetime
import ipaddress

from ..core.network import is_container


def _cli_label(container: dict, key: str) -> str:
    """Pull one label out of `docker ps --format json`'s flattened "k=v,k=v"."""
    for pair in str(container.get('Labels') or '').split(','):
        name, _, value = pair.partition('=')
        if name.strip() == key:
            return value
    return ''


class _UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over an AF_UNIX socket - the whole Docker Engine API client.

    ponytail: 8 lines of stdlib instead of the requests-unixsocket dependency.
    """

    def __init__(self, socket_path, timeout=10):
        super().__init__('localhost', timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class DockerManager:
    def __init__(self):
        # Socket path first: _check_docker_availability() reads it. Setting it
        # afterwards raised AttributeError inside the fallback, so a container
        # with the socket mounted but no `docker` CLI reported "not installed".
        self.docker_socket_path = os.environ.get(
            "DOCKER_SOCKET", "/var/run/docker.sock")
        self.docker_available = self._check_docker_availability()

    def _check_docker_availability(self):
        """Docker'ın sisteme kurulu ve çalışır durumda olup olmadığını kontrol et"""
        try:
            # Docker komutunun varlığını kontrol et
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                # Docker komutu bulunamadıysa, Docker socket'i kontrol et
                if self._check_docker_socket():
                    return True
                return False
                
            # Docker daemon'un çalışıp çalışmadığını kontrol et
            result = subprocess.run(['docker', 'info'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return True
                
            # Docker komutu başarısızsa, Docker socket'i kontrol et
            return self._check_docker_socket()
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # Komut çalışmadıysa, Docker socket'i kontrol et
            return self._check_docker_socket()
    
    def _check_docker_socket(self):
        """Docker socket'inin erişilebilir olup olmadığını kontrol et.

        The API needs to *write* the request too, so R_OK alone is not enough:
        the socket is root:docker 0660 and a non-root container that is not in
        the docker group can stat it but never talk to it.
        """
        try:
            return (os.path.exists(self.docker_socket_path)
                    and os.access(self.docker_socket_path, os.R_OK | os.W_OK))
        except Exception:
            return False

    def _is_running_in_docker(self):
        """Docker container içinde çalışıp çalışmadığını kontrol et.

        /proc/1/cgroup is useless under cgroup v2 - it reads "0::/" inside the
        container and out of it alike, which is why this returned False on any
        modern host and the socket API was never reached.
        """
        return is_container()

    def _use_docker_socket_api(self, endpoint):
        """Docker Engine API over the UNIX socket, stdlib only.

        `requests` cannot speak http+unix:// without the requests-unixsocket
        package, so the previous implementation always raised.
        """
        try:
            conn = _UnixHTTPConnection(self.docker_socket_path, timeout=10)
            try:
                conn.request('GET', '/' + endpoint.lstrip('/'))
                response = conn.getresponse()
                body = response.read()
                if response.status != 200:
                    return None
                return json.loads(body.decode('utf-8'))
            finally:
                conn.close()
        except Exception as e:
            print(f"Docker socket API error: {e}")
            return None
    
    def get_host_name(self):
        """The Docker host's own hostname (docker info -> Name). In a container
        with host networking this is the real host ("rpifx"), unlike
        socket.gethostname() which returns the container name ("mynes"). Cached:
        the host name does not change between scans. Returns "" when unknown."""
        if getattr(self, "_host_name_cache", None) is not None:
            return self._host_name_cache
        name = ""
        try:
            if self.docker_available and self._check_docker_socket():
                info = self._use_docker_socket_api("info")
                name = (info or {}).get("Name", "") or ""
        except Exception:
            name = ""
        self._host_name_cache = name
        return name

    def get_docker_networks(self):
        """Docker network'lerini listele"""
        if not self.docker_available:
            return []
        
        # Docker socket API kullanarak dene (container içinde çalışıyorsa)
        if self._is_running_in_docker() and self._check_docker_socket():
            try:
                networks_data = self._use_docker_socket_api("networks")
                if networks_data:
                    networks = []
                    for network_basic in networks_data:
                        detailed_info = self._get_network_details_from_socket(network_basic['Id'])
                        if detailed_info:
                            networks.append(detailed_info)
                    return networks
            except Exception as e:
                print(f"Docker socket API call failed: {e}")
                # Fallback to docker command
        
        # Normal docker komutunu kullan
        try:
            # Docker network'leri al
            result = subprocess.run(['docker', 'network', 'ls', '--format', 'json'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return []
            
            networks = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        network_basic = json.loads(line)
                        # Her network için detaylı bilgi al
                        detailed_info = self._get_network_details(network_basic['ID'])
                        if detailed_info:
                            networks.append(detailed_info)
                    except json.JSONDecodeError:
                        continue
            
            return networks
            
        except Exception as e:
            print(f"Failed to get Docker network info: {e}")
            return []
    
    def _get_network_details_from_socket(self, network_id):
        """Docker socket API kullanarak network detaylarını al"""
        try:
            network_data = self._use_docker_socket_api(f"networks/{network_id}")
            if not network_data:
                return None
            
            # IPAM bilgilerinden subnet'leri çıkar
            subnets = []
            # Docker returns "Config": null for networks with no IPAM config,
            # so guard the value, not just the key.
            for config in (network_data.get('IPAM') or {}).get('Config') or []:
                if 'Subnet' in config:
                    subnets.append(config['Subnet'])
            
            # Container'ları al
            containers = []
            if 'Containers' in network_data:
                for container_id, container_info in network_data['Containers'].items():
                    containers.append({
                        'id': container_id[:12],  # Kısa ID
                        'name': container_info.get('Name', 'Unknown'),
                        'ipv4_address': container_info.get('IPv4Address', '').split('/')[0],
                        'ipv6_address': container_info.get('IPv6Address', '').split('/')[0],
                        'mac_address': container_info.get('MacAddress', '')
                    })
            
            return {
                'id': network_data['Id'][:12],
                'name': network_data['Name'],
                'driver': network_data['Driver'],
                'scope': network_data['Scope'],
                'created': network_data.get('Created', ''),
                'subnets': subnets,
                'containers': containers,
                'gateway': self._extract_gateway(network_data),
                'internal': network_data.get('Internal', False),
                'attachable': network_data.get('Attachable', False),
                'ingress': network_data.get('Ingress', False)
            }
            
        except Exception as e:
            print(f"Failed to get socket network {network_id} details: {e}")
            return None
    
    def _get_network_details(self, network_id):
        """Belirli bir network'ün detaylı bilgilerini al"""
        try:
            result = subprocess.run(['docker', 'network', 'inspect', network_id], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode != 0:
                return None
                
            network_data = json.loads(result.stdout)[0]
            
            # IPAM bilgilerinden subnet'leri çıkar
            subnets = []
            # Docker returns "Config": null for networks with no IPAM config,
            # so guard the value, not just the key.
            for config in (network_data.get('IPAM') or {}).get('Config') or []:
                if 'Subnet' in config:
                    subnets.append(config['Subnet'])
            
            # Container'ları al
            containers = []
            if 'Containers' in network_data:
                for container_id, container_info in network_data['Containers'].items():
                    containers.append({
                        'id': container_id[:12],  # Kısa ID
                        'name': container_info.get('Name', 'Unknown'),
                        'ipv4_address': container_info.get('IPv4Address', '').split('/')[0],
                        'ipv6_address': container_info.get('IPv6Address', '').split('/')[0],
                        'mac_address': container_info.get('MacAddress', '')
                    })
            
            return {
                'id': network_data['Id'][:12],
                'name': network_data['Name'],
                'driver': network_data['Driver'],
                'scope': network_data['Scope'],
                'created': network_data.get('Created', ''),
                'subnets': subnets,
                'containers': containers,
                'gateway': self._extract_gateway(network_data),
                'internal': network_data.get('Internal', False),
                'attachable': network_data.get('Attachable', False),
                'ingress': network_data.get('Ingress', False)
            }
            
        except Exception as e:
            print(f"Failed to get network {network_id} details: {e}")
            return None
    
    def _extract_gateway(self, network_data):
        """Network'ün gateway IP'sini çıkar"""
        try:
            for config in (network_data.get('IPAM') or {}).get('Config') or []:
                if 'Gateway' in config:
                    return config['Gateway']
        except Exception:
            pass
        return None
    
    def get_docker_containers(self):
        """Çalışan Docker container'ları listele"""
        if not self.docker_available:
            return []

        # The image ships no `docker` CLI, so inside a container the socket is
        # the only route. Try it first when there is no CLI to call.
        if self._check_docker_socket():
            containers = self._containers_via_socket()
            if containers:
                return containers

        try:
            result = subprocess.run(['docker', 'ps', '--format', 'json'],
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return []
            
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        container = json.loads(line)
                        # Container'ın detaylı network bilgilerini al
                        detailed_info = self._get_container_network_details(container['ID'])
                        containers.append({
                            'id': container['ID'][:12],
                            'name': container['Names'],
                            'image': container['Image'],
                            'status': container['Status'],
                            'ports': container.get('Ports', ''),
                            'created': container['CreatedAt'],
                            'networks': detailed_info.get('networks', []),
                            'ip_addresses': detailed_info.get('ip_addresses', []),
                            # The CLI flattens labels to "k=v,k=v"; the API gives
                            # a dict. Both feed the same 'stack' field.
                            'stack': _cli_label(container, 'com.docker.compose.project'),
                            'service': _cli_label(container, 'com.docker.compose.service'),
                        })
                    except json.JSONDecodeError:
                        continue
            
            return containers
            
        except Exception as e:
            print(f"Failed to get Docker container info: {e}")
            return []
    
    def _containers_via_socket(self):
        """`docker ps` equivalent straight off the Engine API."""
        data = self._use_docker_socket_api('containers/json')
        if not data:
            return []

        containers = []
        for c in data:
            settings = c.get('NetworkSettings') or {}
            networks_info = settings.get('Networks') or {}
            ip_addresses = []
            for network_name, info in networks_info.items():
                if info.get('IPAddress'):
                    ip_addresses.append({
                        'network': network_name,
                        'ipv4': info.get('IPAddress', ''),
                        'ipv6': info.get('GlobalIPv6Address', ''),
                        'mac': info.get('MacAddress', ''),
                        'gateway': info.get('Gateway', ''),
                        'gateway_ipv6': info.get('IPv6Gateway', ''),
                    })
            ports = ', '.join(
                f"{p.get('PublicPort')}->{p.get('PrivatePort')}/{p.get('Type')}"
                if p.get('PublicPort') else f"{p.get('PrivatePort')}/{p.get('Type')}"
                for p in (c.get('Ports') or []))
            labels = c.get('Labels') or {}
            containers.append({
                'id': (c.get('Id') or '')[:12],
                # API gives "/name"; the CLI gives "name". Match the CLI.
                'name': ', '.join(n.lstrip('/') for n in (c.get('Names') or [])),
                'image': c.get('Image', ''),
                'status': c.get('Status', ''),
                'ports': ports,
                'created': c.get('Created', ''),
                'networks': list(networks_info.keys()),
                'ip_addresses': ip_addresses,
                # "Stack" in the UI. Compose writes the project name as a label;
                # a container started by plain `docker run` simply has none.
                'stack': labels.get('com.docker.compose.project', ''),
                'service': labels.get('com.docker.compose.service', ''),
            })
        return containers

    def bridge_interface_names(self):
        """Map a host bridge interface (docker0, br-<id>) to its network name.

        Docker names a user-defined bridge's interface br-<first 12 of net id>,
        which is why every one of them showed up as an indistinguishable
        "<host> (Docker)" in the device list.
        """
        names = {}
        data = self._use_docker_socket_api('networks')
        if not data:
            return names
        for net in data:
            name = net.get('Name')
            net_id = net.get('Id') or ''
            if not name:
                continue
            options = net.get('Options') or {}
            iface = options.get('com.docker.network.bridge.name')
            if iface:
                names[iface] = name
            elif net.get('Driver') == 'bridge' and net_id:
                names[f'br-{net_id[:12]}'] = name
        names.setdefault('docker0', 'bridge')
        return names

    def _get_container_network_details(self, container_id):
        """Container'ın network detaylarını al"""
        try:
            result = subprocess.run(['docker', 'inspect', container_id], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode != 0:
                return {'networks': [], 'ip_addresses': []}
                
            container_data = json.loads(result.stdout)[0]
            networks_info = container_data.get('NetworkSettings', {}).get('Networks', {})
            
            networks = []
            ip_addresses = []
            
            for network_name, network_info in networks_info.items():
                networks.append(network_name)
                
                ipv4 = network_info.get('IPAddress', '')
                if ipv4:
                    ip_addresses.append({
                        'network': network_name,
                        'ipv4': ipv4,
                        'ipv6': network_info.get('GlobalIPv6Address', ''),
                        'mac': network_info.get('MacAddress', ''),
                        'gateway': network_info.get('Gateway', ''),
                        'gateway_ipv6': network_info.get('IPv6Gateway', '')
                    })
            
            return {'networks': networks, 'ip_addresses': ip_addresses}
            
        except Exception as e:
            print(f"Failed to get container {container_id} network details: {e}")
            return {'networks': [], 'ip_addresses': []}
    
    def get_docker_scan_ranges(self):
        """Docker network'lerinden tarama için IP aralıkları çıkar"""
        scan_ranges = []
        
        if not self.docker_available:
            return scan_ranges
        
        networks = self.get_docker_networks()
        
        for network in networks:
            # Sadece bridge ve custom network'leri dahil et
            if network['driver'] in ['bridge', 'overlay', 'macvlan', 'ipvlan']:
                for subnet in network['subnets']:
                    try:
                        # Subnet'i validate et
                        network_obj = ipaddress.ip_network(subnet, strict=False)
                        
                        # Çok büyük network'leri atla (/8, /16 gibi)
                        if network_obj.prefixlen >= 16:
                            scan_ranges.append({
                                'network_name': network['name'],
                                'network_id': network['id'],
                                'subnet': subnet,
                                'gateway': network['gateway'],
                                'driver': network['driver'],
                                'container_count': len(network['containers']),
                                'scan_range': str(network_obj)
                            })
                    except ValueError:
                        continue
        
        return scan_ranges
    
    def get_docker_interface_info(self):
        """Docker virtual interface'lerini al (docker0, br-xxx vb.)"""
        docker_interfaces = []
        
        if not self.docker_available:
            return docker_interfaces
        
        try:
            # Network interface'leri listele
            import psutil
            
            for interface_name, interface_info in psutil.net_if_addrs().items():
                # Docker interface'lerini tespit et
                if (interface_name.startswith('docker') or 
                    interface_name.startswith('br-') or 
                    interface_name.startswith('veth')):
                    
                    for addr in interface_info:
                        if addr.family == socket.AF_INET:  # IPv4
                            docker_interfaces.append({
                                'interface': interface_name,
                                'ip': addr.address,
                                'netmask': addr.netmask,
                                'type': 'docker_virtual',
                                'description': self._get_docker_interface_description(interface_name)
                            })
                            break
                            
        except ImportError:
            # psutil yoksa, ip komutunu kullan
            try:
                result = subprocess.run(['ip', 'addr', 'show'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    docker_interfaces.extend(self._parse_ip_addr_output(result.stdout))
            except Exception:
                pass
        except Exception as e:
            print(f"Failed to get Docker interface info: {e}")
        
        return docker_interfaces
    
    def _get_docker_interface_description(self, interface_name):
        """Docker interface açıklaması"""
        if interface_name == 'docker0':
            return 'Docker Default Bridge'
        elif interface_name.startswith('br-'):
            return f'Docker Custom Bridge ({interface_name})'
        elif interface_name.startswith('veth'):
            return 'Docker Container Virtual Ethernet'
        else:
            return 'Docker Virtual Interface'
    
    def _parse_ip_addr_output(self, output):
        """ip addr show çıktısını parse et"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Interface satırı
            if ': ' in line and ('docker' in line or 'br-' in line or 'veth' in line):
                interface_name = line.split(':')[1].strip().split('@')[0]
                current_interface = interface_name
            
            # IP adresi satırı
            elif current_interface and line.startswith('inet ') and 'scope global' in line:
                parts = line.split()
                if len(parts) >= 2:
                    ip_with_cidr = parts[1]
                    if '/' in ip_with_cidr:
                        ip = ip_with_cidr.split('/')[0]
                        cidr = int(ip_with_cidr.split('/')[1])
                        netmask = str(ipaddress.IPv4Network(f'0.0.0.0/{cidr}', strict=False).netmask)
                        
                        interfaces.append({
                            'interface': current_interface,
                            'ip': ip,
                            'netmask': netmask,
                            'type': 'docker_virtual',
                            'description': self._get_docker_interface_description(current_interface)
                        })
                        current_interface = None
        
        return interfaces
    
    def get_docker_stats(self):
        """Docker genel istatistikleri"""
        if not self.docker_available:
            return {
                'available': False,
                # Stable English for API consumers; the UI shows its own
                # localised message instead of echoing this back.
                'error': 'Docker is not installed or not running'
            }
        
        try:
            networks = self.get_docker_networks()
            containers = self.get_docker_containers()
            scan_ranges = self.get_docker_scan_ranges()
            
            return {
                'available': True,
                'networks_count': len(networks),
                'containers_count': len(containers),
                'scan_ranges_count': len(scan_ranges),
                'socket_available': self._check_docker_socket(),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }


# Singleton instance
docker_manager = DockerManager()