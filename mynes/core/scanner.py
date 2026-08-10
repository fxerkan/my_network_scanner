#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN Scanner - Ağdaki cihazları tarar ve detaylı bilgilerini toplar
Enhanced version with configuration management and OUI integration
"""

# Warnings ve logging ayarları
from mynes.paths import config_file, data_file
from mynes.core import arp as arp_discovery
import warnings
import logging

# Scapy ve network uyarılarını bastır
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")

# Scapy verbose output'u kapatmak için
import os
os.environ['SCAPY_VERBOSE'] = '0'

# Console logging'i sınırla
logging.getLogger("scapy").setLevel(logging.ERROR)

import nmap
# import netifaces  # Use network_utils instead for Docker compatibility
from mynes.core.network import get_network_interfaces, get_default_gateway, get_local_ip_ranges, get_host_network_ranges, is_docker_environment
from mynes.analysis import fingerprint, os_detect
import json
import socket
import re
import subprocess
import os
from datetime import datetime
# Scapy import'unu sessizce yap
import sys
from io import StringIO

# STDOUT'u geçici olarak yakala
old_stdout = sys.stdout
old_stderr = sys.stderr
sys.stdout = StringIO()
sys.stderr = StringIO()

try:
    from scapy.all import ARP, Ether, srp
finally:
    # STDOUT'u geri yükle
    sys.stdout = old_stdout
    sys.stderr = old_stderr
from mac_vendor_lookup import MacLookup
from mynes.core.config import ConfigManager
from mynes.analysis.oui import OUIManager
from mynes.integrations.docker import docker_manager
from mynes.security.credentials import get_credential_manager
from mynes.analysis.advanced import AdvancedDeviceScanner
from mynes.analysis.identifier import SmartDeviceIdentifier
from mynes.analysis.hostname import AdvancedHostnameResolver
from mynes.analysis.enhanced import EnhancedDeviceAnalyzer
from mynes.security.sanitizer import DataSanitizer
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import base64
from mynes.core.models import unified_model


def match_combined_rule(rules, vendor_lower, hostname_lower):
    """First rule whose vendor AND hostname patterns both match -> its type.

    Pure, so it is testable without a network. Either side may be omitted or
    left as `.*`, which degrades the rule to the single-signal behaviour the
    old hostname/vendor lists already had. An unparseable regex is skipped
    rather than raised: the rules come from a config file the user edits by
    hand, and one typo must not stop every device from being classified.
    """
    for rule in rules or []:
        vendor_pat = rule.get('vendor') or '.*'
        hostname_pat = rule.get('hostname') or '.*'
        try:
            if not re.search(vendor_pat, vendor_lower, re.IGNORECASE):
                continue
            if not re.search(hostname_pat, hostname_lower, re.IGNORECASE):
                continue
        except re.error:
            continue
        if rule.get('type'):
            return rule['type']
    return None


class LANScanner:
    def __init__(self):
        self.last_arp_method = None
        self.privilege_hint = None
        self.devices = []
        self.mac_lookup = MacLookup()
        self.oui_manager = OUIManager()
        self.scanning = False
        self.config_manager = ConfigManager()
        self.credential_manager = get_credential_manager()
        self.data_sanitizer = DataSanitizer()
        
        # Yeni gelişmiş modüller
        self.advanced_scanner = AdvancedDeviceScanner()
        self.enhanced_analyzer = EnhancedDeviceAnalyzer(self.credential_manager)
        self.smart_identifier = SmartDeviceIdentifier(self.config_manager)
        self.hostname_resolver = AdvancedHostnameResolver()
        
        # Config'den ayarları yükle
        self.load_config_settings()
        
    def load_config_settings(self):
        """Config dosyasından ayarları yükle"""
        self.oui_database = self.config_manager.load_oui_database()
        self.device_types = self.config_manager.load_device_types()
        
        # Config'den ayarları doğru şekilde al
        config = getattr(self.config_manager, 'config', {})
        self.detection_rules = config.get('detection_rules', {})
        self.scan_settings = config.get('scan_settings', {})
        self.port_settings = config.get('port_settings', {})
        self.smart_naming_config = config.get('smart_naming', {
            'enabled': False,
            'auto_alias': True,
            'hostname_resolution': True,
            'advanced_scanning': True,
            'confidence_threshold': 0.5
        })
        
    def get_available_networks(self):
        """Mevcut tüm ağ arayüzlerini ve IP aralıklarını döndürür (Docker network'leri dahil)"""
        networks = []
        try:
            # Use network_utils to get interfaces
            interfaces = get_network_interfaces()
            for interface_info in interfaces:
                interface = interface_info['name']
                ip = interface_info['ip']
                netmask = interface_info['netmask']
                
                # Sanal ve kullanılmayan interface'leri atla
                if (interface.startswith('anpi') or interface.startswith('utun') or 
                    interface.startswith('ipsec') or interface.startswith('llw') or
                    interface.startswith('awdl')):
                    continue
                
                # Loopback ve link-local adresleri atla
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                
                network_range = self._get_network_range(ip, netmask)
                networks.append({
                    'interface': interface,
                    'ip': ip,
                    'netmask': netmask,
                    'network_range': network_range,
                    'type': self._get_interface_type(interface)
                })
            
            # Docker network'lerini ekle
            docker_networks = self.get_docker_networks()
            networks.extend(docker_networks)
            
        except Exception as e:
            print(f"Network interface tarama hatası: {e}")
            
        return networks

    def get_docker_networks(self):
        """Docker network arayüzlerini döndür"""
        docker_networks = []
        
        try:
            # Docker virtual interface'leri al
            docker_interfaces = docker_manager.get_docker_interface_info()
            for interface in docker_interfaces:
                docker_networks.append({
                    'interface': interface['interface'],
                    'ip': interface['ip'],
                    'netmask': interface['netmask'],
                    'network_range': self._get_network_range(interface['ip'], interface['netmask']),
                    'type': 'Docker',
                    'description': interface['description']
                })
            
            # Docker container network'leri al
            docker_ranges = docker_manager.get_docker_scan_ranges()
            for range_info in docker_ranges:
                # Network range'i parse et
                subnet = range_info['subnet']
                if '/' in subnet:
                    try:
                        import ipaddress
                        network = ipaddress.ip_network(subnet, strict=False)
                        
                        docker_networks.append({
                            'interface': f"docker-{range_info['network_name']}",
                            'ip': str(network.network_address),
                            'netmask': str(network.netmask),
                            'network_range': subnet,
                            'type': 'Docker Network',
                            'description': f"Docker {range_info['driver']} network ({range_info['container_count']} containers)",
                            'docker_info': {
                                'network_name': range_info['network_name'],
                                'network_id': range_info['network_id'],
                                'driver': range_info['driver'],
                                'gateway': range_info['gateway'],
                                'container_count': range_info['container_count']
                            }
                        })
                    except Exception as e:
                        print(f"Docker network parse hatası: {e}")
                        continue
        
        except Exception as e:
            print(f"Docker network bilgileri alınamadı: {e}")
        
        return docker_networks

    def _docker_host_ip(self):
        """This machine's LAN address - the box the local containers run on.

        Docker's own bridges (docker0, br-*) are skipped: parenting a container
        to the bridge it is plugged into is circular and tells the user nothing.
        """
        try:
            for iface in get_network_interfaces():
                name = iface.get('name') or iface.get('interface') or ''
                ip = iface.get('ip', '')
                if not ip or ip.startswith('127.'):
                    continue
                if name.startswith(('docker', 'br-', 'veth', 'lo')):
                    continue
                return ip
        except Exception:  # noqa: BLE001 - a missing host IP only costs nesting
            pass
        return ''

    def scan_docker_containers_directly(self):
        """Docker container'larını doğrudan tespit et ve cihazlar listesine ekle"""
        docker_devices = []
        
        # Every container we can see comes from the local Engine, so the host is
        # this machine. Recording its LAN address is what lets the graph and the
        # topology hang containers off the box they actually run on instead of
        # off the gateway.
        host_ip = self._docker_host_ip()

        try:
            # Çalışan container'ları al
            containers = docker_manager.get_docker_containers()

            for container in containers:
                ip_addresses = container.get('ip_addresses', [])
                
                for ip_info in ip_addresses:
                    ip = ip_info.get('ipv4', '')
                    network = ip_info.get('network', '')
                    mac = ip_info.get('mac', '')
                    
                    if ip and ip != '':
                        # Container için cihaz bilgisi oluştur
                        container_name = container['name']
                        # Container name'i temizle (/ karakterini kaldır)
                        if container_name.startswith('/'):
                            container_name = container_name[1:]
                        
                        # Docker container için hostname'i container name olarak ayarla
                        hostname = container_name
                        
                        device = {
                            'ip': ip,
                            'mac': mac or 'Unknown',
                            'hostname': hostname,
                            'vendor': 'Docker',
                            'device_type': 'Docker Container',
                            'status': 'online',
                            'last_seen': datetime.now().isoformat(),
                            'response_time': 0,  # Docker container'lar için 0 ms
                            'open_ports': self._get_container_ports(container),
                            'docker_info': {
                                'container_id': container['id'],
                                'container_name': container_name,
                                'image': container['image'],
                                'network': network,
                                'networks': container.get('networks', []),
                                'stack': container.get('stack', ''),
                                'service': container.get('service', ''),
                                'host_ip': host_ip,
                                'status': container['status']
                            }
                        }
                        
                        docker_devices.append(device)
            
        except Exception as e:
            print(f"Docker container tarama hatası: {e}")
        
        return docker_devices
    
    def _get_container_ports(self, container):
        """Container'ın açık portlarını parse et"""
        ports = []
        ports_str = container.get('ports', '')
        
        if ports_str:
            # Port string'ini parse et: "0.0.0.0:55001->8978/tcp, [::]:55001->8978/tcp"
            import re
            
            # Port mapping'leri bul
            port_mappings = re.findall(r'(\d+)->', ports_str)
            for port in port_mappings:
                try:
                    ports.append(int(port))
                except ValueError:
                    continue
                    
            # Internal portları da bul
            internal_ports = re.findall(r'->(\d+)/', ports_str)
            for port in internal_ports:
                try:
                    port_num = int(port)
                    if port_num not in ports:
                        ports.append(port_num)
                except ValueError:
                    continue
        
        return ports

    def local_interface_label(self, interface_info):
        """A label that tells one local interface from another.

        A host with a dozen containers has a dozen docker bridges, and every
        one of them classified as 'Docker' - so the device list, the graph and
        the topology view each showed a column of identical "<host> (Docker)"
        nodes. Prefer the docker network name, fall back to the kernel
        interface name, and only then to the bare type.
        """
        interface_type = (interface_info or {}).get('interface_type') or 'Other'
        interface_name = (interface_info or {}).get('interface_name') or ''

        if interface_type in ('Docker', 'Docker Network', 'Bridge') and interface_name:
            network = self._docker_bridge_names().get(interface_name)
            return f"docker: {network}" if network else interface_name
        return interface_type

    def _docker_bridge_names(self):
        """bridge interface -> docker network name, resolved once per scan."""
        if getattr(self, '_bridge_name_cache', None) is None:
            try:
                self._bridge_name_cache = docker_manager.bridge_interface_names()
            except Exception:
                self._bridge_name_cache = {}
        return self._bridge_name_cache

    def _get_interface_type(self, interface):
        """Network interface tipini belirle"""
        interface_lower = interface.lower()
        if 'docker' in interface_lower or interface_lower.startswith('br-') or 'veth' in interface_lower:
            return 'Docker'
        elif 'wlan' in interface_lower or 'wifi' in interface_lower or 'wi' in interface_lower:
            return 'WiFi'
        elif 'eth' in interface_lower or interface_lower.startswith('en'):
            # MacOS'ta en0 genellikle WiFi, en8 gibi diğerleri Ethernet olabilir
            if interface_lower == 'en0':
                return 'WiFi'
            else:
                return 'Ethernet'
        elif 'vpn' in interface_lower or 'tun' in interface_lower or 'tap' in interface_lower:
            return 'VPN'
        elif 'bluetooth' in interface_lower or 'bt' in interface_lower:
            return 'Bluetooth'
        elif 'bridge' in interface_lower or 'br' in interface_lower:
            return 'Bridge'
        else:
            return 'Other'

    def get_local_network(self, preferred_interface=None):
        """Yerel ağ aralığını otomatik olarak belirler"""
        try:
            # Config'den default IP range'i kontrol et
            default_range = self.scan_settings.get('default_ip_range', '192.168.1.0/24')
            
            # Docker ortamında host network'leri kullan
            if is_docker_environment():
                print("🐳 Docker container detected - scanning host networks")
                host_ranges = get_host_network_ranges()
                
                # Host network'leri arasından en uygun olanı seç
                for range_info in host_ranges:
                    if range_info.get('is_host_network') and not range_info.get('is_common_range'):
                        # Gateway bazlı host network'ü tercih et
                        print(f"🌐 Host network selected: {range_info['cidr']}")
                        return range_info['cidr']
                
                # Gateway bazlı bulunamazsa, common range'lerden birini seç
                for range_info in host_ranges:
                    if range_info.get('is_host_network') and range_info.get('is_common_range'):
                        print(f"🌐 Common host network selected: {range_info['cidr']}")
                        return range_info['cidr']
            
            if preferred_interface:
                # Belirli bir interface tercih edilmişse
                networks = self.get_available_networks()
                for network in networks:
                    if network.get('interface') == preferred_interface:
                        return network.get('network_range', default_range)
            
            # Default gateway'i bul
            default_gateway = get_default_gateway()
            if default_gateway:
                # Aktif network interface'leri kontrol et
                interfaces = get_network_interfaces()
                for interface_info in interfaces:
                    ip = interface_info['ip']
                    netmask = interface_info['netmask']
                    
                    # Bu IP aralığında gateway var mı kontrol et
                    if self._is_ip_in_range(default_gateway, ip, netmask):
                        return self._get_network_range(ip, netmask)
            
            return default_range
        except Exception as e:
            print(f"Network detection hatası: {e}")
            return self.scan_settings.get('default_ip_range', '192.168.1.0/24')
    
    def _is_ip_in_range(self, ip, network_ip, netmask):
        """IP'nin belirtilen ağ aralığında olup olmadığını kontrol eder"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{network_ip}/{netmask}", strict=False)
            return ipaddress.IPv4Address(ip) in network
        except Exception:
            return False
    
    def _get_network_range(self, ip, netmask):
        """IP ve netmask'ten network range'i hesaplar"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception:
            return "192.168.1.0/24"
    
    def get_local_machine_interfaces(self):
        """Yerel makinenin tüm ağ arayüzlerini tespit eder"""
        local_interfaces = []
        try:
            # Use network_utils to get interfaces
            interfaces = get_network_interfaces()
            for interface_info in interfaces:
                interface = interface_info['name']
                ip = interface_info['ip']
                
                # Sanal ve kullanılmayan interface'leri atla
                if (interface.startswith('anpi') or interface.startswith('utun') or 
                    interface.startswith('ipsec') or interface.startswith('llw') or
                    interface.startswith('awdl') or interface.startswith('lo')):
                    continue
                
                # Loopback ve link-local adresleri atla
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                
                # MAC adresini al (psutil kullanarak)
                mac_addr = 'Unknown'
                try:
                    import psutil
                    net_if_addrs = psutil.net_if_addrs()
                    if interface in net_if_addrs:
                        for addr in net_if_addrs[interface]:
                            if addr.family == psutil.AF_LINK:
                                mac_addr = addr.address
                                break
                except:
                    pass
                
                local_interfaces.append({
                    'interface': interface,
                    'ip': ip,
                    'mac': mac_addr,
                    'type': self._get_interface_type(interface)
                })
        except Exception as e:
            print(f"Yerel interface tarama hatası: {e}")
        
        return local_interfaces
    
    def get_local_machine_hostname(self):
        """Yerel makinenin hostname'ini al"""
        try:
            import socket
            return socket.gethostname()
        except Exception:
            return "LocalMachine"
    
    def scan_network_arp(self, target_ip):
        """Layer-2 tarama.

        Raw ARP root ister; yetki yoksa ping sweep + OS ARP cache'e düşer,
        böylece normal kullanıcıda da cihazlar bulunur. Kullanılan yöntem
        `self.last_arp_method` / `self.privilege_hint` üzerinden UI'ya taşınır.
        """
        result = arp_discovery.discover(target_ip, timeout=3)
        self.last_arp_method = result['method']
        self.privilege_hint = result['hint']
        if result['hint']:
            print(f"⚠️  {result['hint']}")
        return [{'ip': d['ip'], 'mac': d['mac']} for d in result['devices']]

    def get_hostname(self, ip):
        """IP adresinden hostname alır"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return ""

    def get_device_vendor_enhanced(self, mac_address):
        """Gelişmiş üretici firma tespiti using OUI Manager"""
        return self.oui_manager.get_vendor(mac_address)
    
    def get_gateway_ip(self):
        """Default gateway, looked up once. The only hard proof of a router."""
        if not hasattr(self, '_gateway_ip'):
            try:
                self._gateway_ip = get_default_gateway()
            except Exception:
                self._gateway_ip = None
        return self._gateway_ip

    def detect_device_type_smart_enhanced(self, ip, mac, hostname, vendor,
                                          open_ports, signals=None):
        """Cihaz tipi tespiti.

        Order matters. Evidence the device gave us about *itself* (an RTSP
        handshake, an HTTP Server header, an SSH banner, being the gateway)
        outranks the config's regex rules, which in turn outrank a guess made
        from port numbers alone.

        The old port heuristic returned 'Router' for anything with SSH plus a
        web page - which is every Raspberry Pi, NAS and home server on a LAN.
        """
        hostname_lower = hostname.lower() if hostname else ""
        vendor_lower = vendor.lower() if vendor else ""
        port_numbers = [p['port'] if isinstance(p, dict) else p for p in (open_ports or [])]

        if signals is None:
            signals = {
                'ip': ip, 'open_ports': port_numbers, 'vendor': vendor or '',
                'hostname': hostname or '', 'rtsp': None, 'http': [], 'ssh': None,
                'is_gateway': ip == self.get_gateway_ip(),
            }

        # 0. Two-signal rules the user wrote by hand. Vendor alone says "Apple"
        #    for a MacBook, an iPhone and an Apple TV alike, and the strongest
        #    single-signal heuristic below (AirPlay -> "Apple Device") is happy
        #    to stop there. A rule that pins vendor *and* hostname is the only
        #    thing that knows which of the three it is, so it goes first.
        combined = match_combined_rule(
            self.detection_rules.get('combined_rules', []), vendor_lower, hostname_lower)
        if combined:
            return combined

        # 1. Strong, self-reported evidence wins outright.
        verdict = fingerprint.classify(signals)
        if verdict['confidence'] >= 0.8:
            return verdict['device_type']

        # 2. Config rules the user can edit.
        hostname_patterns = self.detection_rules.get('hostname_patterns', [])
        for rule in hostname_patterns:
            try:
                if hostname_lower and re.search(rule['pattern'], hostname_lower, re.IGNORECASE):
                    return rule['type']
            except Exception:
                continue

        vendor_patterns = self.detection_rules.get('vendor_patterns', [])
        for rule in vendor_patterns:
            try:
                if re.search(rule['pattern'], vendor_lower, re.IGNORECASE):
                    if 'conditions' in rule:
                        conditions_met = any(
                            condition in hostname_lower or condition in vendor_lower
                            for condition in rule['conditions']
                        )
                        if conditions_met:
                            return rule['type']
                    else:
                        return rule['type']
            except Exception:
                continue

        # 3. Whatever the weaker fingerprint rules concluded, or Unknown.
        return verdict['device_type']

    def refresh_onvif_cache(self, timeout=3.0):
        """One multicast ONVIF probe per scan -> {ip: {name, model, vendor}}.

        Cameras answer this without credentials with the name their owner
        configured ("C212"), which beats anything we could invent.
        """
        self._onvif_cache = {}
        try:
            from mynes.discovery.onvif import discover as onvif_discover

            for dev in onvif_discover(timeout):
                if dev.ip:
                    self._onvif_cache[dev.ip] = {
                        'name': dev.name, 'model': dev.model, 'vendor': dev.vendor,
                        'port': (dev.attributes.get('onvif') or {}).get('port'),
                    }
        except Exception as e:
            print(f"ONVIF keşif hatası: {e}")
        return self._onvif_cache

    def fingerprint_device(self, ip, open_ports, vendor='', hostname=''):
        """Talk to the open services and return the signal dict.

        Never raises and never blocks a scan: a device that ignores us simply
        contributes no signals.
        """
        port_numbers = [p['port'] if isinstance(p, dict) else p for p in (open_ports or [])]
        try:
            signals = fingerprint.gather(
                ip,
                open_ports=port_numbers,
                vendor=vendor,
                hostname=hostname,
                is_gateway=(ip == self.get_gateway_ip()),
            )
            signals['onvif'] = getattr(self, '_onvif_cache', {}).get(ip)
            return signals
        except Exception as e:
            print(f"Fingerprint hatası {ip}: {e}")
            return {
                'ip': ip, 'open_ports': port_numbers, 'vendor': vendor or '',
                'hostname': hostname or '', 'rtsp': None, 'http': [], 'ssh': None,
                'is_gateway': ip == self.get_gateway_ip(),
            }


    def scan_ports_basic(self, ip):
        """Hızlı temel port taraması.

        Was: nmap on [22, 23, 80, 443, 8080] - which is why not one RTSP camera
        was ever found; 554 was never in the list. Now a stdlib connect scan
        over `fingerprint.SCAN_PORTS`, which includes the camera and NAS ports.
        Also drops the nmap requirement from the fast path entirely.
        """
        try:
            ports = fingerprint.scan_tcp(ip)
        except Exception as e:
            print(f"Hızlı port tarama hatası {ip}: {e}")
            return []

        return [{'port': port,
                 'service': fingerprint.service_name(port),
                 'state': 'open'} for port in ports]

    def scan_ports_enhanced(self, ip, device_type=None):
        """Gelişmiş port taraması - cihaz tipine özgü"""
        try:
            # Default portları al
            default_ports = self.port_settings.get('default_ports', [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443])
            
            # Cihaz tipine özgü portları ekle
            device_specific_ports = self.port_settings.get('device_specific_ports', {})
            if device_type and device_type in device_specific_ports:
                scan_ports = list(set(default_ports + device_specific_ports[device_type]))
            else:
                scan_ports = default_ports
            
            # Port range string'i oluştur
            port_range = ','.join(map(str, scan_ports))
            
            nm = nmap.PortScanner()
            result = nm.scan(ip, port_range, arguments='-sT -T4 --max-retries 1 --host-timeout 30s')
            
            open_ports = []
            if ip in result['scan']:
                if 'tcp' in result['scan'][ip]:
                    for port, info in result['scan'][ip]['tcp'].items():
                        if info['state'] == 'open':
                            service = info.get('name', 'unknown')
                            version = info.get('version', '')
                            open_ports.append({
                                'port': port,
                                'service': service,
                                'version': version,
                                'state': info['state']
                            })
            
            return open_ports
        except Exception as e:
            print(f"Port tarama hatası {ip}: {e}")
            return []

    def detailed_device_analysis(self, ip):
        """Detaylı cihaz analizi - ping, traceroute, service detection vs."""
        analysis_results = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'ping_test': self._ping_test(ip),
            'traceroute': self._traceroute_test(ip),
            'service_detection': self._service_detection(ip),
            'os_detection': self._os_detection(ip)
        }
        
        return analysis_results
    
    def _ping_test(self, ip):
        """Ping testi"""
        try:
            result = subprocess.run(['ping', '-c', '4', ip], 
                                  capture_output=True, text=True, timeout=10)
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'response_time': self._extract_ping_time(result.stdout)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _traceroute_test(self, ip):
        """Traceroute testi"""
        try:
            result = subprocess.run(['traceroute', '-m', '10', ip], 
                                  capture_output=True, text=True, timeout=30)
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'hops': self._extract_hops(result.stdout)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _service_detection(self, ip):
        """Servis tespiti"""
        try:
            nm = nmap.PortScanner()
            result = nm.scan(ip, arguments='-sT -sV --script=default')
            
            services = []
            if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                for port, info in result['scan'][ip]['tcp'].items():
                    if info['state'] == 'open':
                        services.append({
                            'port': port,
                            'service': info.get('name', 'unknown'),
                            'product': info.get('product', ''),
                            'version': info.get('version', ''),
                            'extrainfo': info.get('extrainfo', '')
                        })
            
            return services
        except Exception as e:
            return {'error': str(e)}
    
    def _os_detection(self, ip):
        """İşletim sistemi tespiti"""
        try:
            nm = nmap.PortScanner()
            # OS detection için sadece service banner'larından çıkarım yapalım (root gerektirmez)
            result = nm.scan(ip, arguments='-sT -sV --version-all')
            
            os_info = {}
            # Service version'larından OS bilgisi çıkarmaya çalış
            if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                services = []
                for port, info in result['scan'][ip]['tcp'].items():
                    if info['state'] == 'open':
                        service_info = info.get('product', '') + ' ' + info.get('version', '')
                        services.append(service_info.lower())
                
                # Service bilgilerinden OS tahmin etmeye çalış
                os_hints = []
                for service in services:
                    if 'linux' in service or 'ubuntu' in service or 'debian' in service:
                        os_hints.append('Linux')
                    elif 'windows' in service or 'microsoft' in service:
                        os_hints.append('Windows')
                    elif 'cisco' in service:
                        os_hints.append('Cisco IOS')
                    elif 'openssh' in service:
                        os_hints.append('Unix-like')
                
                if os_hints:
                    os_info = {
                        'name': max(set(os_hints), key=os_hints.count),
                        'accuracy': 60,  # Lower accuracy since it's based on service detection
                        'method': 'service_fingerprinting'
                    }
            
            return os_info
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_ping_time(self, ping_output):
        """Ping çıktısından response time'ı çıkar"""
        try:
            pattern = r'time=(\d+\.?\d*)ms'
            matches = re.findall(pattern, ping_output)
            if matches:
                times = [float(match) for match in matches]
                return {
                    'min': min(times),
                    'max': max(times),
                    'avg': sum(times) / len(times)
                }
        except Exception:
            pass
        return None
    
    def _extract_hops(self, traceroute_output):
        """Traceroute çıktısından hop'ları çıkar"""
        try:
            lines = traceroute_output.strip().split('\n')
            hops = []
            for line in lines[1:]:  # İlk satır header
                if line.strip():
                    hops.append(line.strip())
            return hops
        except Exception:
            pass
        return []

    # Backward compatibility methods
    def get_device_vendor(self, mac_address):
        """MAC adresinden üretici firma bilgisini alır - Backward compatibility"""
        return self.get_device_vendor_enhanced(mac_address)
    
    def detect_device_type_smart(self, ip, mac, hostname, vendor, open_ports):
        """Akıllı cihaz tipi tespiti - Backward compatibility"""
        return self.detect_device_type_smart_enhanced(ip, mac, hostname, vendor, open_ports)
    
    def scan_ports(self, ip, port_range=None, device_type=None):
        """Port taraması - Enhanced version kullan"""
        if port_range:
            # Eski format ile çağrılmışsa
            try:
                nm = nmap.PortScanner()
                result = nm.scan(ip, port_range, arguments='-sT -T4 --max-retries 1 --host-timeout 30s')
                
                open_ports = []
                if ip in result['scan']:
                    if 'tcp' in result['scan'][ip]:
                        for port, info in result['scan'][ip]['tcp'].items():
                            if info['state'] == 'open':
                                service = info.get('name', 'bilinmeyen')
                                open_ports.append({
                                    'port': port,
                                    'service': service,
                                    'state': info['state']
                                })
                
                return open_ports
            except Exception as e:
                print(f"Port tarama hatası {ip}: {e}")
                return []
        else:
            # Yeni enhanced version kullan
            return self.scan_ports_enhanced(ip, device_type)

    def scan_single_device(self, ip, mac, existing_devices=None, detailed_analysis=False, progress_callback=None, local_interface_info=None):
        """Tek bir cihazı tarar - detailed_analysis=True ise gelişmiş analiz yapar"""
        print(f"Taranıyor: {ip}")
        
        # Detaylı logging için helper function
        def log_operation(operation, status="başlatılıyor", details=""):
            if progress_callback and detailed_analysis:
                message = f"{ip} - {operation}: {status}"
                if details:
                    message += f" ({details})"
                progress_callback(message)
        
        # Mevcut cihaz bilgilerini kontrol et
        mac_lower = mac.lower()
        existing_device = existing_devices.get(mac_lower, {}) if existing_devices else {}
        
        # Temel bilgileri al - Mevcut bilgileri öncelikle kullan
        existing_hostname = existing_device.get('hostname', '')
        existing_vendor = existing_device.get('vendor', '')
        
        log_operation("🔍 Hostname Çözümleme", "başlatılıyor")
        
        # Yerel makine için özel hostname belirleme
        if local_interface_info:
            hostname = self.get_local_machine_hostname()
            # Yerel makine hostname'ini interface tipi ile zenginleştir
            if local_interface_info.get('interface_type'):
                hostname = f"{hostname} ({self.local_interface_label(local_interface_info)})"
            log_operation("🔍 Hostname Çözümleme", "yerel makine", hostname)
        elif existing_hostname and not detailed_analysis:
            # Hızlı taramada mevcut hostname'i koru
            hostname = existing_hostname
            log_operation("🔍 Hostname Çözümleme", "korundu", hostname)
        else:
            hostname = self.get_hostname(ip)
            # Yeni hostname yoksa eski'yi koru
            if not hostname and existing_hostname:
                hostname = existing_hostname
                log_operation("🔍 Hostname Çözümleme", "eski korundu", hostname)
            else:
                log_operation("🔍 Hostname Çözümleme", "tamamlandı", hostname or "hostname bulunamadı")
        
        log_operation("🏷️ MAC Vendor Lookup", "başlatılıyor")
        
        # Yerel makine için özel vendor belirleme
        if local_interface_info:
            vendor = self.get_device_vendor_enhanced(mac)
            if not vendor or vendor == "Bilinmeyen":
                vendor = "Apple Inc." if mac.startswith(('00:e0:4c', '1e:48:ac')) else "Local Machine"
            log_operation("🏷️ MAC Vendor Lookup", "yerel makine", vendor)
        elif existing_vendor and not detailed_analysis:
            # Hızlı taramada mevcut vendor'ı koru
            vendor = existing_vendor
            log_operation("🏷️ MAC Vendor Lookup", "korundu", vendor)
        else:
            vendor = self.get_device_vendor_enhanced(mac)
            # Yeni vendor yoksa eski'yi koru
            if not vendor and existing_vendor:
                vendor = existing_vendor
                log_operation("🏷️ MAC Vendor Lookup", "eski korundu", vendor)
            else:
                log_operation("🏷️ MAC Vendor Lookup", "tamamlandı", vendor or "vendor bulunamadı")
        
        # Smart naming aktif mi ve detaylı analiz istenmiş mi kontrol et
        smart_naming_enabled = self.smart_naming_config.get('enabled', False) and detailed_analysis
        
        # Gelişmiş hostname çözümleme (Sadece detaylı analizde)
        enhanced_hostname_info = None
        if smart_naming_enabled and self.smart_naming_config.get('hostname_resolution', True):
            try:
                log_operation("🧠 Gelişmiş Hostname Analizi", "başlatılıyor", "RDN & DNS analizi")
                enhanced_hostname_info = self.hostname_resolver.resolve_hostname_comprehensive(ip)
                if enhanced_hostname_info.get('primary_hostname'):
                    hostname = enhanced_hostname_info['primary_hostname']
                    log_operation("🧠 Gelişmiş Hostname Analizi", "tamamlandı", f"hostname: {hostname}")
                else:
                    log_operation("🧠 Gelişmiş Hostname Analizi", "tamamlandı", "ek hostname bulunamadı")
            except Exception as e:
                log_operation("🧠 Gelişmiş Hostname Analizi", "hata", str(e))
                print(f"Gelişmiş hostname çözümleme hatası {ip}: {e}")
        
        # Port taraması - detaylı analizde daha kapsamlı
        if detailed_analysis:
            log_operation("🔌 Gelişmiş Port Tarama", "başlatılıyor", "tüm servisler")
            open_ports = self.scan_ports_enhanced(ip)
            log_operation("🔌 Gelişmiş Port Tarama", "tamamlandı", f"{len(open_ports)} port bulundu")
        else:
            # Hızlı tarama için sadece temel portlar
            log_operation("🔌 Hızlı Port Tarama", "başlatılıyor", "temel portlar")
            open_ports = self.scan_ports_basic(ip)
            log_operation("🔌 Hızlı Port Tarama", "tamamlandı", f"{len(open_ports)} port bulundu")
        
        port_numbers = [port['port'] if isinstance(port, dict) else port for port in open_ports]

        # Ask the open services what they are. This is what makes an RTSP
        # camera identifiable at all, and what stops a Pi from being a router.
        log_operation("🧬 Servis Parmak İzi", "başlatılıyor", f"{len(port_numbers)} port")
        signals = self.fingerprint_device(ip, port_numbers, vendor, hostname)
        if signals.get('rtsp'):
            log_operation("🧬 Servis Parmak İzi", "tamamlandı",
                          f"RTSP {signals['rtsp']['url']}")
        else:
            evidence = [b.get('server') or b.get('title') for b in signals.get('http') or []]
            evidence = [e for e in evidence if e] or ([signals['ssh']] if signals.get('ssh') else [])
            log_operation("🧬 Servis Parmak İzi", "tamamlandı",
                          '; '.join(evidence)[:120] or "yanıt yok")

        # Gelişmiş cihaz bilgisi toplama (Sadece detaylı analizde)
        enhanced_info = None
        if smart_naming_enabled and self.smart_naming_config.get('advanced_scanning', True):
            try:
                log_operation("🔬 Gelişmiş Cihaz Analizi", "başlatılıyor", "DNS, SNMP, Web, SMB, UPnP")
                enhanced_info = self.advanced_scanner.get_enhanced_device_info(ip, mac, hostname, vendor, progress_callback)
                methods_count = len(enhanced_info.keys()) if enhanced_info else 0
                log_operation("🔬 Gelişmiş Cihaz Analizi", "tamamlandı", f"{methods_count} yöntem kullanıldı")
            except Exception as e:
                log_operation("🔬 Gelişmiş Cihaz Analizi", "hata", str(e))
                print(f"Gelişmiş cihaz analizi hatası {ip}: {e}")
        
        # Cihaz tipini belirle. Only a type the *user* picked is preserved - a
        # type we guessed on an earlier scan gets re-derived, otherwise one bad
        # guess is permanent.
        if existing_device.get('device_type') and existing_device.get('device_type_source') == 'user':
            device_type = existing_device.get('device_type')
            identification_result = {'device_type': device_type, 'confidence': 1.0, 'user_defined': True}
            print(f"Kullanıcı tanımlı device_type korundu: {device_type} ({ip})")
        elif local_interface_info:
            # Yerel makine için özel device_type belirleme
            interface_type = local_interface_info.get('interface_type', 'Other')
            if interface_type == 'Ethernet':
                device_type = 'Desktop/Laptop (Ethernet)'
            elif interface_type == 'WiFi':
                device_type = 'Desktop/Laptop (WiFi)'
            else:
                device_type = f'Local Machine ({interface_type})'
            identification_result = {'device_type': device_type, 'confidence': 1.0, 'local_machine': True}
            print(f"Yerel makine device_type: {device_type} ({ip})")
        else:
            # Smart identification kullan (sadece yeni cihazlar veya tanımlanmamış olanlar için)
            if smart_naming_enabled:
                try:
                    log_operation("🤖 Akıllı Cihaz Tanımlama", "başlatılıyor", "AI algoritması")
                    device_info_for_id = {
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname,
                        'vendor': vendor,
                        'open_ports': open_ports
                    }
                    identification_result = self.smart_identifier.identify_device_with_enhanced_analysis(
                        device_info_for_id, enhanced_info
                    )
                    device_type = identification_result.get('device_type', 'unknown')
                    confidence = identification_result.get('confidence', 0)
                    log_operation("🤖 Akıllı Cihaz Tanımlama", "tamamlandı", f"{device_type} (güven: {confidence:.2f})")
                    
                    # Güven eşiğini kontrol et
                    confidence_threshold = self.smart_naming_config.get('confidence_threshold', 0.5)
                    if identification_result.get('confidence', 0) < confidence_threshold:
                        # Düşük güven skoru, eski yöntemi kullan
                        log_operation("🔄 Fallback Analizi", "başlatılıyor", "düşük güven skoru")
                        device_type = self.detect_device_type_smart_enhanced(ip, mac, hostname, vendor, port_numbers, signals)
                        identification_result['device_type'] = device_type
                        identification_result['fallback'] = True
                        log_operation("🔄 Fallback Analizi", "tamamlandı", device_type)
                        
                except Exception as e:
                    log_operation("🤖 Akıllı Cihaz Tanımlama", "hata", str(e))
                    print(f"Smart identification hatası {ip}: {e}")
                    device_type = self.detect_device_type_smart_enhanced(ip, mac, hostname, vendor, port_numbers, signals)
                    identification_result = {'device_type': device_type, 'confidence': 0.5, 'error': str(e)}
            else:
                # Basit yöntem
                log_operation("🔍 Basit Cihaz Tanımlama", "başlatılıyor")
                device_type = self.detect_device_type_smart_enhanced(ip, mac, hostname, vendor, port_numbers, signals)
                identification_result = {'device_type': device_type, 'confidence': 0.5}
                log_operation("🔍 Basit Cihaz Tanımlama", "tamamlandı", device_type)
        
        # Cihaz tipine özgü detaylı port taraması (sadece detaylı analizde)
        if detailed_analysis and device_type != 'Unknown':
            log_operation("🎯 Cihaz Özel Port Tarama", "başlatılıyor", f"{device_type} için")
            detailed_ports = self.scan_ports_enhanced(ip, device_type)
            if len(detailed_ports) > len(open_ports):
                open_ports = detailed_ports
                log_operation("🎯 Cihaz Özel Port Tarama", "tamamlandı", f"{len(detailed_ports)} ek port bulundu")
            else:
                log_operation("🎯 Cihaz Özel Port Tarama", "tamamlandı", "yeni port bulunamadı")
        
        # Manuel portları ve enhanced analiz portlarını koruyarak birleştir
        manual_ports = existing_device.get('manual_ports', [])
        enhanced_ports = existing_device.get('all_enhanced_ports', [])
        
        # Önce enhanced portları ekle (detaylı analiz sonuçları)
        for enhanced_port in enhanced_ports:
            port_exists = False
            enhanced_port_num = enhanced_port.get('port') if isinstance(enhanced_port, dict) else enhanced_port
            
            for existing_port in open_ports:
                existing_port_num = existing_port.get('port') if isinstance(existing_port, dict) else existing_port
                
                if existing_port_num == enhanced_port_num:
                    # Mevcut port varsa, enhanced bilgileri koru
                    if isinstance(existing_port, dict) and isinstance(enhanced_port, dict):
                        # Enhanced port bilgilerini güncelleyici bilgi olarak koru
                        if enhanced_port.get('description'):
                            existing_port['description'] = enhanced_port['description']
                        if enhanced_port.get('source'):
                            existing_port['source'] = enhanced_port['source']
                        if enhanced_port.get('manual'):
                            existing_port['manual'] = enhanced_port['manual']
                    port_exists = True
                    break
            
            if not port_exists:
                # Enhanced port bulunamadıysa ekle
                open_ports.append(enhanced_port)
                if detailed_analysis:
                    print(f"Enhanced port korundu: {enhanced_port_num} ({ip})")
        
        # Sonra manuel portları ekle
        for manual_port in manual_ports:
            port_exists = False
            manual_port_num = manual_port.get('port') if isinstance(manual_port, dict) else manual_port
            
            for existing_port in open_ports:
                existing_port_num = existing_port.get('port') if isinstance(existing_port, dict) else existing_port
                
                if existing_port_num == manual_port_num:
                    if isinstance(existing_port, dict):
                        existing_port['manual'] = True
                        # Manuel port açıklaması varsa onu kullan
                        if isinstance(manual_port, dict) and manual_port.get('description'):
                            existing_port['description'] = manual_port['description']
                    port_exists = True
                    break
            
            if not port_exists:
                open_ports.append(manual_port)
                print(f"Manuel port korundu: {manual_port_num} ({ip})")
        
        # Cihaz bilgilerini oluştur
        device_info = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor,
            'device_type': device_type,
            'open_ports': open_ports,
            'last_seen': datetime.now().isoformat(),
            'status': 'online',
            'alias': existing_device.get('alias', ''),
            'notes': existing_device.get('notes', '')
        }

        # What the services told us, kept so the UI can show *why* a device was
        # typed the way it was, and so a camera's stream URL is one click away.
        # Mark where the type came from, so the merge on the next scan knows
        # whether it may refresh it.
        device_info['device_type_source'] = (
            'user' if identification_result.get('user_defined') else 'auto')

        device_info['fingerprint'] = {
            'rtsp': signals.get('rtsp'),
            'http': signals.get('http'),
            'ssh': signals.get('ssh'),
            'ftp': signals.get('ftp'),
            'smb': signals.get('smb'),
            'is_gateway': signals.get('is_gateway', False),
            'reasons': fingerprint.classify(signals).get('reasons', []),
        }
        if signals.get('rtsp'):
            device_info['stream_url'] = signals['rtsp']['url']

        # OS family and WiFi-vs-wired are both best-effort guesses, never
        # claimed as measured fact - see mynes/analysis/os_detect.py. A ping
        # TTL from an earlier detailed analysis sharpens the OS guess when
        # nothing else named it; a fresh basic scan has none yet, which is
        # fine, the banner-based signals above already cover most devices.
        ttl_hint = ((existing_device.get('enhanced_info') or {})
                    .get('ping_analysis', {}) or {}).get('ttl')
        device_info['os_guess'] = os_detect.guess_os(signals, ttl=ttl_hint)
        device_info['connection_medium'] = os_detect.guess_connection_medium(
            device_type, vendor, signals)

        # Auto-name. A name the *user* typed is never touched; a name we
        # generated earlier is refreshed, because a later scan knows more.
        alias_source = existing_device.get('alias_source', '')
        if not device_info['alias'] or alias_source == 'auto':
            suggested = fingerprint.suggest_name(signals, device_type)
            if suggested:
                device_info['alias'] = suggested
                device_info['alias_source'] = 'auto'
                log_operation("🏷️ Otomatik İsimlendirme", "tamamlandı", suggested)
        elif alias_source:
            device_info['alias_source'] = alias_source


        # Mevcut enhanced analiz bilgilerini her durumda koru
        if existing_device.get('enhanced_comprehensive_info'):
            device_info['enhanced_comprehensive_info'] = existing_device['enhanced_comprehensive_info']
            print(f"Enhanced comprehensive info korundu ({ip})")
        
        if existing_device.get('advanced_scan_summary'):
            device_info['advanced_scan_summary'] = existing_device['advanced_scan_summary']
            print(f"Advanced scan summary korundu ({ip})")
            
        if existing_device.get('last_enhanced_analysis'):
            device_info['last_enhanced_analysis'] = existing_device['last_enhanced_analysis']
            print(f"Last enhanced analysis timestamp korundu ({ip})")
        
        # Enhanced_info'yu her zaman koru (detaylı analizde üzerine yazılabilir)
        preserve_enhanced_info = existing_device.get('enhanced_info', {})
        if preserve_enhanced_info:
            # Detaylı analizde yeni bilgilerle birleştir, normal taramada tamamen koru
            if detailed_analysis:
                # Mevcut enhanced_info ile yeni bilgileri birleştir
                current_enhanced_info = device_info.get('enhanced_info', {})
                current_enhanced_info.update(preserve_enhanced_info)
                device_info['enhanced_info'] = current_enhanced_info
            else:
                # Normal taramada tamamen koru
                device_info['enhanced_info'] = preserve_enhanced_info
            print(f"Enhanced info korundu ({ip})")
            
        # Detaylı analizde olmasa da önemli enhanced bilgileri koru
        if not detailed_analysis:
            print(f"🔒 Normal tarama - {ip} için tüm enhanced bilgiler korunuyor")
        
        # Smart alias oluşturma (sadece detaylı analizde ve kullanıcı tanımlı alias yoksa)
        if (smart_naming_enabled and 
            self.smart_naming_config.get('auto_alias', True) and 
            not device_info['alias']):
            try:
                log_operation("🏷️ Otomatik Alias Oluşturma", "başlatılıyor")
                smart_alias = self.smart_identifier.generate_smart_alias(
                    device_info, identification_result, enhanced_info
                )
                if smart_alias:
                    device_info['alias'] = smart_alias
                    log_operation("🏷️ Otomatik Alias Oluşturma", "tamamlandı", smart_alias)
                else:
                    log_operation("🏷️ Otomatik Alias Oluşturma", "tamamlandı", "alias oluşturulamadı")
            except Exception as e:
                log_operation("🏷️ Otomatik Alias Oluşturma", "hata", str(e))
                print(f"Smart alias oluşturma hatası {ip}: {e}")
        elif local_interface_info and not device_info['alias']:
            # Yerel makine için özel alias oluşturma
            interface_name = local_interface_info.get('interface_name', 'unknown')
            interface_type = local_interface_info.get('interface_type', 'Other')
            local_hostname = hostname.split(' (')[0]  # Parantez kısmını çıkar
            device_info['alias'] = f"{local_hostname} - {self.local_interface_label(local_interface_info)}"
            print(f"Yerel makine alias oluşturuldu: {device_info['alias']} ({ip})")
        elif device_info['alias']:
            print(f"Kullanıcı tanımlı alias korundu: {device_info['alias']} ({ip})")
        
        # Gelişmiş bilgileri ekle (sadece detaylı analizde)
        if detailed_analysis and enhanced_info:
            # Mevcut enhanced_info'yu koru ve üzerine ekle
            current_enhanced_info = device_info.get('enhanced_info', {})
            current_enhanced_info.update({
                'hostname_resolution': enhanced_hostname_info,
                'identification_result': identification_result,
                'advanced_scan_summary': {
                    'methods_used': list(enhanced_info.keys()),
                    'confidence': identification_result.get('confidence', 0),
                    'smart_naming_used': smart_naming_enabled
                }
            })
            device_info['enhanced_info'] = current_enhanced_info
        
        # Cihaz analizi tamamlandı logu
        if detailed_analysis and progress_callback:
            alias_info = f" - Alias: {device_info.get('alias', 'N/A')}" if device_info.get('alias') else ""
            ports_info = f" - {len(device_info.get('open_ports', []))} port"
            smart_info = " - 🧠 Smart Analiz" if device_info.get('enhanced_info') else ""
            progress_callback(f"✅ {ip} analizi tamamlandı: {device_info.get('device_type', 'Unknown')}{alias_info}{ports_info}{smart_info}")
        
        return device_info
    
    def scan_network(self, progress_callback=None, ip_range=None, include_offline=None):
        """Tüm ağı tarar"""
        self.scanning = True
        self._bridge_name_cache = None  # containers come and go between scans

        # Mevcut cihaz bilgilerini korumak için önce yükle (unified model kullanarak)
        existing_devices = {}
        if os.path.exists(data_file('lan_devices.json')):
            try:
                with open(data_file('lan_devices.json'), 'r', encoding='utf-8') as f:
                    old_devices = json.load(f)
                    # MAC+IP kombinasyonuna göre mevcut cihazları dizinle ve unified format'a migrate et
                    for device in old_devices:
                        mac = device.get('mac', '').lower()
                        ip = device.get('ip', '')
                        # IP is optional: BLE/Zigbee devices are keyed by MAC
                        # alone (mac@) and must survive a rescan too, or every
                        # network scan would silently drop every AirTag/tracker.
                        if mac:
                            # MAC+IP kombinasyonu anahtarı
                            device_key = f"{mac}@{ip}"
                            # Legacy format'tan unified format'a migrate et
                            unified_device = unified_model.migrate_legacy_data(device)
                            existing_devices[device_key] = unified_device
                            print(f"📤 Legacy data migrated: {ip} (MAC: {mac}) - {unified_device.get('alias', 'N/A')}")
            except Exception as e:
                print(f"Mevcut cihaz bilgileri yükleme hatası: {e}")
        
        self.devices = []
        start_time = datetime.now()
        
        # Config'den ayarları al
        if ip_range is None:
            ip_range = self.get_local_network()
        if include_offline is None:
            include_offline = self.scan_settings.get('include_offline', False)
        
        print(f"Taranacak ağ: {ip_range}")

        # One ONVIF probe for the whole sweep: cameras answer with the name
        # their owner configured, which no port scan can tell us.
        if progress_callback:
            progress_callback("ONVIF kamera keşfi...")
        onvif_found = self.refresh_onvif_cache()
        if onvif_found:
            print(f"ONVIF: {len(onvif_found)} kamera bulundu -> "
                  + ', '.join(f"{ip} ({info.get('name') or '?'})"
                              for ip, info in onvif_found.items()))

        if progress_callback:
            progress_callback("ARP taraması başlıyor...")
        
        # ARP ile hızlı tarama
        arp_devices = self.scan_network_arp(ip_range)
        
        # Yerel makinenin interface'lerini de ekle
        local_interfaces = self.get_local_machine_interfaces()
        local_hostname = self.get_local_machine_hostname()
        
        # Yerel interface'leri ARP sonuçlarına ekle. ARP taraması host'un kendi
        # IP'sini bulmuş olsa bile onu local_interface olarak işaretle - yoksa
        # uygulamanın çalıştığı Macbook, jenerik bir cihaz gibi (veya hiç)
        # görünüyordu. Böylece hep "kafein-mbp-erkan (WiFi)" / Laptop olur.
        by_ip = {d['ip']: d for d in arp_devices}
        for interface in local_interfaces:
            existing = by_ip.get(interface['ip'])
            if existing is not None:
                existing['local_interface'] = True
                existing['interface_name'] = interface['interface']
                existing['interface_type'] = interface['type']
                if not existing.get('mac') or existing['mac'] in ('Unknown', 'N/A', ''):
                    existing['mac'] = interface['mac']
                print(f"🖥️ Yerel makine ARP'de bulundu, işaretlendi: {interface['ip']} ({interface['interface']})")
            else:
                arp_devices.append({
                    'ip': interface['ip'],
                    'mac': interface['mac'],
                    'local_interface': True,
                    'interface_name': interface['interface'],
                    'interface_type': interface['type']
                })
                print(f"🖥️ Yerel makine interface'i eklendi: {interface['ip']} (MAC: {interface['mac']}, Interface: {interface['interface']})")
        
        total_devices = len(arp_devices)
        
        if progress_callback:
            progress_callback(f"{total_devices} cihaz bulundu (yerel makine dahil), detaylı tarama başlıyor...")
        
        # Statistics için
        device_types = {}
        vendors = {}
        online_count = 0
        
        # Her cihaz için detaylı tarama
        for i, device in enumerate(arp_devices):
            if not self.scanning:  # Tarama durdurulmuşsa
                break
                
            if progress_callback:
                progress_callback(f"Taranıyor: {device['ip']} ({i+1}/{total_devices})")
            
            try:
                # Yerel makine bilgilerini hazırla
                local_interface_info = None
                if device.get('local_interface'):
                    local_interface_info = {
                        'interface_name': device.get('interface_name'),
                        'interface_type': device.get('interface_type'),
                        'is_local': True
                    }
                
                # Unified model kullanarak cihaz tara
                new_device_info = self.scan_single_device(
                    device['ip'], 
                    device['mac'], 
                    existing_devices, 
                    detailed_analysis=False, 
                    progress_callback=progress_callback,
                    local_interface_info=local_interface_info
                )
                
                # MAC+IP kombinasyonu anahtarı
                current_mac = device['mac'].lower()
                current_ip = device['ip']
                device_key = f"{current_mac}@{current_ip}"
                
                # Mevcut cihazı MAC+IP kombinasyonu ile ara
                existing_device = existing_devices.get(device_key)
                
                if existing_device:
                    # Mevcut cihaz - unified model ile merge et
                    merged_device = unified_model.merge_device_data(existing_device, new_device_info, "normal_scan")
                    self.devices.append(merged_device)
                    print(f"🔄 Unified merge: {current_ip} (MAC: {current_mac}) - {merged_device.get('alias', 'N/A')}")
                else:
                    # Yeni cihaz - unified format'a dönüştür
                    unified_device = unified_model.migrate_legacy_data(new_device_info)
                    self.devices.append(unified_device)
                    print(f"🆕 New unified device: {current_ip} (MAC: {current_mac}) - {unified_device.get('alias', 'N/A')}")
                
                # Statistics - son eklenen cihazı kullan
                online_count += 1
                current_device = self.devices[-1]  # Son eklenen cihaz
                device_type = current_device['device_type']
                vendor = current_device['vendor']
                
                device_types[device_type] = device_types.get(device_type, 0) + 1
                vendors[vendor] = vendors.get(vendor, 0) + 1
                
            except Exception as e:
                print(f"Cihaz tarama hatası {device['ip']}: {e}")
        
        # ALWAYS korumak için eski cihazları kontrol et (include_offline ayarına bakılmaksızın)
        # Kullanıcı tanımlı bilgileri olan tüm cihazları koru
        current_macs = {device['mac'].lower() for device in self.devices}
        
        # Existing devices'tan çevrimdışı olan ama önemli bilgileri olan cihazları ekle
        preserved_count = 0
        current_device_keys = {f"{device['mac'].lower()}@{device['ip']}" for device in self.devices}
        
        for device_key, unified_device in existing_devices.items():
            # Bu cihaz şu anki taramada bulunamadı ama değerli bilgileri var
            if device_key not in current_device_keys:
                # Unified model ile koruma kriterleri kontrol et
                should_preserve = (
                    unified_device.get('alias') or
                    unified_device.get('notes') or 
                    unified_device.get('device_type') or
                    unified_device.get('open_ports') or
                    unified_device.get('analysis_data', {}).get('enhanced_analysis_info') or
                    unified_device.get('analysis_data', {}).get('normal_scan_info') or
                    # Legacy fields için de kontrol et
                    unified_device.get('enhanced_comprehensive_info') or
                    unified_device.get('enhanced_info') or
                    unified_device.get('advanced_scan_summary')
                )
                
                if should_preserve:
                    # Cihazı çevrimdışı olarak işaretle ve ekle. Radyo-only
                    # (BLE) cihazlar ağ taramasında hiç görünmez, bu yüzden
                    # onları offline'a çevirmek yanıltıcı olur - durumlarını
                    # son keşifteki haliyle koru.
                    if not unified_device.get('discovery_only'):
                        unified_device['status'] = 'offline'
                    unified_device['last_seen'] = unified_device.get('last_seen', datetime.now().isoformat())
                    self.devices.append(unified_device)
                    preserved_count += 1
                    print(f"📴 Çevrimdışı cihaz korundu: {unified_device.get('ip', 'N/A')} (MAC: {unified_device.get('mac', 'N/A')}) - {unified_device.get('alias', 'N/A')}")
        
        if preserved_count > 0:
            print(f"✅ {preserved_count} çevrimdışı cihaz korundu")
        
        # Final MAC+IP tekrarı kontrolü ve temizleme
        print(f"\n🔍 Final MAC+IP tekrarı kontrolü...")
        unique_devices = []
        seen_device_keys = set()
        
        for device in self.devices:
            mac = device.get('mac', '').lower()
            ip = device.get('ip', '')
            device_key = f"{mac}@{ip}"
            
            if device_key in seen_device_keys:
                print(f"⚠️ Tekrar eden MAC+IP tespit edildi: {device_key} - atlanıyor")
                continue
            
            seen_device_keys.add(device_key)
            unique_devices.append(device)
        
        if len(unique_devices) != len(self.devices):
            self.devices = unique_devices
            print(f"🧹 {len(self.devices)} unique cihaz kaldı (MAC+IP tekrarlar temizlendi)")
        else:
            print(f"✅ Tüm cihazlar unique - {len(self.devices)} cihaz (MAC+IP bazında)")
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        # Scan history'ye kaydet
        scan_data = {
            'total_devices': len(self.devices),
            'online_devices': online_count,
            'ip_range': ip_range,
            'scan_duration': scan_duration,
            'device_types': device_types,
            'vendors': vendors
        }
        
        self.config_manager.add_scan_history(scan_data)
        
        # Docker container'larını da taramaya ekle
        if progress_callback:
            progress_callback("Docker container'ları tespit ediliyor...")
        
        try:
            docker_devices = self.scan_docker_containers_directly()
            if docker_devices:
                # Docker container'larını mevcut cihazlar listesine ekle
                existing_ips = {device['ip'] for device in self.devices}
                
                for docker_device in docker_devices:
                    # Aynı IP'yi tekrar eklemeyelim
                    if docker_device['ip'] not in existing_ips:
                        self.devices.append(docker_device)
                        
                        # İstatistikleri güncelle
                        device_type = docker_device['device_type']
                        vendor = docker_device['vendor']
                        device_types[device_type] = device_types.get(device_type, 0) + 1
                        vendors[vendor] = vendors.get(vendor, 0) + 1
                        online_count += 1
                
                # İstatistikleri yeniden kaydet
                scan_data = {
                    'total_devices': len(self.devices),
                    'online_devices': online_count,
                    'ip_range': ip_range,
                    'scan_duration': scan_duration,
                    'device_types': device_types,
                    'vendors': vendors
                }
                self.config_manager.add_scan_history(scan_data)
                
                if progress_callback:
                    progress_callback(f"{len(docker_devices)} Docker container eklendi.")
                    
        except Exception as e:
            print(f"Docker container tarama hatası: {e}")
        
        self.scanning = False
        if progress_callback:
            progress_callback(f"Tarama tamamlandı! {len(self.devices)} cihaz bulundu.")
        
        return self.devices
    
    def stop_scan(self):
        """Taramayı durdurur"""
        self.scanning = False
    
    def save_to_json(self, filename=data_file('lan_devices.json')):
        """Cihaz bilgilerini JSON dosyasına kaydeder (credential'ları encrypted olarak)"""
        try:
            # Dizin yoksa oluştur
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            # Cihaz verilerini kopyala ve credential'ları encrypt et
            devices_to_save = []
            for device in self.devices:
                device_copy = device.copy()
                
                # Credential bilgilerini al ve encrypt et
                ip = device.get('ip')
                if ip:
                    stored_credentials = self.credential_manager.get_device_credentials(ip)
                    if stored_credentials:
                        # Credential'ları basit encryption ile sakla
                        device_copy['encrypted_credentials'] = self._encrypt_credentials_simple(stored_credentials)
                
                devices_to_save.append(device_copy)
            
            # Hassas verileri temizle
            sanitized_devices = self.data_sanitizer.sanitize_device_data(devices_to_save)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(sanitized_devices, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"JSON kaydetme hatası: {e}")
            return False
    
    def save_devices(self, filename=data_file('lan_devices.json')):
        """Cihazları kaydet - save_to_json'a yönlendirme"""
        return self.save_to_json(filename)
    
    def load_from_json(self, filename=data_file('lan_devices.json')):
        """JSON dosyasından cihaz bilgilerini yükler (encrypted credential'ları decode eder)"""
        try:
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8') as f:
                    loaded_devices = json.load(f)
                
                # Credential'ları decrypt et ve credential manager'a kaydet
                for device in loaded_devices:
                    if 'encrypted_credentials' in device:
                        ip = device.get('ip')
                        if ip:
                            decrypted_creds = self._decrypt_credentials_simple(device['encrypted_credentials'])
                            if decrypted_creds:
                                # Credential manager'a kaydet
                                for access_type, creds in decrypted_creds.items():
                                    self.credential_manager.save_device_credentials(
                                        ip, access_type, 
                                        creds.get('username'),
                                        creds.get('password'),
                                        creds.get('port'),
                                        creds.get('additional_info')
                                    )
                        
                        # Encrypted credential'ları device'da koru (silme!)
                        # del device['encrypted_credentials']  # Bu satırı yorum yaptık
                
                self.devices = loaded_devices
                return True
            else:
                # Ana dosya yoksa sample dosyasını yükle
                sample_filename = data_file('lan_devices_sample.json')
                if os.path.exists(sample_filename):
                    print(f"Ana dosya bulunamadı, sample veriler yükleniyor: {sample_filename}")
                    return self.load_from_json(sample_filename)
                else:
                    print(f"Dosya bulunamadı: {filename}")
                    return False
        except Exception as e:
            print(f"JSON yükleme hatası: {e}")
            return False
    
    def _encrypt_credentials_simple(self, credentials):
        """Credential'ları basit base64 encoding ile encrypt eder"""
        try:
            if not credentials:
                return None
            
            # JSON string'e çevir ve base64 encode et
            json_str = json.dumps(credentials)
            encoded_bytes = base64.b64encode(json_str.encode('utf-8'))
            return encoded_bytes.decode('utf-8')
        except Exception as e:
            print(f"Credential encryption hatası: {e}")
            return None
    
    def _decrypt_credentials_simple(self, encrypted_data):
        """Base64 encoded credential'ları decrypt eder"""
        try:
            if not encrypted_data:
                return None
            
            # Yeni format (dict) ise, credential manager tarafından işlenecek, skip et
            if isinstance(encrypted_data, dict):
                print(f"🔧 Yeni credential formatı tespit edildi, credential manager tarafından işlenecek")
                return None
            
            # Eski format (string) ise base64 decode et
            if isinstance(encrypted_data, str):
                # Base64 decode et ve JSON parse et
                decoded_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
                json_str = decoded_bytes.decode('utf-8')
                return json.loads(json_str)
            
            print(f"⚠️ Beklenmeyen credential veri tipi: {type(encrypted_data)}")
            return None
            
        except Exception as e:
            print(f"Credential decryption hatası: {e}")
            return None
    
    def update_device(self, ip, updates):
        """Belirli bir cihazın bilgilerini günceller"""
        for i, device in enumerate(self.devices):
            if device['ip'] == ip:
                # IP ve MAC değişikliği kontrolü
                new_ip = updates.get('ip', device['ip'])
                new_mac = updates.get('mac', device['mac'])
                
                # IP veya MAC değişiyorsa, yeni device key oluştur
                old_device_key = f"{device['mac'].lower()}@{device['ip']}"
                new_device_key = f"{new_mac.lower()}@{new_ip}"
                
                if old_device_key != new_device_key:
                    print(f"📍 Device key değişikliği: {old_device_key} -> {new_device_key}")
                    
                    # Yeni device key'in çakışıp çakışmadığını kontrol et
                    for other_device in self.devices:
                        if other_device != device:
                            other_key = f"{other_device['mac'].lower()}@{other_device['ip']}"
                            if other_key == new_device_key:
                                print(f"❌ Device key çakışması: {new_device_key} zaten mevcut")
                                return False
                
                print(f"🔄 Cihaz güncelleniyor: {device['ip']} -> {new_ip} (MAC: {device['mac']} -> {new_mac})")
                # Manuel portları işle
                if 'manual_ports' in updates:
                    manual_ports = updates.pop('manual_ports')  # updates'ten çıkar
                    
                    # Mevcut open_ports'u koru (otomatik taranmış portlar)
                    current_open_ports = device.get('open_ports', [])
                    
                    # Manuel portları open_ports'a ekle
                    for manual_port in manual_ports:
                        port_num = manual_port['port']
                        port_desc = manual_port['description']
                        
                        # Bu port zaten mevcut mu kontrol et
                        port_exists = False
                        for existing_port in current_open_ports:
                            if isinstance(existing_port, dict) and existing_port.get('port') == port_num:
                                # Mevcut portu güncelle
                                existing_port['description'] = port_desc
                                existing_port['manual'] = True
                                port_exists = True
                                break
                            elif isinstance(existing_port, int) and existing_port == port_num:
                                # Eski format (sadece int), yeni formata çevir
                                current_open_ports.remove(existing_port)
                                current_open_ports.append({
                                    'port': port_num,
                                    'description': port_desc,
                                    'manual': True
                                })
                                port_exists = True
                                break
                        
                        # Port mevcut değilse ekle
                        if not port_exists:
                            current_open_ports.append({
                                'port': port_num,
                                'description': port_desc,
                                'manual': True
                            })
                    
                    # Güncellenmiş port listesini kaydet
                    device['open_ports'] = current_open_ports
                
                # Diğer güncellemeleri uygula
                device.update(updates)
                return True
        return False
    
    @staticmethod
    def _dedupe_by_mac_ip(devices):
        """Collapse records sharing the same MAC *and* IP - that pair is one
        device. (MAC alone is not safe: a dual-homed host shows one MAC on two
        IPs, so keying on MAC would wrongly merge its interfaces.) Keeps the
        freshest record and backfills empty fields from the ones it replaces, so
        a later scan that lost a hostname does not erase an earlier one. The
        per-scan cleanup already does this; running it here too means duplicates
        can never reach the UI no matter how they entered self.devices - legacy
        migration and raw JSON loads both appended without deduping."""
        merged, order = {}, []
        for i, d in enumerate(devices):
            mac = (d.get('mac') or '').lower()
            ip = d.get('ip') or ''
            key = f"{mac}@{ip}" if (mac or ip) else f"__noid_{i}"
            if key not in merged:
                merged[key] = d
                order.append(key)
            else:
                keep, drop = merged[key], d
                if (drop.get('last_seen') or '') > (keep.get('last_seen') or ''):
                    keep, drop = drop, keep
                for k, v in drop.items():
                    if v and not keep.get(k):
                        keep[k] = v
                merged[key] = keep
        return [merged[k] for k in order]

    def get_devices(self):
        """Tüm cihazları döndürür. Dedup is idempotent, so cleaning on every
        read is cheap and also persists to disk on the next save."""
        # A loopback/link-local IP is never a real LAN device - it is this host
        # advertising its own .local name (see discovery/mdns.py). Drop it so the
        # scanning machine only appears at its real interface IP, never 127.0.0.1.
        self.devices = [
            d for d in self.devices
            if not str(d.get('ip', '')).startswith(('127.', '169.254.')) and d.get('ip') != '::1'
        ]
        self.devices = self._dedupe_by_mac_ip(self.devices)
        return self.devices
    
    def get_config_manager(self):
        """Config manager'ı döndürür"""
        return self.config_manager
    
    def get_oui_manager(self):
        """OUI manager'ı döndürür"""
        return self.oui_manager
    
    def perform_detailed_analysis(self, progress_callback=None):
        """Mevcut cihazlar için paralel detaylı analiz yapar"""
        if not self.devices:
            if progress_callback:
                progress_callback("Detaylı analiz için önce tarama yapılmalı!")
            return
        
        if progress_callback:
            progress_callback("🚀 Paralel detaylı analiz başlatılıyor...")
        
        # Mevcut cihaz bilgilerini korumak için önce yükle
        existing_devices = {}
        if os.path.exists(data_file('lan_devices.json')):
            try:
                with open(data_file('lan_devices.json'), 'r', encoding='utf-8') as f:
                    old_devices = json.load(f)
                    for device in old_devices:
                        mac = device.get('mac', '').lower()
                        if mac:
                            existing_devices[mac] = {
                                'alias': device.get('alias', ''),
                                'notes': device.get('notes', ''),
                                'device_type': device.get('device_type', ''),
                                'manual_ports': [p for p in device.get('open_ports', []) if p.get('manual', False)]
                            }
            except Exception as e:
                print(f"Mevcut cihaz bilgileri yükleme hatası: {e}")
        
        # Online cihazları al
        online_devices = [d for d in self.devices if d.get('status') == 'online']
        offline_devices = [d for d in self.devices if d.get('status') != 'online']
        total_devices = len(online_devices)
        
        if progress_callback:
            progress_callback(f"📊 {total_devices} online cihaz, {len(offline_devices)} offline cihaz tespit edildi")
        
        analyzed_devices = []
        completed_count = 0
        analysis_lock = threading.Lock()
        
        def analyze_single_device(device, device_index):
            nonlocal completed_count
            try:
                # Thread-safe progress update
                with analysis_lock:
                    completed_count += 1
                    if progress_callback:
                        progress_callback(f"🔍 Analiz başlatılıyor: {device['ip']} ({completed_count}/{total_devices})")
                
                # Detaylı analiz yap
                detailed_device = self.scan_single_device(
                    device['ip'], 
                    device['mac'], 
                    existing_devices, 
                    detailed_analysis=True,
                    progress_callback=progress_callback,
                    local_interface_info=None  # Detaylı analizde yerel makine bilgisi yoktur
                )
                
                # Analiz sonuçlarını cihaz bilgilerine ekle
                detailed_device = self.enhance_device_with_analysis_results(detailed_device)
                
                return detailed_device
                
            except Exception as e:
                print(f"Detaylı analiz hatası {device['ip']}: {e}")
                # Hata durumunda eski cihaz bilgisini koru
                return device
        
        # Paralel işleme için ThreadPoolExecutor kullan
        max_workers = min(4, len(online_devices))  # Maximum 4 thread
        
        if progress_callback:
            progress_callback(f"🛠️ {max_workers} paralel thread kullanılarak analiz başlatılıyor...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Tüm cihazlar için analiz task'larını başlat
            future_to_device = {
                executor.submit(analyze_single_device, device, i): device 
                for i, device in enumerate(online_devices)
            }
            
            # Sonuçları bekle ve topla
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    analyzed_device = future.result()
                    analyzed_devices.append(analyzed_device)
                except Exception as e:
                    print(f"Thread hatası {device['ip']}: {e}")
                    analyzed_devices.append(device)
        
        # Çevrimdışı cihazları da ekle
        analyzed_devices.extend(offline_devices)
        
        # Cihaz listesini güncelle
        self.devices = analyzed_devices
        
        # JSON'a kaydet
        self.save_to_json()
        
        if progress_callback:
            progress_callback(f"✅ Paralel detaylı analiz tamamlandı! {total_devices} cihaz {max_workers} thread ile analiz edildi.")
    
    def enhance_device_with_analysis_results(self, device):
        """Analiz sonuçlarını cihaz bilgilerine ekler"""
        enhanced_info = device.get('enhanced_info', {})
        
        # Açık portlar için detaylı bilgi ekle
        if device.get('open_ports'):
            enhanced_ports_info = []
            for port in device['open_ports']:
                if isinstance(port, dict):
                    port_num = port.get('port')
                    service = port.get('service', '')
                    version = port.get('version', '')
                    
                    if port_num:
                        port_detail = f"Port {port_num}"
                        if service:
                            port_detail += f" ({service})"
                        if version:
                            port_detail += f" - {version}"
                        enhanced_ports_info.append(port_detail)
            
            # Port bilgileri open_ports dizisinde tutulur, notes'a eklenmez
        
        # Gelmiş bilgileri notlara ekle
        if enhanced_info:
            current_notes = device.get('notes', '')
            
            # OS bilgisi
            if enhanced_info.get('ping_analysis', {}).get('os_guess'):
                os_info = enhanced_info['ping_analysis']['os_guess']
                os_text = f"\n\n💻 İşletim Sistemi: {os_info}"
                if "💻 İşletim Sistemi:" not in current_notes:
                    device['notes'] = device.get('notes', '') + os_text
            
            # Web bilgileri
            web_info = enhanced_info.get('web_info', {})
            if web_info.get('server_header') or web_info.get('title'):
                web_text = "\n\n🌍 Web Bilgileri:"
                if web_info.get('title'):
                    web_text += f"\n  • Başlık: {web_info['title']}"
                if web_info.get('server_header'):
                    web_text += f"\n  • Server: {web_info['server_header']}"
                
                if "🌍 Web Bilgileri:" not in current_notes:
                    device['notes'] = device.get('notes', '') + web_text
            
            # SNMP bilgileri
            snmp_info = enhanced_info.get('snmp_info', {})
            if snmp_info.get('system_name') or snmp_info.get('system_description'):
                snmp_text = "\n\n📡 SNMP Bilgileri:"
                if snmp_info.get('system_name'):
                    snmp_text += f"\n  • Sistem Adı: {snmp_info['system_name']}"
                if snmp_info.get('system_description'):
                    snmp_text += f"\n  • Açıklama: {snmp_info['system_description']}"
                
                if "📡 SNMP Bilgileri:" not in current_notes:
                    device['notes'] = device.get('notes', '') + snmp_text
        
        # Alias güncelleme (sadece elle girilmemişse)
        current_alias = device.get('alias', '')
        # Eğer mevcut alias smart tarafından oluşturulmuşsa veya boşsa güncelle
        is_auto_generated = (
            not current_alias or 
            not current_alias.strip() or
            'XEROX CORPORATION' in current_alias or
            'Unknown Device' in current_alias
        )
        
        if is_auto_generated:
            # Yeni alias oluştur
            device_type = device.get('device_type', '')
            vendor = device.get('vendor', '')
            hostname = device.get('hostname', '')
            
            alias_parts = []
            if vendor and vendor != 'Bilinmeyen' and 'XEROX' not in vendor:
                alias_parts.append(vendor.split()[0])  # İlk kelime
            if device_type and device_type != 'Unknown':
                alias_parts.append(device_type)
            if hostname and hostname != device.get('ip', '') and hostname:
                alias_parts.append(hostname.split('.')[0])  # İlk kısım
            
            if alias_parts:
                device['alias'] = ' '.join(alias_parts[:2])  # Maximum 2 kelime
            elif hostname and hostname != device.get('ip', ''):
                device['alias'] = hostname.split('.')[0]
        
        return device
    
    def perform_single_device_detailed_analysis(self, ip_address, progress_callback=None):
        """Tek bir cihaz için detaylı analiz yapar"""
        if progress_callback:
            progress_callback(f"Detaylı Cihaz Analizii başlatılıyor: {ip_address}")
        
        # Cihazı listede bul
        target_device = None
        device_index = -1
        for i, device in enumerate(self.devices):
            if device.get('ip') == ip_address:
                target_device = device
                device_index = i
                break
        
        if not target_device:
            if progress_callback:
                progress_callback(f"Cihaz bulunamadı: {ip_address}")
            return
        
        # Mevcut cihaz bilgilerini korumak için yükle
        existing_devices = {}
        if os.path.exists(data_file('lan_devices.json')):
            try:
                with open(data_file('lan_devices.json'), 'r', encoding='utf-8') as f:
                    old_devices = json.load(f)
                    for device in old_devices:
                        mac = device.get('mac', '').lower()
                        if mac:
                            existing_devices[mac] = {
                                'alias': device.get('alias', ''),
                                'notes': device.get('notes', ''),
                                'device_type': device.get('device_type', ''),
                                'manual_ports': [p for p in device.get('open_ports', []) if p.get('manual', False)]
                            }
            except Exception as e:
                print(f"Mevcut cihaz bilgileri yükleme hatası: {e}")
        
        try:
            # Detaylı analiz yap
            detailed_device = self.scan_single_device(
                target_device['ip'], 
                target_device['mac'], 
                existing_devices, 
                detailed_analysis=True,
                progress_callback=progress_callback,
                local_interface_info=None  # Tek cihaz detaylı analizde yerel makine bilgisi yoktur
            )
            
            # Analiz sonuçlarını cihaz bilgilerine ekle
            detailed_device = self.enhance_device_with_analysis_results(detailed_device)
            
            # Cihazı listede güncelle
            self.devices[device_index] = detailed_device
            
            # JSON'a kaydet
            self.save_to_json()
            
            if progress_callback:
                progress_callback(f"Detaylı analiz tamamlandı: {ip_address}")
                
        except Exception as e:
            error_msg = f"Detaylı analiz hatası {ip_address}: {e}"
            print(error_msg)
            if progress_callback:
                progress_callback(error_msg)

if __name__ == "__main__":
    # Test amaçlı
    scanner = LANScanner()
    print("LAN taraması başlıyor...")
    devices = scanner.scan_network()
    
    print(f"\n{len(devices)} cihaz bulundu:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, "
              f"Hostname: {device['hostname']}, Vendor: {device['vendor']}, "
              f"Tip: {device['device_type']}")
        if device['open_ports']:
            ports = ', '.join([f"{p['port']}/{p['service']}" for p in device['open_ports']])
            print(f"  Açık portlar: {ports}")
    
    # JSON'a kaydet
    scanner.save_to_json()
    print("\nBilgiler lan_devices.json dosyasına kaydedildi.")
