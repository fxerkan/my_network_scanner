#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gelişmiş Cihaz Tarayıcı - nmap haricinde ek bilgi toplama yöntemleri
Advanced Device Scanner - Additional information gathering methods beyond nmap
"""

import socket
import subprocess
import platform
import re
import json
import requests
import time
import threading
from datetime import datetime
from ipaddress import ip_address, ip_network
import dns.resolver
import dns.reversename
import psutil
# import netifaces  # Use network_utils instead for Docker compatibility
from network_utils import get_network_interfaces, get_default_gateway
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedDeviceScanner:
    def __init__(self):
        self.timeout = 5
        self.max_threads = 10
        self.system_os = platform.system()
        
    def get_enhanced_device_info(self, ip, mac, hostname, vendor, progress_callback=None):
        """Gelişmiş cihaz bilgileri toplama"""
        enhanced_info = {
            'basic_info': {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor
            },
            'network_info': {},
            'system_info': {},
            'services': {},
            'security_info': {},
            'additional_info': {}
        }
        
        # Detaylı logging için helper function
        def log_detailed_operation(operation, status="başlatılıyor", details=""):
            if progress_callback:
                message = f"{ip} -    🔬 {operation}: {status}"
                if details:
                    message += f" ({details})"
                progress_callback(message)
        
        # Network bilgileri
        log_detailed_operation("🌐 Network Analizi", "başlatılıyor", "subnet, gateway, interface")
        enhanced_info['network_info'] = self.get_network_info(ip)
        log_detailed_operation("🌐 Network Analizi", "tamamlandı")
        
        # DNS bilgileri
        log_detailed_operation("🔍 DNS Analizi", "başlatılıyor", "reverse DNS, TXT records")
        enhanced_info['dns_info'] = self.get_dns_info(ip, hostname)
        log_detailed_operation("🔍 DNS Analizi", "tamamlandı")
        
        # SSH bilgileri (port 22 açıksa)
        log_detailed_operation("🔐 SSH Banner Grab", "başlatılıyor")
        enhanced_info['ssh_info'] = self.get_ssh_info(ip)
        log_detailed_operation("🔐 SSH Banner Grab", "tamamlandı")
        
        # HTTP/HTTPS bilgileri
        log_detailed_operation("🌍 Web Analizi", "başlatılıyor", "HTTP/HTTPS, headers")
        enhanced_info['web_info'] = self.get_web_info(ip)
        log_detailed_operation("🌍 Web Analizi", "tamamlandı")
        
        # SNMP bilgileri
        log_detailed_operation("📡 SNMP Tarama", "başlatılıyor", "system info")
        enhanced_info['snmp_info'] = self.get_snmp_info(ip)
        log_detailed_operation("📡 SNMP Tarama", "tamamlandı")
        
        # SMB/NetBIOS bilgileri
        log_detailed_operation("📁 SMB/NetBIOS Tarama", "başlatılıyor", "shares, workgroup")
        enhanced_info['smb_info'] = self.get_smb_info(ip)
        log_detailed_operation("📁 SMB/NetBIOS Tarama", "tamamlandı")
        
        # UPnP bilgileri
        log_detailed_operation("🔌 UPnP Keşfi", "başlatılıyor")
        enhanced_info['upnp_info'] = self.get_upnp_info(ip)
        log_detailed_operation("🔌 UPnP Keşfi", "tamamlandı")
        
        # ARP table bilgileri
        log_detailed_operation("🗺 ARP Analizi", "başlatılıyor")
        enhanced_info['arp_info'] = self.get_arp_info(ip, mac)
        log_detailed_operation("🗺 ARP Analizi", "tamamlandı")
        
        # Ping analizi
        log_detailed_operation("🎧 Ping Analizi", "başlatılıyor", "latency, packet loss")
        enhanced_info['ping_analysis'] = self.get_ping_analysis(ip)
        log_detailed_operation("🎧 Ping Analizi", "tamamlandı")
        
        # Traceroute analizi
        log_detailed_operation("🗺 Traceroute Analizi", "başlatılıyor")
        enhanced_info['traceroute_analysis'] = self.get_traceroute_analysis(ip)
        log_detailed_operation("🗺 Traceroute Analizi", "tamamlandı")
        
        return enhanced_info
    
    def get_network_info(self, ip):
        """Ağ bilgileri toplama"""
        network_info = {}
        
        try:
            # Reverse DNS lookup
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
                network_info['reverse_dns'] = reverse_dns
            except:
                network_info['reverse_dns'] = None
            
            # Subnet bilgisi
            network_info['subnet'] = self.get_subnet_info(ip)
            
            # Gateway bilgisi
            network_info['gateway'] = self.get_gateway_info(ip)
            
            # Interface bilgisi
            network_info['interface'] = self.get_interface_info(ip)
            
        except Exception as e:
            network_info['error'] = str(e)
        
        return network_info
    
    def get_dns_info(self, ip, hostname):
        """DNS bilgileri toplama"""
        dns_info = {}
        
        try:
            # DNS kayıtları
            if hostname:
                dns_info['hostname'] = hostname
                
                # A kaydı
                try:
                    result = dns.resolver.resolve(hostname, 'A')
                    dns_info['a_records'] = [str(rdata) for rdata in result]
                except:
                    dns_info['a_records'] = []
                
                # AAAA kaydı
                try:
                    result = dns.resolver.resolve(hostname, 'AAAA')
                    dns_info['aaaa_records'] = [str(rdata) for rdata in result]
                except:
                    dns_info['aaaa_records'] = []
                
                # MX kaydı
                try:
                    result = dns.resolver.resolve(hostname, 'MX')
                    dns_info['mx_records'] = [str(rdata) for rdata in result]
                except:
                    dns_info['mx_records'] = []
                
                # TXT kaydı
                try:
                    result = dns.resolver.resolve(hostname, 'TXT')
                    dns_info['txt_records'] = [str(rdata) for rdata in result]
                except:
                    dns_info['txt_records'] = []
            
            # Reverse DNS
            try:
                reverse_name = dns.reversename.from_address(ip)
                result = dns.resolver.resolve(reverse_name, 'PTR')
                dns_info['ptr_records'] = [str(rdata) for rdata in result]
            except:
                dns_info['ptr_records'] = []
                
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info
    
    def get_ssh_info(self, ip):
        """SSH bilgileri toplama"""
        ssh_info = {}
        
        try:
            # SSH banner grabbing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if sock.connect_ex((ip, 22)) == 0:
                ssh_info['port_open'] = True
                try:
                    banner = sock.recv(1024).decode('utf-8').strip()
                    ssh_info['banner'] = banner
                    
                    # SSH versiyonu
                    if 'SSH-' in banner:
                        ssh_info['version'] = banner.split('\n')[0]
                    
                    # OpenSSH versiyonu
                    if 'OpenSSH' in banner:
                        match = re.search(r'OpenSSH_(\d+\.\d+)', banner)
                        if match:
                            ssh_info['openssh_version'] = match.group(1)
                    
                except:
                    pass
            else:
                ssh_info['port_open'] = False
            
            sock.close()
            
        except Exception as e:
            ssh_info['error'] = str(e)
        
        return ssh_info
    
    def get_web_info(self, ip):
        """HTTP/HTTPS bilgileri toplama"""
        web_info = {'http': {}, 'https': {}}
        
        # HTTP
        try:
            response = requests.get(f'http://{ip}', timeout=self.timeout, verify=False)
            web_info['http']['status_code'] = response.status_code
            web_info['http']['headers'] = dict(response.headers)
            web_info['http']['title'] = self.extract_title(response.text)
            web_info['http']['server'] = response.headers.get('Server', '')
            web_info['http']['powered_by'] = response.headers.get('X-Powered-By', '')
            
        except Exception as e:
            web_info['http']['error'] = str(e)
        
        # HTTPS
        try:
            response = requests.get(f'https://{ip}', timeout=self.timeout, verify=False)
            web_info['https']['status_code'] = response.status_code
            web_info['https']['headers'] = dict(response.headers)
            web_info['https']['title'] = self.extract_title(response.text)
            web_info['https']['server'] = response.headers.get('Server', '')
            web_info['https']['powered_by'] = response.headers.get('X-Powered-By', '')
            
        except Exception as e:
            web_info['https']['error'] = str(e)
        
        return web_info
    
    def get_snmp_info(self, ip):
        """SNMP bilgileri toplama"""
        snmp_info = {}
        
        try:
            # SNMP community strings to try
            communities = ['public', 'private', 'admin', 'default']
            
            for community in communities:
                try:
                    # System description
                    cmd = f'snmpwalk -v2c -c {community} {ip} 1.3.6.1.2.1.1.1.0'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                    
                    if result.returncode == 0 and result.stdout:
                        snmp_info['community'] = community
                        snmp_info['system_description'] = result.stdout.strip()
                        
                        # System name
                        cmd = f'snmpwalk -v2c -c {community} {ip} 1.3.6.1.2.1.1.5.0'
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                        if result.returncode == 0:
                            snmp_info['system_name'] = result.stdout.strip()
                        
                        # System uptime
                        cmd = f'snmpwalk -v2c -c {community} {ip} 1.3.6.1.2.1.1.3.0'
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                        if result.returncode == 0:
                            snmp_info['system_uptime'] = result.stdout.strip()
                        
                        break
                        
                except:
                    continue
                    
        except Exception as e:
            snmp_info['error'] = str(e)
        
        return snmp_info
    
    def get_smb_info(self, ip):
        """SMB/NetBIOS bilgileri toplama"""
        smb_info = {}
        
        try:
            # NetBIOS name
            try:
                cmd = f'nmblookup -A {ip}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                if result.returncode == 0:
                    smb_info['netbios_name'] = self.parse_netbios_output(result.stdout)
            except:
                pass
            
            # SMB version
            try:
                cmd = f'smbclient -L {ip} -N'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                if result.returncode == 0:
                    smb_info['smb_shares'] = self.parse_smb_shares(result.stdout)
            except:
                pass
            
            # Alternative SMB enumeration
            try:
                cmd = f'enum4linux -a {ip}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                if result.returncode == 0:
                    smb_info['enum4linux'] = self.parse_enum4linux_output(result.stdout)
            except:
                pass
                
        except Exception as e:
            smb_info['error'] = str(e)
        
        return smb_info
    
    def get_upnp_info(self, ip):
        """UPnP bilgileri toplama"""
        upnp_info = {}
        
        try:
            # UPnP discovery
            ssdp_request = (
                'M-SEARCH * HTTP/1.1\r\n'
                'HOST: 239.255.255.250:1900\r\n'
                'MAN: "ssdp:discover"\r\n'
                'ST: upnp:rootdevice\r\n'
                'MX: 3\r\n\r\n'
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send to specific IP if it's a UPnP device
            try:
                sock.sendto(ssdp_request.encode(), (ip, 1900))
                response, addr = sock.recvfrom(1024)
                upnp_info['response'] = response.decode()
                upnp_info['location'] = self.extract_upnp_location(response.decode())
            except:
                pass
            
            sock.close()
            
        except Exception as e:
            upnp_info['error'] = str(e)
        
        return upnp_info
    
    def get_arp_info(self, ip, mac):
        """ARP table bilgileri"""
        arp_info = {}
        
        try:
            # ARP table'dan bilgi al
            if self.system_os == 'Windows':
                cmd = 'arp -a'
            else:
                cmd = 'arp -a'
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                arp_info['arp_table'] = self.parse_arp_table(result.stdout, ip, mac)
                
        except Exception as e:
            arp_info['error'] = str(e)
        
        return arp_info
    
    def get_ping_analysis(self, ip):
        """Detaylı ping analizi"""
        ping_info = {}
        
        try:
            if self.system_os == 'Windows':
                cmd = f'ping -n 4 {ip}'
            else:
                cmd = f'ping -c 4 {ip}'
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout * 2)
            
            if result.returncode == 0:
                ping_info['output'] = result.stdout
                ping_info['statistics'] = self.parse_ping_statistics(result.stdout)
                ping_info['ttl'] = self.extract_ttl(result.stdout)
                ping_info['estimated_os'] = self.estimate_os_from_ttl(ping_info['ttl'])
                
        except Exception as e:
            ping_info['error'] = str(e)
        
        return ping_info
    
    def get_traceroute_analysis(self, ip):
        """Detaylı traceroute analizi"""
        traceroute_info = {}
        
        try:
            if self.system_os == 'Windows':
                cmd = f'tracert -h 10 {ip}'
            else:
                cmd = f'traceroute -m 10 {ip}'
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout * 3)
            
            if result.returncode == 0:
                traceroute_info['output'] = result.stdout
                traceroute_info['hops'] = self.parse_traceroute_hops(result.stdout)
                traceroute_info['path_analysis'] = self.analyze_network_path(result.stdout)
                
        except Exception as e:
            traceroute_info['error'] = str(e)
        
        return traceroute_info
    
    def get_wmi_info(self, ip):
        """WMI bilgileri (Windows için)"""
        wmi_info = {}
        
        try:
            # WMI query for Windows machines
            wmi_queries = [
                'SELECT * FROM Win32_ComputerSystem',
                'SELECT * FROM Win32_OperatingSystem',
                'SELECT * FROM Win32_Processor',
                'SELECT * FROM Win32_LogicalDisk',
                'SELECT * FROM Win32_NetworkAdapter',
                'SELECT * FROM Win32_Share'
            ]
            
            for query in wmi_queries:
                try:
                    cmd = f'wmic /node:{ip} /user:guest /password: "{query}"'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                    
                    if result.returncode == 0:
                        wmi_info[query] = result.stdout
                        
                except:
                    continue
                    
        except Exception as e:
            wmi_info['error'] = str(e)
        
        return wmi_info
    
    def get_ldap_info(self, ip):
        """LDAP bilgileri toplama"""
        ldap_info = {}
        
        try:
            # LDAP rootDSE query
            cmd = f'ldapsearch -x -h {ip} -s base -b "" objectclass=*'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                ldap_info['rootdse'] = result.stdout
                ldap_info['domain_info'] = self.parse_ldap_domain_info(result.stdout)
                
        except Exception as e:
            ldap_info['error'] = str(e)
        
        return ldap_info
    
    # Helper methods
    def extract_title(self, html):
        """HTML'den title çıkarma"""
        try:
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            return match.group(1) if match else ''
        except:
            return ''
    
    def parse_netbios_output(self, output):
        """NetBIOS çıktısını parse etme"""
        try:
            lines = output.split('\n')
            for line in lines:
                if '<00>' in line and 'UNIQUE' in line:
                    return line.split()[0]
        except:
            pass
        return None
    
    def parse_smb_shares(self, output):
        """SMB shares parse etme"""
        shares = []
        try:
            lines = output.split('\n')
            for line in lines:
                if 'Disk' in line or 'IPC' in line:
                    shares.append(line.strip())
        except:
            pass
        return shares
    
    def parse_enum4linux_output(self, output):
        """enum4linux çıktısını parse etme"""
        parsed = {}
        try:
            # Domain info
            if 'Domain Name:' in output:
                match = re.search(r'Domain Name: (.+)', output)
                if match:
                    parsed['domain'] = match.group(1).strip()
            
            # OS info
            if 'OS:' in output:
                match = re.search(r'OS: (.+)', output)
                if match:
                    parsed['os'] = match.group(1).strip()
                    
        except:
            pass
        return parsed
    
    def extract_upnp_location(self, response):
        """UPnP location URL çıkarma"""
        try:
            match = re.search(r'LOCATION: (.+)', response, re.IGNORECASE)
            return match.group(1).strip() if match else ''
        except:
            return ''
    
    def parse_arp_table(self, output, target_ip, target_mac):
        """ARP table parse etme"""
        parsed = {}
        try:
            lines = output.split('\n')
            for line in lines:
                if target_ip in line or target_mac.lower() in line.lower():
                    parsed['entry'] = line.strip()
                    break
        except:
            pass
        return parsed
    
    def parse_ping_statistics(self, output):
        """Ping istatistiklerini parse etme"""
        stats = {}
        try:
            # Packet loss
            loss_match = re.search(r'(\d+)% packet loss', output)
            if loss_match:
                stats['packet_loss'] = int(loss_match.group(1))
            
            # RTT statistics
            rtt_match = re.search(r'min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
            if rtt_match:
                stats['rtt'] = {
                    'min': float(rtt_match.group(1)),
                    'avg': float(rtt_match.group(2)),
                    'max': float(rtt_match.group(3)),
                    'mdev': float(rtt_match.group(4))
                }
        except:
            pass
        return stats
    
    def extract_ttl(self, output):
        """TTL değerini çıkarma"""
        try:
            match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
            return int(match.group(1)) if match else None
        except:
            return None
    
    def estimate_os_from_ttl(self, ttl):
        """TTL'den işletim sistemi tahmini"""
        if ttl is None:
            return 'Unknown'
        
        if ttl <= 64:
            return 'Linux/Unix'
        elif ttl <= 128:
            return 'Windows'
        elif ttl <= 255:
            return 'Network Device'
        else:
            return 'Unknown'
    
    def parse_traceroute_hops(self, output):
        """Traceroute hop'larını parse etme"""
        hops = []
        try:
            lines = output.split('\n')
            for line in lines:
                if re.match(r'^\s*\d+', line):
                    hops.append(line.strip())
        except:
            pass
        return hops
    
    def analyze_network_path(self, output):
        """Network path analizi"""
        analysis = {}
        try:
            hops = self.parse_traceroute_hops(output)
            analysis['hop_count'] = len(hops)
            analysis['path_type'] = 'local' if len(hops) <= 3 else 'remote'
        except:
            pass
        return analysis
    
    def parse_ldap_domain_info(self, output):
        """LDAP domain bilgileri parse etme"""
        domain_info = {}
        try:
            if 'defaultNamingContext:' in output:
                match = re.search(r'defaultNamingContext: (.+)', output)
                if match:
                    domain_info['domain'] = match.group(1).strip()
        except:
            pass
        return domain_info
    
    def get_subnet_info(self, ip):
        """Subnet bilgilerini alma"""
        try:
            # Local network interfaces kontrol et
            interfaces = get_network_interfaces()
            for interface_info in interfaces:
                network = ip_network(f"{interface_info['ip']}/{interface_info['netmask']}", strict=False)
                if ip_address(ip) in network:
                    return {
                        'network': str(network),
                        'interface': interface_info['name'],
                        'local_ip': interface_info['ip']
                    }
        except:
            pass
        return {}
    
    def get_gateway_info(self, ip):
        """Gateway bilgilerini alma"""
        try:
            return get_default_gateway()
        except:
            pass
        return None
    
    def get_interface_info(self, ip):
        """Interface bilgilerini alma"""
        try:
            interfaces = get_network_interfaces()
            for interface_info in interfaces:
                network = ip_network(f"{interface_info['ip']}/{interface_info['netmask']}", strict=False)
                if ip_address(ip) in network:
                    return interface_info['name']
        except:
            pass
        return None