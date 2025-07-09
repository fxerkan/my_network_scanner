#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gelişmiş Hostname Çözümleme Sistemi
Advanced Hostname Resolution System
"""

import socket
import subprocess
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address

class AdvancedHostnameResolver:
    def __init__(self, timeout=5, max_threads=10):
        self.timeout = timeout
        self.max_threads = max_threads
        self.cache = {}
        self.cache_timeout = 3600  # 1 saat cache
        
    def resolve_hostname_comprehensive(self, ip_address_str):
        """Kapsamlı hostname çözümleme"""
        
        # Cache kontrolü
        cache_key = f"hostname_{ip_address_str}"
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        hostname_info = {
            'ip': ip_address_str,
            'hostnames': [],
            'methods_used': [],
            'primary_hostname': None,
            'domain_info': {},
            'netbios_name': None,
            'rdns_info': {},
            'mdns_info': {},
            'alternative_names': []
        }
        
        # Çeşitli yöntemlerle hostname çözümleme
        methods = [
            ('standard_dns', self._resolve_standard_dns),
            ('reverse_dns', self._resolve_reverse_dns),
            ('netbios', self._resolve_netbios),
            ('mdns', self._resolve_mdns),
            ('smb_enumeration', self._resolve_smb_hostname),
            ('snmp_hostname', self._resolve_snmp_hostname),
            ('rdn_analysis', self._resolve_rdn_analysis),
            ('lazy_text_analysis', self._lazy_text_hostname_analysis)
        ]
        
        # Paralel çözümleme
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_method = {
                executor.submit(method_func, ip_address_str): method_name 
                for method_name, method_func in methods
            }
            
            try:
                for future in as_completed(future_to_method, timeout=self.timeout * 2):
                    method_name = future_to_method[future]
                    try:
                        result = future.result(timeout=self.timeout)
                        if result:
                            hostname_info['methods_used'].append(method_name)
                            self._merge_hostname_result(hostname_info, result, method_name)
                    except Exception as e:
                        # Sessizce devam et, tüm yöntemlerin başarısız olması normal
                        pass
            except Exception as e:
                # Futures timeout hatası - kalan future'ları temizle
                for future in future_to_method:
                    if not future.done():
                        future.cancel()
                print(f"Gelişmiş hostname çözümleme hatası {ip_address_str}: futures timeout")
        
        # En iyi hostname'i seç
        hostname_info['primary_hostname'] = self._select_best_hostname(hostname_info)
        
        # Cache'e kaydet
        self._cache_result(cache_key, hostname_info)
        
        return hostname_info
    
    def _resolve_standard_dns(self, ip_address_str):
        """Standart DNS çözümleme"""
        try:
            hostname = socket.gethostbyaddr(ip_address_str)[0]
            return {
                'hostname': hostname,
                'method': 'standard_dns',
                'confidence': 0.9
            }
        except Exception:
            return None
    
    def _resolve_reverse_dns(self, ip_address_str):
        """Reverse DNS çözümleme"""
        try:
            # nslookup kullanarak
            result = subprocess.run(
                ['nslookup', ip_address_str], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                hostname = self._parse_nslookup_output(result.stdout)
                if hostname:
                    return {
                        'hostname': hostname,
                        'method': 'reverse_dns',
                        'confidence': 0.8,
                        'raw_output': result.stdout
                    }
        except Exception:
            pass
        
        return None
    
    def _resolve_netbios(self, ip_address_str):
        """NetBIOS name çözümleme"""
        try:
            # nmblookup kullanarak
            result = subprocess.run(
                ['nmblookup', '-A', ip_address_str], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                netbios_info = self._parse_nmblookup_output(result.stdout)
                if netbios_info:
                    return {
                        'hostname': netbios_info.get('computer_name'),
                        'netbios_name': netbios_info.get('computer_name'),
                        'workgroup': netbios_info.get('workgroup'),
                        'method': 'netbios',
                        'confidence': 0.7,
                        'raw_output': result.stdout
                    }
        except Exception:
            pass
        
        return None
    
    def _resolve_mdns(self, ip_address_str):
        """mDNS (Bonjour/Avahi) çözümleme"""
        try:
            # avahi-resolve kullanarak
            result = subprocess.run(
                ['avahi-resolve', '-a', ip_address_str], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                hostname = self._parse_avahi_output(result.stdout)
                if hostname:
                    return {
                        'hostname': hostname,
                        'method': 'mdns',
                        'confidence': 0.6,
                        'raw_output': result.stdout
                    }
        except Exception:
            pass
        
        # Alternative: DNS-SD query
        try:
            result = subprocess.run(
                ['dns-sd', '-q', ip_address_str, 'PTR'], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                hostname = self._parse_dns_sd_output(result.stdout)
                if hostname:
                    return {
                        'hostname': hostname,
                        'method': 'mdns_dns_sd',
                        'confidence': 0.6,
                        'raw_output': result.stdout
                    }
        except Exception:
            pass
        
        return None
    
    def _resolve_smb_hostname(self, ip_address_str):
        """SMB hostname çözümleme"""
        try:
            # smbclient ile hostname bilgisi alma
            result = subprocess.run(
                ['smbclient', '-L', ip_address_str, '-N'], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                smb_info = self._parse_smbclient_output(result.stdout)
                if smb_info:
                    return {
                        'hostname': smb_info.get('hostname'),
                        'domain': smb_info.get('domain'),
                        'os': smb_info.get('os'),
                        'method': 'smb',
                        'confidence': 0.7,
                        'raw_output': result.stdout
                    }
        except Exception:
            pass
        
        return None
    
    def _resolve_snmp_hostname(self, ip_address_str):
        """SNMP hostname çözümleme"""
        try:
            # SNMP sysName OID: 1.3.6.1.2.1.1.5.0
            communities = ['public', 'private', 'admin']
            
            for community in communities:
                try:
                    result = subprocess.run(
                        ['snmpget', '-v2c', '-c', community, ip_address_str, '1.3.6.1.2.1.1.5.0'], 
                        capture_output=True, 
                        text=True, 
                        timeout=self.timeout
                    )
                    
                    if result.returncode == 0:
                        hostname = self._parse_snmp_output(result.stdout)
                        if hostname:
                            return {
                                'hostname': hostname,
                                'community': community,
                                'method': 'snmp',
                                'confidence': 0.8,
                                'raw_output': result.stdout
                            }
                except Exception:
                    continue
        except Exception:
            pass
        
        return None
    
    def _resolve_rdn_analysis(self, ip_address_str):
        """Relative Distinguished Name (RDN) analizi"""
        try:
            # DNS kayıtlarından RDN bilgisi çıkarma
            import dns.resolver
            import dns.reversename
            
            # PTR kaydı al
            reverse_name = dns.reversename.from_address(ip_address_str)
            result = dns.resolver.resolve(reverse_name, 'PTR')
            
            rdn_info = {}
            for rdata in result:
                ptr_name = str(rdata)
                rdn_analysis = self._analyze_rdn_structure(ptr_name)
                if rdn_analysis:
                    rdn_info.update(rdn_analysis)
            
            if rdn_info:
                return {
                    'hostname': rdn_info.get('hostname'),
                    'domain': rdn_info.get('domain'),
                    'organization': rdn_info.get('organization'),
                    'location': rdn_info.get('location'),
                    'method': 'rdn_analysis',
                    'confidence': 0.6,
                    'rdn_structure': rdn_info
                }
        except Exception:
            pass
        
        return None
    
    def _lazy_text_hostname_analysis(self, ip_address_str):
        """Lazy text algoritması ile hostname analizi"""
        try:
            # Çeşitli kaynaklardan metin toplama
            text_sources = []
            
            # HTTP başlıkları
            try:
                import requests
                response = requests.get(f'http://{ip_address_str}', timeout=3)
                text_sources.append(response.text[:1000])  # İlk 1000 karakter
                
                # Server header
                server_header = response.headers.get('Server', '')
                if server_header:
                    text_sources.append(server_header)
            except Exception:
                pass
            
            # HTTPS sertifikası
            try:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip_address_str, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=ip_address_str) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            subject = cert.get('subject', ())
                            for rdn in subject:
                                for name, value in rdn:
                                    if name == 'commonName':
                                        text_sources.append(value)
            except Exception:
                pass
            
            # Banner grabbing
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 993, 995]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    if sock.connect_ex((ip_address_str, port)) == 0:
                        banner = sock.recv(512).decode('utf-8', errors='ignore')
                        if banner:
                            text_sources.append(banner)
                    sock.close()
                except Exception:
                    pass
            
            # Metinlerden hostname çıkarma
            hostnames = []
            for text in text_sources:
                extracted_hostnames = self._extract_hostnames_from_text(text, ip_address_str)
                hostnames.extend(extracted_hostnames)
            
            if hostnames:
                # En iyi hostname'i seç (en sık geçen)
                hostname_counts = {}
                for hostname in hostnames:
                    hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
                
                best_hostname = max(hostname_counts, key=hostname_counts.get)
                
                return {
                    'hostname': best_hostname,
                    'alternative_hostnames': list(set(hostnames)),
                    'method': 'lazy_text_analysis',
                    'confidence': 0.4,
                    'text_sources': len(text_sources)
                }
        except Exception:
            pass
        
        return None
    
    def _analyze_rdn_structure(self, dn_string):
        """RDN yapısını analiz etme"""
        rdn_info = {}
        
        try:
            # DNS name'i parse et
            parts = dn_string.lower().rstrip('.').split('.')
            
            if len(parts) >= 2:
                rdn_info['hostname'] = parts[0]
                rdn_info['domain'] = '.'.join(parts[1:])
                
                # Özel pattern'ları ara
                patterns = {
                    'organization': [r'corp', r'company', r'inc', r'ltd', r'llc'],
                    'location': [r'ny', r'ca', r'tx', r'fl', r'office', r'branch'],
                    'function': [r'mail', r'web', r'ftp', r'dns', r'proxy', r'gateway']
                }
                
                full_name = dn_string.lower()
                for category, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if pattern in full_name:
                            if category not in rdn_info:
                                rdn_info[category] = []
                            rdn_info[category].append(pattern)
        except Exception:
            pass
        
        return rdn_info
    
    def _extract_hostnames_from_text(self, text, ip_address_str):
        """Metinden hostname'leri çıkarma"""
        hostnames = []
        
        try:
            # Hostname pattern'leri
            patterns = [
                r'hostname[:\s]+([a-zA-Z0-9\-\.]+)',
                r'computer[:\s]+([a-zA-Z0-9\-\.]+)',
                r'server[:\s]+([a-zA-Z0-9\-\.]+)',
                r'device[:\s]+([a-zA-Z0-9\-\.]+)',
                r'name[:\s]+([a-zA-Z0-9\-\.]+)',
                r'([a-zA-Z0-9\-]+\.local)',
                r'([a-zA-Z0-9\-]+\.lan)',
                r'([a-zA-Z0-9\-]{3,20})',  # Genel hostname pattern
            ]
            
            text_lower = text.lower()
            for pattern in patterns:
                matches = re.findall(pattern, text_lower, re.IGNORECASE)
                for match in matches:
                    if self._is_valid_hostname(match, ip_address_str):
                        hostnames.append(match)
        except Exception:
            pass
        
        return hostnames
    
    def _is_valid_hostname(self, hostname, ip_address_str):
        """Hostname'in geçerli olup olmadığını kontrol et"""
        try:
            # Çok kısa veya çok uzun
            if len(hostname) < 3 or len(hostname) > 63:
                return False
            
            # Sadece rakam
            if hostname.isdigit():
                return False
            
            # IP adresi formatı
            try:
                ip_address(hostname)
                return False  # Bu bir IP adresi
            except Exception:
                pass
            
            # Geçersiz karakterler
            if not re.match(r'^[a-zA-Z0-9\-\.]+$', hostname):
                return False
            
            # Başlangıç ve bitiş tire
            if hostname.startswith('-') or hostname.endswith('-'):
                return False
            
            # Aynı IP adresi
            if hostname == ip_address_str:
                return False
            
            return True
        except Exception:
            return False
    
    def _merge_hostname_result(self, hostname_info, result, method_name):
        """Hostname sonuçlarını birleştirme"""
        if not result:
            return
        
        hostname = result.get('hostname')
        if hostname:
            hostname_info['hostnames'].append({
                'hostname': hostname,
                'method': method_name,
                'confidence': result.get('confidence', 0.5),
                'details': result
            })
        
        # Özel alanları birleştir
        if method_name == 'netbios' and result.get('netbios_name'):
            hostname_info['netbios_name'] = result['netbios_name']
        
        if method_name == 'rdn_analysis' and result.get('rdn_structure'):
            hostname_info['rdns_info'] = result['rdn_structure']
        
        if method_name.startswith('mdns') and result.get('hostname'):
            hostname_info['mdns_info'][method_name] = result
        
        # Domain bilgisi
        domain = result.get('domain')
        if domain:
            hostname_info['domain_info'][method_name] = domain
        
        # Alternative names
        alt_names = result.get('alternative_hostnames', [])
        hostname_info['alternative_names'].extend(alt_names)
    
    def _select_best_hostname(self, hostname_info):
        """En iyi hostname'i seçme"""
        if not hostname_info['hostnames']:
            return None
        
        # Güven skorlarına göre sırala
        sorted_hostnames = sorted(
            hostname_info['hostnames'], 
            key=lambda x: x['confidence'], 
            reverse=True
        )
        
        # En yüksek güven skoru
        best_hostname = sorted_hostnames[0]['hostname']
        
        # Aynı hostname'in farklı yöntemlerle bulunması
        hostname_counts = {}
        for item in hostname_info['hostnames']:
            hostname = item['hostname']
            hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
        
        # En çok tekrar eden hostname varsa onu tercih et
        most_common = max(hostname_counts, key=hostname_counts.get)
        if hostname_counts[most_common] > 1:
            return most_common
        
        return best_hostname
    
    def _is_cache_valid(self, cache_key):
        """Cache'in geçerli olup olmadığını kontrol et"""
        if cache_key not in self.cache:
            return False
        
        cache_time = self.cache[cache_key]['timestamp']
        return (time.time() - cache_time) < self.cache_timeout
    
    def _cache_result(self, cache_key, data):
        """Sonucu cache'e kaydet"""
        self.cache[cache_key] = {
            'data': data,
            'timestamp': time.time()
        }
    
    # Parser methods
    def _parse_nslookup_output(self, output):
        """nslookup çıktısını parse etme"""
        try:
            lines = output.split('\n')
            for line in lines:
                if 'name =' in line.lower():
                    match = re.search(r'name = (.+)', line, re.IGNORECASE)
                    if match:
                        return match.group(1).strip().rstrip('.')
        except Exception:
            pass
        return None
    
    def _parse_nmblookup_output(self, output):
        """nmblookup çıktısını parse etme"""
        try:
            info = {}
            lines = output.split('\n')
            
            for line in lines:
                if '<00>' in line and 'UNIQUE' in line:
                    # Computer name
                    match = re.search(r'^\s*([^\s<]+)', line)
                    if match:
                        info['computer_name'] = match.group(1)
                elif '<1e>' in line and 'GROUP' in line:
                    # Workgroup
                    match = re.search(r'^\s*([^\s<]+)', line)
                    if match:
                        info['workgroup'] = match.group(1)
            
            return info if info else None
        except Exception:
            pass
        return None
    
    def _parse_avahi_output(self, output):
        """avahi-resolve çıktısını parse etme"""
        try:
            lines = output.split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].rstrip('.')
        except Exception:
            pass
        return None
    
    def _parse_dns_sd_output(self, output):
        """dns-sd çıktısını parse etme"""
        try:
            lines = output.split('\n')
            for line in lines:
                if 'PTR' in line:
                    match = re.search(r'PTR\s+(.+)', line)
                    if match:
                        return match.group(1).strip().rstrip('.')
        except Exception:
            pass
        return None
    
    def _parse_smbclient_output(self, output):
        """smbclient çıktısını parse etme"""
        try:
            info = {}
            lines = output.split('\n')
            
            for line in lines:
                if 'Domain=' in line:
                    match = re.search(r'Domain=\[([^\]]+)\]', line)
                    if match:
                        info['domain'] = match.group(1)
                elif 'OS=' in line:
                    match = re.search(r'OS=\[([^\]]+)\]', line)
                    if match:
                        info['os'] = match.group(1)
                elif 'Server=' in line:
                    match = re.search(r'Server=\[([^\]]+)\]', line)
                    if match:
                        info['hostname'] = match.group(1)
            
            return info if info else None
        except Exception:
            pass
        return None
    
    def _parse_snmp_output(self, output):
        """SNMP çıktısını parse etme"""
        try:
            match = re.search(r'STRING:\s*(.+)', output)
            if match:
                return match.group(1).strip().strip('"')
        except Exception:
            pass
        return None