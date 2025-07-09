#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Akıllı Cihaz Tanımlama ve İsimlendirme Sistemi
Smart Device Identification and Naming System
"""

import re
import json
import hashlib
from datetime import datetime
from collections import defaultdict

class SmartDeviceIdentifier:
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.device_signatures = self.load_device_signatures()
        self.name_generators = self.load_name_generators()
        
        # OUI Manager'ı import et
        try:
            from oui_manager import OUIManager
            self.oui_manager = OUIManager()
        except ImportError:
            self.oui_manager = None
        
    def load_device_signatures(self):
        """Cihaz imzalarını yükle"""
        return {
            'router': {
                'hostname_patterns': [
                    r'.*router.*', r'.*gateway.*', r'.*gw.*', r'.*rt.*',
                    r'.*modem.*', r'.*dsl.*', r'.*fiber.*', r'.*adsl.*'
                ],
                'vendor_patterns': [
                    r'tp-?link.*', r'asus.*', r'netgear.*', r'linksys.*',
                    r'cisco.*', r'mikrotik.*', r'ubiquiti.*', r'dlink.*'
                ],
                'service_patterns': [
                    {'services': ['http', 'https'], 'ports': [80, 443]},
                    {'services': ['ssh', 'telnet'], 'ports': [22, 23]},
                    {'services': ['snmp'], 'ports': [161]}
                ],
                'web_signatures': [
                    r'router', r'gateway', r'administration', r'modem',
                    r'wireless', r'broadband', r'dsl', r'fiber'
                ]
            },
            'camera': {
                'hostname_patterns': [
                    r'.*cam.*', r'.*camera.*', r'.*ipcam.*', r'.*nvr.*',
                    r'.*dvr.*', r'.*cctv.*', r'.*surveillance.*'
                ],
                'vendor_patterns': [
                    r'hikvision.*', r'dahua.*', r'axis.*', r'foscam.*',
                    r'amcrest.*', r'reolink.*', r'wyze.*', r'ring.*'
                ],
                'service_patterns': [
                    {'services': ['rtsp'], 'ports': [554, 8554]},
                    {'services': ['http', 'https'], 'ports': [80, 443, 8080]}
                ],
                'web_signatures': [
                    r'camera', r'surveillance', r'video', r'streaming',
                    r'rtsp', r'nvr', r'dvr', r'security'
                ]
            },
            'printer': {
                'hostname_patterns': [
                    r'.*printer.*', r'.*print.*', r'.*mfp.*', r'.*scanner.*',
                    r'.*copier.*', r'.*canon.*', r'.*hp.*', r'.*epson.*'
                ],
                'vendor_patterns': [
                    r'canon.*', r'hp.*', r'epson.*', r'brother.*',
                    r'kyocera.*', r'ricoh.*', r'xerox.*', r'samsung.*'
                ],
                'service_patterns': [
                    {'services': ['ipp'], 'ports': [631]},
                    {'services': ['lpd'], 'ports': [515]},
                    {'services': ['http'], 'ports': [80, 9100]}
                ],
                'web_signatures': [
                    r'printer', r'print', r'scanner', r'copier',
                    r'cartridge', r'toner', r'paper', r'queue'
                ]
            },
            'nas': {
                'hostname_patterns': [
                    r'.*nas.*', r'.*storage.*', r'.*synology.*', r'.*qnap.*',
                    r'.*drobo.*', r'.*buffalo.*', r'.*wd.*', r'.*seagate.*'
                ],
                'vendor_patterns': [
                    r'synology.*', r'qnap.*', r'drobo.*', r'buffalo.*',
                    r'western.*digital.*', r'seagate.*', r'netgear.*'
                ],
                'service_patterns': [
                    {'services': ['smb', 'cifs'], 'ports': [445, 139]},
                    {'services': ['nfs'], 'ports': [2049]},
                    {'services': ['ftp'], 'ports': [21]},
                    {'services': ['http', 'https'], 'ports': [5000, 5001, 8080]}
                ],
                'web_signatures': [
                    r'nas', r'storage', r'diskstation', r'file.*server',
                    r'synology', r'qnap', r'share', r'volume'
                ]
            },
            'smart_tv': {
                'hostname_patterns': [
                    r'.*tv.*', r'.*smart.*tv.*', r'.*android.*tv.*',
                    r'.*roku.*', r'.*firetv.*', r'.*appletv.*'
                ],
                'vendor_patterns': [
                    r'samsung.*', r'lg.*', r'sony.*', r'toshiba.*',
                    r'philips.*', r'roku.*', r'amazon.*', r'apple.*'
                ],
                'service_patterns': [
                    {'services': ['http'], 'ports': [8008, 8080, 9080]},
                    {'services': ['upnp'], 'ports': [1900]}
                ],
                'web_signatures': [
                    r'smart.*tv', r'android.*tv', r'webos', r'tizen',
                    r'roku', r'fire.*tv', r'apple.*tv', r'chromecast'
                ]
            },
            'smartphone': {
                'hostname_patterns': [
                    r'.*phone.*', r'.*mobile.*', r'.*android.*', r'.*iphone.*',
                    r'.*samsung.*', r'.*huawei.*', r'.*xiaomi.*'
                ],
                'vendor_patterns': [
                    r'apple.*', r'samsung.*', r'huawei.*', r'xiaomi.*',
                    r'oppo.*', r'vivo.*', r'oneplus.*', r'google.*'
                ],
                'service_patterns': [
                    {'services': ['http'], 'ports': [8080, 5555]},
                    {'services': ['adb'], 'ports': [5555]}
                ],
                'web_signatures': [
                    r'mobile', r'android', r'ios', r'phone',
                    r'smartphone', r'cellular', r'wifi.*calling'
                ]
            },
            'gaming_console': {
                'hostname_patterns': [
                    r'.*xbox.*', r'.*playstation.*', r'.*ps[345].*',
                    r'.*nintendo.*', r'.*switch.*', r'.*wii.*'
                ],
                'vendor_patterns': [
                    r'microsoft.*', r'sony.*', r'nintendo.*'
                ],
                'service_patterns': [
                    {'services': ['http'], 'ports': [80, 443]},
                    {'services': ['xbox-live'], 'ports': [3074]},
                    {'services': ['psn'], 'ports': [80, 443, 9293]}
                ],
                'web_signatures': [
                    r'xbox', r'playstation', r'nintendo', r'gaming',
                    r'console', r'game.*system'
                ]
            },
            'iot_device': {
                'hostname_patterns': [
                    r'.*iot.*', r'.*smart.*', r'.*sensor.*', r'.*hub.*',
                    r'.*philips.*hue.*', r'.*echo.*', r'.*google.*home.*'
                ],
                'vendor_patterns': [
                    r'philips.*', r'amazon.*', r'google.*', r'belkin.*',
                    r'tp-?link.*kasa.*', r'wyze.*', r'ring.*'
                ],
                'service_patterns': [
                    {'services': ['http'], 'ports': [80, 8080]},
                    {'services': ['mqtt'], 'ports': [1883, 8883]}
                ],
                'web_signatures': [
                    r'smart.*home', r'iot', r'automation', r'sensor',
                    r'hub', r'bulb', r'switch', r'plug'
                ]
            },
            'air_conditioner': {
                'hostname_patterns': [
                    r'.*ac.*', r'.*aircon.*', r'.*hvac.*', r'.*climate.*',
                    r'.*cooling.*', r'.*heating.*', r'.*thermostat.*'
                ],
                'vendor_patterns': [
                    r'daikin.*', r'mitsubishi.*', r'lg.*', r'samsung.*',
                    r'carrier.*', r'trane.*', r'honeywell.*', r'nest.*'
                ],
                'service_patterns': [
                    {'services': ['http'], 'ports': [80, 8080, 443]},
                    {'services': ['modbus'], 'ports': [502]},
                    {'services': ['bacnet'], 'ports': [47808]}
                ],
                'web_signatures': [
                    r'air.*condition', r'hvac', r'climate', r'temperature',
                    r'cooling', r'heating', r'thermostat', r'energy.*save'
                ]
            },
            'apple_device': {
                'hostname_patterns': [
                    r'.*iphone.*', r'.*ipad.*', r'.*ipod.*', r'.*macbook.*',
                    r'.*imac.*', r'.*mac.*mini.*', r'.*apple.*tv.*'
                ],
                'vendor_patterns': [
                    r'apple.*', r'cupertino.*'
                ],
                'service_patterns': [
                    {'services': ['airplay'], 'ports': [7000, 7001]},
                    {'services': ['bonjour'], 'ports': [5353]},
                    {'services': ['ssh'], 'ports': [22]}
                ],
                'web_signatures': [
                    r'apple', r'ios', r'macos', r'safari', r'webkit',
                    r'airplay', r'airdrop', r'icloud'
                ]
            },
            'pet_device': {
                'hostname_patterns': [
                    r'.*pet.*', r'.*feeder.*', r'.*water.*fountain.*',
                    r'.*litter.*', r'.*pet.*cam.*', r'.*pet.*track.*'
                ],
                'vendor_patterns': [
                    r'petnet.*', r'sure.*petcare.*', r'whistle.*', r'fitbark.*',
                    r'petcube.*', r'furbo.*', r'petzi.*'
                ],
                'service_patterns': [
                    {'services': ['http'], 'ports': [80, 8080]},
                    {'services': ['rtsp'], 'ports': [554]}
                ],
                'web_signatures': [
                    r'pet', r'feeder', r'litter', r'fountain', r'tracking',
                    r'camera.*pet', r'pet.*care', r'animal'
                ]
            }
        }
    
    def load_name_generators(self):
        """İsim üretici şablonlarını yükle"""
        return {
            'router': {
                'patterns': [
                    '{vendor} {model} Router',
                    '{vendor} Gateway',
                    '{hostname} Router',
                    'Router-{location}',
                    'Gateway-{network}'
                ],
                'defaults': ['Main Router', 'Gateway', 'Home Router']
            },
            'camera': {
                'patterns': [
                    '{vendor} Camera',
                    '{location} Camera',
                    'IP Camera-{number}',
                    '{vendor} {model}',
                    'Security Camera-{location}'
                ],
                'defaults': ['IP Camera', 'Security Camera', 'Surveillance Camera']
            },
            'printer': {
                'patterns': [
                    '{vendor} {model}',
                    '{vendor} Printer',
                    '{location} Printer',
                    'Printer-{number}',
                    '{vendor} MFP'
                ],
                'defaults': ['Network Printer', 'Printer', 'MFP']
            },
            'nas': {
                'patterns': [
                    '{vendor} NAS',
                    '{vendor} {model}',
                    'NAS-{location}',
                    '{hostname} Storage',
                    'File Server-{location}'
                ],
                'defaults': ['Network Storage', 'NAS', 'File Server']
            },
            'smart_tv': {
                'patterns': [
                    '{vendor} Smart TV',
                    '{vendor} {model}',
                    '{location} TV',
                    'Smart TV-{location}',
                    '{vendor} Android TV'
                ],
                'defaults': ['Smart TV', 'Android TV', 'TV']
            },
            'smartphone': {
                'patterns': [
                    '{vendor} {model}',
                    '{user}\'s {vendor}',
                    '{vendor} Phone',
                    'Mobile-{user}',
                    '{vendor} {os}'
                ],
                'defaults': ['Smartphone', 'Mobile Device', 'Phone']
            },
            'gaming_console': {
                'patterns': [
                    '{vendor} {model}',
                    '{model} Console',
                    '{location} {model}',
                    'Gaming Console-{location}',
                    '{vendor} Gaming'
                ],
                'defaults': ['Gaming Console', 'Game System', 'Console']
            },
            'iot_device': {
                'patterns': [
                    '{vendor} {type}',
                    'Smart {type}',
                    '{location} {type}',
                    'IoT-{type}-{number}',
                    '{vendor} Smart Device'
                ],
                'defaults': ['Smart Device', 'IoT Device', 'Smart Home']
            },
            'air_conditioner': {
                'patterns': [
                    '{vendor} AC',
                    '{vendor} {model}',
                    '{location} AC',
                    'AC-{location}',
                    '{vendor} Climate Control'
                ],
                'defaults': ['Air Conditioner', 'AC Unit', 'Climate Control']
            },
            'apple_device': {
                'patterns': [
                    '{user}\'s {model}',
                    '{vendor} {model}',
                    'Apple {type}',
                    '{model}-{location}',
                    '{user} Apple Device'
                ],
                'defaults': ['Apple Device', 'iOS Device', 'macOS Device']
            },
            'pet_device': {
                'patterns': [
                    '{vendor} Pet {type}',
                    'Pet {type}',
                    '{location} Pet Device',
                    'Pet-{type}-{number}',
                    '{vendor} Pet Care'
                ],
                'defaults': ['Pet Device', 'Pet Feeder', 'Pet Camera']
            }
        }
    
    def identify_device_comprehensive(self, device_info, enhanced_info=None):
        """Kapsamlı cihaz tanımlama"""
        
        # Temel bilgiler
        ip = device_info.get('ip', '')
        mac = device_info.get('mac', '')
        hostname = device_info.get('hostname', '')
        vendor = device_info.get('vendor', '')
        open_ports = device_info.get('open_ports', [])
        
        # Gelişmiş bilgiler
        web_info = enhanced_info.get('web_info', {}) if enhanced_info else {}
        snmp_info = enhanced_info.get('snmp_info', {}) if enhanced_info else {}
        dns_info = enhanced_info.get('dns_info', {}) if enhanced_info else {}
        
        # Scoring system
        device_scores = defaultdict(int)
        device_details = defaultdict(dict)
        
        # Hostname analizi
        hostname_lower = hostname.lower() if hostname else ''
        for device_type, signatures in self.device_signatures.items():
            for pattern in signatures.get('hostname_patterns', []):
                if re.search(pattern, hostname_lower, re.IGNORECASE):
                    device_scores[device_type] += 10
                    device_details[device_type]['hostname_match'] = pattern
        
        # Vendor analizi - hem pattern hem de OUI database'den
        vendor_lower = vendor.lower() if vendor else ''
        for device_type, signatures in self.device_signatures.items():
            for pattern in signatures.get('vendor_patterns', []):
                if re.search(pattern, vendor_lower, re.IGNORECASE):
                    device_scores[device_type] += 8
                    device_details[device_type]['vendor_match'] = pattern
        
        # OUI Database'den vendor device type'larını kontrol et
        if self.oui_manager and mac:
            try:
                vendor_info = self.oui_manager.get_vendor_with_device_types(mac)
                possible_types = vendor_info.get('possible_device_types', [])
                
                for device_type in possible_types:
                    device_scores[device_type] += 12  # OUI database'den yüksek skor
                    device_details[device_type]['oui_match'] = vendor_info['vendor']
                    device_details[device_type]['oui_confidence'] = 'high'
                    
            except Exception as e:
                pass  # OUI lookup hatası sessizce yoksay
        
        # Port analizi
        port_numbers = []
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port_numbers.append(port_info.get('port', 0))
            else:
                port_numbers.append(port_info)
        
        for device_type, signatures in self.device_signatures.items():
            for service_pattern in signatures.get('service_patterns', []):
                matching_ports = set(port_numbers) & set(service_pattern.get('ports', []))
                if matching_ports:
                    device_scores[device_type] += len(matching_ports) * 5
                    device_details[device_type]['port_matches'] = list(matching_ports)
        
        # Web içerik analizi
        web_content = ''
        for protocol in ['http', 'https']:
            if protocol in web_info:
                title = web_info[protocol].get('title', '')
                server = web_info[protocol].get('server', '')
                web_content += f"{title} {server}".lower()
        
        if web_content:
            for device_type, signatures in self.device_signatures.items():
                for pattern in signatures.get('web_signatures', []):
                    if re.search(pattern, web_content, re.IGNORECASE):
                        device_scores[device_type] += 6
                        device_details[device_type]['web_match'] = pattern
        
        # SNMP bilgisi analizi
        if snmp_info.get('system_description'):
            snmp_desc = snmp_info['system_description'].lower()
            for device_type, signatures in self.device_signatures.items():
                for pattern in signatures.get('vendor_patterns', []):
                    if re.search(pattern, snmp_desc, re.IGNORECASE):
                        device_scores[device_type] += 7
                        device_details[device_type]['snmp_match'] = pattern
        
        # En yüksek skoru alan cihaz tipini seç
        if device_scores:
            best_device_type = max(device_scores, key=device_scores.get)
            confidence = min(device_scores[best_device_type] / 20.0, 1.0)  # 0-1 arası güven skoru
            
            return {
                'device_type': best_device_type,
                'confidence': confidence,
                'scores': dict(device_scores),
                'details': dict(device_details),
                'model_info': self.extract_model_info(device_info, enhanced_info),
                'system_info': self.extract_system_info(device_info, enhanced_info)
            }
        
        return {
            'device_type': 'unknown',
            'confidence': 0.0,
            'scores': {},
            'details': {},
            'model_info': {},
            'system_info': {}
        }
    
    def analyze_enhanced_info_for_device_type(self, enhanced_info):
        """Enhanced analysis sonuçlarından device type çıkarma"""
        device_type_indicators = {}
        
        if not enhanced_info:
            return device_type_indicators
        
        try:
            # Raspberry Pi analizi
            raspberry_info = enhanced_info.get('raspberry_pi_analysis', {})
            if raspberry_info.get('raspberry_pi_probability', 0) > 0.5:
                device_type_indicators['computer'] = raspberry_info.get('raspberry_pi_probability', 0)
                device_type_indicators['iot_device'] = raspberry_info.get('raspberry_pi_probability', 0) * 0.8
            
            # System identification
            system_id = enhanced_info.get('system_identification', {})
            if system_id:
                os_info = system_id.get('os_details', {})
                hardware = system_id.get('hardware_info', {})
                
                # Linux sistemler genellikle server/router/iot
                if 'linux' in str(os_info).lower():
                    device_type_indicators['computer'] = 0.6
                    device_type_indicators['iot_device'] = 0.4
                
                # Windows sistemler
                if 'windows' in str(os_info).lower():
                    device_type_indicators['computer'] = 0.8
                    device_type_indicators['laptop'] = 0.6
            
            # Web servis analizi
            web_services = enhanced_info.get('web_services', {})
            for port, service_info in web_services.items():
                title = service_info.get('title', '').lower()
                
                # Router/Admin interface
                if any(keyword in title for keyword in ['router', 'admin', 'management', 'configuration']):
                    device_type_indicators['router'] = 0.9
                
                # IP Camera
                if any(keyword in title for keyword in ['camera', 'webcam', 'surveillance', 'ipcam']):
                    device_type_indicators['camera'] = 0.9
                
                # Printer
                if any(keyword in title for keyword in ['printer', 'print', 'cups']):
                    device_type_indicators['printer'] = 0.9
                
                # NAS
                if any(keyword in title for keyword in ['nas', 'storage', 'synology', 'qnap']):
                    device_type_indicators['nas'] = 0.9
                
                # Smart TV/Media
                if any(keyword in title for keyword in ['tv', 'media', 'streaming', 'roku']):
                    device_type_indicators['smart_tv'] = 0.8
            
            # Network services analizi
            network_services = enhanced_info.get('network_services', {})
            if network_services:
                # SSH genellikle server/linux cihazlar
                if 'ssh' in network_services:
                    device_type_indicators['computer'] = 0.7
                
                # SNMP genellikle router/printer/network cihazlar
                if 'snmp' in network_services:
                    device_type_indicators['router'] = 0.6
                    device_type_indicators['printer'] = 0.4
                
                # HTTP/HTTPS
                if 'http' in network_services or 'https' in network_services:
                    device_type_indicators['computer'] = 0.4
                    device_type_indicators['camera'] = 0.3
                    device_type_indicators['router'] = 0.3
            
            # IoT analysis
            iot_analysis = enhanced_info.get('iot_analysis', {})
            if iot_analysis:
                iot_score = iot_analysis.get('iot_probability', 0)
                if iot_score > 0.5:
                    device_type_indicators['iot_device'] = iot_score
                    device_type_indicators['sensor'] = iot_score * 0.6
            
        except Exception as e:
            print(f"Enhanced info analysis error: {e}")
        
        return device_type_indicators
    
    def identify_device_with_enhanced_analysis(self, device_info, enhanced_info=None):
        """Enhanced analysis sonuçlarını da dahil eden gelişmiş cihaz tanımlama"""
        
        # Önce normal tanımlama yap
        basic_result = self.identify_device_comprehensive(device_info, enhanced_info)
        
        # Enhanced analysis'ten device type indicators al
        enhanced_indicators = self.analyze_enhanced_info_for_device_type(enhanced_info)
        
        # Skorları birleştir
        combined_scores = basic_result['scores'].copy()
        
        for device_type, score in enhanced_indicators.items():
            # Enhanced analysis'ten gelen skorları da ekle (1-10 arası normalize et)
            enhanced_score = int(score * 10)
            combined_scores[device_type] = combined_scores.get(device_type, 0) + enhanced_score
        
        # En yüksek skoru al
        if combined_scores:
            best_device_type = max(combined_scores, key=combined_scores.get)
            
            # Güven skoru hesapla
            max_score = combined_scores[best_device_type]
            total_possible = 30  # Maksimum skor (hostname:10 + vendor:8 + oui:12)
            confidence = min(max_score / total_possible, 1.0)
            
            # Eğer enhanced analysis'ten geliyorsa güveni artır
            if best_device_type in enhanced_indicators:
                confidence = min(confidence + 0.2, 1.0)
            
            return {
                'device_type': best_device_type,
                'confidence': confidence,
                'scores': combined_scores,
                'details': basic_result['details'],
                'enhanced_indicators': enhanced_indicators,
                'model_info': basic_result['model_info'],
                'system_info': basic_result['system_info']
            }
        
        return basic_result
    
    def extract_model_info(self, device_info, enhanced_info=None):
        """Model ve üretici bilgilerini çıkarma"""
        model_info = {}
        
        hostname = device_info.get('hostname', '')
        vendor = device_info.get('vendor', '')
        
        # Hostname'den model çıkarma
        if hostname:
            # Model numarası pattern'leri
            model_patterns = [
                r'([A-Z]{1,2}-?[A-Z0-9]{3,10})',  # RT-AC68U, WR841N gibi
                r'([A-Z]+\d+[A-Z]*)',  # AC1200, N300 gibi
                r'(\d+[A-Z]+)',  # 1200AC gibi
            ]
            
            for pattern in model_patterns:
                match = re.search(pattern, hostname, re.IGNORECASE)
                if match:
                    model_info['model'] = match.group(1)
                    break
        
        # SNMP'den sistem bilgisi
        if enhanced_info and 'snmp_info' in enhanced_info:
            snmp_info = enhanced_info['snmp_info']
            if 'system_description' in snmp_info:
                desc = snmp_info['system_description']
                model_info['system_description'] = desc
                
                # Description'dan model çıkarma
                desc_patterns = [
                    r'Model:\s*([A-Z0-9\-]+)',
                    r'Hardware:\s*([A-Z0-9\-]+)',
                    r'Device:\s*([A-Z0-9\-]+)'
                ]
                
                for pattern in desc_patterns:
                    match = re.search(pattern, desc, re.IGNORECASE)
                    if match:
                        model_info['model'] = match.group(1)
                        break
        
        # Web title'dan model çıkarma
        if enhanced_info and 'web_info' in enhanced_info:
            web_info = enhanced_info['web_info']
            for protocol in ['http', 'https']:
                if protocol in web_info and 'title' in web_info[protocol]:
                    title = web_info[protocol]['title']
                    if title:
                        model_info['web_title'] = title
                        
                        # Title'dan model çıkarma
                        title_patterns = [
                            r'([A-Z]{1,2}-?[A-Z0-9]{3,10})',
                            r'Model\s+([A-Z0-9\-]+)',
                            r'([A-Z0-9\-]+)\s+Router'
                        ]
                        
                        for pattern in title_patterns:
                            match = re.search(pattern, title, re.IGNORECASE)
                            if match:
                                model_info['model'] = match.group(1)
                                break
        
        return model_info
    
    def extract_system_info(self, device_info, enhanced_info=None):
        """Sistem bilgilerini çıkarma"""
        system_info = {}
        
        if enhanced_info:
            # OS bilgisi
            if 'ping_analysis' in enhanced_info:
                ping_info = enhanced_info['ping_analysis']
                if 'estimated_os' in ping_info:
                    system_info['os'] = ping_info['estimated_os']
                if 'ttl' in ping_info:
                    system_info['ttl'] = ping_info['ttl']
            
            # SNMP sistem bilgisi
            if 'snmp_info' in enhanced_info:
                snmp_info = enhanced_info['snmp_info']
                if 'system_name' in snmp_info:
                    system_info['system_name'] = snmp_info['system_name']
                if 'system_uptime' in snmp_info:
                    system_info['uptime'] = snmp_info['system_uptime']
            
            # DNS bilgisi
            if 'dns_info' in enhanced_info:
                dns_info = enhanced_info['dns_info']
                if 'ptr_records' in dns_info and dns_info['ptr_records']:
                    system_info['reverse_dns'] = dns_info['ptr_records'][0]
            
            # SSH bilgisi
            if 'ssh_info' in enhanced_info:
                ssh_info = enhanced_info['ssh_info']
                if 'banner' in ssh_info:
                    system_info['ssh_banner'] = ssh_info['banner']
                if 'openssh_version' in ssh_info:
                    system_info['ssh_version'] = ssh_info['openssh_version']
        
        return system_info
    
    def generate_smart_alias(self, device_info, identification_result, enhanced_info=None):
        """Akıllı alias oluşturma"""
        device_type = identification_result.get('device_type', 'unknown')
        model_info = identification_result.get('model_info', {})
        system_info = identification_result.get('system_info', {})
        
        # Mevcut alias varsa koru
        if device_info.get('alias'):
            return device_info['alias']
        
        # Name generator pattern'leri
        name_generator = self.name_generators.get(device_type, {})
        patterns = name_generator.get('patterns', [])
        defaults = name_generator.get('defaults', ['Unknown Device'])
        
        # Değişken değerleri
        variables = {
            'vendor': device_info.get('vendor', ''),
            'model': model_info.get('model', ''),
            'hostname': device_info.get('hostname', ''),
            'ip': device_info.get('ip', ''),
            'location': self.guess_location(device_info),
            'network': self.guess_network_name(device_info),
            'number': self.generate_device_number(device_info),
            'user': self.guess_user_name(device_info),
            'type': device_type.replace('_', ' ').title(),
            'os': system_info.get('os', '')
        }
        
        # Pattern'leri dene
        for pattern in patterns:
            try:
                # Tüm değişkenlerin dolduğunu kontrol et
                test_name = pattern.format(**variables)
                if not re.search(r'\{.*\}', test_name):  # Doldurulmamış değişken yok
                    # Boş değerler varsa temizle
                    clean_name = re.sub(r'\s+', ' ', test_name).strip()
                    if clean_name and not clean_name.startswith(' ') and not clean_name.endswith(' '):
                        return clean_name
            except KeyError:
                continue
        
        # Pattern çalışmazsa default'u kullan
        vendor = variables['vendor']
        model = variables['model']
        
        if vendor and model:
            return f"{vendor} {model}"
        elif vendor:
            return f"{vendor} {defaults[0]}"
        elif model:
            return f"{model} {defaults[0]}"
        else:
            return defaults[0]
    
    def guess_location(self, device_info):
        """Konumu tahmin etme"""
        ip = device_info.get('ip', '')
        hostname = device_info.get('hostname', '')
        
        # Hostname'den konum ipuçları
        location_patterns = {
            'living': ['living', 'salon', 'oturma'],
            'kitchen': ['kitchen', 'mutfak'],
            'bedroom': ['bedroom', 'yatak', 'room'],
            'office': ['office', 'ofis', 'work'],
            'garage': ['garage', 'garaj'],
            'basement': ['basement', 'bodrum'],
            'upstairs': ['upstairs', 'üst'],
            'downstairs': ['downstairs', 'alt']
        }
        
        hostname_lower = hostname.lower() if hostname else ''
        for location, patterns in location_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return location.title()
        
        # IP'den konum tahmini (subnet bazlı)
        if ip:
            last_octet = ip.split('.')[-1]
            if last_octet.isdigit():
                octet_num = int(last_octet)
                if octet_num < 50:
                    return 'Main'
                elif octet_num < 100:
                    return 'Second'
                elif octet_num < 150:
                    return 'Third'
                else:
                    return 'Fourth'
        
        return 'Home'
    
    def guess_network_name(self, device_info):
        """Ağ adını tahmin etme"""
        ip = device_info.get('ip', '')
        
        if ip:
            # Subnet bazlı ağ adı
            subnet = '.'.join(ip.split('.')[:-1])
            if subnet == '192.168.1':
                return 'Home'
            elif subnet == '192.168.0':
                return 'Guest'
            elif subnet == '10.0.0':
                return 'Office'
            elif subnet.startswith('172.'):
                return 'VPN'
            else:
                return 'Network'
        
        return 'LAN'
    
    def generate_device_number(self, device_info):
        """Cihaz numarası oluşturma"""
        ip = device_info.get('ip', '')
        mac = device_info.get('mac', '')
        
        if ip:
            last_octet = ip.split('.')[-1]
            if last_octet.isdigit():
                return last_octet
        
        if mac:
            # MAC'in son 2 karakterini kullan
            mac_clean = mac.replace(':', '').replace('-', '')
            if len(mac_clean) >= 2:
                return str(int(mac_clean[-2:], 16))
        
        return '1'
    
    def guess_user_name(self, device_info):
        """Kullanıcı adını tahmin etme"""
        hostname = device_info.get('hostname', '')
        
        if hostname:
            # Hostname'den kullanıcı adı çıkarma
            user_patterns = [
                r'([a-zA-Z]+)\'s',  # John's iPhone
                r'([a-zA-Z]+)-',    # John-iPhone
                r'^([a-zA-Z]+)',    # John iPhone
            ]
            
            for pattern in user_patterns:
                match = re.search(pattern, hostname, re.IGNORECASE)
                if match:
                    user = match.group(1)
                    if len(user) > 2 and user.lower() not in ['the', 'and', 'for']:
                        return user.title()
        
        return 'User'
    
    def update_device_icon(self, device_type, identification_result):
        """Cihaz tipine göre ikonu güncelle"""
        device_types = self.config_manager.load_device_types()
        
        if device_type in device_types:
            return device_types[device_type].get('icon', '❓')
        
        # Özel durumlar
        confidence = identification_result.get('confidence', 0)
        if confidence < 0.5:
            return '❓'  # Düşük güven
        
        # Fallback icon'lar
        fallback_icons = {
            'router': '🌐',
            'camera': '📹',
            'printer': '🖨️',
            'nas': '💾',
            'smart_tv': '📺',
            'smartphone': '📱',
            'gaming_console': '🎮',
            'iot_device': '🔗',
            'unknown': '❓'
        }
        
        return fallback_icons.get(device_type, '❓')
    
    def should_enable_smart_naming(self):
        """Smart naming özelliğinin aktif olup olmadığını kontrol et"""
        config = getattr(self.config_manager, 'config', {})
        return config.get('smart_naming', {}).get('enabled', False)
    
    def get_smart_naming_config(self):
        """Smart naming konfigürasyonunu al"""
        config = getattr(self.config_manager, 'config', {})
        return config.get('smart_naming', {
            'enabled': False,
            'auto_alias': True,
            'hostname_resolution': True,
            'advanced_scanning': True,
            'confidence_threshold': 0.5
        })