#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN Scanner Configuration Manager
"""

import json
import os
from datetime import datetime

class ConfigManager:
    def __init__(self):
        self.config_file = 'config/config.json'
        self.oui_file = 'config/oui_database.json'
        self.device_types_file = 'config/device_types.json'
        self.scan_history_file = 'data/scan_history.json'
        
        self.default_config = {
            'scan_settings': {
                'ip_ranges': ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24'],
                'default_ip_range': '192.168.1.0/24',
                'timeout': 3,
                'max_threads': 50,
                'include_offline': False
            },
            'port_settings': {
                'default_ports': [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443],
                'device_specific_ports': {
                    'Router': [22, 23, 80, 443, 8080],
                    'Camera': [80, 443, 554, 8080, 8443],
                    'IP Camera': [80, 443, 554, 8080, 8443],
                    'Printer': [80, 443, 515, 631, 9100],
                    'Smart TV': [80, 8008, 8080, 9080],
                    'Gaming Console': [80, 443, 1935, 3478, 3479, 3480],
                    'Game Console': [80, 443, 1935, 3074, 53, 88],
                    'Air Conditioner': [80, 443, 502, 47808],
                    'Apple Device': [22, 80, 443, 5353, 7000, 7001],
                    'Pet Camera': [80, 443, 554, 8080],
                    'Pet Feeder': [80, 443, 8080],
                    'Pet Tracker': [80, 443],
                    'NAS': [21, 22, 80, 139, 443, 445, 548, 5000, 5001]
                }
            },
            'detection_rules': {
                'hostname_patterns': [
                    {'pattern': r'.*router.*|.*gateway.*|.*modem.*', 'type': 'Router'},
                    {'pattern': r'.*camera.*|.*cam.*|.*ipcam.*', 'type': 'IP Camera'},
                    {'pattern': r'.*printer.*|.*print.*', 'type': 'Printer'},
                    {'pattern': r'.*tv.*|.*smart.*tv.*', 'type': 'Smart TV'},
                    {'pattern': r'.*nas.*|.*storage.*', 'type': 'NAS'},
                    {'pattern': r'.*phone.*|.*mobile.*', 'type': 'Smartphone'},
                    {'pattern': r'.*iphone.*|.*ipad.*|.*macbook.*|.*imac.*', 'type': 'Apple Device'},
                    {'pattern': r'.*xbox.*|.*playstation.*|.*ps[345].*|.*nintendo.*', 'type': 'Game Console'},
                    {'pattern': r'.*ac.*|.*aircon.*|.*hvac.*|.*climate.*', 'type': 'Air Conditioner'},
                    {'pattern': r'.*pet.*|.*feeder.*|.*litter.*', 'type': 'Pet Camera'},
                    {'pattern': r'.*tablet.*|.*ipad.*', 'type': 'Tablet'},
                    {'pattern': r'.*laptop.*|.*notebook.*', 'type': 'Laptop'},
                    {'pattern': r'.*desktop.*|.*pc.*', 'type': 'Desktop'},
                    {'pattern': r'.*xbox.*|.*playstation.*|.*nintendo.*', 'type': 'Gaming Console'}
                ],
                'vendor_patterns': [
                    {'pattern': r'Apple.*', 'type': 'Smartphone', 'conditions': ['iphone', 'ios']},
                    {'pattern': r'Apple.*', 'type': 'Tablet', 'conditions': ['ipad']},
                    {'pattern': r'Apple.*', 'type': 'Laptop', 'conditions': ['macbook', 'mac']},
                    {'pattern': r'Samsung.*', 'type': 'Smartphone', 'conditions': ['galaxy', 'android']},
                    {'pattern': r'Samsung.*', 'type': 'Smart TV', 'conditions': ['tv', 'display']},
                    {'pattern': r'LG.*', 'type': 'Smart TV', 'conditions': ['tv', 'display']},
                    {'pattern': r'Sony.*', 'type': 'Gaming Console', 'conditions': ['playstation']},
                    {'pattern': r'Microsoft.*', 'type': 'Gaming Console', 'conditions': ['xbox']},
                    {'pattern': r'TP-Link.*|TpLink.*', 'type': 'Router'},
                    {'pattern': r'Asus.*', 'type': 'Router'},
                    {'pattern': r'Netgear.*', 'type': 'Router'},
                    {'pattern': r'Dyson.*', 'type': 'Smart Home'},
                    {'pattern': r'Xiaomi.*', 'type': 'Smartphone'},
                    {'pattern': r'Petkit.*', 'type': 'Pet Feeder'},
                    {'pattern': r'Apple.*', 'type': 'Apple Device'},
                    {'pattern': r'Daikin.*', 'type': 'Air Conditioner'},
                    {'pattern': r'Mitsubishi.*Electric.*', 'type': 'Air Conditioner'},
                    {'pattern': r'Sony.*', 'type': 'Gaming Console', 'condition': 'has_gaming_ports'},
                    {'pattern': r'Microsoft.*', 'type': 'Game Console', 'condition': 'has_gaming_ports'},
                    {'pattern': r'Nintendo.*', 'type': 'Game Console'}
                ]
            }
        }
        
        self.default_device_types = {
            'Unknown': {'icon': '❓', 'category': 'unknown'},
            'Router': {'icon': '🌐', 'category': 'network'},
            'Switch': {'icon': '🔀', 'category': 'network'},
            'Access Point': {'icon': '📡', 'category': 'network'},
            'Modem': {'icon': '📶', 'category': 'network'},
            'Smartphone': {'icon': '📱', 'category': 'mobile'},
            'Tablet': {'icon': '📃', 'category': 'mobile'},
            'Laptop': {'icon': '💻', 'category': 'computer'},
            'Desktop': {'icon': '🖥️', 'category': 'computer'},
            'Server': {'icon': '🖧', 'category': 'computer'},
            'Printer': {'icon': '🖨️', 'category': 'peripheral'},
            'Scanner': {'icon': '📷', 'category': 'peripheral'},
            'IP Camera': {'icon': '📹', 'category': 'security'},
            'Security System': {'icon': '🔒', 'category': 'security'},
            'Smart TV': {'icon': '📺', 'category': 'entertainment'},
            'Streaming Device': {'icon': '📡', 'category': 'entertainment'},
            'Gaming Console': {'icon': '🎮', 'category': 'entertainment'},
            'Smart Speaker': {'icon': '🔊', 'category': 'smart_home'},
            'Smart Light': {'icon': '💡', 'category': 'smart_home'},
            'Smart Thermostat': {'icon': '🌡️', 'category': 'smart_home'},
            'Smart Lock': {'icon': '🔐', 'category': 'smart_home'},
            'Air Conditioner': {'icon': '❄️', 'category': 'appliance'},
            'Washing Machine': {'icon': '🧺', 'category': 'appliance'},
            'Refrigerator': {'icon': '🧊', 'category': 'appliance'},
            'Dishwasher': {'icon': '🍽️', 'category': 'appliance'},
            'Vacuum Cleaner': {'icon': '🧹', 'category': 'appliance'},
            'Pet Feeder': {'icon': '🐕', 'category': 'pet'},
            'Pet Water Fountain': {'icon': '💧', 'category': 'pet'},
            'Apple Device': {'icon': '🍎', 'category': 'mobile'},
            'Game Console': {'icon': '🕹️', 'category': 'entertainment'},
            'Pet Camera': {'icon': '🐕', 'category': 'smart_home'},
            'Pet Tracker': {'icon': '🐾', 'category': 'smart_home'},
            'NAS': {'icon': '💾', 'category': 'storage'},
            'IoT Device': {'icon': '🔗', 'category': 'iot'},
            'Smart Home': {'icon': '🏠', 'category': 'smart_home'}
        }
        
        self.default_oui_database = {
            # Apple
            '001122': 'Apple', '00036D': 'Apple', '000393': 'Apple', '0003FF': 'Apple',
            '000A27': 'Apple', '000A95': 'Apple', '000D93': 'Apple', '0010FA': 'Apple',
            '001124': 'Apple', '0014A4': 'Apple', '0016CB': 'Apple', '0017F2': 'Apple',
            '0019E3': 'Apple', '001B63': 'Apple', '001EC2': 'Apple', '0021E9': 'Apple',
            '002241': 'Apple', '002332': 'Apple', '002436': 'Apple', '0025BC': 'Apple',
            '002608': 'Apple', '002713': 'Apple', '0050E4': 'Apple', '006171': 'Apple',
            '0078CA': 'Apple', '009148': 'Apple', '00A040': 'Apple', '04489A': 'Apple',
            '0452F3': 'Apple', '049F06': 'Apple', '04E536': 'Apple', '1499E2': 'Apple',
            '20A2E4': 'Apple', '28ED6A': 'Apple', '2C200B': 'Apple', '34159E': 'Apple',
            '38C986': 'Apple', '3C0754': 'Apple', '40A6D9': 'Apple', '442A60': 'Apple',
            '4860BC': 'Apple', '4C7C5F': 'Apple', '58B035': 'Apple', '5CF938': 'Apple',
            '609AC1': 'Apple', '64200C': 'Apple', '683E34': 'Apple', '6C3E6D': 'Apple',
            '70DEE2': 'Apple', '7073CB': 'Apple', '78A3E4': 'Apple', '8030DC': 'Apple',
            '8485CE': 'Apple', '8C5877': 'Apple', '9027E4': 'Apple', '94F901': 'Apple',
            '9803D8': 'Apple', '9C84BF': 'Apple', 'A45E60': 'Apple', 'A8667F': 'Apple',
            'A8FAD8': 'Apple', 'AC3613': 'Apple', 'B09FBA': 'Apple', 'B418D1': 'Apple',
            'BC9FEF': 'Apple', 'C0847A': 'Apple', 'C82A14': 'Apple', 'CC08E0': 'Apple',
            'D4619D': 'Apple', 'D89E3F': 'Apple', 'E0F847': 'Apple', 'E80688': 'Apple',
            'F0DBE2': 'Apple', 'F40F24': 'Apple', 'F82793': 'Apple', 'FC253F': 'Apple',
            
            # Samsung
            '001377': 'Samsung', '0015B9': 'Samsung', '0016DB': 'Samsung', '001632': 'Samsung',
            '0018AF': 'Samsung', '001D25': 'Samsung', '002454': 'Samsung', '0024E9': 'Samsung',
            '002566': 'Samsung', '34BE00': 'Samsung', '38AA3C': 'Samsung', '3CB87A': 'Samsung',
            '40B395': 'Samsung', '44D884': 'Samsung', '5C0A5B': 'Samsung', '68A86D': 'Samsung',
            '78D6F0': 'Samsung', '8CE748': 'Samsung', 'AC5A14': 'Samsung', 'B4B603': 'Samsung',
            'C06599': 'Samsung', 'CC07AB': 'Samsung', 'E8039A': 'Samsung', 'EC1F72': 'Samsung',
            
            # Xiaomi
            '2C56DC': 'Xiaomi', '34CE00': 'Xiaomi', '50EC50': 'Xiaomi', '64B473': 'Xiaomi',
            '68DF7C': 'Xiaomi', '6C5AB0': 'Xiaomi', '786A89': 'Xiaomi', '7C1DD9': 'Xiaomi',
            '8CFABA': 'Xiaomi', '98FAE3': 'Xiaomi', 'A01081': 'Xiaomi', 'A0B4A5': 'Xiaomi',
            'B0E235': 'Xiaomi', 'F48E92': 'Xiaomi', 'F4F5DB': 'Xiaomi', 'FC64BA': 'Xiaomi',
            
            # TP-Link
            '001FE2': 'TP-Link', '04921A': 'TP-Link', '0C80D4': 'TP-Link', '1045BE': 'TP-Link',
            '14CC20': 'TP-Link', '186596': 'TP-Link', '24B52F': 'TP-Link', '50C7BF': 'TP-Link',
            'A0F3C1': 'TP-Link', 'B0487A': 'TP-Link', 'C4E984': 'TP-Link', 'DC9FDB': 'TP-Link',
            'E8DE27': 'TP-Link', 'F09FC2': 'TP-Link', 'F4F26D': 'TP-Link',
            
            # Dyson
            '2C5D93': 'Dyson', '90E2BA': 'Dyson',
            
            # Petkit
            '34AB37': 'Petkit', '7C49EB': 'Petkit',
            
            # Cisco
            '002511': 'Cisco', '00907C': 'Cisco', '001C58': 'Cisco',
            '001E13': 'Cisco', '001E14': 'Cisco', '001E58': 'Cisco', '001E7A': 'Cisco',
            
            # Netgear
            '00146C': 'Netgear', '001B2F': 'Netgear', '001E2A': 'Netgear', '002140': 'Netgear',
            '00223F': 'Netgear', '0024B2': 'Netgear', '20768F': 'Netgear',
            
            # ASUS
            '001731': 'ASUS', '001E8C': 'ASUS', '002618': 'ASUS', '00E018': 'ASUS',
            '107B44': 'ASUS', '1C872C': 'ASUS', '38D547': 'ASUS',
            
            # Arçelik
            '00A0D2': 'Arçelik', 'B8D9CE': 'Arçelik',
            
            # Vestel
            '7CE4AA': 'Vestel',
            
            # Toshiba
            '000039': 'Toshiba', '001560': 'Toshiba', '005004': 'Toshiba', '00608C': 'Toshiba',
            
            # Fujitsu (bazı Toshiba ile overlap olabilir, farklı OUI'ler kullanıyoruz)
            '001B38': 'Fujitsu', '002268': 'Fujitsu',
            
            # S-Link
            '00E04C': 'S-Link',
            
            # Zyxel
            '001349': 'Zyxel', '00A0C5': 'Zyxel', '001FE9': 'Zyxel'
        }
        
        self.load_config()
    
    def load_config(self):
        """Konfigürasyonu dosyadan yükle"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            else:
                self.config = self.default_config.copy()
                self.save_config()
        except Exception as e:
            print(f"Config yükleme hatası: {e}")
            self.config = self.default_config.copy()
    
    def save_config(self):
        """Konfigürasyonu dosyaya kaydet"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Config kaydetme hatası: {e}")
    
    def load_oui_database(self):
        """OUI veritabanını yükle"""
        try:
            if os.path.exists(self.oui_file):
                with open(self.oui_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                self.save_oui_database(self.default_oui_database)
                return self.default_oui_database.copy()
        except Exception as e:
            print(f"OUI database yükleme hatası: {e}")
            return self.default_oui_database.copy()
    
    def save_oui_database(self, oui_data):
        """OUI veritabanını kaydet"""
        try:
            os.makedirs(os.path.dirname(self.oui_file), exist_ok=True)
            with open(self.oui_file, 'w', encoding='utf-8') as f:
                json.dump(oui_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"OUI database kaydetme hatası: {e}")
    
    def load_device_types(self):
        """Cihaz tiplerini yükle"""
        try:
            if os.path.exists(self.device_types_file):
                with open(self.device_types_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                self.save_device_types(self.default_device_types)
                return self.default_device_types.copy()
        except Exception as e:
            print(f"Device types yükleme hatası: {e}")
            return self.default_device_types.copy()
    
    def save_device_types(self, device_types):
        """Cihaz tiplerini kaydet"""
        try:
            os.makedirs(os.path.dirname(self.device_types_file), exist_ok=True)
            with open(self.device_types_file, 'w', encoding='utf-8') as f:
                json.dump(device_types, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Device types kaydetme hatası: {e}")
    
    def add_scan_history(self, scan_data):
        """Tarama geçmişine kayıt ekle"""
        try:
            history = self.load_scan_history()
            history.append({
                'timestamp': datetime.now().isoformat(),
                'total_devices': scan_data.get('total_devices', 0),
                'online_devices': scan_data.get('online_devices', 0),
                'ip_range': scan_data.get('ip_range', ''),
                'scan_duration': scan_data.get('scan_duration', 0),
                'device_types': scan_data.get('device_types', {}),
                'vendors': scan_data.get('vendors', {})
            })
            
            # Son 100 kayıtı tut
            if len(history) > 100:
                history = history[-100:]
            
            os.makedirs(os.path.dirname(self.scan_history_file), exist_ok=True)
            with open(self.scan_history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Scan history kaydetme hatası: {e}")
    
    def load_scan_history(self):
        """Tarama geçmişini yükle"""
        try:
            if os.path.exists(self.scan_history_file):
                with open(self.scan_history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Scan history yükleme hatası: {e}")
            return []
    
    def get_setting(self, section, key, default=None):
        """Belirli bir ayarı al"""
        try:
            return self.config.get(section, {}).get(key, default)
        except Exception:
            return default
    
    def set_setting(self, section, key, value):
        """Belirli bir ayarı güncelle"""
        try:
            if section not in self.config:
                self.config[section] = {}
            self.config[section][key] = value
            self.save_config()
            return True
        except Exception as e:
            print(f"Setting güncelleme hatası: {e}")
            return False
    
    def save_scan_result(self, scan_result):
        """Tarama sonucunu history'ye kaydet"""
        try:
            history = self.load_scan_history()
            history.append(scan_result)
            
            # Son 100 kayıtı tut
            if len(history) > 100:
                history = history[-100:]
            
            os.makedirs(os.path.dirname(self.scan_history_file), exist_ok=True)
            with open(self.scan_history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Scan result kaydetme hatası: {e}")
