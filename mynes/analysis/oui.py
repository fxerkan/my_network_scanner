#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced OUI Database Manager with CSV import and API integration
Supports multiple IEEE CSV sources, online MAC lookups, and local database management.
"""

import csv
import json
import requests
import re
import os
from datetime import datetime
import time
import urllib3

# Disable SSL warnings for IEEE CSV downloads
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OUIManager:
    def __init__(self, config_dir='config', data_dir='data'):
        self.config_dir = config_dir
        self.data_dir = data_dir
        self.oui_file = os.path.join(config_dir, 'oui_database.json')
        
        # IEEE CSV files and their URLs
        self.ieee_csv_files = {
            'oui': os.path.join(config_dir, 'oui.csv'),
            'mam': os.path.join(config_dir, 'mam.csv'), 
            'oui36': os.path.join(config_dir, 'oui36.csv'),
            'iab': os.path.join(config_dir, 'iab.csv'),
            'cid': os.path.join(config_dir, 'cid.csv')
        }
        
        self.ieee_urls = {
            'oui': 'http://standards-oui.ieee.org/oui/oui.csv',
            'mam': 'http://standards-oui.ieee.org/oui28/mam.csv',
            'oui36': 'http://standards-oui.ieee.org/oui36/oui36.csv',
            'iab': 'http://standards-oui.ieee.org/iab/iab.csv',
            'cid': 'http://standards-oui.ieee.org/cid/cid.csv'
        }
        
        # Vendor to device type mapping based on common patterns
        self.vendor_device_types = {
            'apple': ['smartphone', 'tablet', 'laptop', 'smart_tv', 'apple_device'],
            'samsung': ['smartphone', 'tablet', 'smart_tv', 'tablet'],
            'lg': ['smart_tv', 'air_conditioner', 'appliance'],
            'sony': ['smart_tv', 'game_console', 'camera'],
            'microsoft': ['laptop', 'tablet', 'game_console'],
            'nintendo': ['game_console'],
            'intel': ['laptop', 'computer'],
            'broadcom': ['router', 'network'],
            'qualcomm': ['smartphone', 'iot_device'],
            'raspberry pi': ['computer', 'iot_device'],
            'espressif': ['iot_device', 'sensor'],
            'texas instruments': ['iot_device', 'sensor'],
            'mediatek': ['router', 'iot_device'],
            'realtek': ['network', 'router'],
            'tp-link': ['router', 'network'],
            'cisco': ['router', 'network'],
            'netgear': ['router', 'network'],
            'asus': ['router', 'network', 'laptop'],
            'hikvision': ['camera'],
            'dahua': ['camera'],
            'axis': ['camera'],
            'foscam': ['camera'],
            'wyze': ['camera', 'iot_device'],
            'ring': ['camera', 'iot_device'],
            'nest': ['camera', 'thermostat', 'iot_device'],
            'philips': ['smart_lighting', 'iot_device'],
            'xiaomi': ['smartphone', 'iot_device', 'camera'],
            'huawei': ['smartphone', 'router', 'network'],
            'dlink': ['router', 'network', 'camera'],
            'linksys': ['router', 'network'],
            'belkin': ['router', 'iot_device'],
            'dyson': ['air_conditioner', 'appliance'],
            'mxchip': ['iot_device', 'sensor', 'microcontroller'],
            'shanghai mxchip': ['iot_device', 'sensor', 'microcontroller'],
            'honeywell': ['thermostat', 'iot_device', 'sensor'],
            'siemens': ['industrial', 'iot_device'],
            'bosch': ['appliance', 'iot_device', 'sensor'],
            'whirlpool': ['appliance'],
            'ge': ['appliance', 'iot_device'],
            'fitbit': ['wearable', 'iot_device'],
            'garmin': ['wearable', 'gps_device'],
            'tesla': ['car', 'iot_device'],
            'roku': ['smart_tv', 'streaming'],
            'amazon': ['smart_speaker', 'streaming', 'iot_device'],
            'google': ['smart_speaker', 'streaming', 'iot_device'],
            'sonos': ['smart_speaker', 'audio'],
            'bose': ['audio', 'smart_speaker'],
            'jbl': ['audio'],
            'logitech': ['computer', 'camera', 'audio'],
            'canon': ['printer', 'camera'],
            'epson': ['printer'],
            'hp': ['printer', 'laptop', 'computer'],
            'brother': ['printer'],
            'synology': ['nas', 'storage'],
            'qnap': ['nas', 'storage'],
            'western digital': ['nas', 'storage'],
            'seagate': ['storage'],
            'drobo': ['nas', 'storage']
        }

        # API endpoints for online MAC lookup
        self.api_endpoints = [
            {
                'name': 'macvendorlookup.com',
                'url': 'https://www.macvendorlookup.com/api/v2/{mac}',
                'method': 'GET',
                'rate_limit': 1000  # per day
            },
            {
                'name': 'maclookup.app',
                'url': 'https://api.maclookup.app/v2/macs/{mac}',
                'method': 'GET',
                'rate_limit': 1000  # per month
            },
            {
                'name': 'macvendors.co',
                'url': 'https://macvendors.co/api/{mac}',
                'method': 'GET',
                'rate_limit': 1000
            }
        ]
        
        self.oui_database = {}
        self.load_database()
    
    def load_database(self):
        """Load the OUI database from JSON file"""
        try:
            if os.path.exists(self.oui_file):
                with open(self.oui_file, 'r', encoding='utf-8') as f:
                    self.oui_database = json.load(f)
                print(f"OUI database loaded: {len(self.oui_database)} entries")
            else:
                print("OUI database not found, creating new one...")
                self.oui_database = {}
                # Try to build from existing CSV files or download new ones
                self.build_database_from_csv_files()
        except Exception as e:
            print(f"Error loading OUI database: {e}")
            self.oui_database = {}
    
    def save_database(self):
        """Save the OUI database to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.oui_file), exist_ok=True)
            with open(self.oui_file, 'w', encoding='utf-8') as f:
                json.dump(self.oui_database, f, ensure_ascii=False, indent=2)
            print(f"OUI database saved: {len(self.oui_database)} entries")
            return True
        except Exception as e:
            print(f"Error saving OUI database: {e}")
            return False
    
    def download_ieee_databases(self):
        """Download all IEEE CSV databases"""
        print("Downloading IEEE databases...")
        total_downloaded = 0
        
        for db_type, url in self.ieee_urls.items():
            try:
                print(f"Downloading: {db_type} from {url}")
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/csv,application/csv,text/plain,*/*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Connection': 'keep-alive'
                }
                
                response = requests.get(url, headers=headers, timeout=60, verify=False)
                if response.status_code == 200:
                    file_path = self.ieee_csv_files[db_type]
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(response.text)
                    
                    print(f"✅ {db_type}.csv downloaded ({len(response.text)} bytes)")
                    total_downloaded += 1
                else:
                    print(f"❌ Failed to download {db_type}: HTTP {response.status_code}")
                    
                # Rate limiting
                time.sleep(1)
                    
            except Exception as e:
                print(f"❌ Error downloading {db_type}: {e}")
        
        print(f"Total downloaded: {total_downloaded}/{len(self.ieee_urls)} files")
        return total_downloaded > 0
    
    def build_database_from_csv_files(self):
        """Build OUI database from all IEEE CSV files"""
        print("Building OUI database from CSV files...")
        
        # First try to download latest CSV files
        if not self.download_ieee_databases():
            print("Could not download IEEE files, checking for existing files...")
        
        total_processed = 0
        
        for db_type, file_path in self.ieee_csv_files.items():
            if os.path.exists(file_path):
                processed = self._process_csv_file(file_path, db_type)
                total_processed += processed
                print(f"✅ {db_type}: {processed} entries processed")
            else:
                print(f"❌ {db_type} file not found: {file_path}")
        
        print(f"Total processed: {total_processed} OUI entries")
        if total_processed > 0:
            self.save_database()
        return total_processed
    
    def _process_csv_file(self, file_path, db_type):
        """Process a single CSV file"""
        processed_count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                csv_reader = csv.DictReader(f)
                for row in csv_reader:
                    oui, org_name = self._extract_oui_and_org(row, db_type)
                    
                    if oui and org_name:
                        # Clean organization name
                        clean_name = self.clean_organization_name(org_name)
                        
                        # If this OUI already exists, use the shorter/cleaner name
                        if oui in self.oui_database:
                            if len(clean_name) < len(self.oui_database[oui]):
                                self.oui_database[oui] = clean_name
                        else:
                            self.oui_database[oui] = clean_name
                        
                        processed_count += 1
                        
        except Exception as e:
            print(f"Error processing CSV file ({db_type}): {e}")
        
        return processed_count
    
    def _extract_oui_and_org(self, row, db_type):
        """Extract OUI and organization name from CSV row"""
        try:
            if db_type == 'oui':
                # MA-L format: XX-XX-XX
                assignment = row.get('Assignment', '').strip()
                org_name = row.get('Organization Name', '').strip()
                registry = row.get('Registry', '').strip()
                
                if registry == 'MA-L' and assignment and org_name:
                    oui = assignment.replace('-', '').replace(':', '').upper()
                    if len(oui) == 6:
                        return oui, org_name
                        
            elif db_type == 'mam':
                # MA-M format: XX-XX-XX-X
                assignment = row.get('Assignment', '').strip()
                org_name = row.get('Organization Name', '').strip()
                
                if assignment and org_name:
                    oui = assignment.replace('-', '').replace(':', '').upper()
                    if len(oui) >= 7:  # MA-M is 28-bit
                        return oui[:6], org_name  # Take first 6 characters
                        
            elif db_type == 'oui36':
                # OUI-36 format: XX-XX-XX-X
                assignment = row.get('Assignment', '').strip()
                org_name = row.get('Organization Name', '').strip()
                
                if assignment and org_name:
                    oui = assignment.replace('-', '').replace(':', '').upper()
                    if len(oui) >= 9:  # OUI-36 is 36-bit
                        return oui[:6], org_name  # Take first 6 characters
                        
            elif db_type == 'iab':
                # IAB format
                assignment = row.get('Assignment', '').strip()
                org_name = row.get('Organization Name', '').strip()
                
                if assignment and org_name:
                    oui = assignment.replace('-', '').replace(':', '').upper()
                    if len(oui) >= 6:
                        return oui[:6], org_name
                        
            elif db_type == 'cid':
                # CID format
                assignment = row.get('Assignment', '').strip()
                org_name = row.get('Organization Name', '').strip()
                
                if assignment and org_name:
                    oui = assignment.replace('-', '').replace(':', '').upper()
                    if len(oui) >= 6:
                        return oui[:6], org_name
                        
        except Exception as e:
            print(f"Row extraction error ({db_type}): {e}")
        
        return None, None
    
    def clean_organization_name(self, org_name):
        """Clean and normalize organization name"""
        if not org_name:
            return "Unknown"
            
        # Remove quotes
        clean_name = org_name.strip('"').strip("'")
        
        # Common suffix replacements
        replacements = {
            ', Ltd.': ' Ltd',
            ', LLC': ' LLC',
            ', Inc.': ' Inc',
            ', Corp.': ' Corp',
            ', Co., Ltd.': ' Co Ltd',
            'Corporation': 'Corp',
            'Limited': 'Ltd',
            'Company': 'Co',
            'Technologies': 'Tech',
            'International': 'Intl'
        }
        
        for old, new in replacements.items():
            clean_name = clean_name.replace(old, new)
        
        # Clean extra whitespace
        clean_name = re.sub(r'\s+', ' ', clean_name).strip()
        
        return clean_name
    
    def lookup_mac_api(self, mac_address):
        """Perform MAC lookup using online APIs"""
        # Extract OUI (first 6 characters)
        oui = mac_address.replace(':', '').replace('-', '').upper()[:6]
        
        # Check local database first
        if oui in self.oui_database:
            return self.oui_database[oui]
        
        # Try APIs
        mac_for_api = mac_address.replace('-', ':')  # APIs usually prefer : format
        
        for api in self.api_endpoints:
            try:
                url = api['url'].format(mac=mac_for_api)
                
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    vendor = None
                    if api['name'] == 'macvendorlookup.com':
                        if isinstance(data, list) and len(data) > 0:
                            vendor = data[0].get('company')
                    elif api['name'] == 'maclookup.app':
                        vendor = data.get('company')
                    elif api['name'] == 'macvendors.co':
                        vendor = data.get('result', {}).get('company')
                    
                    if vendor:
                        clean_vendor = self.clean_organization_name(vendor)
                        # Add new information to database
                        self.oui_database[oui] = clean_vendor
                        self.save_database()
                        return clean_vendor
                
                # Rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                print(f"API lookup error ({api['name']}): {e}")
                continue
        
        return "Unknown"
    
    def get_vendor(self, mac_address):
        """Get vendor information from MAC address"""
        if not mac_address:
            return "Unknown"
        
        # Extract OUI
        oui = mac_address.replace(':', '').replace('-', '').upper()[:6]
        
        # Check local database
        if oui in self.oui_database:
            return self.oui_database[oui]
        
        # Try API lookup (only when not found locally)
        return self.lookup_mac_api(mac_address)
    
    def add_oui(self, oui, vendor):
        """Add new OUI entry"""
        clean_oui = oui.replace(':', '').replace('-', '').upper()[:6]
        if len(clean_oui) == 6:
            self.oui_database[clean_oui] = vendor
            self.save_database()
            return True
        return False
    
    def remove_oui(self, oui):
        """Remove OUI entry"""
        clean_oui = oui.replace(':', '').replace('-', '').upper()[:6]
        if clean_oui in self.oui_database:
            del self.oui_database[clean_oui]
            self.save_database()
            return True
        return False
    
    def search_vendor(self, query):
        """Search vendors by name"""
        query_lower = query.lower()
        results = {}
        
        for oui, vendor in self.oui_database.items():
            if query_lower in vendor.lower():
                results[oui] = vendor
        
        return results
    
    def get_stats(self):
        """Get database statistics"""
        return {
            'total_ouis': len(self.oui_database),
            'last_updated': datetime.now().isoformat(),
            'database_file': self.oui_file
        }
    
    def export_database(self):
        """Export database"""
        return self.oui_database.copy()
    
    def import_database(self, new_data):
        """Import new database data"""
        if isinstance(new_data, dict):
            self.oui_database.update(new_data)
            self.save_database()
            return True
        return False
    
    def update_database(self):
        """Update database by downloading latest IEEE files"""
        print("Updating OUI database...")
        old_count = len(self.oui_database)
        
        # Download and process latest files
        success = self.build_database_from_csv_files()
        
        new_count = len(self.oui_database)
        print(f"Database updated: {old_count} -> {new_count} entries")
        
        return success
    
    def get_device_types_from_vendor(self, vendor_name):
        """Vendor ismine göre olası device type'ları döndürür"""
        if not vendor_name:
            return []
        
        vendor_lower = vendor_name.lower()
        possible_types = []
        
        # Vendor mapping'den kontrol et
        for vendor_key, device_types in self.vendor_device_types.items():
            if vendor_key in vendor_lower:
                possible_types.extend(device_types)
        
        # Dublicate'leri temizle ve sırala
        return list(set(possible_types))
    
    def get_vendor_with_device_types(self, mac_address):
        """MAC address için vendor ve olası device type'ları döndürür"""
        vendor = self.get_vendor(mac_address)
        device_types = self.get_device_types_from_vendor(vendor)
        
        return {
            'vendor': vendor,
            'possible_device_types': device_types,
            'mac_oui': mac_address.replace(':', '').replace('-', '').upper()[:6]
        }
    
    def update_oui_database_with_device_types(self):
        """Mevcut OUI database'i device type bilgileriyle günceller"""
        print("🔄 OUI database'e device type bilgileri ekleniyor...")
        
        updated_count = 0
        enhanced_database = {}
        
        for oui, vendor in self.oui_database.items():
            device_types = self.get_device_types_from_vendor(vendor)
            
            enhanced_database[oui] = {
                'vendor': vendor,
                'possible_device_types': device_types,
                'updated_at': datetime.now().isoformat()
            }
            
            if device_types:
                updated_count += 1
        
        # Enhanced database'i kaydet
        enhanced_file = os.path.join(self.config_dir, 'enhanced_oui_database.json')
        try:
            with open(enhanced_file, 'w', encoding='utf-8') as f:
                json.dump(enhanced_database, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Enhanced OUI database kaydedildi: {enhanced_file}")
            print(f"📊 {updated_count}/{len(self.oui_database)} entry'de device type bilgisi eklendi")
            
            return enhanced_file
            
        except Exception as e:
            print(f"❌ Enhanced database kaydetme hatası: {e}")
            return None

# Test functionality
if __name__ == "__main__":
    manager = OUIManager()
    
    # Test MAC addresses
    test_macs = [
        "00:11:22:33:44:55",  # Unknown
        "00:11:22:33:44:56",  # Generic example
        "00:11:22:33:44:57"   # Generic example
    ]
    
    print("Testing MAC address lookups:")
    for mac in test_macs:
        vendor = manager.get_vendor(mac)
        print(f"MAC: {mac} -> Vendor: {vendor}")
    
    stats = manager.get_stats()
    print(f"\nDatabase stats: {stats}")
