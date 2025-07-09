#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data sanitizer for LAN Scanner - removes sensitive information from device data
"""

import json
import re
import copy
from typing import Dict, List, Any

class DataSanitizer:
    """Cihaz verilerinden hassas bilgileri temizler"""
    
    def __init__(self):
        # Hassas header adları (case-insensitive)
        self.sensitive_headers = {
            'set-cookie', 'cookie', 'authorization', 'x-csrf-token', 
            'csrf-token', 'x-xsrf-token', 'xsrf-token', 'x-auth-token', 'x-api-key',
            'api-key', 'x-session-id', 'session-id'
        }
        
        # Hassas alanlar
        self.sensitive_fields = {
            'password', 'pass', 'pwd', 'secret', 'key', 'token', 
            'session', 'cookie', 'auth', 'credential'
        }
        
        # Temizlenecek dosya uzantıları
        self.asset_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'
        }
        
    def sanitize_device_data(self, devices: List[Dict]) -> List[Dict]:
        """Cihaz listesindeki hassas verileri temizler"""
        sanitized_devices = []
        
        for device in devices:
            sanitized_device = self._sanitize_single_device(copy.deepcopy(device))
            sanitized_devices.append(sanitized_device)
            
        return sanitized_devices
    
    def _sanitize_single_device(self, device: Dict) -> Dict:
        """Tek bir cihazın verilerini temizler"""
        # Legacy format fields
        if 'enhanced_info' in device and device['enhanced_info']:
            device['enhanced_info'] = self._sanitize_enhanced_info(device['enhanced_info'])
        
        if 'enhanced_comprehensive_info' in device and device['enhanced_comprehensive_info']:
            device['enhanced_comprehensive_info'] = self._sanitize_enhanced_info(device['enhanced_comprehensive_info'])
        
        if 'advanced_scan_summary' in device and device['advanced_scan_summary']:
            device['advanced_scan_summary'] = self._sanitize_enhanced_info(device['advanced_scan_summary'])
        
        # Unified format fields
        if 'analysis_data' in device and device['analysis_data']:
            analysis_data = device['analysis_data']
            
            if 'normal_scan_info' in analysis_data and analysis_data['normal_scan_info']:
                analysis_data['normal_scan_info'] = self._sanitize_enhanced_info(analysis_data['normal_scan_info'])
                
            if 'enhanced_analysis_info' in analysis_data and analysis_data['enhanced_analysis_info']:
                analysis_data['enhanced_analysis_info'] = self._sanitize_enhanced_info(analysis_data['enhanced_analysis_info'])
        
        # Top-level web services info'yu temizle
        if 'web_services' in device and device['web_services']:
            device['web_services'] = self._sanitize_web_services(device['web_services'])
            
        return device
    
    def _sanitize_enhanced_info(self, enhanced_info: Dict) -> Dict:
        """Enhanced info bölümünü temizler"""
        sanitized = copy.deepcopy(enhanced_info)
        
        # Web services temizleme
        if 'web_services' in sanitized:
            sanitized['web_services'] = self._sanitize_web_services(sanitized['web_services'])
            
        return sanitized
    
    def _sanitize_web_services(self, web_services: Dict) -> Dict:
        """Web servis bilgilerini temizler"""
        sanitized = {}
        
        for service_key, service_data in web_services.items():
            if isinstance(service_data, dict):
                sanitized_service = self._sanitize_service_data(service_data)
                # Eğer temizlendikten sonra boş kalmadıysa ekle
                if sanitized_service:
                    sanitized[service_key] = sanitized_service
            else:
                sanitized[service_key] = service_data
                
        return sanitized
    
    def _sanitize_service_data(self, service_data: Dict) -> Dict:
        """Tek bir servis verisini temizler"""
        sanitized = {}
        
        for key, value in service_data.items():
            if key.lower() == 'headers' and isinstance(value, dict):
                # Headers'ı temizle
                clean_headers = self._sanitize_headers(value)
                if clean_headers:
                    sanitized[key] = clean_headers
            elif key.lower() == 'links' and isinstance(value, list):
                # Links'i temizle
                clean_links = self._sanitize_links(value)
                if clean_links:
                    sanitized[key] = clean_links
            elif not self._is_sensitive_field(key):
                # Diğer alanları kontrol et
                sanitized[key] = value
                
        return sanitized
    
    def _sanitize_headers(self, headers: Dict) -> Dict:
        """HTTP headers'larını temizler"""
        clean_headers = {}
        
        for header_name, header_value in headers.items():
            if not self._is_sensitive_header(header_name):
                # Header value içinde token, session vb. geçiyorsa da temizle
                if not self._is_sensitive_header_value(header_value):
                    clean_headers[header_name] = header_value
                
        return clean_headers
    
    def _is_sensitive_header_value(self, header_value: str) -> bool:
        """Header değerinin hassas veri içerip içermediğini kontrol eder"""
        if not isinstance(header_value, str):
            return False
            
        value_lower = header_value.lower()
        sensitive_patterns = [
            'xsrf-token=', 'csrf-token=', 'session=', '_token=',
            'laravel_session=', 'phpsessid=', 'jsessionid='
        ]
        
        return any(pattern in value_lower for pattern in sensitive_patterns)
    
    def _sanitize_links(self, links: List) -> List:
        """Link listesini temizler"""
        clean_links = []
        
        for link in links:
            if isinstance(link, str):
                # Data URI'larını filtrele (data:image/, data:application/ vb.)
                if link.startswith('data:'):
                    continue
                # Asset dosyalarını filtrele
                if not self._is_asset_file(link):
                    # Docker overlay path'lerini filtrele
                    if not self._is_docker_overlay_path(link):
                        clean_links.append(link)
            else:
                clean_links.append(link)
                
        return clean_links
    
    def _is_sensitive_header(self, header_name: str) -> bool:
        """Header'ın hassas olup olmadığını kontrol eder"""
        return header_name.lower() in self.sensitive_headers
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Alanın hassas olup olmadığını kontrol eder"""
        field_lower = field_name.lower()
        return any(sensitive in field_lower for sensitive in self.sensitive_fields)
    
    def _is_asset_file(self, link: str) -> bool:
        """Link'in asset dosyası olup olmadığını kontrol eder"""
        link_lower = link.lower()
        
        # Dosya uzantısına göre kontrol et
        for ext in self.asset_extensions:
            if ext in link_lower:
                return True
                
        # Path pattern'lerine göre kontrol et
        asset_patterns = [
            r'/images?/',
            r'/css/',
            r'/js/',
            r'/assets?/',
            r'/static/',
            r'/media/',
            r'/fonts?/',
            r'\.css\?',
            r'\.js\?'
        ]
        
        for pattern in asset_patterns:
            if re.search(pattern, link_lower):
                return True
                
        return False
    
    def _is_docker_overlay_path(self, link: str) -> bool:
        """Link'in Docker overlay path'i olup olmadığını kontrol eder"""
        docker_patterns = [
            r'/var/lib/docker/overlay',
            r'/overlay/',
            r'docker/overlay',
            r'overlay\d+/',
        ]
        
        for pattern in docker_patterns:
            if re.search(pattern, link, re.IGNORECASE):
                return True
                
        return False
    
    def sanitize_file(self, input_file: str, output_file: str = None) -> bool:
        """Dosyayı temizler"""
        try:
            # Dosyayı oku
            with open(input_file, 'r', encoding='utf-8') as f:
                devices = json.load(f)
            
            # Temizle
            sanitized_devices = self.sanitize_device_data(devices)
            
            # Çıktı dosyası belirtilmemişse aynı dosyaya yaz
            if output_file is None:
                output_file = input_file
            
            # Temizlenmiş veriyi yaz
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(sanitized_devices, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"Dosya temizleme hatası: {e}")
            return False
    
    def get_sanitization_stats(self, original_devices: List[Dict], sanitized_devices: List[Dict]) -> Dict:
        """Temizleme istatistiklerini döndürür"""
        stats = {
            'total_devices': len(original_devices),
            'headers_removed': 0,
            'links_removed': 0,
            'fields_removed': 0
        }
        
        # Bu istatistikler sadece yaklaşık değerler
        # Gerçek implementation'da daha detaylı sayım yapılabilir
        
        return stats

def main():
    """Test fonksiyonu"""
    sanitizer = DataSanitizer()
    
    # Test için lan_devices.json dosyasını temizle
    input_file = 'data/lan_devices.json'
    backup_file = 'data/lan_devices_backup.json'
    
    # Önce backup al
    import shutil
    try:
        shutil.copy2(input_file, backup_file)
        print(f"Backup oluşturuldu: {backup_file}")
        
        # Dosyayı temizle
        if sanitizer.sanitize_file(input_file):
            print(f"Dosya temizlendi: {input_file}")
        else:
            print("Dosya temizleme başarısız!")
            
    except Exception as e:
        print(f"Hata: {e}")

if __name__ == "__main__":
    main()