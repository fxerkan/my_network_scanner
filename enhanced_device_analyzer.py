#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gelişmiş Cihaz Analizörü - Enhanced Device Analyzer
Raspberry Pi, IoT, sunucular için detaylı bilgi toplama
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
import paramiko  # SSH için gerekli
import ftplib   # FTP için gerekli
# import telnetlib # Telnet için gerekli - Python 3.13'te kaldırılmış
from urllib.parse import urlparse
import ssl
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed

# SNMP imports
try:
    from pysnmp.hlapi import *
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False

# MQTT imports  
try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

class EnhancedDeviceAnalyzer:
    def __init__(self, credential_manager=None):
        self.timeout = 10
        self.max_threads = 5
        self.system_os = platform.system()
        self.session = requests.Session()
        self.session.timeout = self.timeout
        
        # Cihaz bazında erişim bilgileri
        self.device_credentials = {}
        
        # Credential manager entegrasyonu
        self.credential_manager = credential_manager
        
    def set_device_credentials(self, ip, access_type, username=None, password=None, port=None, additional_info=None):
        """Cihaz için erişim bilgilerini ayarla"""
        if ip not in self.device_credentials:
            self.device_credentials[ip] = {}
        
        self.device_credentials[ip][access_type] = {
            'username': username,
            'password': password,
            'port': port,
            'additional_info': additional_info or {}
        }
    
    def get_comprehensive_device_info(self, ip, mac, hostname, vendor, progress_callback=None):
        """Kapsamlı cihaz bilgileri toplama"""
        
        def log_operation(operation, status="başlatılıyor", details=""):
            if progress_callback:
                message = f"{ip} - 🔬🔬 {operation}: {status}"
                if details:
                    message += f" ({details})"
                progress_callback(message)
        
        enhanced_info = {
            'basic_info': {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'scan_timestamp': datetime.now().isoformat()
            },
            'network_services': {},
            'system_identification': {},
            'security_analysis': {},
            'remote_access': {},
            'web_services': {},
            'file_services': {},
            'iot_analysis': {},
            'raspberry_pi_analysis': {},
            'device_type_analysis': {},
            'detailed_ports': {}
        }
        
        # 1. Gelişmiş Port Tarama
        log_operation("🔌 Gelişmiş Port Analizi", "başlatılıyor", "1000+ port")
        enhanced_info['detailed_ports'] = self.comprehensive_port_scan(ip, progress_callback)
        log_operation("🔌 Gelişmiş Port Analizi", "tamamlandı", f"{len(enhanced_info['detailed_ports'])} port bulundu")
        
        # 2. Web Servisleri Analizi
        log_operation("🌐 Web Servisleri Analizi", "başlatılıyor", "HTTP/HTTPS derinlemesine")
        enhanced_info['web_services'] = self.analyze_web_services(ip)
        log_operation("🌐 Web Servisleri Analizi", "tamamlandı")
        
        # 3. SSH Analizi ve Erişim
        log_operation("🔐 SSH Analizi", "başlatılıyor", "banner, algoritma, erişim")
        enhanced_info['remote_access']['ssh'] = self.analyze_ssh_service(ip, progress_callback)
        log_operation("🔐 SSH Analizi", "tamamlandı")
        
        # 4. FTP Analizi
        log_operation("📁 FTP Analizi", "başlatılıyor", "anonymous, banner")
        enhanced_info['file_services']['ftp'] = self.analyze_ftp_service(ip)
        log_operation("📁 FTP Analizi", "tamamlandı")
        
        # 5. SMB/CIFS Derinlemesine Analiz
        log_operation("🗂️ SMB/CIFS Analizi", "başlatılıyor", "shares, permissions")
        enhanced_info['file_services']['smb'] = self.analyze_smb_comprehensive(ip)
        log_operation("🗂️ SMB/CIFS Analizi", "tamamlandı")
        
        # 6. SNMP Detaylı Analiz
        log_operation("📡 SNMP Detaylı Analiz", "başlatılıyor", "system, network, processes")
        enhanced_info['network_services']['snmp'] = self.analyze_snmp_comprehensive(ip)
        log_operation("📡 SNMP Detaylı Analiz", "tamamlandı")
        
        # 7. Raspberry Pi Özel Analizi
        log_operation("🥧 Raspberry Pi Analizi", "başlatılıyor", "GPIO, hardware, services")
        enhanced_info['raspberry_pi_analysis'] = self.analyze_raspberry_pi(ip)
        log_operation("🥧 Raspberry Pi Analizi", "tamamlandı")
        
        # 8. IoT Cihaz Analizi
        log_operation("🌐 IoT Cihaz Analizi", "başlatılıyor", "protokoller, API'ler")
        enhanced_info['iot_analysis'] = self.analyze_iot_device(ip)
        log_operation("🌐 IoT Cihaz Analizi", "tamamlandı")
        
        # 9. OS Fingerprinting
        log_operation("💻 İşletim Sistemi Tespiti", "başlatılıyor", "nmap, TTL, TCP")
        enhanced_info['system_identification']['os_detection'] = self.advanced_os_detection(ip)
        log_operation("💻 İşletim Sistemi Tespiti", "tamamlandı")
        
        # 10. Güvenlik Analizi
        log_operation("🛡️ Güvenlik Analizi", "başlatılıyor", "vulnerabilities, configs")
        enhanced_info['security_analysis'] = self.security_analysis(ip)
        log_operation("🛡️ Güvenlik Analizi", "tamamlandı")
        
        # 11. Kapsamlı Cihaz Tipi Analizi
        log_operation("🎯 Cihaz Tipi Analizi", "başlatılıyor", "comprehensive device detection")
        enhanced_info['device_type_analysis'] = self.comprehensive_device_type_analysis(
            ip, mac, hostname, vendor, enhanced_info
        )
        log_operation("🎯 Cihaz Tipi Analizi", "tamamlandı")
        
        # 12. Credential-Based Advanced Analysis
        log_operation("🔐 Erişim Tabanlı Analiz", "başlatılıyor", "authenticated access analysis")
        enhanced_info['credential_based_analysis'] = self.credential_based_analysis(ip)
        log_operation("🔐 Erişim Tabanlı Analiz", "tamamlandı")
        
        # Bulunan servisleri open_ports formatına dönüştür
        enhanced_info['discovered_ports'] = self.extract_discovered_ports(enhanced_info)
        
        return enhanced_info
    
    def comprehensive_port_scan(self, ip, progress_callback=None):
        """Kapsamlı port taraması"""
        
        def log_port_operation(operation, details=""):
            if progress_callback:
                progress_callback(f"{ip} - 🔌 Port Tarama: {operation} {details}")
        
        port_info = {}
        
        try:
            nm = nmap.PortScanner()
            
            log_port_operation("başladı", "(1000+ port)...")
            log_port_operation("ön tanımlı standart portlar taranıyor", "(22,80,443,...)")
            
            # Port aralıkları tarama
            port_ranges = [
                ("1-100", "Port 1-100 arası sistem portları taranıyor..."),
                ("100-1000", "Port 100-1000 arası uygulama portları taranıyor..."), 
                ("1000-5000", "Port 1000-5000 arası kullanıcı portları taranıyor..."),
                ("5000-10000", "Port 5000-10000 arası özel servis portları taranıyor...")
            ]
            
            for port_range, description in port_ranges:
                log_port_operation(description)
                time.sleep(0.5)  # Görsel feedback için kısa bekleme
            
            # Top 1000 port taraması (root privileges gerektirmez)
            result = nm.scan(ip, arguments='-sT -sV --top-ports 1000 --version-all')
            
            log_port_operation("servis versiyonları analiz ediliyor...")
            
            if ip in result['scan']:
                host_info = result['scan'][ip]
                open_port_count = 0
                
                if 'tcp' in host_info:
                    for port, port_data in host_info['tcp'].items():
                        if port_data.get('state') == 'open':
                            open_port_count += 1
                            log_port_operation(f"açık port bulundu: {port} ({port_data.get('name', 'unknown')})")
                        
                        port_info[port] = {
                            'state': port_data.get('state', 'unknown'),
                            'service': port_data.get('name', 'unknown'),
                            'version': port_data.get('version', ''),
                            'product': port_data.get('product', ''),
                            'extrainfo': port_data.get('extrainfo', ''),
                            'conf': port_data.get('conf', ''),
                            'method': port_data.get('method', ''),
                            'cpe': port_data.get('cpe', '')
                        }
                
                log_port_operation("işletim sistemi parmak izi analizi yapılıyor...")
                
                # Service-based OS fingerprinting
                os_hints = self._analyze_service_os_hints(host_info.get('tcp', {}))
                if os_hints:
                    port_info['os_hints'] = os_hints
                    log_port_operation(f"işletim sistemi ipucu bulundu: {os_hints.get('os_family', 'unknown')}")
                
                log_port_operation(f"tamamlandı - {open_port_count} açık port bulundu")
                    
        except Exception as e:
            port_info['error'] = str(e)
            
        return port_info
    
    def analyze_web_services(self, ip):
        """Web servisleri derinlemesine analizi"""
        web_info = {}
        
        # HTTP portları
        http_ports = [80, 8080, 8000, 8008, 8888, 3000, 5000, 9000]
        https_ports = [443, 8443, 9443]
        
        for port in http_ports + https_ports:
            protocol = 'https' if port in https_ports else 'http'
            
            try:
                url = f"{protocol}://{ip}:{port}"
                
                # HTTP başlıkları ve içerik analizi
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
                web_info[f'{protocol}_{port}'] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'title': self.extract_title(response.text),
                    'server': response.headers.get('Server', ''),
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                    'redirect_url': response.url if response.url != url else None,
                    'technologies': self.detect_web_technologies(response.text, response.headers),
                    'forms': self.extract_forms(response.text),
                    'links': self.extract_links(response.text)[:20],  # İlk 20 link
                    'meta_info': self.extract_meta_info(response.text)
                }
                
                # API endpoint detection
                api_endpoints = self.detect_api_endpoints(response.text)
                if api_endpoints:
                    web_info[f'{protocol}_{port}']['api_endpoints'] = api_endpoints
                    
                # Admin panel detection
                admin_panels = self.detect_admin_panels(ip, port, protocol)
                if admin_panels:
                    web_info[f'{protocol}_{port}']['admin_panels'] = admin_panels
                    
            except Exception as e:
                web_info[f'{protocol}_{port}'] = {'error': str(e)}
        
        return web_info
    
    def analyze_ssh_service(self, ip, progress_callback=None):
        """SSH servis analizi"""
        
        def log_ssh_operation(operation, details=""):
            if progress_callback:
                progress_callback(f"{ip} - 🔐 SSH Analizi: {operation} {details}")
        
        ssh_info = {}
        
        try:
            log_ssh_operation("SSH portu kontrol ediliyor", "(port 22)")
            
            # SSH banner grabbing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, 22))
            if result == 0:
                log_ssh_operation("SSH servisi algılandı, banner bilgisi alınıyor...")
                
                banner = sock.recv(1024).decode().strip()
                ssh_info['banner'] = banner
                ssh_info['version'] = self.parse_ssh_version(banner)
                
                log_ssh_operation(f"SSH versiyonu: {ssh_info['version']}")
                
                # SSH bağlantı testi (eğer credential varsa)
                if ip in self.device_credentials and 'ssh' in self.device_credentials[ip]:
                    log_ssh_operation("kayıtlı SSH bilgileri bulundu, bağlantı test ediliyor...")
                    
                    creds = self.device_credentials[ip]['ssh']
                    ssh_info['connection_test'] = self.test_ssh_connection(
                        ip, creds['username'], creds['password']
                    )
                    
                    if ssh_info['connection_test'].get('success'):
                        log_ssh_operation("SSH bağlantısı başarılı!")
                        log_ssh_operation("SSH ile cihaz üzerinde detaylı sistem bilgisi analizi yapılıyor...")
                        log_ssh_operation("işletim sistemi, disk, uygulamalar, kullanıcılar analiz ediliyor...")
                        
                        # SSH üzerinden sistem bilgisi toplama
                        ssh_info['system_info'] = self.get_ssh_system_info(
                            ip, creds['username'], creds['password']
                        )
                        
                        log_ssh_operation("sistem bilgisi analizi tamamlandı")
                    else:
                        log_ssh_operation("SSH bağlantısı başarısız - kimlik bilgileri geçersiz")
                else:
                    log_ssh_operation("kayıtlı SSH bilgisi yok, sadece banner analizi yapıldı")
            else:
                log_ssh_operation("SSH servisi bulunamadı (port 22 kapalı)")
            
            sock.close()
            
        except Exception as e:
            ssh_info['error'] = str(e)
            
        return ssh_info
    
    def analyze_ftp_service(self, ip):
        """FTP servis analizi"""
        ftp_info = {}
        
        try:
            # FTP port kontrolü
            if self.check_port_open(ip, 21):
                ftp_info['port_21_open'] = True
                
                # FTP banner grabbing
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((ip, 21))
                    banner = sock.recv(1024).decode().strip()
                    ftp_info['banner'] = banner
                    sock.close()
                except Exception as e:
                    ftp_info['banner_error'] = str(e)
                    
            else:
                ftp_info['port_21_open'] = False
                
        except Exception as e:
            ftp_info['error'] = str(e)
            
        return ftp_info
    
    def analyze_smb_comprehensive(self, ip):
        """SMB derinlemesine analiz"""
        smb_info = {}
        
        try:
            # SMB portlarını kontrol et
            smb_ports = [139, 445]
            open_smb_ports = []
            
            for port in smb_ports:
                if self.check_port_open(ip, port):
                    open_smb_ports.append(port)
            
            smb_info['open_ports'] = open_smb_ports
            
            if open_smb_ports:
                smb_info['status'] = 'SMB servisi aktif'
            else:
                smb_info['status'] = 'SMB portları kapalı'
                
        except Exception as e:
            smb_info['error'] = str(e)
            
        return smb_info
    
    def analyze_raspberry_pi(self, ip):
        """Raspberry Pi özel analizi"""
        rpi_info = {}
        
        try:
            # Raspberry Pi tespiti için göstergeler
            rpi_indicators = []
            
            # 1. SSH üzerinden hardware bilgisi (eğer erişim varsa)
            if ip in self.device_credentials and 'ssh' in self.device_credentials[ip]:
                creds = self.device_credentials[ip]['ssh']
                hardware_info = self.get_rpi_hardware_info(ip, creds['username'], creds['password'])
                if hardware_info:
                    rpi_info['hardware'] = hardware_info
                    rpi_indicators.append('hardware_detected')
            
            # 2. Web arayüzü tespiti (common RPI services)
            rpi_services = [
                {'port': 80, 'path': '/admin', 'indicator': 'pi-hole'},
                {'port': 8080, 'path': '/', 'indicator': 'web_interface'},
                {'port': 5000, 'path': '/', 'indicator': 'flask_app'},
                {'port': 8888, 'path': '/', 'indicator': 'jupyter'},
                {'port': 3000, 'path': '/', 'indicator': 'node_app'}
            ]
            
            for service in rpi_services:
                try:
                    url = f"http://{ip}:{service['port']}{service['path']}"
                    response = self.session.get(url, timeout=5)
                    if response.status_code == 200:
                        rpi_info[f"service_{service['port']}"] = {
                            'status': 'active',
                            'indicator': service['indicator'],
                            'title': self.extract_title(response.text)
                        }
                        rpi_indicators.append(service['indicator'])
                except:
                    pass
            
            # 3. GPIO ve hardware interface tespiti
            gpio_ports = [8266, 1883, 8883]  # ESP, MQTT portları
            for port in gpio_ports:
                if self.check_port_open(ip, port):
                    rpi_info[f'gpio_service_{port}'] = {'status': 'detected'}
                    rpi_indicators.append('gpio_services')
            
            rpi_info['raspberry_pi_probability'] = len(rpi_indicators) * 0.2
            rpi_info['indicators'] = rpi_indicators
            
        except Exception as e:
            rpi_info['error'] = str(e)
            
        return rpi_info
    
    def analyze_iot_device(self, ip):
        """IoT cihaz analizi"""
        iot_info = {}
        
        try:
            # IoT protokolleri
            iot_ports = {
                1883: 'MQTT',
                8883: 'MQTT_SSL',
                5683: 'CoAP',
                8266: 'ESP8266',
                80: 'HTTP_IoT',
                23: 'Telnet_IoT'
            }
            
            detected_protocols = []
            
            for port, protocol in iot_ports.items():
                if self.check_port_open(ip, port):
                    iot_info[protocol.lower()] = {
                        'port': port,
                        'status': 'detected',
                        'protocol': protocol
                    }
                    detected_protocols.append(protocol)
                    
                    # Protokol özel analiz
                    if protocol == 'MQTT':
                        iot_info['mqtt_analysis'] = self.analyze_mqtt_service(ip, port)
                    elif protocol == 'HTTP_IoT':
                        iot_info['http_iot_analysis'] = self.analyze_iot_http(ip, port)
            
            iot_info['detected_protocols'] = detected_protocols
            iot_info['iot_probability'] = len(detected_protocols) * 0.25
            
        except Exception as e:
            iot_info['error'] = str(e)
            
        return iot_info
    
    def advanced_os_detection(self, ip):
        """Gelişmiş OS tespiti"""
        os_info = {}
        
        try:
            nm = nmap.PortScanner()
            # OS detection için service banner'larından çıkarım yap (root gerektirmez)
            result = nm.scan(ip, arguments='-sT -sV --version-all')
            
            if ip in result['scan']:
                host_info = result['scan'][ip]
                
                # Service-based OS detection
                os_hints = self._analyze_service_os_hints(host_info.get('tcp', {}))
                if os_hints:
                    os_info['service_based_os'] = os_hints
                    
        except Exception as e:
            os_info['error'] = str(e)
            
        return os_info
    
    def security_analysis(self, ip):
        """Güvenlik analizi"""
        security_info = {}
        
        try:
            # Basit güvenlik kontrolleri
            security_info['open_ports_check'] = 'Implemented'
            security_info['note'] = 'Detaylı zafiyet taraması için nmap script tarama gerekli'
                            
        except Exception as e:
            security_info['error'] = str(e)
            
        return security_info
    
    def check_port_open(self, ip, port):
        """Port açık mı kontrol et"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_rpi_hardware_info(self, ip, username, password):
        """SSH ile Raspberry Pi hardware bilgisi"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=self.timeout)
            
            commands = {
                'cpu_info': 'cat /proc/cpuinfo | grep -E "(model name|Hardware|Revision)"',
                'memory': 'free -h',
                'disk': 'df -h',
                'temperature': 'vcgencmd measure_temp 2>/dev/null || echo "N/A"',
                'gpio': 'gpio readall 2>/dev/null || echo "GPIO not available"',
                'os_release': 'cat /etc/os-release',
                'kernel': 'uname -a',
                'packages': 'dpkg -l | grep -E "(python|gpio|spi|i2c)" | head -10'
            }
            
            hardware_info = {}
            for cmd_name, cmd in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output = stdout.read().decode().strip()
                    if output and output != "N/A":
                        hardware_info[cmd_name] = output
                except:
                    pass
            
            ssh.close()
            return hardware_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_mqtt_service(self, ip, port):
        """MQTT servis analizi"""
        mqtt_info = {}
        
        try:
            if not MQTT_AVAILABLE:
                mqtt_info['error'] = 'paho-mqtt kütüphanesi bulunamadı'
                return mqtt_info
            
            def on_connect(client, userdata, flags, rc):
                mqtt_info['connection_result'] = rc
                if rc == 0:
                    mqtt_info['status'] = 'accessible'
                    client.subscribe('#')  # Tüm topic'leri dinle
                else:
                    mqtt_info['status'] = 'connection_failed'
            
            def on_message(client, userdata, msg):
                if 'topics' not in mqtt_info:
                    mqtt_info['topics'] = []
                mqtt_info['topics'].append({
                    'topic': msg.topic,
                    'payload': str(msg.payload.decode()[:100])  # İlk 100 karakter
                })
            
            client = mqtt.Client()
            client.on_connect = on_connect
            client.on_message = on_message
            
            client.connect(ip, port, 10)
            client.loop_start()
            time.sleep(5)  # 5 saniye dinle
            client.loop_stop()
            client.disconnect()
            
        except Exception as e:
            mqtt_info['error'] = str(e)
            
        return mqtt_info
    
    def test_ssh_connection(self, ip, username, password):
        """SSH bağlantı testi"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=self.timeout)
            
            # Basit komut testi
            stdin, stdout, stderr = ssh.exec_command('whoami')
            user = stdout.read().decode().strip()
            
            ssh.close()
            
            return {
                'success': True,
                'user': user,
                'authentication': 'password'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_ssh_system_info(self, ip, username, password):
        """SSH ile sistem bilgisi toplama"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=self.timeout)
            
            commands = {
                'hostname': 'hostname',
                'uptime': 'uptime',
                'users': 'who',
                'processes': 'ps aux | head -10',
                'network': 'ip addr show',
                'services': 'systemctl list-units --type=service --state=active | head -15',
                'mounted': 'mount | grep -v tmpfs',
                'last_login': 'last | head -5'
            }
            
            system_info = {}
            for cmd_name, cmd in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output = stdout.read().decode().strip()
                    if output:
                        system_info[cmd_name] = output
                except:
                    pass
            
            ssh.close()
            return system_info
            
        except Exception as e:
            return {'error': str(e)}
    
    # Helper methods
    def extract_title(self, html):
        """HTML'den title çıkar"""
        try:
            import re
            match = re.search(r'<title.*?>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip() if match else ''
        except:
            return ''
    
    def detect_web_technologies(self, html, headers):
        """Web teknolojileri tespit et"""
        technologies = []
        
        # Server header analizi
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'microsoft' in server:
            technologies.append('IIS')
            
        # HTML analizi
        html_lower = html.lower()
        if 'wordpress' in html_lower:
            technologies.append('WordPress')
        if 'drupal' in html_lower:
            technologies.append('Drupal')
        if 'joomla' in html_lower:
            technologies.append('Joomla')
        if 'react' in html_lower:
            technologies.append('React')
        if 'angular' in html_lower:
            technologies.append('Angular')
        if 'vue' in html_lower:
            technologies.append('Vue.js')
            
        return technologies
    
    def extract_forms(self, html):
        """HTML'den formları çıkar"""
        try:
            import re
            forms = re.findall(r'<form.*?</form>', html, re.IGNORECASE | re.DOTALL)
            return len(forms)
        except:
            return 0
    
    def extract_links(self, html):
        """HTML'den linkleri çıkar"""
        try:
            import re
            links = re.findall(r'href=[\'"]?([^\'" >]+)', html, re.IGNORECASE)
            return [link for link in links if not link.startswith('#')]
        except:
            return []
    
    def extract_meta_info(self, html):
        """Meta bilgilerini çıkar"""
        meta_info = {}
        try:
            import re
            
            # Description
            desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
            if desc_match:
                meta_info['description'] = desc_match.group(1)
                
            # Keywords
            keywords_match = re.search(r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
            if keywords_match:
                meta_info['keywords'] = keywords_match.group(1)
                
            # Generator
            gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
            if gen_match:
                meta_info['generator'] = gen_match.group(1)
                
        except:
            pass
            
        return meta_info
    
    def detect_api_endpoints(self, html):
        """API endpoint'leri tespit et"""
        endpoints = []
        try:
            import re
            
            # JavaScript'te API call'ları ara
            api_patterns = [
                r'/api/[^\s"\']+',
                r'/rest/[^\s"\']+',
                r'/v\d+/[^\s"\']+',
                r'fetch\(["\']([^"\']*)["\']',
                r'\.get\(["\']([^"\']*)["\']',
                r'\.post\(["\']([^"\']*)["\']'
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                endpoints.extend(matches)
                
        except:
            pass
            
        return list(set(endpoints))[:10]  # İlk 10 unique endpoint
    
    def detect_admin_panels(self, ip, port, protocol):
        """Admin panel tespiti"""
        admin_paths = [
            '/admin', '/administrator', '/admin.php', '/wp-admin',
            '/cpanel', '/plesk', '/phpmyadmin', '/adminer',
            '/manager/html', '/console', '/dashboard'
        ]
        
        admin_panels = []
        for path in admin_paths:
            try:
                url = f"{protocol}://{ip}:{port}{path}"
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    admin_panels.append({
                        'path': path,
                        'title': self.extract_title(response.text),
                        'status': 'accessible'
                    })
            except:
                pass
                
        return admin_panels
    
    def parse_ssh_version(self, banner):
        """SSH banner'dan versiyon çıkar"""
        try:
            return banner.split('-')[1] if '-' in banner else banner
        except:
            return banner
    
    def analyze_smb_comprehensive(self, ip):
        """SMB derinlemesine analiz"""
        smb_info = {}
        
        try:
            # smbclient ile share listesi
            cmd = f'smbclient -L {ip} -N 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                shares = self.parse_smb_shares(result.stdout)
                smb_info['shares'] = shares
                
                # Her share için detaylı bilgi
                for share in shares:
                    try:
                        cmd = f'smbclient //{ip}/{share} -N -c "ls" 2>/dev/null'
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                        if result.returncode == 0:
                            smb_info[f'share_{share}'] = {
                                'accessible': True,
                                'content': result.stdout[:500]  # İlk 500 karakter
                            }
                    except:
                        pass
            
        except Exception as e:
            smb_info['error'] = str(e)
            
        return smb_info
    
    def parse_smb_shares(self, output):
        """SMB share listesini parse et"""
        shares = []
        try:
            import re
            lines = output.split('\n')
            for line in lines:
                if 'Disk' in line or 'IPC' in line:
                    parts = line.split()
                    if parts:
                        share_name = parts[0].strip()
                        if share_name and share_name not in ['IPC$', 'print$']:
                            shares.append(share_name)
        except:
            pass
        return shares
    
    def analyze_snmp_comprehensive(self, ip):
        """SNMP kapsamlı analiz"""
        snmp_info = {}
        
        try:
            if not SNMP_AVAILABLE:
                snmp_info['error'] = 'pysnmp kütüphanesi bulunamadı'
                return snmp_info
            
            # SNMP OID'ler
            oids = {
                'system_description': '1.3.6.1.2.1.1.1.0',
                'system_name': '1.3.6.1.2.1.1.5.0',
                'system_uptime': '1.3.6.1.2.1.1.3.0',
                'system_contact': '1.3.6.1.2.1.1.4.0',
                'system_location': '1.3.6.1.2.1.1.6.0'
            }
            
            for name, oid in oids.items():
                try:
                    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                        SnmpEngine(),
                        CommunityData('public'),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False):
                        
                        if errorIndication:
                            break
                        elif errorStatus:
                            break
                        else:
                            for varBind in varBinds:
                                snmp_info[name] = str(varBind[1])
                            break
                except:
                    pass
                    
        except Exception as e:
            snmp_info['error'] = str(e)
            
        return snmp_info
    
    def advanced_os_detection(self, ip):
        """Gelişmiş OS tespiti"""
        os_info = {}
        
        try:
            nm = nmap.PortScanner()
            # OS detection için service banner'larından çıkarım yap (root gerektirmez)
            result = nm.scan(ip, arguments='-sT -sV --version-all')
            
            if ip in result['scan']:
                host_info = result['scan'][ip]
                
                # Service-based OS detection
                os_hints = self._analyze_service_os_hints(host_info.get('tcp', {}))
                if os_hints:
                    os_info['service_based_os'] = os_hints
                    
                if 'uptime' in host_info:
                    os_info['uptime'] = host_info['uptime']
                    
        except Exception as e:
            os_info['error'] = str(e)
            
        return os_info
    
    def security_analysis(self, ip):
        """Güvenlik analizi"""
        security_info = {}
        
        try:
            # Açık portlarda zafiyet taraması - Non-privileged alternative
            nm = nmap.PortScanner()
            # Use service detection instead of vuln scripts (no root required)
            result = nm.scan(ip, arguments='-sT -sV --version-all --script-timeout 30s')
            
            if ip in result['scan']:
                host_info = result['scan'][ip]
                if 'tcp' in host_info:
                    for port, port_data in host_info['tcp'].items():
                        if 'script' in port_data:
                            security_info[f'port_{port}_vulns'] = port_data['script']
                            
        except Exception as e:
            security_info['error'] = str(e)
            
        return security_info
    
    def analyze_iot_http(self, ip, port):
        """IoT HTTP servisleri analizi"""
        iot_http_info = {}
        
        try:
            # IoT cihaz spesifik endpoint'ler
            iot_endpoints = [
                '/', '/status', '/info', '/config', '/api',
                '/cgi-bin/luci', '/setup.cgi', '/index.cgi'
            ]
            
            for endpoint in iot_endpoints:
                try:
                    url = f"http://{ip}:{port}{endpoint}"
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        iot_http_info[endpoint] = {
                            'status': 'accessible',
                            'title': self.extract_title(response.text),
                            'size': len(response.content),
                            'iot_indicators': self.detect_iot_indicators(response.text)
                        }
                except:
                    pass
                    
        except Exception as e:
            iot_http_info['error'] = str(e)
            
        return iot_http_info
    
    def detect_iot_indicators(self, html):
        """IoT göstergelerini tespit et"""
        indicators = []
        html_lower = html.lower()
        
        iot_keywords = [
            'temperature', 'humidity', 'sensor', 'gpio', 'arduino',
            'raspberry', 'esp8266', 'esp32', 'mqtt', 'zigbee',
            'homekit', 'alexa', 'google home', 'smart home'
        ]
        
        for keyword in iot_keywords:
            if keyword in html_lower:
                indicators.append(keyword)
                
        return indicators
    
    def extract_discovered_ports(self, enhanced_info):
        """Enhanced analiz sonucunda bulunan servisleri open_ports formatına dönüştürür"""
        discovered_ports = []
        
        try:
            # 1. Web servisleri analizi
            web_services = enhanced_info.get('web_services', {})
            for service_key, service_data in web_services.items():
                if isinstance(service_data, dict) and 'error' not in service_data:
                    # Service key'den port ve protokolü çıkar (örn: http_8080, https_443)
                    port_match = re.search(r'(\d+)$', service_key)
                    if port_match:
                        port = int(port_match.group(1))
                        
                        # Servis tanımını oluştur
                        description = self.generate_service_description(service_data, service_key)
                        
                        if description:
                            discovered_ports.append({
                                'port': port,
                                'description': description,
                                'manual': True,
                                'source': 'enhanced_analysis'
                            })
            
            # 2. Raspberry Pi servisleri
            rpi_analysis = enhanced_info.get('raspberry_pi_analysis', {})
            for key, data in rpi_analysis.items():
                if key.startswith('service_') and isinstance(data, dict):
                    port_str = key.replace('service_', '')
                    try:
                        port = int(port_str)
                        indicator = data.get('indicator', '')
                        title = data.get('title', '')
                        
                        # RPI servis tanımını oluştur
                        description = self.generate_rpi_service_description(indicator, title)
                        
                        if description:
                            discovered_ports.append({
                                'port': port,
                                'description': description,
                                'manual': True,
                                'source': 'raspberry_pi_analysis'
                            })
                    except ValueError:
                        continue
            
            # 3. SSH servisi
            ssh_info = enhanced_info.get('remote_access', {}).get('ssh', {})
            if ssh_info.get('banner'):
                discovered_ports.append({
                    'port': 22,
                    'description': f"SSH - {ssh_info.get('banner', 'OpenSSH')}",
                    'manual': True,
                    'source': 'ssh_analysis'
                })
            
            # 4. Detailed ports analizi
            detailed_ports = enhanced_info.get('detailed_ports', {})
            for port_key, port_data in detailed_ports.items():
                if isinstance(port_key, (int, str)) and str(port_key).isdigit():
                    port = int(port_key)
                    if isinstance(port_data, dict) and port_data.get('state') == 'open':
                        service = port_data.get('service', '')
                        version = port_data.get('version', '')
                        product = port_data.get('product', '')
                        
                        # Detaylı servis tanımını oluştur
                        description = self.generate_detailed_port_description(service, version, product)
                        
                        if description and port not in [p['port'] for p in discovered_ports]:
                            discovered_ports.append({
                                'port': port,
                                'description': description,
                                'manual': True,
                                'source': 'port_scan'
                            })
            
            # 5. IoT protokolleri
            iot_analysis = enhanced_info.get('iot_analysis', {})
            for protocol_key, protocol_data in iot_analysis.items():
                if isinstance(protocol_data, dict) and protocol_data.get('port'):
                    port = protocol_data['port']
                    protocol = protocol_data.get('protocol', protocol_key.upper())
                    
                    discovered_ports.append({
                        'port': port,
                        'description': f"{protocol} Service",
                        'manual': True,
                        'source': 'iot_analysis'
                    })
            
        except Exception as e:
            print(f"Extract discovered ports hatası: {e}")
        
        return discovered_ports
    
    def generate_service_description(self, service_data, service_key):
        """Web servis verilerinden açıklama oluşturur"""
        try:
            title = service_data.get('title', '').strip()
            server = service_data.get('server', '').strip()
            
            # Özel uygulama tespitleri
            if 'qbittorrent' in title.lower() or 'qbittorrent' in server.lower():
                return "qBittorrent WebUI"
            elif 'speedtest' in title.lower():
                return "Speedtest Tracker"
            elif 'pi-hole' in title.lower():
                return "Pi-hole Admin"
            elif 'jupyter' in title.lower():
                return "Jupyter Notebook"
            elif 'portainer' in title.lower():
                return "Portainer Docker Management"
            elif 'grafana' in title.lower():
                return "Grafana Dashboard"
            elif 'prometheus' in title.lower():
                return "Prometheus Monitoring"
            elif 'nginx' in server.lower() and not title:
                return "Nginx Web Server"
            elif 'apache' in server.lower() and not title:
                return "Apache Web Server"
            elif title and len(title) > 3:
                # Genel title kullan (çok kısa değilse)
                return f"Web Service - {title[:50]}"
            elif server:
                return f"Web Server - {server}"
            else:
                # Protocol'e göre genel isim
                if 'https' in service_key:
                    return "HTTPS Web Service"
                else:
                    return "HTTP Web Service"
                    
        except Exception as e:
            print(f"Service description hatası: {e}")
            return "Web Service"
    
    def generate_rpi_service_description(self, indicator, title):
        """Raspberry Pi servis verilerinden açıklama oluşturur"""
        try:
            if indicator == 'pi-hole':
                return "Pi-hole DNS"
            elif indicator == 'jupyter':
                return f"Jupyter - {title}" if title else "Jupyter Notebook"
            elif indicator == 'web_interface':
                if 'qbittorrent' in title.lower():
                    return "qBittorrent WebUI"
                elif title:
                    return f"Web Interface - {title[:30]}"
                else:
                    return "Web Interface"
            elif indicator == 'flask_app':
                return f"Flask App - {title}" if title else "Flask Application"
            elif indicator == 'node_app':
                return f"Node.js App - {title}" if title else "Node.js Application"
            else:
                return f"RPI Service - {indicator}" if indicator else "Raspberry Pi Service"
                
        except Exception as e:
            print(f"RPI service description hatası: {e}")
            return "Raspberry Pi Service"
    
    def generate_detailed_port_description(self, service, version, product):
        """Detaylı port verilerinden açıklama oluşturur"""
        try:
            description_parts = []
            
            if product:
                description_parts.append(product)
            elif service and service != 'unknown':
                description_parts.append(service.upper())
            
            if version:
                description_parts.append(version)
            
            if description_parts:
                return " - ".join(description_parts)
            else:
                return None
                
        except Exception as e:
            print(f"Detailed port description hatası: {e}")
            return None
    
    def _analyze_service_os_hints(self, tcp_ports):
        """Service banner'larından OS hint'leri çıkar"""
        os_hints = {
            'detected_systems': [],
            'confidence_scores': {},
            'service_evidence': []
        }
        
        for port, service_info in tcp_ports.items():
            if service_info.get('state') == 'open':
                product = service_info.get('product', '').lower()
                version = service_info.get('version', '').lower()
                name = service_info.get('name', '').lower()
                extrainfo = service_info.get('extrainfo', '').lower()
                
                # Service evidence toplama
                evidence = f"Port {port}: {product} {version} ({name}) {extrainfo}".strip()
                os_hints['service_evidence'].append(evidence)
                
                # OS detection patterns
                if 'openssh' in product:
                    if 'ubuntu' in version or 'debian' in version:
                        self._add_os_hint(os_hints, 'Linux (Ubuntu/Debian)', 0.7)
                    elif 'centos' in version or 'rhel' in version:
                        self._add_os_hint(os_hints, 'Linux (CentOS/RHEL)', 0.7)
                    else:
                        self._add_os_hint(os_hints, 'Linux/Unix', 0.5)
                
                elif 'microsoft' in product or 'windows' in product:
                    self._add_os_hint(os_hints, 'Windows', 0.8)
                
                elif 'apache' in product:
                    if 'ubuntu' in extrainfo or 'debian' in extrainfo:
                        self._add_os_hint(os_hints, 'Linux (Ubuntu/Debian)', 0.6)
                    elif 'win' in extrainfo:
                        self._add_os_hint(os_hints, 'Windows', 0.6)
                    else:
                        self._add_os_hint(os_hints, 'Unix-like', 0.4)
                
                elif 'nginx' in product:
                    self._add_os_hint(os_hints, 'Linux/Unix', 0.5)
                
                elif 'cisco' in product or 'ios' in extrainfo:
                    self._add_os_hint(os_hints, 'Cisco IOS', 0.9)
                
                elif name == 'netbios-ssn' or name == 'microsoft-ds':
                    self._add_os_hint(os_hints, 'Windows', 0.7)
                
                elif name == 'telnet' and 'cisco' in extrainfo:
                    self._add_os_hint(os_hints, 'Cisco IOS', 0.8)
        
        # En yüksek confidence'lı sistemleri belirle
        if os_hints['confidence_scores']:
            sorted_os = sorted(os_hints['confidence_scores'].items(), 
                             key=lambda x: x[1], reverse=True)
            os_hints['detected_systems'] = [os_type for os_type, score in sorted_os if score > 0.3]
        
        return os_hints if os_hints['detected_systems'] else None
    
    def _add_os_hint(self, os_hints, os_type, confidence):
        """OS hint ekle ve confidence score'u güncelle"""
        if os_type in os_hints['confidence_scores']:
            # Mevcut confidence'ı güncelle (max'ı al)
            os_hints['confidence_scores'][os_type] = max(
                os_hints['confidence_scores'][os_type], confidence
            )
        else:
            os_hints['confidence_scores'][os_type] = confidence
    
    def comprehensive_device_type_analysis(self, ip, mac, hostname, vendor, enhanced_info):
        """Kapsamlı cihaz tipi analizi - tüm cihaz tiplerini değerlendir"""
        try:
            # SmartDeviceIdentifier kullanarak cihaz tipini belirle
            from smart_device_identifier import SmartDeviceIdentifier
            from config import ConfigManager
            
            config_manager = ConfigManager()
            identifier = SmartDeviceIdentifier(config_manager)
            
            # Device info oluştur
            device_info = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'open_ports': self._extract_open_ports_from_enhanced(enhanced_info)
            }
            
            # Kapsamlı tanımlama yap
            identification_result = identifier.identify_device_comprehensive(
                device_info, enhanced_info
            )
            
            # Tüm cihaz tiplerinin skorlarını al
            all_scores = identification_result.get('scores', {})
            
            # Cihaz tipi analizi sonucu
            analysis_result = {
                'detected_type': identification_result.get('device_type', 'unknown'),
                'confidence': identification_result.get('confidence', 0.0),
                'device_probabilities': {},
                'indicators': {},
                'detailed_analysis': identification_result.get('details', {})
            }
            
            # Her cihaz tipi için olasılık hesapla
            device_types = [
                'camera', 'smart_tv', 'air_conditioner', 'apple_device', 
                'gaming_console', 'pet_device', 'router', 'printer', 
                'nas', 'smartphone', 'iot_device'
            ]
            
            max_score = max(all_scores.values()) if all_scores else 1
            
            for device_type in device_types:
                score = all_scores.get(device_type, 0)
                probability = min(score / max(max_score, 20), 1.0) if max_score > 0 else 0
                
                analysis_result['device_probabilities'][device_type] = probability
                
                # Her cihaz tipi için göstergeleri topla
                analysis_result['indicators'][device_type] = self._get_device_type_indicators(
                    device_type, enhanced_info, device_info
                )
            
            return analysis_result
            
        except Exception as e:
            print(f"Comprehensive device type analysis hatası: {e}")
            return {
                'detected_type': 'unknown',
                'confidence': 0.0,
                'device_probabilities': {},
                'indicators': {},
                'detailed_analysis': {}
            }
    
    def _extract_open_ports_from_enhanced(self, enhanced_info):
        """Enhanced info'dan açık portları çıkar"""
        open_ports = []
        
        # Detailed ports'tan al
        detailed_ports = enhanced_info.get('detailed_ports', {})
        for port, port_info in detailed_ports.items():
            if port_info.get('state') == 'open':
                open_ports.append({
                    'port': port,
                    'service': port_info.get('service', 'unknown'),
                    'description': port_info.get('service', 'unknown')
                })
        
        return open_ports
    
    def _get_device_type_indicators(self, device_type, enhanced_info, device_info):
        """Cihaz tipi için spesifik göstergeleri topla"""
        indicators = []
        
        try:
            hostname = device_info.get('hostname', '').lower()
            vendor = device_info.get('vendor', '').lower()
            web_services = enhanced_info.get('web_services', {})
            open_ports = device_info.get('open_ports', [])
            port_numbers = [p.get('port') if isinstance(p, dict) else p for p in open_ports]
            
            if device_type == 'camera':
                if 'cam' in hostname or 'camera' in hostname:
                    indicators.append('camera_hostname')
                if 554 in port_numbers:  # RTSP
                    indicators.append('rtsp_service')
                if any('hikvision' in vendor or 'dahua' in vendor for vendor in [vendor]):
                    indicators.append('camera_vendor')
                for protocol in ['http', 'https']:
                    if protocol in web_services:
                        title = web_services[protocol].get('title', '').lower()
                        if 'camera' in title or 'surveillance' in title:
                            indicators.append('camera_web_interface')
            
            elif device_type == 'smart_tv':
                if 'tv' in hostname:
                    indicators.append('tv_hostname')
                if any(p in port_numbers for p in [8008, 9080]):
                    indicators.append('tv_ports')
                if any(v in vendor for v in ['samsung', 'lg', 'sony']):
                    indicators.append('tv_vendor')
            
            elif device_type == 'air_conditioner':
                if any(word in hostname for word in ['ac', 'aircon', 'hvac']):
                    indicators.append('ac_hostname')
                if 502 in port_numbers:  # Modbus
                    indicators.append('modbus_protocol')
                if any(v in vendor for v in ['daikin', 'mitsubishi']):
                    indicators.append('ac_vendor')
            
            elif device_type == 'apple_device':
                if any(word in hostname for word in ['iphone', 'ipad', 'macbook', 'imac']):
                    indicators.append('apple_hostname')
                if 'apple' in vendor:
                    indicators.append('apple_vendor')
                if any(p in port_numbers for p in [7000, 7001, 5353]):
                    indicators.append('apple_services')
            
            elif device_type == 'gaming_console':
                if any(word in hostname for word in ['xbox', 'playstation', 'ps3', 'ps4', 'ps5']):
                    indicators.append('console_hostname')
                if any(v in vendor for v in ['microsoft', 'sony']):
                    indicators.append('console_vendor')
                if any(p in port_numbers for p in [3074, 1935]):
                    indicators.append('gaming_ports')
            
            elif device_type == 'pet_device':
                if any(word in hostname for word in ['pet', 'feeder', 'litter']):
                    indicators.append('pet_hostname')
                if any(v in vendor for v in ['petnet', 'petcube']):
                    indicators.append('pet_vendor')
            
        except Exception as e:
            print(f"Device type indicators hatası ({device_type}): {e}")
        
        return indicators
    
    def credential_based_analysis(self, ip):
        """Credential manager'dan alınan erişim bilgileri ile derin analiz"""
        analysis_result = {
            'access_methods': {},
            'system_info': {},
            'services_discovered': {},
            'detailed_commands': {},
            'security_analysis': {}
        }
        
        if not self.credential_manager:
            analysis_result['error'] = 'Credential manager mevcut değil'
            return analysis_result
        
        try:
            # Tüm kaydedilmiş credential'ları al
            all_credentials = self.credential_manager.get_all_device_credentials(ip)
            
            for access_type, creds in all_credentials.items():
                if not creds:
                    continue
                    
                analysis_result['access_methods'][access_type] = {
                    'available': True,
                    'tested': False,
                    'data': {}
                }
                
                # Her erişim türü için özel analiz
                if access_type == 'ssh':
                    ssh_analysis = self._analyze_via_ssh(ip, creds)
                    analysis_result['access_methods']['ssh']['data'] = ssh_analysis
                    analysis_result['access_methods']['ssh']['tested'] = True
                    
                elif access_type == 'http':
                    http_analysis = self._analyze_via_http(ip, creds)
                    analysis_result['access_methods']['http']['data'] = http_analysis
                    analysis_result['access_methods']['http']['tested'] = True
                    
                elif access_type == 'ftp':
                    ftp_analysis = self._analyze_via_ftp(ip, creds)
                    analysis_result['access_methods']['ftp']['data'] = ftp_analysis
                    analysis_result['access_methods']['ftp']['tested'] = True
                    
                elif access_type == 'snmp':
                    snmp_analysis = self._analyze_via_snmp(ip, creds)
                    analysis_result['access_methods']['snmp']['data'] = snmp_analysis
                    analysis_result['access_methods']['snmp']['tested'] = True
                    
                elif access_type == 'api':
                    api_analysis = self._analyze_via_api(ip, creds)
                    analysis_result['access_methods']['api']['data'] = api_analysis
                    analysis_result['access_methods']['api']['tested'] = True
            
            # Genel sistem bilgilerini birleştir
            self._merge_system_info(analysis_result)
            
        except Exception as e:
            analysis_result['error'] = f'Credential based analysis hatası: {str(e)}'
        
        return analysis_result
    
    def _analyze_via_ssh(self, ip, creds):
        """SSH üzerinden detaylı sistem analizi"""
        analysis = {
            'system_info': {},
            'services': [],
            'processes': [],
            'network_config': {},
            'hardware_info': {},
            'logs': {},
            'security_check': {}
        }
        
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                ip, 
                username=creds.get('username'),
                password=creds.get('password'),
                port=creds.get('port', 22),
                timeout=10
            )
            
            # Sistem bilgileri komutları
            commands = {
                'system_info': {
                    'uname': 'uname -a',
                    'os_release': 'cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null',
                    'uptime': 'uptime',
                    'whoami': 'whoami',
                    'hostname': 'hostname',
                    'date': 'date'
                },
                'hardware_info': {
                    'cpu_info': 'cat /proc/cpuinfo | head -20',
                    'memory': 'free -h',
                    'disk_usage': 'df -h',
                    'lscpu': 'lscpu 2>/dev/null',
                    'temperature': 'vcgencmd measure_temp 2>/dev/null'  # Raspberry Pi
                },
                'network_config': {
                    'interfaces': 'ip addr show 2>/dev/null || ifconfig',
                    'route': 'ip route 2>/dev/null || route -n',
                    'dns': 'cat /etc/resolv.conf',
                    'listening_ports': 'netstat -tlnp 2>/dev/null || ss -tlnp'
                },
                'services': {
                    'systemctl': 'systemctl list-units --type=service --state=active 2>/dev/null | head -20',
                    'ps_aux': 'ps aux | head -20',
                    'docker': 'docker ps 2>/dev/null',
                    'crontab': 'crontab -l 2>/dev/null'
                },
                'security_check': {
                    'users': 'cat /etc/passwd | grep -v nologin | grep -v false',
                    'sudo_config': 'sudo -l 2>/dev/null',
                    'ssh_config': 'cat /etc/ssh/sshd_config 2>/dev/null | grep -v "#"',
                    'last_login': 'last | head -10'
                }
            }
            
            # Komutları çalıştır
            for category, cmd_dict in commands.items():
                analysis[category] = {}
                for cmd_name, command in cmd_dict.items():
                    try:
                        stdin, stdout, stderr = ssh.exec_command(command)
                        output = stdout.read().decode('utf-8', errors='ignore').strip()
                        if output:
                            analysis[category][cmd_name] = output
                    except Exception as e:
                        analysis[category][cmd_name] = f'Error: {str(e)}'
            
            ssh.close()
            
        except Exception as e:
            analysis['error'] = f'SSH analiz hatası: {str(e)}'
        
        return analysis
    
    def _analyze_via_http(self, ip, creds):
        """HTTP üzerinden web arayüzü analizi"""
        analysis = {
            'web_interface': {},
            'api_endpoints': [],
            'admin_panels': [],
            'technology_stack': {},
            'security_headers': {}
        }
        
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            port = creds.get('port', 80)
            username = creds.get('username')
            password = creds.get('password')
            
            protocols = ['http', 'https'] if port in [443, 8443] else ['http']
            
            for protocol in protocols:
                try:
                    base_url = f"{protocol}://{ip}:{port}"
                    
                    # Ana sayfa analizi
                    response = requests.get(
                        base_url, 
                        auth=HTTPBasicAuth(username, password) if username else None,
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        analysis['web_interface']['title'] = self._extract_title(response.text)
                        analysis['web_interface']['server'] = response.headers.get('Server', '')
                        analysis['web_interface']['technology'] = self._detect_technology(response)
                        analysis['security_headers'] = dict(response.headers)
                        
                        # API endpoint'lerini tara
                        api_endpoints = ['/api', '/api/v1', '/status', '/config', '/admin', '/management']
                        for endpoint in api_endpoints:
                            try:
                                api_response = requests.get(
                                    f"{base_url}{endpoint}",
                                    auth=HTTPBasicAuth(username, password) if username else None,
                                    timeout=5,
                                    verify=False
                                )
                                if api_response.status_code == 200:
                                    analysis['api_endpoints'].append({
                                        'endpoint': endpoint,
                                        'status': api_response.status_code,
                                        'content_type': api_response.headers.get('Content-Type', '')
                                    })
                            except:
                                pass
                        
                        break  # Başarılıysa diğer protokolü deneme
                        
                except Exception as e:
                    continue
            
        except Exception as e:
            analysis['error'] = f'HTTP analiz hatası: {str(e)}'
        
        return analysis
    
    def _analyze_via_ftp(self, ip, creds):
        """FTP üzerinden dosya sistemi analizi"""
        analysis = {
            'directory_structure': {},
            'file_listing': [],
            'permissions': {},
            'server_info': {}
        }
        
        try:
            import ftplib
            
            ftp = ftplib.FTP()
            ftp.connect(ip, creds.get('port', 21))
            ftp.login(creds.get('username'), creds.get('password'))
            
            # Server bilgisi
            analysis['server_info']['welcome'] = ftp.getwelcome()
            
            # Dizin listesi
            try:
                files = ftp.nlst()
                analysis['file_listing'] = files[:20]  # İlk 20 dosya
                
                # Detaylı liste
                detailed_list = []
                ftp.retrlines('LIST', detailed_list.append)
                analysis['directory_structure']['detailed'] = detailed_list[:10]
                
            except Exception as e:
                analysis['directory_structure']['error'] = str(e)
            
            ftp.quit()
            
        except Exception as e:
            analysis['error'] = f'FTP analiz hatası: {str(e)}'
        
        return analysis
    
    def _analyze_via_snmp(self, ip, creds):
        """SNMP üzerinden sistem yönetim bilgileri"""
        analysis = {
            'system_info': {},
            'network_interfaces': {},
            'performance_data': {},
            'device_info': {}
        }
        
        try:
            from pysnmp.hlapi import (
                SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity, nextCmd
            )
            
            port = creds.get('port', 161)
            community = creds.get('username', 'public')
            
            # Sistem OID'leri
            oids = {
                'system_description': '1.3.6.1.2.1.1.1.0',
                'system_uptime': '1.3.6.1.2.1.1.3.0',
                'system_contact': '1.3.6.1.2.1.1.4.0',
                'system_name': '1.3.6.1.2.1.1.5.0',
                'system_location': '1.3.6.1.2.1.1.6.0'
            }
            
            for name, oid in oids.items():
                try:
                    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                        SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, port), timeout=10),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False,
                        maxRows=1
                    ):
                        if not errorIndication and not errorStatus:
                            for varBind in varBinds:
                                analysis['system_info'][name] = varBind[1].prettyPrint()
                        break
                except Exception as e:
                    analysis['system_info'][name] = f'Error: {str(e)}'
            
        except ImportError:
            analysis['error'] = 'SNMP analiz için pysnmp kütüphanesi gerekli'
        except Exception as e:
            analysis['error'] = f'SNMP analiz hatası: {str(e)}'
        
        return analysis
    
    def _analyze_via_api(self, ip, creds):
        """API üzerinden sistem bilgisi toplama"""
        analysis = {
            'api_info': {},
            'endpoints': [],
            'data': {},
            'capabilities': []
        }
        
        try:
            import requests
            
            port = creds.get('port', 80)
            token = creds.get('password')
            additional_info = creds.get('additional_info', {})
            
            protocols = ['http', 'https'] if port in [443, 8443] else ['http']
            
            for protocol in protocols:
                base_url = f"{protocol}://{ip}:{port}"
                
                # Farklı auth yöntemlerini dene
                auth_headers = [
                    {'Authorization': f'Bearer {token}'},
                    {'X-API-Key': token},
                    {'API-Key': token}
                ]
                
                for headers in auth_headers:
                    try:
                        # API bilgi endpoint'lerini dene
                        info_endpoints = ['/api/info', '/api/status', '/api/version', '/info', '/status']
                        
                        for endpoint in info_endpoints:
                            response = requests.get(
                                f"{base_url}{endpoint}",
                                headers=headers,
                                timeout=10,
                                verify=False
                            )
                            
                            if response.status_code == 200:
                                try:
                                    data = response.json()
                                    analysis['data'][endpoint] = data
                                    analysis['endpoints'].append(endpoint)
                                except:
                                    analysis['data'][endpoint] = response.text[:500]
                        
                        if analysis['endpoints']:  # Başarılıysa dur
                            break
                            
                    except Exception as e:
                        continue
                
                if analysis['endpoints']:  # Başarılıysa diğer protokolü deneme
                    break
            
        except Exception as e:
            analysis['error'] = f'API analiz hatası: {str(e)}'
        
        return analysis
    
    def _merge_system_info(self, analysis_result):
        """Farklı kaynaklardan gelen sistem bilgilerini birleştir"""
        system_info = {}
        
        # SSH'dan sistem bilgisi
        if 'ssh' in analysis_result['access_methods']:
            ssh_data = analysis_result['access_methods']['ssh'].get('data', {})
            if 'system_info' in ssh_data:
                system_info.update(ssh_data['system_info'])
        
        # SNMP'den sistem bilgisi
        if 'snmp' in analysis_result['access_methods']:
            snmp_data = analysis_result['access_methods']['snmp'].get('data', {})
            if 'system_info' in snmp_data:
                system_info.update(snmp_data['system_info'])
        
        # API'den sistem bilgisi
        if 'api' in analysis_result['access_methods']:
            api_data = analysis_result['access_methods']['api'].get('data', {})
            system_info['api_info'] = api_data
        
        analysis_result['system_info'] = system_info
    
    def _extract_title(self, html):
        """HTML'den title çıkar"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ''
    
    def _detect_technology(self, response):
        """Response'dan teknoloji stack'ini tespit et"""
        tech = []
        
        # Header'lardan
        server = response.headers.get('Server', '').lower()
        if 'nginx' in server:
            tech.append('Nginx')
        if 'apache' in server:
            tech.append('Apache')
        if 'flask' in server:
            tech.append('Flask')
        
        # Content'ten
        content = response.text.lower()
        if 'react' in content:
            tech.append('React')
        if 'vue' in content:
            tech.append('Vue.js')
        if 'angular' in content:
            tech.append('Angular')
        if 'jquery' in content:
            tech.append('jQuery')
        
        return tech