#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Güvenli Credential Yöneticisi
SSH, FTP, API vs. gibi hassas bilgileri encrypted olarak saklar
"""

import os
import json
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import getpass
from datetime import datetime

class CredentialManager:
    def __init__(self, config_dir='config'):
        self.config_dir = config_dir
        # Artık lan_devices.json kullanıyoruz
        self.devices_file = os.path.join('data', 'lan_devices.json')
        self.salt_file = os.path.join(config_dir, '.salt')
        self.key_file = os.path.join(config_dir, '.key_info')
        self.config_file = os.path.join(config_dir, 'config.json')
        
        # Master password için multiple sources kontrol et
        self.master_password = self._get_master_password_from_sources()
        
        # Encryption key'i initialize et
        self.fernet = None
        self._initialize_encryption()
        
        # Data dizinini oluştur
        os.makedirs('data', exist_ok=True)
    
    def _initialize_encryption(self):
        """Encryption sistemini başlatır"""
        try:
            # Config dizinini oluştur
            os.makedirs(self.config_dir, exist_ok=True)
            
            # Salt dosyası var mı kontrol et
            if not os.path.exists(self.salt_file):
                # İlk kez çalışıyor, yeni salt oluştur
                print(f"📁 Yeni salt dosyası oluşturuluyor: {self.salt_file}")
                self._create_new_salt()
            
            # Salt'ı yükle
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            
            # Master password al
            if not self.master_password:
                print("🔐 Master password alınıyor...")
                self.master_password = self._get_master_password()
            else:
                print("✅ Master password config'den alındı")
            
            # Key'i derive et
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            self.fernet = Fernet(key)
            
            # Key info dosyasını güncelle
            self._update_key_info()
            
            print("✅ Encryption başarıyla başlatıldı")
            
        except Exception as e:
            print(f"❌ Encryption initialization hatası: {e}")
            raise
    
    def _create_new_salt(self):
        """Yeni salt oluşturur"""
        salt = secrets.token_bytes(16)
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        
        # Salt dosyasını gizle (Unix sistemlerde)
        if os.name == 'posix':
            os.chmod(self.salt_file, 0o600)
    
    def _update_key_info(self):
        """Key bilgilerini günceller"""
        key_info = {
            'created_at': datetime.now().isoformat(),
            'algorithm': 'PBKDF2HMAC-SHA256',
            'iterations': 100000,
            'salt_length': 16
        }
        
        with open(self.key_file, 'w') as f:
            json.dump(key_info, f, indent=2)
        
        # Key info dosyasını gizle
        if os.name == 'posix':
            os.chmod(self.key_file, 0o600)
    
    def _get_master_password_from_sources(self):
        """Master password'ü farklı kaynaklardan alır"""
        # 1. Environment variable kontrol et
        env_password = os.environ.get('LAN_SCANNER_PASSWORD')
        if env_password:
            return env_password
        
        # 2. Config.json'dan kontrol et
        config_password = self._get_password_from_config()
        if config_password:
            return config_password
        
        # 3. Hiçbiri yoksa kullanıcıdan iste
        return None
    
    def _get_password_from_config(self):
        """Config.json'dan master password'ü okur"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                security_settings = config.get('security_settings', {})
                return security_settings.get('master_password')
        except Exception as e:
            print(f"Config dosyasından password okuma hatası: {e}")
        return None
    
    def _get_master_password(self):
        """Master password'ü kullanıcıdan alır"""
        # İlk kez mi çalışıyor kontrol et - salt file varsa eskiden kurulmuş
        if not os.path.exists(self.salt_file):
            print("🔐 LAN Scanner Credential Manager")
            print("İlk kez çalıştırıyorsunuz. Lütfen bir master password belirleyin.")
            print("Bu password tüm cihaz erişim bilgilerinizi koruyacak.")
            print("İpucu: Password'ü config.json'da 'security_settings.master_password' olarak saklayabilirsiniz.")
            
            while True:
                password1 = getpass.getpass("Master Password: ")
                password2 = getpass.getpass("Master Password (tekrar): ")
                
                if password1 == password2:
                    if len(password1) < 8:
                        print("❌ Password en az 8 karakter olmalıdır!")
                        continue
                    
                    # Config.json'a kaydetme seçeneği sun
                    save_to_config = input("\nBu password'ü config.json'a kaydetmek ister misiniz? (y/n): ").lower() == 'y'
                    if save_to_config:
                        self._save_password_to_config(password1)
                        print("✅ Password config.json'a kaydedildi.")
                    
                    return password1
                else:
                    print("❌ Password'ler eşleşmiyor!")
        else:
            # Mevcut dosya var, password iste
            return getpass.getpass("Master Password: ")
    
    def _save_password_to_config(self, password):
        """Master password'ü config.json'a kaydeder"""
        try:
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            
            if 'security_settings' not in config:
                config['security_settings'] = {}
            
            config['security_settings']['master_password'] = password
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"Config'e password kaydetme hatası: {e}")
    
    def save_device_credentials(self, ip, access_type, username=None, password=None, port=None, additional_info=None):
        """Cihaz credential'larını lan_devices.json'a şifreli olarak kaydeder"""
        try:
            # lan_devices.json'u yükle
            devices = self._load_devices()
            
            # IP'yi bul
            device_index = None
            for i, d in enumerate(devices):
                if d.get('ip') == ip:
                    device_index = i
                    break
            
            if device_index is None:
                print(f"⚠️ Cihaz bulunamadı: {ip}")
                return False
            
            # Encrypted credentials alanını oluştur
            if 'encrypted_credentials' not in devices[device_index]:
                devices[device_index]['encrypted_credentials'] = {}
            elif isinstance(devices[device_index]['encrypted_credentials'], str):
                # Eski format'tan yeni format'a çevir
                devices[device_index]['encrypted_credentials'] = {}
            
            # Credential bilgilerini hazırla
            credential_data = {
                'username': username,
                'password': password,
                'port': port,
                'additional_info': additional_info or {},
                'created_at': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }
            
            # Encrypt et ve base64 encode et
            json_data = json.dumps(credential_data)
            encrypted_data = self.fernet.encrypt(json_data.encode()).decode()
            devices[device_index]['encrypted_credentials'][access_type] = encrypted_data
            
            # Dosyaya kaydet
            self._save_devices(devices)
            
            print(f"✅ Credential kaydedildi: {ip} -> {access_type} ({username})")
            return True
            
        except Exception as e:
            print(f"❌ Credential kaydetme hatası: {e}")
            return False
    
    def get_device_credentials(self, ip, access_type=None):
        """Cihaz credential'larını lan_devices.json'dan yükler ve decrypt eder"""
        try:
            devices = self._load_devices()
            
            # IP'yi bul
            device = None
            for d in devices:
                if d.get('ip') == ip:
                    device = d
                    break
            
            if not device or 'encrypted_credentials' not in device:
                return None
            
            encrypted_creds = device['encrypted_credentials']
            
            # Eski string formatı kontrol et ve düzelt
            if isinstance(encrypted_creds, str):
                print(f"⚠️ {ip} - Eski credential formatı tespit edildi, temizleniyor...")
                self._remove_corrupted_credential(ip, None)
                return None
            
            # Dict değilse hata
            if not isinstance(encrypted_creds, dict):
                print(f"⚠️ {ip} - Beklenmeyen credential formatı: {type(encrypted_creds)}")
                return None
            
            if access_type:
                # Belirli bir access type iste
                if access_type in encrypted_creds:
                    encrypted_data = encrypted_creds[access_type]
                    
                    # String ise decrypt et
                    if isinstance(encrypted_data, str):
                        try:
                            decrypted_data = self.fernet.decrypt(encrypted_data.encode()).decode()
                            return json.loads(decrypted_data)
                        except Exception as decrypt_error:
                            print(f"❌ {ip} {access_type} decrypt hatası: {decrypt_error}")
                            print(f"⚠️ Bozuk şifreli veri, temizleniyor...")
                            # Bozuk credential'ı sil
                            self._remove_corrupted_credential(ip, access_type)
                            return None
                    else:
                        print(f"⚠️ {ip} {access_type} - Beklenmeyen veri tipi: {type(encrypted_data)}")
                        self._remove_corrupted_credential(ip, access_type)
                        return None
                    
                return None
            else:
                # Tüm credential'ları decrypt et
                result = {}
                corrupted_keys = []
                
                for acc_type, encrypted_data in encrypted_creds.items():
                    try:
                        # String ise decrypt et
                        if isinstance(encrypted_data, str):
                            try:
                                decrypted_data = self.fernet.decrypt(encrypted_data.encode()).decode()
                                credential_obj = json.loads(decrypted_data)
                                result[acc_type] = credential_obj
                                result[acc_type]['has_password'] = bool(credential_obj.get('password'))
                            except Exception as decrypt_error:
                                print(f"❌ {ip} {acc_type} decrypt hatası: {decrypt_error}")
                                print(f"⚠️ Bozuk şifreli veri, temizleniyor...")
                                corrupted_keys.append(acc_type)
                                continue
                        else:
                            print(f"⚠️ {ip} {acc_type} - Beklenmeyen veri tipi: {type(encrypted_data)}")
                            corrupted_keys.append(acc_type)
                            continue
                    except Exception as e:
                        print(f"⚠️ {ip} {acc_type} genel hata: {e}")
                        corrupted_keys.append(acc_type)
                        continue
                
                # Bozuk credential'ları temizle
                for key in corrupted_keys:
                    self._remove_corrupted_credential(ip, key)
                
                return result
            
        except Exception as e:
            print(f"❌ Credential yükleme hatası: {e}")
            return None
    
    def _load_devices(self):
        """lan_devices.json dosyasını yükler"""
        try:
            if os.path.exists(self.devices_file):
                with open(self.devices_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"❌ Devices dosyası yükleme hatası: {e}")
            return []
    
    def _save_devices(self, devices):
        """lan_devices.json dosyasını kaydeder"""
        try:
            with open(self.devices_file, 'w', encoding='utf-8') as f:
                json.dump(devices, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"❌ Devices dosyası kaydetme hatası: {e}")
            return False
            return None
    
    def get_all_credentials(self):
        """Tüm credential'ları döndürür"""
        try:
            return self._load_credentials()
        except Exception as e:
            print(f"❌ Tüm credential'ları yükleme hatası: {e}")
            return {}
    
    def delete_device_credentials(self, ip, access_type=None):
        """Cihaz credential'larını siler"""
        try:
            credentials = self._load_credentials()
            
            if ip in credentials:
                if access_type:
                    if access_type in credentials[ip]:
                        del credentials[ip][access_type]
                        print(f"✅ Credential silindi: {ip} -> {access_type}")
                else:
                    del credentials[ip]
                    print(f"✅ Tüm credential'lar silindi: {ip}")
                
                self._save_credentials(credentials)
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Credential silme hatası: {e}")
            return False
    
    def _load_credentials(self):
        """ESKİ METOD - Artık kullanılmıyor, lan_devices.json kullanıyoruz"""
        if not os.path.exists(self.credentials_file):
            print(f"📝 Credential dosyası bulunamadı, yeni oluşturulacak: {self.credentials_file}")
            return {}
        
        try:
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                print("⚠️ Credential dosyası boş")
                return {}
            
            # Şifreyi çöz
            decrypted_data = self.fernet.decrypt(encrypted_data)
            credentials = json.loads(decrypted_data.decode())
            
            print(f"✅ Credential dosyası başarıyla yüklendi: {len(credentials)} cihaz")
            return credentials
            
        except Exception as e:
            print(f"❌ Credential dosyası yükleme hatası: {e}")
            print(f"❌ Dosya boyutu: {os.path.getsize(self.credentials_file) if os.path.exists(self.credentials_file) else 'N/A'} bytes")
            
            # Corrupted dosya varsa backup oluştur
            if os.path.exists(self.credentials_file):
                backup_file = f"{self.credentials_file}.backup.{int(datetime.now().timestamp())}"
                try:
                    os.rename(self.credentials_file, backup_file)
                    print(f"⚠️ Bozuk credential dosyası yedeklendi: {backup_file}")
                except Exception as backup_error:
                    print(f"❌ Backup oluşturma hatası: {backup_error}")
                    # Backup başarısız olursa dosyayı sil
                    try:
                        os.remove(self.credentials_file)
                        print("🗑️ Bozuk dosya silindi")
                    except Exception as delete_error:
                        print(f"❌ Dosya silme hatası: {delete_error}")
            
            return {}
    
    def _save_credentials(self, credentials):
        """Credential'ları şifreli olarak kaydeder"""
        try:
            if not self.fernet:
                print("❌ Fernet instance yok, encryption başlatılıyor...")
                self._initialize_encryption()
            
            # JSON olarak serialize et
            json_data = json.dumps(credentials, indent=2, ensure_ascii=False)
            
            # Şifrele
            encrypted_data = self.fernet.encrypt(json_data.encode('utf-8'))
            
            # Dosyaya yaz
            os.makedirs(self.config_dir, exist_ok=True)
            
            # Önce temp dosyaya yaz, sonra rename et (atomic operation)
            temp_file = self.credentials_file + '.tmp'
            with open(temp_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Atomic rename
            os.rename(temp_file, self.credentials_file)
            
            # Dosya izinlerini sıkılaştır
            if os.name == 'posix':
                os.chmod(self.credentials_file, 0o600)
            
            print(f"✅ Credential dosyası kaydedildi: {len(credentials)} cihaz, {len(encrypted_data)} bytes")
            
        except Exception as e:
            print(f"❌ Credential dosyası kaydetme hatası: {e}")
            # Temp dosyayı temizle
            temp_file = self.credentials_file + '.tmp'
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
            raise
    
    def test_credentials(self, ip, access_type):
        """Credential'ların doğru çalışıp çalışmadığını test eder"""
        try:
            creds = self.get_device_credentials(ip, access_type)
            if not creds:
                return {'success': False, 'error': 'Credential bulunamadı'}
            
            if access_type == 'ssh':
                return self._test_ssh_credentials(ip, creds)
            elif access_type == 'ftp':
                return self._test_ftp_credentials(ip, creds)
            elif access_type == 'http':
                return self._test_http_credentials(ip, creds)
            elif access_type == 'telnet':
                return self._test_telnet_credentials(ip, creds)
            elif access_type == 'snmp':
                return self._test_snmp_credentials(ip, creds)
            elif access_type == 'api':
                return self._test_api_credentials(ip, creds)
            else:
                return {'success': False, 'error': f'Desteklenmeyen erişim türü: {access_type}'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _test_ssh_credentials(self, ip, creds):
        """SSH credential'larını test eder"""
        try:
            import paramiko
            import socket
            
            # First check basic connectivity
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                port = creds.get('port', 22)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result != 0:
                    return {
                        'success': False,
                        'error': f'Port {port} kapalı veya erişilemiyor'
                    }
            except socket.error as e:
                error_msg = str(e)
                if "Can't assign requested address" in error_msg:
                    return {
                        'success': False,
                        'error': f'Ağ bağlantısı hatası: {ip} adresine erişilemiyor (routing problemi olabilir)'
                    }
                elif "Connection refused" in error_msg:
                    return {
                        'success': False,
                        'error': f'Bağlantı reddedildi: {ip}:{port} SSH servisi çalışmıyor olabilir'
                    }
                elif "Network is unreachable" in error_msg:
                    return {
                        'success': False,
                        'error': f'Ağ erişilemez: {ip} yerel ağda mı? VPN bağlantısı var mı?'
                    }
                elif "Host is down" in error_msg:
                    return {
                        'success': False,
                        'error': f'Hedef cihaz kapalı: {ip} çevrimiçi değil'
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Ağ hatası: {error_msg}'
                    }
            
            # If connectivity is OK, try SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                ip, 
                username=creds.get('username'),
                password=creds.get('password'),
                port=creds.get('port', 22),
                timeout=10
            )
            
            # Basit komut testi
            stdin, stdout, stderr = ssh.exec_command('whoami')
            user = stdout.read().decode().strip()
            
            ssh.close()
            
            return {
                'success': True,
                'user': user,
                'message': 'SSH bağlantısı başarılı'
            }
            
        except paramiko.AuthenticationException:
            return {
                'success': False,
                'error': 'SSH kimlik doğrulama hatası: Kullanıcı adı/şifre yanlış'
            }
        except paramiko.SSHException as e:
            error_msg = str(e)
            if "Unable to connect" in error_msg:
                return {
                    'success': False,
                    'error': f'SSH bağlantısı kurulamadı: {error_msg}'
                }
            else:
                return {
                    'success': False,
                    'error': f'SSH protokol hatası: {error_msg}'
                }
        except socket.error as e:
            error_msg = str(e)
            if "Can't assign requested address" in error_msg:
                return {
                    'success': False,
                    'error': f'Ağ bağlantısı hatası: {ip} adresine erişilemiyor (IP adresi geçersiz olabilir)'
                }
            else:
                return {
                    'success': False,
                    'error': f'Ağ hatası: {error_msg}'
                }
        except Exception as e:
            return {
                'success': False,
                'error': f'SSH test hatası: {str(e)}'
            }
    
    def _test_ftp_credentials(self, ip, creds):
        """FTP credential'larını test eder"""
        try:
            import ftplib
            import socket
            
            # First check basic connectivity
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                port = creds.get('port', 21)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result != 0:
                    return {
                        'success': False,
                        'error': f'FTP port {port} kapalı veya erişilemiyor'
                    }
            except socket.error as e:
                error_msg = str(e)
                if "Can't assign requested address" in error_msg:
                    return {
                        'success': False,
                        'error': f'Ağ bağlantısı hatası: {ip} adresine erişilemiyor'
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Ağ hatası: {error_msg}'
                    }
            
            ftp = ftplib.FTP()
            ftp.connect(ip, creds.get('port', 21))
            ftp.login(creds.get('username'), creds.get('password'))
            
            # Basit dizin listesi testi
            ftp.nlst()
            ftp.quit()
            
            return {
                'success': True,
                'message': 'FTP bağlantısı başarılı'
            }
            
        except ftplib.error_perm as e:
            return {
                'success': False,
                'error': f'FTP kimlik doğrulama hatası: {str(e)}'
            }
        except ftplib.error_temp as e:
            return {
                'success': False,
                'error': f'FTP geçici hata: {str(e)}'
            }
        except socket.error as e:
            error_msg = str(e)
            if "Can't assign requested address" in error_msg:
                return {
                    'success': False,
                    'error': f'Ağ bağlantısı hatası: {ip} adresine erişilemiyor'
                }
            else:
                return {
                    'success': False,
                    'error': f'Ağ hatası: {error_msg}'
                }
        except Exception as e:
            return {
                'success': False,
                'error': f'FTP test hatası: {str(e)}'
            }
    
    def _test_http_credentials(self, ip, creds):
        """HTTP Basic Auth credential'larını test eder"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            port = creds.get('port', 80)
            username = creds.get('username')
            password = creds.get('password')
            
            # HTTP ve HTTPS'i dene
            protocols = ['http', 'https'] if port in [80, 443, 8080, 8443] else ['http']
            
            for protocol in protocols:
                try:
                    url = f"{protocol}://{ip}:{port}/"
                    
                    # Önce credential olmadan dene
                    response = requests.get(url, timeout=10, verify=False)
                    
                    if response.status_code == 401:  # Unauthorized - auth gerekli
                        # Credential ile tekrar dene
                        auth_response = requests.get(
                            url, 
                            auth=HTTPBasicAuth(username, password),
                            timeout=10,
                            verify=False
                        )
                        
                        if auth_response.status_code == 200:
                            return {
                                'success': True,
                                'message': f'HTTP Basic Auth başarılı ({protocol.upper()})',
                                'details': f'Status: {auth_response.status_code}'
                            }
                        else:
                            return {
                                'success': False,
                                'error': f'HTTP Auth başarısız: Status {auth_response.status_code}'
                            }
                    
                    elif response.status_code == 200:
                        return {
                            'success': True,
                            'message': f'HTTP bağlantısı başarılı (auth gerekmedi)',
                            'details': f'Status: {response.status_code}'
                        }
                    
                except requests.exceptions.RequestException:
                    continue
            
            return {
                'success': False,
                'error': 'HTTP servisi ulaşılamıyor'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'HTTP test hatası: {str(e)}'
            }
    
    def _test_telnet_credentials(self, ip, creds):
        """Telnet credential'larını test eder - Socket tabanlı implementasyon"""
        try:
            import socket
            
            port = creds.get('port', 23)
            username = creds.get('username')
            password = creds.get('password')
            
            # Socket ile telnet bağlantısı
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((ip, port))
                
                # Basit bağlantı testi
                response = sock.recv(1024).decode('ascii', errors='ignore')
                
                if response:  # Herhangi bir response varsa bağlantı başarılı
                    sock.close()
                    return {
                        'success': True,
                        'message': 'Telnet portu açık ve yanıt veriyor',
                        'details': f'Response: {response[:50]}...'
                    }
                else:
                    sock.close()
                    return {
                        'success': True,
                        'message': 'Telnet portu açık (response yok)'
                    }
                    
            except socket.error as e:
                sock.close()
                error_msg = str(e)
                if "Can't assign requested address" in error_msg:
                    return {
                        'success': False,
                        'error': f'Ağ bağlantısı hatası: {ip} adresine erişilemiyor'
                    }
                elif "Connection refused" in error_msg:
                    return {
                        'success': False,
                        'error': f'Telnet servisi kapalı: {ip}:{port}'
                    }
                elif "Network is unreachable" in error_msg:
                    return {
                        'success': False,
                        'error': f'Ağ erişilemez: {ip} yerel ağda mı?'
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Telnet bağlantı hatası: {error_msg}'
                    }
            except Exception as e:
                sock.close()
                return {
                    'success': False,
                    'error': f'Telnet bağlantı hatası: {str(e)}'
                }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Telnet test hatası: {str(e)}'
            }
    
    def _test_snmp_credentials(self, ip, creds):
        """SNMP community string'ini test eder"""
        try:
            # SNMP test için pysnmp gerekli
            try:
                from pysnmp.hlapi import (
                    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
                    ObjectType, ObjectIdentity, nextCmd
                )
            except ImportError:
                return {
                    'success': False,
                    'error': 'SNMP test için pysnmp kütüphanesi gerekli'
                }
            
            port = creds.get('port', 161)
            community = creds.get('username', 'public')  # SNMP'de username = community string
            
            # System OID'yi sorgulamaya çalış
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, port), timeout=10),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),  # sysDescr
                lexicographicMode=False,
                maxRows=1
            ):
                if errorIndication:
                    return {
                        'success': False,
                        'error': f'SNMP hatası: {errorIndication}'
                    }
                elif errorStatus:
                    return {
                        'success': False,
                        'error': f'SNMP hatası: {errorStatus.prettyPrint()}'
                    }
                else:
                    # Başarılı response
                    for varBind in varBinds:
                        value = varBind[1].prettyPrint()
                        return {
                            'success': True,
                            'message': 'SNMP community string geçerli',
                            'details': f'System: {value[:50]}...'
                        }
            
            return {
                'success': False,
                'error': 'SNMP response alınamadı'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'SNMP test hatası: {str(e)}'
            }
    
    def _test_api_credentials(self, ip, creds):
        """API Token'ini test eder"""
        try:
            import requests
            
            port = creds.get('port', 80)
            token = creds.get('password')  # API token password alanında
            additional_info = creds.get('additional_info', {})
            
            # Eğer ek bilgilerde endpoint varsa kullan
            endpoints = []
            if isinstance(additional_info, dict):
                if 'endpoint' in additional_info:
                    endpoints.append(additional_info['endpoint'])
                if 'endpoints' in additional_info:
                    endpoints.extend(additional_info['endpoints'])
            
            # Varsayılan API endpoint'leri
            if not endpoints:
                endpoints = ['/api', '/api/v1', '/api/status', '/status', '/']
            
            protocols = ['http', 'https'] if port in [443, 8443] else ['http']
            
            for protocol in protocols:
                for endpoint in endpoints:
                    try:
                        url = f"{protocol}://{ip}:{port}{endpoint}"
                        
                        # Farklı auth yöntemlerini dene
                        auth_methods = [
                            {'headers': {'Authorization': f'Bearer {token}'}},
                            {'headers': {'X-API-Key': token}},
                            {'headers': {'API-Key': token}},
                            {'params': {'token': token}},
                            {'params': {'api_key': token}}
                        ]
                        
                        for auth_method in auth_methods:
                            response = requests.get(
                                url,
                                timeout=10,
                                verify=False,
                                **auth_method
                            )
                            
                            if response.status_code in [200, 201]:
                                return {
                                    'success': True,
                                    'message': f'API token geçerli',
                                    'details': f'Endpoint: {endpoint}, Status: {response.status_code}'
                                }
                            
                    except requests.exceptions.RequestException:
                        continue
            
            return {
                'success': False,
                'error': 'API token geçersiz veya endpoint ulaşılamıyor'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'API test hatası: {str(e)}'
            }
    
    def get_all_device_credentials(self, ip):
        """Bir cihaz için tüm erişim türlerinin credential'larını döndür"""
        try:
            all_creds = {}
            access_types = ['ssh', 'ftp', 'http', 'telnet', 'snmp', 'api']
            
            for access_type in access_types:
                creds = self.get_device_credentials(ip, access_type)
                if creds:
                    all_creds[access_type] = creds
            
            return all_creds
            
        except Exception as e:
            print(f"Get all device credentials hatası: {e}")
            return {}
    
    def change_master_password(self):
        """Master password'ü değiştirir"""
        try:
            print("🔐 Master Password Değiştirme")
            
            # Mevcut credential'ları yükle (lan_devices.json'dan)
            devices = self._load_devices()
            
            # Yeni password al
            while True:
                new_password1 = getpass.getpass("Yeni Master Password: ")
                new_password2 = getpass.getpass("Yeni Master Password (tekrar): ")
                
                if new_password1 == new_password2:
                    if len(new_password1) < 8:
                        print("❌ Password en az 8 karakter olmalıdır!")
                        continue
                    break
                else:
                    print("❌ Password'ler eşleşmiyor!")
            
            # Yeni salt oluştur
            self._create_new_salt()
            
            # Yeni key ile sistemi yeniden başlat
            self.master_password = new_password1
            self._initialize_encryption()
            
            # Credential'ları yeni key ile re-encrypt et
            for device in devices:
                if 'encrypted_credentials' in device:
                    # Her credential'ı decrypt et ve yeni key ile encrypt et
                    temp_creds = {}
                    for access_type, encrypted_data in device['encrypted_credentials'].items():
                        try:
                            # Eski key ile decrypt
                            decrypted_data = self.fernet.decrypt(encrypted_data.encode()).decode()
                            temp_creds[access_type] = json.loads(decrypted_data)
                        except Exception as e:
                            print(f"⚠️ {device['ip']} {access_type} decrypt hatası: {e}")
                    
                    # Yeni key ile encrypt et
                    device['encrypted_credentials'] = {}
                    for access_type, cred_data in temp_creds.items():
                        json_data = json.dumps(cred_data)
                        encrypted_data = self.fernet.encrypt(json_data.encode()).decode()
                        device['encrypted_credentials'][access_type] = encrypted_data
            
            # Güncellenmiş devices'i kaydet
            self._save_devices(devices)
            
            print("✅ Master password başarıyla değiştirildi!")
            return True
            
        except Exception as e:
            print(f"❌ Master password değiştirme hatası: {e}")
            return False
    
    def _remove_corrupted_credential(self, ip, access_type):
        """Bozuk credential'ı temizler"""
        try:
            devices = self._load_devices()
            
            # IP'yi bul
            device_index = None
            for i, d in enumerate(devices):
                if d.get('ip') == ip:
                    device_index = i
                    break
            
            if device_index is not None and 'encrypted_credentials' in devices[device_index]:
                if access_type is None:
                    # Tüm credential'ları temizle
                    devices[device_index]['encrypted_credentials'] = {}
                    self._save_devices(devices)
                    print(f"🗑️ Tüm bozuk credential'lar temizlendi: {ip}")
                elif access_type in devices[device_index]['encrypted_credentials']:
                    # Belirli access_type'ı temizle
                    del devices[device_index]['encrypted_credentials'][access_type]
                    self._save_devices(devices)
                    print(f"🗑️ Bozuk credential temizlendi: {ip} -> {access_type}")
                    
        except Exception as e:
            print(f"❌ Bozuk credential temizleme hatası: {e}")
    
    def export_credentials(self, export_file, include_passwords=False):
        """Credential'ları export eder"""
        try:
            credentials = self._load_credentials()
            
            if not include_passwords:
                # Password'leri gizle
                for ip in credentials:
                    for access_type in credentials[ip]:
                        if 'password' in credentials[ip][access_type]:
                            credentials[ip][access_type]['password'] = '***HIDDEN***'
            
            with open(export_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            
            print(f"✅ Credential'lar export edildi: {export_file}")
            return True
            
        except Exception as e:
            print(f"❌ Export hatası: {e}")
            return False
    
    def get_statistics(self):
        """Credential istatistiklerini döndürür"""
        try:
            credentials = self._load_credentials()
            
            total_devices = len(credentials)
            total_credentials = sum(len(creds) for creds in credentials.values())
            
            access_types = {}
            for device_creds in credentials.values():
                for access_type in device_creds.keys():
                    access_types[access_type] = access_types.get(access_type, 0) + 1
            
            return {
                'total_devices': total_devices,
                'total_credentials': total_credentials,
                'access_types': access_types,
                'encrypted_file': os.path.exists(self.credentials_file),
                'file_size': os.path.getsize(self.credentials_file) if os.path.exists(self.credentials_file) else 0
            }
            
        except Exception as e:
            print(f"❌ İstatistik hatası: {e}")
            return {}


# Singleton instance
credential_manager = None
_initialization_lock = False

def get_credential_manager():
    """Global credential manager instance'ını döndürür"""
    global credential_manager, _initialization_lock
    
    if credential_manager is None and not _initialization_lock:
        _initialization_lock = True
        try:
            print("🔧 CredentialManager instance oluşturuluyor...")
            credential_manager = CredentialManager()
            print("✅ CredentialManager instance hazır")
        except Exception as e:
            print(f"❌ CredentialManager oluşturma hatası: {e}")
            _initialization_lock = False
            raise
        finally:
            _initialization_lock = False
    elif _initialization_lock:
        print("⏳ CredentialManager zaten oluşturuluyor, bekleniyor...")
        import time
        while _initialization_lock:
            time.sleep(0.1)
    
    return credential_manager


if __name__ == "__main__":
    # Test kodu
    cm = CredentialManager()
    
    # Test credential'ı ekle
    cm.save_device_credentials(
        '192.168.1.100', 
        'ssh', 
        username='demo_user', 
        password='demo_password', 
        port=22
    )
    
    # Test credential'ı oku
    creds = cm.get_device_credentials('192.168.1.100', 'ssh')
    print(f"Yüklenen credential: {creds}")
    
    # İstatistikleri göster
    stats = cm.get_statistics()
    print(f"İstatistikler: {stats}")