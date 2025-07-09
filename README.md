# My Network Scanner (MyNeS) 🌐

**My Network Scanner (MyNeS)**, "*Y*our Family's User-Friendly Network Scanner" mottosu ile geliştirilmiş, yerel ağınızdaki tüm cihazları (Router/Modem, Laptop, Tablet, Desktop, Server, IP Camera, Gaming Console, Smart Home Appliances, .....) tarayıp, tespit ettiği cihazlar ile ilgili detaylı bilgileri toplayıp, kullanıcı dostu ve kolay bir arayüz üzerinden cihazlarınızı yönetebilmenizi sağlayan profesyonel bir uygulamadır.

Modern ve kullanıcı dostu web arayüzü ile ağ yönetimini kolaylaştırır. Gelişmiş ve detaylı tarama, AI destekli cihaz tanıma ve güvenlik özellikleri sunar.

![Alt text](assets/mynes.png "a title")

> *Bu uygulama tümüyle **AI destekli** olarak (**Agentic Mode**) [Claude Code](https://www.anthropic.com/claude-code)*, [Github Copilot](https://github.com/features/copilot) ve *[Visual Studio Code](https://code.visualstudio.com/) kullanılarak tümüyle **Open-Source** olarak geliştirilmiştir.*

## ✨ Özellikler

### 🔍 Kapsamlı Ağ Taraması

- **Otomatik Ağ Keşfi**: Yerel ağ aralığını otomatik olarak belirler
- **ARP Taraması**: Hızlı cihaz keşfi için ARP protokolü kullanır
- **Gelişmiş Port Taraması**: 1000+ port ile kapsamlı servis tespiti
- **Cihaz Tipleri**: Router, bilgisayar, telefon, kamera vb. otomatik tespit
- **Docker Entegrasyonu**: Container ve virtual network tespiti
- **Multi-Protocol Analiz**: SSH, FTP, HTTP, SNMP desteği

### 📊 Detaylı Cihaz Bilgileri

- **IP Adresleri**: IPv4 adresleri
- **MAC Adresleri**: Fiziksel ağ adresleri
- **Hostname**: Cihaz isimleri
- **Üretici Bilgisi**: IEEE OUI veritabanı ve online API'ler ile gelişmiş vendor tespiti
- **Açık Portlar**: Aktif servisler ve port numaraları
- **Cihaz Tipi**: Otomatik cihaz kategorilendirmesi
- **Sistem Bilgileri**: İşletim sistemi, donanım özellikleri
- **Güvenlik Analizi**: Zafiyetler ve güvenlik durumu
- **Docker Bilgileri**: Container durumu ve network mapping

### 🏭 Gelişmiş OUI/Vendor Yönetimi

- **Multi-Source IEEE Desteği**: OUI, MA-M, OUI-36, IAB, CID kayıtlarını destekler
- **Otomatik Güncellemeler**: IEEE kaynaklarından güncel veritabanı indirme
- **Online API Fallback**: Bilinmeyen MAC'ler için otomatik online arama
- **37,000+ Üretici Kaydı**: Kapsamlı vendor veritabanı
- **Akıllı Vendor Temizleme**: Organizasyon isimlerini normalize etme

### 🎯 AI Destekli Akıllı Cihaz Tanıma

Uygulama aşağıdaki bilgileri kullanarak cihaz tipini otomatik olarak belirler:

- **Hostname Analizi**: Cihaz isimlerinden pattern tanıma
- **Üretici Firma Bilgisi**: Vendor tabanlı sınıflandırma
- **Açık Port Analizi**: Servis tabanlı tespit
- **Bilinen Cihaz İmzaları**: Makine öğrenmesi ile güven skorları
- **Akıllı İsimlendirme**: Otomatik alias ve isim üretimi
- **Kategori Sınıflandırması**: IoT, Sunucu, Router vb. kategoriler

### 🖥️ Modern Web Arayüzü

- **Modular Tasarım**: CSS, JavaScript ve HTML dosyaları ayrılmış
- **Responsive Tasarım**: Mobil ve masaüstü uyumlu
- **Gerçek Zamanlı İlerleme**: Tarama sırasında canlı güncellemeler
- **Arama ve Filtreleme**: Cihazlarda hızlı arama
- **Düzenleme**: Cihaz bilgilerini manuel olarak düzenleme
- **Import/Export**: JSON formatında veri alışverişi
- **Gelişmiş Analiz Arayüzü**: Detaylı cihaz analizi görünümü
- **Credential Yönetimi**: Güvenli giriş bilgisi yönetimi
- **Docker Görselleştirmesi**: Container ve network haritası

### 💾 Veri Yönetimi

- **Organize Dosya Yapısı**: Config ve data dosyaları ayrı dizinlerde
- **JSON Depolama**: Tüm veriler JSON formatında saklanır
- **Manuel Düzenleme**: Cihaz bilgilerini web arayüzünden düzenleme
- **Veri Export/Import**: Verileri yedekleme ve geri yükleme
- **Kalıcı Depolama**: Tarama sonuçları otomatik olarak kaydedilir
- **Birleşik Veri Modeli**: Tutarlı veri yapısı ve validasyon
- **Veri Temizleme**: Güvenli export için hassas veri temizleme

### 🔐 Güvenlik Özellikleri

- **Şifreli Credential Depolama**: Fernet simetrik şifreleme
- **PBKDF2 Anahtar Türetme**: 100,000 iterasyon ile güçlü koruma
- **Master Password Koruması**: Çevre değişkeni desteği
- **Çok Protokol Desteği**: SSH, FTP, HTTP, SNMP credential'ları
- **Güvenli Dosya İzinleri**: Gizli dosyalar için kısıtlı erişim
- **Hassas Veri Temizleme**: Export sırasında otomatik temizleme

### 🐳 Docker Entegrasyonu

- **Container Tespiti**: Çalışan Docker container'ları bulma
- **Network Mapping**: Docker network'leri ve IP atamaları
- **Virtual Interface**: Docker sanal arayüzleri tespiti
- **Container Detayları**: Metadata ve yapılandırma bilgileri
- **Network İzolasyonu**: Container iletişim analizi

## 🛠️ Kurulum

### Gereksinimler

- Python 3.7+
- Nmap (sistem seviyesinde kurulu olmalı)
- Root/Administrator yetkileri (port taraması için)
- Docker (opsiyonel - container tespiti için)
- SSH/FTP/SNMP araçları (gelişmiş analiz için)

### 1. Nmap Kurulumu

**macOS:**

```bash
brew install nmap
```

**Ubuntu/Debian:**

```bash
sudo apt-get update
sudo apt-get install nmap
```

**CentOS/RHEL:**

```bash
sudo yum install nmap
```

### 2. Python Bağımlılıkları

Virtual environment oluşturun (önerilir):

```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# veya
.venv\Scripts\activate     # Windows
```

Gerekli paketleri yükleyin:

```bash
pip install -r requirements.txt
```

## 🚀 Kullanım

### Web Arayüzü ile Kullanım

1. **Uygulamayı Başlatın:**

```bash
source .venv/bin/activate
python app.py
```

2. **Web Arayüzüne Erişin:**
   Tarayıcınızda `http://localhost:5003` adresine gidin
3. **Ağı Tarayın:**

- "Ağı Tara" butonuna tıklayın
- Tarama ilerlemesini takip edin
- Sonuçları inceleyin

### 🔐 Master Password Kurulumu

Güvenli credential depolama için master password ayarlayın:

```bash
export LAN_SCANNER_PASSWORD="your_secure_password"
```

### 🐳 Docker Desteği

Docker container'larını tespit etmek için Docker'ın kurulu ve çalışır durumda olduğundan emin olun:

```bash
docker --version
docker info
```

### Komut Satırı ile Kullanım

```bash
python lan_scanner.py
```

## 📋 Kullanım Kılavuzu

### Web Arayüzü Özellikleri

#### 🔍 Ağ Taraması

- **Ağı Tara**: Yeni bir ağ taraması başlatır
- **Gelişmiş Analiz**: Detaylı cihaz analizi yapar
- **Durdur**: Devam eden taramayı durdurur
- **Yenile**: Mevcut verileri yeniden yükler

#### 📊 İstatistikler

- Toplam cihaz sayısı
- Çevrimiçi cihaz sayısı
- Farklı cihaz tipi sayısı
- Toplam açık port sayısı
- Docker container sayısı
- Güvenlik analizi sonuçları

#### 🔎 Arama ve Filtreleme

Arama kutusunu kullanarak cihazları filtreleyebilirsiniz:

- IP adresi ile arama
- MAC adresi ile arama
- Hostname ile arama
- Cihaz tipi ile arama
- Üretici firma ile arama

#### ✏️ Cihaz Düzenleme

Her cihaz kartında "Düzenle" butonuna tıklayarak:

- Cihaz adını değiştirebilirsiniz
- Cihaz tipini manuel olarak ayarlayabilirsiniz
- Üretici bilgisini düzenleyebilirsiniz
- Notlar ekleyebilirsiniz
- Credential bilgilerini güncelleyebilirsiniz

#### 🔐 Credential Yönetimi

Cihazlar için güvenli giriş bilgileri saklayabilirsiniz:

- **SSH**: Kullanıcı adı ve şifre
- **FTP**: FTP erişim bilgileri
- **HTTP**: Web arayüzü giriş bilgileri
- **SNMP**: SNMP topluluk stringleri
- **Şifreli Depolama**: Tüm bilgiler AES-256 ile şifrelenir

#### 💾 Veri Yönetimi

- **Export**: Tüm cihaz verilerini JSON dosyası olarak indirir
- **Import**: Önceden export edilmiş JSON dosyasını yükler
- **Veri Temizleme**: Export sırasında hassas veriler otomatik temizlenir
- **Birleşik Model**: Tutarlı veri yapısı ile güvenilir depolama

### Desteklenen Cihaz Tipleri

Uygulama aşağıdaki cihaz tiplerini otomatik olarak tespit edebilir:

- 🖥️ **Bilgisayarlar**: Masaüstü, Laptop, Sunucu
- 📱 **Mobil Cihazlar**: Akıllı telefon, Tablet
- 🌐 **Ağ Cihazları**: Router, Modem, Switch, Hub
- 📺 **Eğlence**: Smart TV, Medya oynatıcı
- 📷 **Güvenlik**: IP Kamera, NVR
- 🖨️ **Ofis**: Yazıcı, Tarayıcı
- 💾 **Depolama**: NAS, Dosya sunucusu
- ☎️ **İletişim**: VoIP telefon, Interkom
- 🔧 **Geliştirme**: Raspberry Pi, Arduino, IoT cihazları
- 💻 **Sanallaştırma**: VMware, VirtualBox
- 🐳 **Container**: Docker, Kubernetes pod'ları
- 🏢 **Kurumsal**: Sunucu, SAN, Load Balancer

## 🔧 Yapılandırma

### Port Tarama Ayarları

Varsayılan olarak şu portlar taranır:

- **22**: SSH
- **80, 443, 8080, 8443**: Web servisleri
- **3389**: Remote Desktop
- **554, 8554**: RTSP (IP kameralar)
- **631**: IPP (yazıcılar)
- **5060, 5061**: SIP (VoIP)
- **161**: SNMP
- **21**: FTP
- **23**: Telnet
- **Gelişmiş Tarama**: 1000+ port analizi

Port listesini `lan_scanner.py` dosyasında `scan_ports` metodunda değiştirebilirsiniz.

### Ağ Aralığı

Uygulama otomatik olarak yerel ağ aralığını tespit eder. Manuel olarak değiştirmek için `get_local_network` metodunu düzenleyebilirsiniz. Docker network'leri de otomatik olarak algılanır.

### Master Password Yapılandırması

Güvenli credential depolama için master password ayarları:

```bash
# Çevre değişkeni ile
export LAN_SCANNER_PASSWORD="your_master_password"

# Veya program başlatıldığında girilir
```

### Gelişmiş Analiz Ayarları

Enhanced Device Analyzer için yapılandırma seçenekleri:

- **Timeout**: Bağlantı zaman aşımı (varsayılan: 10 saniye)
- **Thread Sayısı**: Paralel analiz thread'leri (varsayılan: 5)
- **Protokol Desteği**: SSH, FTP, HTTP, SNMP, Telnet
- **Güvenlik Taraması**: Zafiyet tespiti aktif/pasif

## 🛡️ Güvenlik Notları

- **Root Yetkileri**: Port taraması için yönetici yetkileri gerekebilir
- **Güvenlik Duvarı**: Bazı güvenlik duvarları taramayı engelleyebilir
- **Etik Kullanım**: Sadece kendi ağınızı tarayın
- **Performans**: Büyük ağlarda tarama uzun sürebilir
- **Credential Güvenliği**: Tüm giriş bilgileri AES-256 ile şifrelenir
- **Veri Temizleme**: Export sırasında hassas veriler otomatik temizlenir
- **Güvenli Erişim**: SSH anahtar tabanlı kimlik doğrulama önerilir

## 🐛 Sorun Giderme

### Yaygın Sorunlar

#### "Permission denied" Hatası

```bash
sudo python app.py
```

#### Nmap Bulunamadı

Nmap'in sistem PATH'inde olduğundan emin olun:

```bash
nmap --version
```

#### Port Tarama Çalışmıyor

- Güvenlik duvarı ayarlarını kontrol edin
- Yönetici yetkileri ile çalıştırın
- Antivirüs yazılımını geçici olarak devre dışı bırakın

#### Web Arayüzüne Erişim Problemi

- Port 5003'ün kullanımda olmadığından emin olun
- Güvenlik duvarı kurallarını kontrol edin
- `http://127.0.0.1:5003` adresini deneyin

#### Master Password Sorunları

- Çevre değişkeni doğru ayarlandı mı kontrol edin
- Salt dosyalarının (.salt, .key_info) var olduğundan emin olun
- Dosya izinlerini kontrol edin (600 olmalı)

#### Docker Tespiti Çalışmıyor

- Docker servisinin çalıştığını kontrol edin: `docker info`
- Kullanıcının Docker grubunda olduğundan emin olun
- Docker socket'inin erişilebilir olduğunu kontrol edin

#### Credential Şifreleme Hatası

- Master password doğru girildiğinden emin olun
- Config dizininin yazılabilir olduğunu kontrol edin
- Encryption key dosyalarını silin ve yeniden oluşturun

## 📁 Dosya Yapısı

```
lan_scanner/
├── app.py                      # Flask web uygulaması
├── lan_scanner.py              # Ana tarama modülü
├── enhanced_device_analyzer.py # Gelişmiş cihaz analizi
├── smart_device_identifier.py  # AI destekli cihaz tanıma
├── unified_device_model.py     # Birleşik veri modeli
├── credential_manager.py       # Güvenli credential yönetimi
├── docker_manager.py           # Docker container tespiti
├── version.py                  # Dinamik versiyon yönetimi
├── data_sanitizer.py           # Güvenli veri temizleme
├── oui_manager.py              # OUI veritabanı yönetimi
├── config.py                   # Yapılandırma yönetimi
├── requirements.txt            # Python bağımlılıkları
├── config/
│   ├── config.json            # Ana yapılandırma
│   ├── device_types.json      # Cihaz tipi tanımları
│   ├── oui_database.json      # OUI veritabanı
│   ├── .salt                  # Şifreleme salt'ı (gizli)
│   └── .key_info             # Anahtar türetme bilgisi (gizli)
├── data/
│   ├── lan_devices.json       # Cihaz verileri (birleşik model)
│   └── scan_history.json      # Tarama geçmişi
├── templates/
│   └── index.html            # Web arayüzü template
├── static/                    # CSS/JS dosyaları
└── README.md                  # Bu dosya
```

## 🔄 Güncelleme Geçmişi

### v1.0.1 (2025-07-09)

- ✅ AI destekli cihaz tanıma sistemi
- ✅ Gelişmiş cihaz analizi (SSH, FTP, HTTP, SNMP)
- ✅ Güvenli credential yönetimi (AES-256 şifreleme)
- ✅ Docker container tespiti ve network mapping
- ✅ Birleşik veri modeli ve tutarlılık
- ✅ Veri temizleme ve güvenlik özellikleri
- ✅ Dinamik versiyon yönetimi
- ✅ 1000+ port ile kapsamlı tarama
- ✅ Güvenlik analizi ve zafiyet tespiti
- ✅ Raspberry Pi özel tespiti

### v1.0.0 (2025-07-02)

- ✅ İlk sürüm
- ✅ ARP ve port taraması
- ✅ Web arayüzü
- ✅ Cihaz tipı tespiti
- ✅ JSON veri depolama
- ✅ Import/Export özelliği

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

---

**Not**: Bu araç sadece eğitim ve kendi ağınızdaki cihazlar hakkında bilgi sahibi olmak amacıyla kullanılmalıdır.

Başkalarının ağlarını izinsiz taramak yasalara aykırıdır, My Network Scanner (MyNeS) bu tip kullanımları önermez ve desteklemez.
