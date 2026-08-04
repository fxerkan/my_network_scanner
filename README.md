# 🌐 My Network Scanner (MyNeS)

**Beni Oku (Türkçe)** | [**Readme (English)**](README_ENG.md)

**My Network Scanner (MyNeS)**, "***Ailenizin Kullanıcı Dostu Ağ Tarayıcısı***" mottosu ile geliştirilmiş, yerel ağınızdaki tüm cihazları (Router/Modem, Laptop, Tablet, Desktop, Server, IP Camera, Gaming Console, Smart Home Appliances, .....) tarayıp, tespit ettiği cihazlar ile ilgili detaylı bilgileri kullanıcı dostu ve kolay bir arayüz üzerinden kolaylıkla yönetebilmenizi sağlayan profesyonel bir uygulamadır.

Modern ve kullanıcı dostu web arayüzü ile ağ yönetimini kolaylaştırır. Gelişmiş ve detaylı tarama, AI destekli cihaz tanıma ve güvenlik özellikleri sunar.

![Alt text](assets/mynes.png "a title")

> *Bu uygulama tümüyle **AI destekli** olarak (**Agentic Mode**) [Claude Code](https://www.anthropic.com/claude-code)*, [Github Copilot](https://github.com/features/copilot) ve *[Visual Studio Code](https://code.visualstudio.com/) kullanılarak **Open-Source** olarak geliştirilmiştir.*

## 🆕 v2'de Yenilikler

**Home Lab için çoklu protokol keşfi** — IP taraması ev ağının yarısını kaçırır.
MyNeS artık kendini duyuran her şeyi dinliyor:

| Protokol                 | Bulduğu cihazlar                                                                             |
| ------------------------ | --------------------------------------------------------------------------------------------- |
| **mDNS / Bonjour** | Yazıcılar, NAS, Chromecast, HomeKit, Home Assistant, Raspberry Pi                           |
| **Matter**         | `_matter._tcp` / `_matterc._udp` üzerinden Matter düğümleri (mDNS ile birlikte gelir) |
| **SSDP / UPnP**    | Router, Smart TV, DLNA, IP kamera, oyun konsolları                                           |
| **Bluetooth LE**   | Takip cihazları, sensörler, kulaklıklar, saatler —*IP'si olmayan cihazlar*              |
| **MQTT**           | Zigbee2MQTT, Z-Wave JS, Tasmota, Home Assistant MQTT discovery                                |

**Periyodik izleme ve bildirim** — Ağı belirli aralıklarla tarar, iki tarama
arasındaki farkı çıkarır ve önemli olanı bildirir:

- Yeni cihaz, cihaz çevrimdışı, IP değişimi, **MAC değişimi (ARP spoofing)**
- Yeni açık port (SSH/RDP/SMB gibi hassas portlarda *kritik*)
- **Düşük voltaj** (Raspberry Pi / Orange Pi güç sorunları), düşük pil,
  yüksek gecikme, zayıf sinyal
- Kanallar: ntfy (telefon push), Telegram, Webhook, Slack, Discord, E-posta
- Tek bir kayıp yanıt bildirim göndermez — eşik ayarlanabilir

**Home Assistant entegrasyonu** — İki yönlü:

- **Push:** MQTT Discovery ile her cihaz otomatik olarak bir HA
  `device_tracker` + tanılama sensörlerine dönüşür. YAML yok.
- **Pull:** HA'nın kendi cihaz listesini okuyup MyNeS'in bulduklarıyla
  karşılaştırır (Zigbee/Z-Wave/Matter cihazları dahil).

**Kökensiz (root'suz) çalışan tarama** — Ham ARP root ister. Yetki yoksa MyNeS
artık sessizce boş liste döndürmek yerine ping sweep + işletim sistemi ARP
cache yöntemine düşüyor. Gerçek bir /24 ağda: **2 → 29 cihaz**.

**Her ekranda çalışan arayüz** — Yeni tasarım sistemi (açık/koyu tema),
PWA (telefona/tablete kurulabilir), 320px telefondan TV'ye kadar duyarlı
yerleşim, TV kumandası için ok tuşu navigasyonu, erişilebilirlik iyileştirmeleri.

📱 Mobil uygulama (Faz 2) planı: [`docs/PHASE2_MOBILE.md`](docs/PHASE2_MOBILE.md)

## ✨ Özellikler

- 🌐 **Web-based Interface** - Modern, kullanıcı dostu Web tabanlı arayüz
- **🔍 Otomatik Ağ Keşfi**: Yerel ağ aralığını otomatik olarak belirler
- **🔬 ARP Taraması**: Hızlı cihaz keşfi için ARP protokolü kullanır
- **🔌 Gelişmiş Port Taraması**: 1000+ port ile kapsamlı servis tespiti
- **🖥️ Cihaz Tipi Tespiti**: Router, bilgisayar, telefon, kamera vb. otomatik tespit
- **🐳 Docker Entegrasyonu**: Container ve virtual network tespiti
- **🔐 Multi-Protocol Analiz**: SSH, FTP, HTTP, SNMP desteği
- **📝 Cihaz Yönetini**: Cihaz bilgilerini elle değiştirebilme, yeni bilgiler ekleyebilme
- **🎛️ Yedekleme ve Aktarım**: JSON tabanalı basit ve kolay cihaz bilgilerini yedekleme ve geri yükleme
- **📊 Geçmiş Tarama Analizi**: Geçmiş tarama sonuçlarını ve istatistiklerini takip edebilme
- 🌍 **Çoklu Dil Desteği** - Türkçe ve İngilizce dil desteği

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

### 🔐 Güvenlik Özellikleri

- **Şifreli Credential Depolama**: Fernet simetrik şifreleme
- **Çok Protokol Desteği**: SSH, FTP, HTTP, SNMP credential'ları
- **Güvenli Dosya İzinleri**: Gizli dosyalar için kısıtlı erişim
- **Hassas Veri Temizleme**: Export sırasında otomatik temizleme

### 🐳 Docker Entegrasyonu

- **Container Tespiti**: Çalışan Docker container'ları bulma
- **Network Mapping**: Docker network'leri ve IP atamaları
- **Virtual Interface**: Docker sanal arayüzleri tespiti
- **Container Detayları**: Metadata ve yapılandırma bilgileri

## 🚀 Hızlı Başlangıç - Docker

[![Docker Pulls](https://img.shields.io/docker/pulls/fxerkan/my_network_scanner)](https://hub.docker.com/r/fxerkan/my_network_scanner) [![Docker Image Size](https://img.shields.io/docker/image-size/fxerkan/my_network_scanner/latest)](https://hub.docker.com/r/fxerkan/my_network_scanner) [![GitHub Release](https://img.shields.io/github/v/release/fxerkan/my_network_scanner)](https://github.com/fxerkan/my_network_scanner/releases) [![GitHub Stars](https://img.shields.io/github/stars/fxerkan/my_network_scanner?style=social)](https://github.com/fxerkan/my_network_scanner)

Bu container imajı  `amd64` ve `arm64` mimarilerinin tümünü destekler.

### 🐳 Docker Compose (Tavsiye Edilen)

```yaml
services:
  my-network-scanner:
    image: fxerkan/my_network_scanner:latest
    container_name: my-network-scanner
    ports:
      - "5883:5883"
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    environment:
      - FLASK_ENV=production
      - LAN_SCANNER_PASSWORD=your-secure-password
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - NET_RAW
    privileged: true
```

### 🐳 Docker Run

```bash
# Pull and run the container
docker run -d \
  --name my-network-scanner \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -p 5883:5883 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  -e LAN_SCANNER_PASSWORD=your-secure-password \
  fxerkan/my_network_scanner:latest

# Access the application
open http://localhost:5883
```

## 🛠️ Kurulum ve Geliştirme

**Gereksinimler**

- Python 3.9+
- Nmap (port/servis tespiti için — yoksa tarama çalışır, port taraması atlanır)
- Root/Administrator yetkisi *önerilir* (ham ARP taraması için; yoksa MyNeS
  otomatik olarak ping sweep + işletim sistemi ARP cache yöntemine düşer)
- Docker (opsiyonel — container tespiti için)

### 1. Nmap kurulumu

```bash
brew install nmap                          # macOS
sudo apt-get install nmap                  # Ubuntu/Debian
sudo dnf install nmap                      # Fedora/RHEL
winget install Insecure.Nmap               # Windows
```

### 2. Çalıştırma (Windows / macOS / Linux — tek komut)

```bash
git clone https://github.com/fxerkan/my_network_scanner.git
cd my_network_scanner
python scripts/run.py
```

`scripts/run.py` sanal ortamı oluşturur, bağımlılıkları kurar, nmap'i kontrol
eder ve uygulamayı başlatır. Sadece standart kütüphane kullandığı için hiçbir
şey kurulu olmadan da çalışır.

**Elle kurulum:**

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[all]"            # veya: pip install -r requirements.txt
python -m mynes                    # veya: mynes
```

Arayüz: `http://localhost:5883`

**Docker:**

```bash
docker compose -f deploy/docker-compose.yml up -d
```

`network_mode: host` ARP/mDNS/SSDP keşfinin LAN'ı gerçekten görebilmesi için
gereklidir. Docker Desktop'ta (macOS/Windows) host modu kısıtlıdır; compose
dosyasındaki `ports:` bloğunu açın (keşif kapsamı daralır).

### 3. Tam tarama yetkisi (önerilir)

Ham ARP taraması root ister. MyNeS yetki yoksa ping sweep'e düşer ve ICMP'ye
yanıt vermeyen cihazları kaçırır. Her platformda, **her şeyi root olarak
çalıştırmadan** kalıcı çözüm var:

```bash
python -m mynes.platform.privileges            # ne gerektiğini söyler
python -m mynes.platform.privileges --apply    # komutları çalıştırır (parola sorar)
```

| Platform          | Yöntem                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------- |
| **Linux**   | Python ikilisine`setcap cap_net_raw,cap_net_admin+eip` — sadece iki yetenek, root yok             |
| **macOS**   | `access_bpf` grubu + açılışta çalışan ChmodBPF LaunchDaemon (Wireshark ile aynı mekanizma) |
| **Windows** | Npcap sürücüsü, "Administrators only" seçeneği**kapalı** kurulur                        |

macOS'ta grup üyeliği **yeni oturumda** geçerli olur — çıkış yapıp tekrar girin.
Durum arayüzde de görünür: **Discovery → System setup**.

### 4. Arka planda çalıştırma

Zamanlanmış tarama tarayıcı açık olmadan da sürsün:

```bash
python -m mynes.platform.service install     # oturum açılışında başlar
python -m mynes.platform.service status
python -m mynes.platform.service uninstall
```

macOS'ta LaunchAgent, Linux'ta systemd *user* unit, Windows'ta Zamanlanmış
Görev kurar. Üçü de kullanıcı seviyesindedir — sudo istemez, kaldırmak tek
dosya silmektir. Gerçek bir açılış servisi (headless sunucu) için Docker imajını
kullanın.

Linux'ta oturumu kapattığınızda da çalışması için: `sudo loginctl enable-linger $USER`

### 5. Sistem tepsisi / menü çubuğu ikonu

```bash
pip install "mynes[tray]"
python -m mynes.tray                              # sunucuyu da başlatır
python -m mynes.tray --connect http://nas.local:5883   # sadece ikon
```

Cihaz sayısı ve okunmamış uyarı rozeti simgede görünür; menüden "Scan now",
"Open MyNeS" ve "Mark alerts read" var. İkon rengi durumu taşır (yeşil / sarı /
kırmızı / gri).

### 6. Yapılandırma

```bash
export MYNES_PASSWORD="ana_parolaniz"    # yoksa otomatik üretilir
export MYNES_PORT=5883
export MYNES_DATA_DIR=/veri/yolu         # MYNES_CONFIG_DIR, MYNES_HOME de var

# Home Assistant entegrasyonu (opsiyonel)
export HA_URL="http://homeassistant.local:8123"
export HA_TOKEN="uzun_omurlu_erisim_tokeni"

# MQTT / Zigbee2MQTT keşfi ve HA'ya yayın (opsiyonel)
export MYNES_MQTT_HOST="192.168.1.10"
export MYNES_MQTT_USERNAME="mynes"
export MYNES_MQTT_PASSWORD="..."
```

> **Güvenlik:** Ana parolayı `config/config.json` içine **yazmayın**. Bu dosya
> git'te takiplidir. Parola `MYNES_PASSWORD` ortam değişkeninden ya da git'e
> girmeyen `config/.master_password` dosyasından okunur.

## 📁 Dosya Yapısı

```
my_network_scanner/
├── mynes/                       # Uygulama paketi
│   ├── paths.py                 # Dizinler (CWD'den değil paketten çözülür)
│   ├── core/
│   │   ├── scanner.py           # Ana tarama motoru
│   │   ├── arp.py               # Yetkisiz çalışan layer-2 keşif
│   │   ├── models.py            # Birleşik cihaz modeli
│   │   ├── network.py           # Arayüz/ağ yardımcıları
│   │   ├── config.py            # Yapılandırma yönetimi
│   │   └── version.py           # Dinamik versiyon
│   ├── discovery/               # Çoklu protokol keşfi
│   │   ├── mdns.py              # mDNS/Bonjour + Matter
│   │   ├── ssdp.py              # SSDP/UPnP (sadece stdlib)
│   │   ├── bluetooth.py         # BLE (bleak, opsiyonel)
│   │   └── mqtt.py              # Zigbee2MQTT / Z-Wave / Tasmota
│   ├── analysis/                # Derin analiz, OUI, cihaz tanıma
│   ├── monitoring/              # Zamanlayıcı, kurallar, bildirimler
│   ├── integrations/            # Home Assistant, Docker
│   ├── security/                # Şifreli credential, veri temizleme
│   └── web/                     # Flask app, API, şablonlar, statikler
├── config/                      # Yapılandırma + OUI veritabanı
├── data/                        # Tarama sonuçları, uyarılar, geçmiş
├── deploy/                      # Dockerfile, docker-compose
├── scripts/run.py               # Çapraz platform başlatıcı
├── docs/                        # PHASE2_MOBILE.md ve diğer dokümanlar
├── tests/                       # Smoke + kural testleri
└── .claude/skills/              # UI/UX ve full-stack Claude Skills
```

- **Root Yetkileri**: Port taraması için yönetici yetkileri gerekebilir
- **Güvenlik Duvarı**: Bazı güvenlik duvarları taramayı engelleyebilir
- **Etik Kullanım**: Sadece kendi ağınızı tarayın
- **Performans**: Büyük ağlarda tarama uzun sürebilir
- **Credential Güvenliği**: Tüm giriş bilgileri AES-256 ile şifrelenir
- **Veri Temizleme**: Export sırasında hassas veriler otomatik temizlenir
- **Güvenli Erişim**: SSH anahtar tabanlı kimlik doğrulama önerilir

## 🐛 Sorun Giderme

### Yaygın Sorunlar

#### "Sadece 2-3 cihaz buluyor"

Neredeyse her zaman ham soket yetkisi eksikliğidir. MyNeS bu durumda ping sweep

+ ARP cache'e düşer; bu yöntem ICMP'ye yanıt vermeyen ve bu makineyle hiç
  konuşmamış cihazları kaçırır. Durumu `GET /api/capabilities` söyler.

```bash
sudo .venv/bin/python -m mynes          # macOS/Linux
# Windows: PowerShell'i "Yönetici olarak çalıştır" ile açın
# Docker: compose dosyası zaten NET_RAW + NET_ADMIN veriyor
```

#### "Permission denied" Hatası

```bash
sudo .venv/bin/python -m mynes
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

- Port `5883`'ün kullanımda olmadığından emin olun
- Güvenlik duvarı kurallarını kontrol edin
- `http://127.0.0.1:5883` adresini deneyin

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

## 🔗 Linkler

- **GitHub Repository**: [https://github.com/fxerkan/my_network_scanner](https://github.com/fxerkan/my_network_scanner)
- **Documentation**: [CLAUDE.md](CLAUDE.md)
- **Turkish README**: [README.md](README.md)

## 🙏 Teşekkürler

- **[Claude Code](https://www.anthropic.com/claude-code)**: AI-assisted development
- **[IEEE](https://www.ieee.org/)**: OUI database
- **[Nmap](https://nmap.org/)**: Network scanning engine
- **[Flask](https://flask.palletsprojects.com/en/stable/)**: Web framework
- **[Python](https://www.python.org/)**: Libraries and tools

---

**Bu uygulama [FXerkan](https://github.com/fxerkan) tarafından "*Code more, worry less*" mottosu ile geliştirilmiştir - Made with ❤️ & 🤖 by [FXerkan](https://github.com/fxerkan)**

**ÖNEMLİ** : Bu araç sadece eğitim amacıyla ve sadece kendi ağınızdaki cihazlar hakkında bilgi sahibi olmak amacıyla kullanılmalıdır.

**DİKKAT** : Başkalarının ağlarını izinsiz taramak yasalara aykırıdır, My Network Scanner (MyNeS) bu tip kullanımları önermez ve desteklemez.
