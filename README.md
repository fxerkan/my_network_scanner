<img src="assets/logo.svg" alt="MyNeS" width="72" align="left" hspace="12">

# My Network Scanner (MyNeS)

**Beni Oku (Türkçe)** | [**Readme (English)**](docs/README_ENG.md)

**My Network Scanner (MyNeS)**, "***Ailenizin Kullanıcı Dostu Ağ Tarayıcısı***" mottosu ile geliştirilmiş, yerel ağınızdaki tüm cihazları (Router/Modem, Laptop, Tablet, Desktop, Server, IP Camera, Gaming Console, Smart Home Appliances, .....) tarayıp, tespit ettiği cihazlar ile ilgili detaylı bilgileri kullanıcı dostu ve kolay bir arayüz üzerinden kolaylıkla yönetebilmenizi sağlayan profesyonel bir uygulamadır.

Modern ve kullanıcı dostu web arayüzü ile ağ yönetimini kolaylaştırır. Gelişmiş ve detaylı tarama, AI destekli cihaz tanıma ve güvenlik özellikleri sunar.

![Alt text](assets/mynes.png "a title")

> Sürüm değişiklikleri: [**CHANGELOG.md**](CHANGELOG.md)

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
- 📡 **Çoklu Protokol Keşfi**: mDNS/Bonjour, Matter, SSDP/UPnP, Bluetooth LE ve MQTT (Zigbee2MQTT / Z-Wave JS / Tasmota) — IP taramasının göremediği cihazlar
- 🔔 **Periyodik İzleme ve Bildirim**: Değişiklikleri tespit eder, uyarır
- 🏠 **Home Assistant Entegrasyonu**: MQTT Discovery ile push, REST/WebSocket ile pull
- 🗺️ **Beş Görünüm**: Kart, Tablo, Grafik, Topoloji ve Ev Planı
- 📱 **PWA**: Telefona/tablete kurulabilir, açık/koyu tema, 320px'den TV'ye duyarlı

### 🗺️ Görünümler

Cihaz listesini beş farklı şekilde okuyabilirsiniz — araç çubuğundaki görünüm
anahtarından geçiş yapılır.

| Görünüm          | Ne işe yarar                                                                    |
| ------------------- | -------------------------------------------------------------------------------- |
| Kart / Tablo        | Ayrıntı ve toplu düzenleme                                                    |
| **Grafik**    | Ağın bütününü tek bakışta görmek; alt ağ geçitleri merkez             |
| **Topoloji**  | Neyin neye bağlı olduğu:`İnternet → router → switch/AP → grup → cihaz` |
| **Ev Planı** | Cihazları evinizin planına sürükleyip bırakmak                              |

![Grafik görünümü](assets/screenshots/graph-view.png)

![Topoloji diyagramı](assets/screenshots/topology-view.png)

![Ev planı görünümü](assets/screenshots/home-view.png)

### 📡 Çoklu Protokol Keşfi

Bir IP taraması ev ağının yarısını kaçırır. MyNeS kendini duyuran her şeyi
dinler: mDNS/Bonjour (yazıcı, NAS, Chromecast, HomeKit), Matter, SSDP/UPnP
(router, Smart TV, kamera, konsol), Bluetooth LE (*IP'si olmayan cihazlar*) ve
MQTT üzerinden Zigbee/Z-Wave cihazları.

![Keşif](assets/screenshots/discovery.png)

### 🔔 İzleme, Uyarı ve Bildirim

Ağı belirli aralıklarla tarar, iki tarama arasındaki farkı çıkarır ve önemli
olanı bildirir: yeni cihaz, cihaz çevrimdışı, IP değişimi, **MAC değişimi
(ARP spoofing)**, yeni açık port, düşük voltaj (Raspberry Pi güç sorunları),
düşük pil, yüksek gecikme, zayıf sinyal.

Bildirim kanalları: **MyNeS'in kendi push'u** (Web Push — Home Assistant veya
üçüncü taraf bir servise gerek yok), **Home Assistant `notify` servisi**,
ntfy, Telegram, Webhook, Slack, Discord ve e-posta.

![İzleme ve uyarılar](assets/screenshots/monitoring-alerts.png)

### 📱 Telefonda

Uygulama bir PWA: ana ekrana eklenebilir, açık/koyu temayı işletim sisteminden
alır ve 320px genişlikten TV'ye kadar uyum sağlar.

<p>
  <img src="assets/screenshots/mobile-1.png" alt="Mobil - cihaz listesi" width="45%">
  <img src="assets/screenshots/mobile-2.png" alt="Mobil - cihaz detayı" width="45%">
</p>

### 📈 Geçmiş ve İstatistikler

![Tarama geçmişi](assets/screenshots/history.png)

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

![Detaylı cihaz analizi](assets/screenshots/detailed-scan.png)

### 🏭 Gelişmiş OUI/Vendor Yönetimi

- **Multi-Source IEEE Desteği**: OUI, MA-M, OUI-36, IAB, CID kayıtlarını destekler
- **Otomatik Güncellemeler**: IEEE kaynaklarından güncel veritabanı indirme
- **Online API Fallback**: Bilinmeyen MAC'ler için otomatik online arama
- **37,000+ Üretici Kaydı**: Kapsamlı vendor veritabanı
- **Akıllı Vendor Temizleme**: Organizasyon isimlerini normalize etme

![OUI veritabanı](assets/screenshots/oui-database.png)

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

[![Docker Pulls](https://img.shields.io/docker/pulls/fxerkan/my_network_scanner)](https://hub.docker.com/r/fxerkan/my_network_scanner)
[![Docker Image Size](https://img.shields.io/docker/image-size/fxerkan/my_network_scanner/latest)](https://hub.docker.com/r/fxerkan/my_network_scanner)
[![GitHub Release](https://img.shields.io/github/v/release/fxerkan/my_network_scanner)](https://github.com/fxerkan/my_network_scanner/releases)
[![GitHub Stars](https://img.shields.io/github/stars/fxerkan/my_network_scanner?style=social)](https://github.com/fxerkan/my_network_scanner)

İmaj `linux/amd64` ve `linux/arm64` için yayınlanır — Raspberry Pi ve Orange Pi'de de çalışır.

### 🐳 Docker Compose (önerilen)

```yaml
services:
  mynes:
    image: fxerkan/my_network_scanner:latest
    container_name: mynes
    # LAN'ı gerçekten görebilmesini sağlayan şey host ağı. Aşağıdaki nota bakın.
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    environment:
      MYNES_PORT: 5883
      # Boş bırakılırsa ilk açılışta otomatik üretilir.
      MYNES_PASSWORD: ""
      # İsteğe bağlı: Zigbee2MQTT / Z-Wave JS / Tasmota cihazlarını da görmek için
      MYNES_MQTT_HOST: ""
      # İsteğe bağlı: Home Assistant entegrasyonu
      MYNES_HA_URL: ""
      MYNES_HA_TOKEN: ""
    restart: unless-stopped
```

```bash
docker compose up -d
```

Depodaki hazır dosya: `docker compose -f deploy/docker-compose.yml up -d`

### 🐳 Docker Run

```bash
docker run -d \
  --name mynes \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/config:/app/config" \
  -e MYNES_PORT=5883 \
  --restart unless-stopped \
  fxerkan/my_network_scanner:latest
```

Arayüz: **http://\<sunucu-ip\>:5883**

### ⚠️ Neden host ağı ve NET_RAW?

MyNeS ham ARP paketleri gönderir ve mDNS/SSDP multicast dinler. İkisi de host ağ
namespace'i ister — bridge ağından yalnızca bridge'i görür, LAN'ı göremez.

- `NET_RAW` ARP paketlerini oluşturmasını sağlar.
- `NET_ADMIN` arayüz durumunu okumasını sağlar.
- **root olarak çalışmaz** (`USER scanner`, uid 1000) ve **`privileged` değildir.**
- Bu yetkiler olmadan hata vermez; ping taraması + işletim sistemi ARP önbelleğine
  düşer ve daha az cihaz bulur. Neyin eksik olduğunu `/api/capabilities` söyler.

Docker Desktop (macOS/Windows) host ağını tam desteklemez. Orada `network_mode: host`
yerine `ports: ["5883:5883"]` kullanın; keşif yeteneği kısıtlı olur.

> Yalnızca size ait ağları tarayın.

### 🔧 Ortam Değişkenleri

| Değişken | Açıklama | Varsayılan |
| --- | --- | --- |
| `MYNES_PORT` | Web arayüzü portu | `5883` |
| `MYNES_PASSWORD` | Kayıtlı cihaz kimlik bilgilerini şifreleyen ana parola | otomatik üretilir |
| `MYNES_MQTT_HOST` | MQTT broker adresi (Zigbee/Z-Wave/Tasmota keşfi) | boş |
| `MYNES_MQTT_USERNAME` / `MYNES_MQTT_PASSWORD` | MQTT kimlik bilgileri | boş |
| `MYNES_HA_URL` / `MYNES_HA_TOKEN` | Home Assistant adresi ve uzun ömürlü jeton | boş |
| `TZ` | Konteyner saat dilimi | `UTC` |

`HA_URL` / `HA_TOKEN` de kabul edilir. Depo kökündeki `.env` dosyası her giriş
noktası tarafından okunur; gerçek ortam değişkenleri dosyayı ezer.

### 📁 Kalıcı Dizinler

| Yol | İçerik |
| --- | --- |
| `/app/data` | Cihaz envanteri, tarama geçmişi, uyarılar |
| `/app/config` | Yapılandırma ve şifrelenmiş kimlik bilgileri |

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

### 6. Giriş (login) koruması

MyNeS ağındaki tüm cihazları listeler; portu görebilen herkese bu haritayı
vermemek için basit bir oturum girişi var. **Varsayılan olarak kapalıdır.**

1. `.env` içine kullanıcı adı ve parolayı yazın:

   ```
   MYNES_AUTH_USERNAME=admin
   MYNES_AUTH_PASSWORD=uzun-bir-parola
   ```

   Parolayı düz metin yerine hash olarak tutmak isterseniz:
   `python -m mynes.web.auth --hash`
2. MyNeS'i yeniden başlatın.
3. **Settings → Access control → Require sign-in** anahtarını açın.

Giriş sayfasında "30 gün boyunca oturumu açık tut" seçeneği vardır. Kimlik
bilgisi tanımlı değilken anahtar açılamaz — kendinizi kilitlemezsiniz.
Parolayı unutursanız sunucudaki `.env` dosyasına bakın.

> Ard arda 8 hatalı denemeden sonra o IP 5 dakika kilitlenir.
> Oturum çerezi `MYNES_SECRET_KEY` ile imzalanır; HTTPS arkasındaysanız
> `MYNES_HTTPS=true` yapın (çerez `Secure` olur).

### 7. Yapılandırma

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

## 🔄 Değişiklik Geçmişi

Sürüm sürüm tüm değişiklikler: [**CHANGELOG.md**](CHANGELOG.md)

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

**Bu uygulama [FXerkan](https://fxerkan.com) tarafından "*Code more, worry less*" mottosu ile geliştirilmiştir - Made with ❤️ & 🤖**

**ÖNEMLİ** : Bu araç sadece eğitim amacıyla ve sadece kendi ağınızdaki cihazlar hakkında bilgi sahibi olmak amacıyla kullanılmalıdır.

**DİKKAT** : Başkalarının ağlarını izinsiz taramak yasalara aykırıdır, My Network Scanner (MyNeS) bu tip kullanımları önermez ve desteklemez.
