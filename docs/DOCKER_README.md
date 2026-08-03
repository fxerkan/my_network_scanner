# 🌐 My Network Scanner (MyNeS) - Docker Hub

[![Docker Hub](https://img.shields.io/docker/pulls/fxerkan/my_network_scanner.svg)](https://hub.docker.com/r/fxerkan/my_network_scanner) [![Docker Image Size](https://img.shields.io/docker/image-size/fxerkan/my_network_scanner/latest)](https://hub.docker.com/r/fxerkan/my_network_scanner) [![GitHub](https://img.shields.io/github/stars/fxerkan/my_network_scanner?style=social)](https://github.com/fxerkan/my_network_scanner)

**Your Family's User-Friendly Network Scanner** - A comprehensive LAN scanner application with web interface, device discovery, and advanced analysis capabilities.

## 🚀 Quick Start

### Docker Compose (Recommended)

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

### Docker Run

```bash
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
```

Access the application at: **http://localhost:5883**

## ✨ Features

- 🌐 **Modern Web Interface** - User-friendly web-based management
- 🔍 **Automatic Network Discovery** - Auto-detects local network ranges
- 🔬 **ARP Scanning** - Fast device discovery using ARP protocol
- 🔌 **Advanced Port Scanning** - Comprehensive service detection with 1000+ ports
- 🖥️ **Device Type Detection** - Automatic identification of routers, computers, phones, cameras, etc.
- 🐳 **Docker Integration** - Container and virtual network detection
- 🔐 **Multi-Protocol Analysis** - SSH, FTP, HTTP, SNMP support
- 📝 **Device Management** - Edit device information and add custom data
- 🎛️ **Backup & Export** - JSON-based device data backup and restore
- 📊 **Scan History Analysis** - Track scan results and statistics over time
- 🌍 **Multi-Language Support** - Turkish and English language support

## 🏭 Advanced Capabilities

### AI-Powered Device Identification

- Hostname pattern analysis
- Vendor-based classification
- Port signature detection
- Machine learning confidence scores
- Smart device naming and aliasing

### Security Features

- Encrypted credential storage (AES-256)
- Multi-protocol authentication support
- Secure file permissions
- Automatic data sanitization for exports

### Docker Integration

- Running container detection
- Docker network mapping
- Virtual interface discovery
- Container metadata analysis

## 🛡️ Security & Requirements

- **Privileged Mode**: Required for network scanning capabilities
- **Network Capabilities**: NET_ADMIN and NET_RAW capabilities needed
- **Port Access**: Uses port 5883 for web interface
- **Data Persistence**: Volumes for `/app/data` and `/app/config`

## 📋 Supported Architectures

This image supports multiple architectures:

- `linux/amd64` (x86_64)
- `linux/arm64` (aarch64)

## 🔧 Environment Variables

| Variable                 | Description                               | Default        |
| ------------------------ | ----------------------------------------- | -------------- |
| `FLASK_ENV`            | Flask environment                         | `production` |
| `FLASK_PORT`           | Web interface port                        | `5883`       |
| `LAN_SCANNER_PASSWORD` | Master password for credential encryption | None           |

## 📁 Volume Mounts

| Path            | Description                         |
| --------------- | ----------------------------------- |
| `/app/data`   | Scan results and device data        |
| `/app/config` | Configuration files and credentials |

## 🔗 Links

- **GitHub Repository**: [https://github.com/fxerkan/my_network_scanner](https://github.com/fxerkan/my_network_scanner)
- **Issues & Support**: [GitHub Issues](https://github.com/fxerkan/my_network_scanner/issues)
- **Documentation**: [Project Documentation](https://github.com/fxerkan/my_network_scanner/blob/main/CLAUDE.md)

## 📄 License

This project is licensed under the MIT License.

---

**Made with ❤️ & 🤖 by [fxerkan](https://github.com/fxerkan)**

> This tool is for educational purposes and monitoring your own network devices only.
