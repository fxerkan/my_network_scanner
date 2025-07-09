# My Network Scanner (MyNeS) 🌐

[**Beni Oku (Türkçe)**](README.md) | **Readme (English)**

**My Network Scanner (MyNeS)**, developed with the motto "*Your Family's User-Friendly Network Scanner*", is a professional application that scans all devices in your local network (Router/Modem, Laptop, Tablet, Desktop, Server, IP Camera, Gaming Console, Smart Home Appliances, etc.), collects detailed information about detected devices, and allows you to manage your devices through a user-friendly and easy interface.

It simplifies network management with a modern and user-friendly web interface. It offers advanced and detailed scanning, AI-powered device identification, and security features.

![Alt text](assets/mynes.png "MyNeS Interface")

> *This application has been developed entirely **AI-assisted** (**Agentic Mode**) using [Claude Code](https://www.anthropic.com/claude-code), [Github Copilot](https://github.com/features/copilot), and [Visual Studio Code](https://code.visualstudio.com/) as **Open-Source**.*

## ✨ Features

### 🔍 Comprehensive Network Scanning

- **Automatic Network Discovery**: Automatically determines local network range
- **ARP Scanning**: Uses ARP protocol for fast device discovery
- **Advanced Port Scanning**: Comprehensive service detection with 1000+ ports
- **Device Types**: Automatic detection of routers, computers, phones, cameras, etc.
- **Docker Integration**: Container and virtual network detection
- **Multi-Protocol Analysis**: SSH, FTP, HTTP, SNMP support

### 📊 Detailed Device Information

- **IP Addresses**: IPv4 addresses
- **MAC Addresses**: Physical network addresses
- **Hostname**: Device names
- **Vendor Information**: Advanced vendor detection with IEEE OUI database and online APIs
- **Open Ports**: Active services and port numbers
- **Device Type**: Automatic device categorization
- **System Information**: Operating system, hardware specifications
- **Security Analysis**: Vulnerabilities and security status
- **Docker Information**: Container status and network mapping

### 🏭 Advanced OUI/Vendor Management

- **Multi-Source IEEE Support**: Supports OUI, MA-M, OUI-36, IAB, CID records
- **Automatic Updates**: Download current database from IEEE sources
- **Online API Fallback**: Automatic online search for unknown MACs
- **37,000+ Vendor Records**: Comprehensive vendor database
- **Smart Vendor Cleaning**: Normalize organization names

### 🎯 AI-Powered Smart Device Recognition

The application automatically determines device type using the following information:

- **Hostname Analysis**: Pattern recognition from device names
- **Vendor Information**: Vendor-based classification
- **Open Port Analysis**: Service-based detection
- **Known Device Signatures**: Confidence scores with machine learning
- **Smart Naming**: Automatic alias and name generation

### 🔐 Enhanced Security Features

- **Encrypted Credential Storage**: Military-grade Fernet symmetric encryption
- **PBKDF2-HMAC-SHA256**: Key derivation with 100,000 iterations
- **Multi-Protocol Access**: SSH, FTP, HTTP, SNMP credential management
- **Master Password Protection**: Environment variable support
- **Data Sanitization**: Security-focused data cleaning for export
- **Secure File Permissions**: Hidden key files with restrictive permissions (600)

### 🌐 Web Interface & Usability

- **Modern Web UI**: Responsive design for all devices
- **Real-time Updates**: Live progress tracking during scans
- **Advanced Filtering**: Filter by device type, status, vendor
- **Smart Search**: Search by IP, MAC, hostname, alias
- **Export/Import**: JSON-based data exchange
- **Configuration Management**: Easy settings management
- **Scan History**: Historical data and statistics

### 🐳 Docker & Virtualization

- **Docker Container Detection**: Running container identification
- **Virtual Network Mapping**: Docker network and IP assignments
- **Container Information**: Detailed container metadata
- **Network Isolation**: Container network communication analysis

### 🔄 Data Management

- **Unified Device Model**: Consistent data structure across all scan types
- **Legacy Data Migration**: Automatic upgrade from older formats
- **Data Validation**: Ensures data integrity and consistency
- **Background Analysis**: Detailed device analysis with command execution
- **Bulk Operations**: Mass device management capabilities

## 🛠️ Technical Architecture

### Core Technologies

- **Backend**: Python 3.7+ with Flask
- **Network Scanning**: Nmap, Scapy, ARP
- **Security**: Cryptography, Fernet encryption
- **Data Storage**: JSON-based with encryption
- **Frontend**: Modern HTML5/CSS3/JavaScript
- **Database**: IEEE OUI database with 37,000+ entries

### Key Components

1. **LAN Scanner Engine** (`lan_scanner.py`) - Core scanning functionality
2. **Enhanced Device Analyzer** (`enhanced_device_analyzer.py`) - Advanced analysis
3. **Smart Device Identifier** (`smart_device_identifier.py`) - AI-powered identification
4. **Credential Manager** (`credential_manager.py`) - Encrypted credential storage
5. **Docker Manager** (`docker_manager.py`) - Container detection
6. **OUI Manager** (`oui_manager.py`) - Vendor database management
7. **Data Sanitizer** (`data_sanitizer.py`) - Security data cleaning

### Multi-Language Support

- **Languages**: Turkish and English
- **Dynamic Switching**: Real-time language changes
- **Translation Management**: JSON-based translation files
- **Template Integration**: Jinja2 template support

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- Nmap (system-wide installation required)
- Root/Administrator privileges may be required for port scanning

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/fxerkan/my_network_scanner.git
cd my_network_scanner
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the application:**
```bash
python app.py
# or use the startup script
./start.sh
```

4. **Access the web interface:**
Open your browser and navigate to `http://localhost:5003`

### Quick Commands

```bash
# Start the application
python app.py

# Run network scan (command line)
python lan_scanner.py

# Use the startup script (recommended)
./start.sh
```

### Configuration

The application supports various configuration options:

```bash
# Set master password for credential encryption
export LAN_SCANNER_PASSWORD="your_master_password"

# Custom Flask configuration
export FLASK_SECRET_KEY="your_secret_key"
```

## 📋 Usage Guide

### Basic Network Scanning

1. **Start a Scan**: Click "Scan Network" button
2. **Monitor Progress**: Real-time progress tracking
3. **View Results**: Devices appear in the table automatically
4. **Filter & Search**: Use filters to find specific devices

### Device Management

1. **Edit Device**: Click on device IP or edit button
2. **Add Credentials**: Set SSH, FTP, HTTP access credentials
3. **Manual Ports**: Add custom ports and descriptions
4. **Enhanced Analysis**: Run detailed analysis on specific devices

### Advanced Features

1. **Bulk Analysis**: Analyze all devices simultaneously
2. **Export Data**: Download device information as JSON
3. **Import Data**: Restore from backup files
4. **Configuration**: Customize scan settings and detection rules

## 🔧 Configuration Files

```
config/
├── config.json              # Main application settings
├── device_types.json        # Device type definitions
├── oui_database.json        # Local OUI database
├── .salt                    # Cryptographic salt (hidden)
├── .key_info               # Key derivation info (hidden)
└── *.csv                   # IEEE CSV files (auto-downloaded)

data/
├── lan_devices.json        # Device scan results
├── scan_history.json       # Scan history
└── backups/               # Automatic backups
```

## 🛡️ Security Best Practices

- **Network Permissions**: Requires appropriate network scanning rights
- **Firewall Alerts**: May trigger security software alerts
- **Authorized Scanning**: Only scan networks you own or have permission to scan
- **Credential Security**: All credentials encrypted with military-grade encryption
- **Data Protection**: Sensitive data automatically removed during export

## 🤝 Contributing

We welcome contributions! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **GitHub Repository**: [https://github.com/fxerkan/my_network_scanner](https://github.com/fxerkan/my_network_scanner)
- **Documentation**: [CLAUDE.md](CLAUDE.md)
- **Turkish README**: [README.md](README.md)

## 🙏 Acknowledgments

- **Claude Code**: AI-assisted development
- **GitHub Copilot**: Code assistance
- **IEEE**: OUI database
- **Nmap**: Network scanning engine
- **Flask**: Web framework
- **Python Community**: Libraries and tools

## 📞 Support

For support, questions, or feature requests, please open an issue on GitHub.

---

**My Network Scanner (MyNeS)** - *Your Family's User-Friendly Network Scanner* 🌐