# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a comprehensive LAN Scanner application built with Python and Flask that performs network device discovery and analysis. The application provides a web interface for scanning local networks, identifying devices, and managing device information with advanced security features, AI-powered device identification, and enterprise-grade capabilities.

## Common Commands

### Development

```bash
# Start the application
python app.py

# Use the startup script (recommended)
./start.sh

# Run network scan (command line)
python lan_scanner.py

# Install dependencies
pip install -r requirements.txt
```

### Virtual Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
```

### System Requirements

- Python 3.7+
- Nmap (must be installed system-wide)
- Root/Administrator privileges may be required for port scanning

## Architecture

### Core Components

#### 1. Flask Web Application (`app.py`)

- Main web server running on port `5883`
- Comprehensive REST API endpoints for device management
- Real-time progress tracking for scans with WebSocket-like updates
- Background thread management for scanning operations
- Configuration and history management
- Device analysis engine integration
- Credential management system integration
- Smart device naming and alias generation

#### 2. LAN Scanner Engine (`lan_scanner.py`)

- Core scanning functionality using ARP and nmap
- Network discovery with automatic IP range detection
- Device classification and port scanning
- Integration with OUI database for vendor identification
- Support for both online and offline device tracking
- Unified device model for data consistency
- Enhanced device analysis integration
- Smart device identification with confidence scoring

#### 3. OUI Manager (`oui_manager.py`)

- IEEE OUI database management
- Automatic downloads from IEEE CSV sources
- Online API fallback for unknown MAC addresses
- Local database caching and vendor name normalization

#### 4. Configuration Manager (`config.py`)

- JSON-based configuration system
- Device type definitions and detection rules
- Port scanning configurations
- Scan history management

#### 5. Enhanced Device Analyzer (`enhanced_device_analyzer.py`)

- Advanced device analysis with SSH, FTP, HTTP, and SNMP access
- Comprehensive port scanning with service detection
- Web service analysis and content extraction
- System identification through multiple protocols
- Security analysis and vulnerability assessment
- IoT and Raspberry Pi specific detection
- Real-time progress tracking with detailed logging

#### 6. Smart Device Identifier (`smart_device_identifier.py`)

- AI-powered device identification using pattern matching
- Confidence scoring for device type predictions
- Hostname and vendor-based classification
- Smart device naming with alias generation
- Device category classification (IoT, Server, Router, etc.)
- Comprehensive device type detection rules

#### 7. Unified Device Model (`unified_device_model.py`)

- Standardized data structure across all scan types
- Data consistency and validation
- Legacy format support with migration
- Merging of multiple scan results
- Comprehensive device data normalization

#### 8. Credential Manager (`credential_manager.py`)

- Fernet symmetric encryption for credential storage
- PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations
- Multi-protocol credential support (SSH, FTP, HTTP, SNMP)
- Master password protection with environment variable support
- Secure file permissions and hidden key files

#### 9. Docker Manager (`docker_manager.py`)

- Docker container detection and network mapping
- Virtual network interface discovery
- Container IP address tracking
- Docker network subnet analysis
- Integration with main scanning engine

#### 10. Dynamic Version Management (`version.py`)

- Git-based version tracking
- Automatic version generation from commits
- Clean/dirty working directory detection
- Build timestamp tracking
- Fallback version support

#### 11. Data Sanitizer (`data_sanitizer.py`)

- Security-focused data cleaning for export
- Sensitive header and field removal
- Asset file filtering
- Docker overlay path cleanup
- Sanitization statistics tracking

### Data Flow

1. **Network Discovery**: Uses ARP scanning to find active devices
2. **Device Analysis**: For each device, performs:
   - Hostname resolution
   - MAC address vendor lookup via OUI database
   - Port scanning with service detection
   - Device type classification based on rules
   - Enhanced analysis with credential-based access
   - Smart device identification with confidence scoring
   - Docker container detection and mapping
3. **Data Processing**:
   - Unified device model standardization
   - Data sanitization for security
   - Credential encryption and secure storage
4. **Data Storage**: Results stored in JSON format with persistent configuration
5. **Web Interface**: Real-time updates via REST API endpoints

### Key Features

- **Multi-source OUI Database**: Supports OUI, MA-M, OUI-36, IAB, and CID registries
- **Smart Device Detection**: Pattern-based classification using hostname and vendor rules
- **Configurable Port Scanning**: Device-specific port lists for efficient scanning
- **Offline Device Tracking**: Maintains history of previously seen devices
- **Background Analysis**: Detailed device analysis with command execution
- **Export/Import**: JSON-based data exchange
- **AI-Powered Device Identification**: Machine learning-based device classification with confidence scoring
- **Enhanced Security Analysis**: Multi-protocol access with SSH, FTP, HTTP, and SNMP
- **Docker Integration**: Container and virtual network detection
- **Encrypted Credential Storage**: Secure storage of authentication credentials
- **Real-time Progress Tracking**: Detailed logging and progress updates
- **Data Sanitization**: Security-focused data cleaning for export
- **Unified Data Model**: Consistent data structure across all scan types
- **Dynamic Version Management**: Git-based versioning with automatic updates

### File Structure

```
config/           # Configuration files
├── config.json   # Main application settings
├── device_types.json  # Device type definitions
├── oui_database.json  # Local OUI database
├── .salt         # Cryptographic salt (hidden)
├── .key_info     # Key derivation information (hidden)
└── *.csv        # IEEE CSV files (auto-downloaded)

data/            # Runtime data
├── lan_devices.json    # Device scan results (unified model)
├── scan_history.json   # Scan history
└── *_fx.json    # Additional data files

Core Modules:
├── app.py                      # Main Flask application
├── lan_scanner.py              # Core scanning engine
├── enhanced_device_analyzer.py # Advanced device analysis
├── smart_device_identifier.py  # AI-powered device identification
├── unified_device_model.py     # Data model standardization
├── credential_manager.py       # Encrypted credential storage
├── docker_manager.py           # Docker container detection
├── version.py                  # Dynamic version management
├── data_sanitizer.py           # Security data cleaning
├── oui_manager.py              # OUI database management
└── config.py                   # Configuration management

Web Interface:
├── templates/       # HTML templates
├── static/         # CSS/JS assets
└── _ex/           # Example/backup files
```

### Network Interface Detection

The application automatically detects available network interfaces and their IP ranges. It prioritizes interfaces with active gateways and supports manual IP range specification. Additionally, it detects Docker virtual interfaces and container networks for comprehensive network mapping.

### Port Scanning Strategy

- **Default Ports**: Common services (SSH, HTTP, HTTPS, etc.)
- **Device-Specific Ports**: Additional ports based on detected device type
- **Configurable Timeouts**: Optimized for network performance
- **Service Detection**: Uses nmap's service fingerprinting
- **Enhanced Analysis**: Comprehensive port scanning with 1000+ ports
- **Multi-Protocol Support**: SSH, FTP, HTTP, SNMP, and Telnet access
- **Credential-Based Access**: Authenticated scanning for detailed information

### Vendor Identification

1. **Local OUI Database**: First checks local IEEE database
2. **API Fallback**: Uses multiple online APIs for unknown MACs
3. **Name Normalization**: Cleans and standardizes vendor names
4. **Automatic Updates**: Downloads latest IEEE registries

## Web Interface

- **Main Page**: Device listing with search and filtering
- **Config Page**: Settings and database management
- **History Page**: Scan history and statistics
- **Real-time Updates**: WebSocket-like progress tracking via polling
- **Enhanced Analysis**: Device-specific detailed analysis interface
- **Credential Management**: Secure credential storage and management UI
- **Docker Integration**: Container and network visualization

## Security Features

### Encrypted Credential Storage

- **Secure Storage**: All device credentials (SSH, FTP, etc.) are encrypted using Fernet symmetric encryption
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations for master password protection
- **File Security**: Encrypted files stored in `config/` directory with restrictive permissions (600)
- **Environment Support**: Master password can be set via `LAN_SCANNER_PASSWORD` environment variable
- **Multiple Access Types**: Supports SSH, FTP, HTTP authentication per device

### Security Files

```
config/
├── .salt                  # Cryptographic salt (hidden)
└── .key_info             # Key derivation information (hidden)
```

### Security Best Practices

- Requires network scanning permissions
- May trigger firewall/security alerts
- Only scan networks you own or have permission to scan
- Uses HTTPS for external API calls where possible
- Never stores credentials in plain text or memory
- Data sanitization removes sensitive information before export
- Secure credential storage with military-grade encryption

## Advanced Features

### AI-Powered Device Identification

The Smart Device Identifier provides advanced device classification:

- **Pattern-Based Recognition**: Uses hostname and vendor patterns for identification
- **Confidence Scoring**: Provides confidence levels for device type predictions
- **Smart Naming**: Generates human-readable device names and aliases
- **Category Classification**: Classifies devices into categories (IoT, Server, Router, etc.)
- **Vendor-Specific Rules**: Tailored detection rules for different manufacturers

### Enhanced Device Analysis

The Enhanced Device Analyzer provides deep device inspection:

- **Multi-Protocol Access**: SSH, FTP, HTTP, SNMP, and Telnet support
- **System Information**: OS detection, system specifications, and running services
- **Security Analysis**: Vulnerability assessment and security posture evaluation
- **Web Service Analysis**: Content extraction and link discovery
- **File System Access**: Directory listing and file analysis (with credentials)
- **IoT Detection**: Specialized detection for IoT devices and embedded systems
- **Raspberry Pi Analysis**: Specific analysis for Raspberry Pi devices

### Docker Integration

The Docker Manager provides container ecosystem visibility:

- **Container Detection**: Identifies running Docker containers
- **Network Mapping**: Maps Docker networks and IP assignments
- **Virtual Interface Discovery**: Detects Docker virtual network interfaces
- **Container Information**: Provides detailed container metadata
- **Network Isolation**: Identifies container network isolation and communication

### Data Management

#### Unified Device Model

- **Consistent Structure**: Standardized data format across all scan types
- **Legacy Support**: Maintains compatibility with older data formats
- **Data Validation**: Ensures data integrity and consistency
- **Merge Operations**: Combines data from multiple scan sources

#### Data Sanitization

- **Sensitive Data Removal**: Removes authentication tokens and sensitive headers
- **Asset Filtering**: Filters out unnecessary asset files and links
- **Export Security**: Ensures safe data export without exposing credentials
- **Docker Path Cleanup**: Removes Docker overlay paths from exported data

### Version Management

Dynamic version tracking system:

- **Git Integration**: Automatic version detection from Git tags and commits
- **Build Information**: Tracks build timestamps and commit hashes
- **Development Status**: Indicates clean/dirty working directory status
- **Fallback Support**: Provides fallback version when Git is unavailable

### Real-time Progress Tracking

Advanced progress monitoring:

- **Detailed Logging**: Comprehensive operation logging with timestamps
- **Real-time Updates**: Live progress updates during scanning operations
- **Operation Status**: Detailed status for each scanning phase
- **Error Tracking**: Captures and reports errors during analysis

## API Endpoints

### Device Management

- `GET /api/devices` - Get all devices
- `POST /api/devices/scan` - Start network scan
- `GET /api/devices/{ip}` - Get specific device information
- `POST /api/devices/{ip}/analyze` - Perform enhanced analysis
- `POST /api/devices/{ip}/credentials` - Set device credentials

### Configuration

- `GET /api/config` - Get application configuration
- `POST /api/config` - Update configuration
- `GET /api/version` - Get application version information

### History and Statistics

- `GET /api/history` - Get scan history
- `GET /api/stats` - Get scanning statistics
- `POST /api/export` - Export device data (sanitized)

## Dependencies

### Core Dependencies

- **Flask**: Web framework for API and interface
- **nmap**: Network scanning and service detection
- **paramiko**: SSH client for device access
- **requests**: HTTP client for web analysis
- **cryptography**: Encryption for credential storage
- **psutil**: System and network information

### Optional Dependencies

- **pysnmp**: SNMP protocol support
- **paho-mqtt**: MQTT client for IoT devices
- **docker**: Docker API integration (if Docker is available)

## Configuration Options

### Master Password

Set via environment variable:

```bash
export LAN_SCANNER_PASSWORD="your_master_password"
```

### Credential Storage

Device credentials are encrypted and stored per device:

```json
{
  "ip": "192.168.1.100",
  "ssh": {
    "username": "admin",
    "password": "encrypted_password",
    "port": 22
  },
  "http": {
    "username": "admin",
    "password": "encrypted_password"
  }
}
```

### Device Type Configuration

Device types are defined in `config/device_types.json` with detection rules:

```json
{
  "device_types": {
    "raspberry_pi": {
      "patterns": ["raspberrypi", "raspberry"],
      "vendor_patterns": ["Raspberry Pi Foundation"],
      "ports": [22, 80, 443, 5000]
    }
  }
}
```
