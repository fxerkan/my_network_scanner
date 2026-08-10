#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN Scanner Web UI - Flask tabanlı gelişmiş web arayüzü
Enhanced version with configuration management and additional features
"""

# Warnings'leri bastır
from mynes.paths import config_file, data_file
import warnings
import os
import sys

# Cryptography deprecation uyarılarını gizle
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy")

# Scapy ve network interface uyarılarını gizle
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# App logging: rotating file + in-memory ring buffer feeding Settings > Logs.
from mynes.core import logsetup
logsetup.setup_logging(os.environ.get("MYNES_LOG_LEVEL", "INFO"))

# Environment variables için dotenv desteği
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Flask ve diğer import'lar
from flask import Flask, render_template, jsonify, request, send_from_directory, session, redirect, url_for
import threading
from datetime import datetime
from mynes.core.scanner import LANScanner
from mynes.analysis.oui import OUIManager
from mynes.integrations.docker import docker_manager
from mynes.security.credentials import get_credential_manager
from mynes.core.version import get_version, get_version_info
from mynes.security.sanitizer import DataSanitizer
from mynes.core.models import unified_model
from mynes.web.i18n import language_manager, _, get_language_manager
import re
import requests
import csv
import json
import os

app = Flask(__name__)
# Use environment variable or generate a random secret key
def _secret_key():
    """Stable across restarts, otherwise every restart signs everyone out.

    Order: env var -> a generated key kept beside the other local secrets.
    """
    from mynes.paths import CONFIG_DIR

    env = os.environ.get('MYNES_SECRET_KEY') or os.environ.get('FLASK_SECRET_KEY')
    if env:
        return env

    key_path = CONFIG_DIR / '.secret_key'
    if key_path.exists():
        return key_path.read_text().strip()

    import secrets as _secrets
    key = _secrets.token_hex(32)
    key_path.write_text(key)
    if os.name == 'posix':
        os.chmod(key_path, 0o600)
    return key


app.secret_key = _secret_key()

# Disable caching for all requests (for development and translation updates)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
# Reflect template edits without a restart - same freshness intent as the
# no-store headers below. Negligible cost (an mtime check per render) and it
# spares the "I edited the HTML but nothing changed" confusion.
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.after_request
def after_request(response):
    """Add cache control headers to prevent caching issues"""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Global değişkenler
scanner = LANScanner()
oui_manager = OUIManager()
scan_progress = {"status": "idle", "message": "ready", "devices_found": 0}
scan_thread = None

# Global değişkenler için background analysis tracking
background_analysis = {"status": "idle", "message": "ready"}
detailed_analysis_thread = None

# Enhanced analysis tracking
enhanced_analysis_status = {}
bulk_analysis_status = {}

# Secure credential manager
credential_manager = get_credential_manager()

# v2 API: multi-protocol discovery, scheduled monitoring, Home Assistant.
from mynes.web.api import create_api  # noqa: E402  (needs `scanner` above)

api_v2, monitor = create_api(scanner, scanner.get_config_manager())
app.register_blueprint(api_v2)

# Optional login gate. Off unless config enables it AND credentials exist in the
# environment, so an existing install can never lock itself out on upgrade.
from mynes.web import auth as _auth  # noqa: E402

auth_bp = _auth.install(app, scanner.get_config_manager())

# Template context processor for language support
@app.context_processor
def inject_language_data():
    """Inject language data into all templates"""
    return {
        '_': _,
        'language_info': language_manager.get_language_info(),
        'current_language': language_manager.get_current_language(),
        'translations': language_manager.get_all_translations(),
        'translate_device_type': language_manager.get_device_type_translation
    }

@app.route('/set-language/<language_code>')
def set_language(language_code):
    """Set the current language"""
    if language_manager.set_language(language_code):
        # Redirect back to the referring page or home
        return redirect(request.referrer or url_for('index'))
    else:
        return jsonify({'error': _('invalid_language')}), 400

@app.route('/api/language/info')
def get_language_info():
    """Get language information"""
    return jsonify(language_manager.get_language_info())

@app.route('/api/language/set', methods=['POST'])
def api_set_language():
    """API endpoint to set language"""
    data = request.get_json()
    language_code = data.get('language')
    
    if language_manager.set_language(language_code):
        return jsonify({
            'success': True,
            'message': _('language_changed'),
            'current_language': language_manager.get_current_language()
        })
    else:
        return jsonify({
            'success': False,
            'error': _('invalid_language')
        }), 400

@app.route('/api/language/translations/<language_code>')
def get_translations(language_code):
    """Get translations for a specific language"""
    return jsonify(language_manager.get_all_translations(language_code))

@app.route('/api/device-types/translated')
def get_translated_device_types():
    """Get device types translated to current language"""
    # Config'den device types'ı yükle
    config_manager = scanner.get_config_manager()
    device_types_config = config_manager.load_device_types()
    current_language = language_manager.get_current_language()
    
    translated_types = {}
    for device_type, info in device_types_config.items():
        translated_name = language_manager.get_device_type_translation(device_type, current_language)
        translated_types[device_type] = {
            'name': translated_name,
            'icon': info.get('icon', '❓'),
            'category': info.get('category', 'unknown')
        }
    
    return jsonify(translated_types)

def progress_callback(message):
    """Callback for scan progress"""
    global scan_progress
    scan_progress["message"] = message
    if "cihaz bulundu" in message:
        try:
            # "X cihaz bulundu" mesajından sayıyı çıkar
            devices_count = int(message.split()[0])
            scan_progress["devices_found"] = devices_count
        except Exception:
            pass

def detailed_analysis_callback(message):
    """Callback for detailed-analysis progress"""
    global background_analysis
    background_analysis["message"] = message

def scan_network_thread():
    """Run the network scan in a separate thread"""
    global scan_progress
    try:
        start_time = datetime.now()
        scan_progress["status"] = "scanning"
        scanner.scan_network(progress_callback)
        scanner.save_to_json()
        
        # Tarama sonuçlarını tarihçeye kaydet
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        devices = scanner.get_devices()
        online_devices = [d for d in devices if d.get('status') == 'online']
        
        # Cihaz tipi ve vendor istatistiklerini hesapla
        device_types = {}
        vendors = {}
        for device in devices:
            device_type = device.get('device_type', 'Bilinmeyen')
            vendor = device.get('vendor', 'Bilinmeyen')
            device_types[device_type] = device_types.get(device_type, 0) + 1
            vendors[vendor] = vendors.get(vendor, 0) + 1
        
        # Tarama sonucunu history'ye kaydet
        config_manager = scanner.get_config_manager()
        scan_result = {
            "timestamp": end_time.isoformat(),
            "ip_range": getattr(config_manager, 'config', {}).get('scan_settings', {}).get('default_ip_range', 'Auto'),
            "total_devices": len(devices),
            "online_devices": len(online_devices),
            "scan_duration": scan_duration,
            "device_types": device_types,
            "vendors": vendors
        }
        config_manager.save_scan_result(scan_result)
        
        scan_progress["status"] = "completed"
        scan_progress["message"] = f"Tarama tamamlandı! {len(devices)} cihaz bulundu."
    except Exception as e:
        scan_progress["status"] = "error"
        scan_progress["message"] = f"Tarama hatası: {str(e)}"

def scan_network_custom_thread(ip_range=None, include_offline=False):
    """Run the network scan with custom settings in a separate thread"""
    global scan_progress
    try:
        start_time = datetime.now()
        scan_progress["status"] = "scanning"
        scanner.scan_network(progress_callback, ip_range, include_offline)
        scanner.save_to_json()
        
        # Tarama sonuçlarını tarihçeye kaydet
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        devices = scanner.get_devices()
        online_devices = [d for d in devices if d.get('status') == 'online']
        
        # Cihaz tipi ve vendor istatistiklerini hesapla
        device_types = {}
        vendors = {}
        for device in devices:
            device_type = device.get('device_type', 'Bilinmeyen')
            vendor = device.get('vendor', 'Bilinmeyen')
            device_types[device_type] = device_types.get(device_type, 0) + 1
            vendors[vendor] = vendors.get(vendor, 0) + 1
        
        # Tarama sonucunu history'ye kaydet
        config_manager = scanner.get_config_manager()
        scan_result = {
            "timestamp": end_time.isoformat(),
            "ip_range": ip_range or 'Auto',
            "total_devices": len(devices),
            "online_devices": len(online_devices),
            "scan_duration": scan_duration,
            "device_types": device_types,
            "vendors": vendors,
            "include_offline": include_offline
        }
        config_manager.save_scan_result(scan_result)
        
        scan_progress["status"] = "completed"
        scan_progress["message"] = f"Tarama tamamlandı! {len(devices)} cihaz bulundu."
    except Exception as e:
        scan_progress["status"] = "error"
        scan_progress["message"] = f"Tarama hatası: {str(e)}"

def run_detailed_analysis():
    """Run detailed analysis in a separate thread"""
    global background_analysis
    try:
        background_analysis["status"] = "analyzing"
        scanner.perform_detailed_analysis(detailed_analysis_callback)
        background_analysis["status"] = "completed"
        background_analysis["message"] = "Detaylı analiz tamamlandı!"
    except Exception as e:
        background_analysis["status"] = "error"
        background_analysis["message"] = f"Detaylı analiz hatası: {str(e)}"

def run_single_device_analysis(ip_address):
    """Run detailed device analysis in a separate thread"""
    global background_analysis
    try:
        background_analysis["status"] = "analyzing"
        scanner.perform_single_device_detailed_analysis(ip_address, detailed_analysis_callback)
        background_analysis["status"] = "completed"
        background_analysis["message"] = f"Detaylı analiz tamamlandı: {ip_address}"
    except Exception as e:
        background_analysis["status"] = "error"
        background_analysis["message"] = f"Detaylı analiz hatası: {str(e)}"

@app.route('/test_detailed_analysis')
def test_detailed_analysis():
    """Detailed-analysis test page"""
    return send_from_directory('.', 'test_detailed_analysis.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files with proper cache control"""
    response = send_from_directory(os.path.join(app.root_path, 'static'), filename)
    
    # Prevent aggressive caching for development and dynamic content
    if filename.endswith('.js') or filename.endswith('.css'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

@app.route('/favicon.ico')
def favicon():
    """Serve favicon.ico"""
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/manifest.webmanifest')
def manifest():
    """PWA manifest. Served from root so `scope: /` is valid."""
    return send_from_directory(
        os.path.join(app.root_path, 'static'), 'manifest.webmanifest',
        mimetype='application/manifest+json')


@app.route('/service-worker.js')
def service_worker():
    """Service worker must be root-scoped to control every page."""
    response = send_from_directory(
        os.path.join(app.root_path, 'static'), 'service-worker.js',
        mimetype='application/javascript')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response


@app.route('/discovery')
def discovery_page():
    """Multi-protocol discovery: mDNS/Matter, SSDP, BLE, MQTT/Zigbee."""
    return render_template('discovery.html', active_page='discovery')


@app.route('/alerts')
def alerts_page():
    """Scheduled monitoring, alert history and notification channels."""
    return render_template('alerts.html', active_page='alerts')


@app.route('/security')
def security_page():
    """Fleet-wide CVE/attack-surface overview with bulk acknowledge/watch/
    export/re-scan. The per-device data comes from /api/security/overview."""
    return render_template('security.html', active_page='security')


@app.route('/api/security/rescan', methods=['POST'])
def security_rescan():
    """Re-fingerprint a set of devices so their CVE/exposure assessment is
    fresh. Reuses the single-device detailed-analysis worker, one device after
    another in a single background thread (the analysis machinery is guarded to
    one run at a time)."""
    global detailed_analysis_thread, background_analysis
    ips = (request.get_json(silent=True) or {}).get('ips') or []
    known = {d['ip'] for d in scanner.get_devices()}
    ips = [ip for ip in ips if ip in known]
    if not ips:
        return jsonify({"error": "no known devices to re-scan"}), 400
    if background_analysis.get("status") == "analyzing" or (
            detailed_analysis_thread and detailed_analysis_thread.is_alive()):
        return jsonify({"error": "analysis already running"}), 409

    def _run(targets):
        global background_analysis
        background_analysis["status"] = "analyzing"
        try:
            for ip in targets:
                scanner.perform_single_device_detailed_analysis(ip, detailed_analysis_callback)
            background_analysis["status"] = "completed"
            background_analysis["message"] = f"Re-scan complete: {len(targets)} device(s)"
        except Exception as e:  # noqa: BLE001
            background_analysis["status"] = "error"
            background_analysis["message"] = f"Re-scan error: {e}"

    thread = threading.Thread(target=_run, args=(ips,), daemon=True)
    thread.start()
    detailed_analysis_thread = thread
    return jsonify({"message": f"Re-scan started for {len(ips)} device(s)", "ips": ips})


@app.route('/')
def index():
    """Home page"""
    # Önceki tarama sonuçlarını yükle
    scanner.load_from_json()
    devices = scanner.get_devices()
    
    # Config'den cihaz tiplerini al
    config_manager = scanner.get_config_manager()
    device_types = config_manager.load_device_types()
    
    return render_template('index.html', devices=devices, device_types=device_types)

@app.route('/config')
def config_page():
    """Config/Settings page"""
    config_manager = scanner.get_config_manager()
    
    # Mevcut ayarları yükle
    oui_database = config_manager.load_oui_database()
    device_types = config_manager.load_device_types()
    scan_settings = config_manager.get_setting('scan_settings', {})
    port_settings = config_manager.get_setting('port_settings', {})
    detection_rules = config_manager.get_setting('detection_rules', {})
    
    # Available networks
    available_networks = scanner.get_available_networks()
    
    return render_template('config.html', 
                         oui_database=oui_database,
                         device_types=device_types,
                         scan_settings=scan_settings,
                         port_settings=port_settings,
                         detection_rules=detection_rules,
                         available_networks=available_networks)

@app.route('/history')
def history_page():
    """History and statistics page"""
    config_manager = scanner.get_config_manager()
    scan_history = config_manager.load_scan_history()
    
    return render_template('history.html', scan_history=scan_history)

@app.route('/scan')
def start_scan():
    """Start a new scan"""
    global scan_thread, scan_progress
    
    if scan_progress["status"] == "scanning":
        return jsonify({"error": "Tarama zaten devam ediyor"}), 400
    
    # Tarama thread'ini başlat
    scan_thread = threading.Thread(target=scan_network_thread)
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({"message": "Tarama başlatıldı"})

@app.route('/scan_custom', methods=['POST'])
def start_custom_scan():
    """Start a scan with custom settings"""
    global scan_thread, scan_progress
    
    if scan_progress["status"] == "scanning":
        return jsonify({"error": "Tarama zaten devam ediyor"}), 400
    
    try:
        data = request.json
        ip_range = data.get('ip_range')
        include_offline = data.get('include_offline', False)
        
        # Custom tarama thread'ini başlat
        scan_thread = threading.Thread(
            target=lambda: scan_network_custom_thread(ip_range, include_offline)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({"message": "Özel tarama başlatıldı"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/stop_scan')
def stop_scan():
    """Stop the running scan"""
    global scan_progress
    scanner.stop_scan()
    scan_progress["status"] = "stopped"
    scan_progress["message"] = "Tarama durduruldu"
    return jsonify({"message": "Tarama durduruldu"})

@app.route('/progress')
def get_progress():
    """Return scan progress"""
    return jsonify(scan_progress)

@app.route('/detailed_analysis')
def start_detailed_analysis():
    """Start bulk detailed analysis"""
    global detailed_analysis_thread, background_analysis
    
    if background_analysis["status"] == "analyzing":
        return jsonify({"error": "Detaylı analiz zaten çalışıyor"}), 400
    
    # Önceki thread'i temizle
    if detailed_analysis_thread and detailed_analysis_thread.is_alive():
        return jsonify({"error": "Önceki analiz henüz tamamlanmadı"}), 400
    
    # Yeni thread başlat
    thread = threading.Thread(target=run_detailed_analysis)
    thread.daemon = True
    thread.start()
    detailed_analysis_thread = thread
    
    return jsonify({"message": "Detaylı analiz başlatıldı"})

@app.route('/detailed_analysis_status')
def get_detailed_analysis_status():
    """Return detailed-analysis status"""
    return jsonify(background_analysis)

@app.route('/analyze_device/<ip>')
def analyze_single_device(ip):
    """Start detailed analysis for a single device"""
    global detailed_analysis_thread, background_analysis
    
    if background_analysis["status"] == "analyzing":
        return jsonify({"error": "Detaylı analiz zaten çalışıyor"}), 400
    
    # Önceki thread'i temizle
    if detailed_analysis_thread and detailed_analysis_thread.is_alive():
        return jsonify({"error": "Önceki analiz henüz tamamlanmadı"}), 400
    
    # Cihazın var olup olmadığını kontrol et
    devices = scanner.get_devices()
    device = next((d for d in devices if d['ip'] == ip), None)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    
    # Yeni thread başlat
    thread = threading.Thread(target=run_single_device_analysis, args=(ip,))
    thread.daemon = True
    thread.start()
    detailed_analysis_thread = thread
    
    return jsonify({"message": f"Detaylı analiz başlatıldı: {ip}"})

@app.route('/devices')
@app.route('/get_devices')
def get_devices():
    """Return all devices as JSON"""
    devices = scanner.get_devices()
    return jsonify(devices)

@app.route('/device/<ip>')
def get_device(ip):
    """Return details for a specific device"""
    devices = scanner.get_devices()
    device = next((d for d in devices if d['ip'] == ip), None)
    if device:
        # JSON-safe hale getir - karışık key türlerini düzelt
        safe_device = make_json_safe(device)
        return jsonify(safe_device)
    return jsonify({"error": "Cihaz bulunamadı"}), 404

def make_json_safe(obj):
    """Make an object safe for JSON serialization"""
    import copy
    if isinstance(obj, dict):
        # Dict key'lerini string'e çevir ve değerleri de recursive olarak işle
        safe_dict = {}
        for key, value in obj.items():
            safe_key = str(key)  # Tüm key'leri string yap
            safe_dict[safe_key] = make_json_safe(value)
        return safe_dict
    elif isinstance(obj, list):
        return [make_json_safe(item) for item in obj]
    elif isinstance(obj, (int, float, str, bool)) or obj is None:
        return obj
    else:
        # Diğer türleri string'e çevir
        return str(obj)

@app.route('/update_device/<ip>', methods=['POST'])
def update_device(ip):
    """Update device information"""
    try:
        data = request.json
        success = scanner.update_device(ip, data)
        if success:
            scanner.save_to_json()
            return jsonify({"message": "Cihaz güncellendi"})
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/analyze_device/<ip>')
def analyze_device(ip):
    """Run detailed analysis for a specific device"""
    try:
        if scan_progress["status"] == "scanning":
            return jsonify({"error": "Tarama devam ederken analiz yapılamaz"}), 400
        
        analysis = scanner.detailed_device_analysis(ip)
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/analyze_device_background/<ip>')
def analyze_device_background(ip):
    """Start background detailed analysis for a specific device"""
    try:
        import uuid
        analysis_id = str(uuid.uuid4())
        
        # Arka plan analiz durumunu başlat
        background_analysis[analysis_id] = {
            "status": "starting",
            "ip": ip,
            "progress": 0,
            "message": "Analiz başlatılıyor...",
            "start_time": datetime.now(),
            "result": None,
            "commands": [],
            "current_command": None
        }
        
        # Arka plan thread başlat
        def background_analysis_thread():
            try:
                background_analysis[analysis_id]["status"] = "running"
                background_analysis[analysis_id]["message"] = "Detaylı analiz yapılıyor..."
                
                # Komutları sırayla çalıştır - Python-nmap kullanarak root gerektirmeyen
                commands = [
                    {"name": "Ping Testi", "command": f"ping -c 4 {ip}"},
                    {"name": "Port Tarama", "type": "nmap", "args": "-sT -p 1-1000"},
                    {"name": "Servis Tespiti", "type": "nmap", "args": "-sT -sV"},
                    {"name": "OS Fingerprint", "type": "nmap", "args": "-sT -sV --version-all"},
                ]
                
                total_commands = len(commands)
                for i, cmd in enumerate(commands):
                    background_analysis[analysis_id]["current_command"] = cmd["name"]
                    background_analysis[analysis_id]["progress"] = int((i / total_commands) * 100)
                    background_analysis[analysis_id]["message"] = f"Çalıştırılıyor: {cmd['name']}"
                    
                    # Komut çalıştır - Python-nmap veya subprocess kullanarak
                    import subprocess
                    import time
                    import nmap
                    start_time = time.time()
                    try:
                        if cmd.get("type") == "nmap":
                            # Python-nmap kullan (root gerektirmez)
                            nm = nmap.PortScanner()
                            result = nm.scan(ip, arguments=cmd["args"])
                            output = f"Nmap scan completed for {ip}\n"
                            if ip in result['scan']:
                                host_info = result['scan'][ip]
                                if 'tcp' in host_info:
                                    output += f"TCP ports: {list(host_info['tcp'].keys())}\n"
                                    for port, port_data in host_info['tcp'].items():
                                        output += f"Port {port}: {port_data.get('state', 'unknown')} - {port_data.get('name', 'unknown')}\n"
                            error = ""
                            return_code = 0
                        else:
                            # Subprocess kullan
                            result = subprocess.run(
                                cmd["command"].split(), 
                                capture_output=True, 
                                text=True, 
                                timeout=30
                            )
                            output = result.stdout
                            error = result.stderr
                            return_code = result.returncode
                        
                        end_time = time.time()
                        
                        background_analysis[analysis_id]["commands"].append({
                            "name": cmd["name"],
                            "command": cmd.get("command", f"nmap {cmd.get('args', '')} {ip}"),
                            "output": output,
                            "error": error,
                            "duration": round(end_time - start_time, 2),
                            "return_code": return_code
                        })
                        
                    except subprocess.TimeoutExpired:
                        background_analysis[analysis_id]["commands"].append({
                            "name": cmd["name"],
                            "command": cmd.get("command", f"nmap {cmd.get('args', '')} {ip}"),
                            "output": "Komut zaman aşımına uğradı",
                            "error": "Timeout",
                            "duration": 30.0,
                            "return_code": -1
                        })
                    except Exception as e:
                        background_analysis[analysis_id]["commands"].append({
                            "name": cmd["name"],
                            "command": cmd.get("command", f"nmap {cmd.get('args', '')} {ip}"),
                            "output": "",
                            "error": str(e),
                            "duration": 0,
                            "return_code": -1
                        })
                
                # Analiz tamamlandı
                background_analysis[analysis_id]["status"] = "completed"
                background_analysis[analysis_id]["progress"] = 100
                background_analysis[analysis_id]["message"] = "Analiz tamamlandı"
                background_analysis[analysis_id]["end_time"] = datetime.now()
                
                # Gelişmiş analiz sonucu oluştur
                analysis_result = scanner.detailed_device_analysis(ip)
                background_analysis[analysis_id]["result"] = analysis_result
                
            except Exception as e:
                background_analysis[analysis_id]["status"] = "error"
                background_analysis[analysis_id]["message"] = f"Analiz hatası: {str(e)}"
                background_analysis[analysis_id]["error"] = str(e)
        
        # Thread'i başlat
        analysis_thread = threading.Thread(target=background_analysis_thread)
        analysis_thread.daemon = True
        analysis_thread.start()
        
        return jsonify({
            "analysis_id": analysis_id,
            "message": "Arka plan analizi başlatıldı"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/analysis_status/<analysis_id>')
def get_analysis_status(analysis_id):
    """Get background analysis status"""
    if analysis_id in background_analysis:
        analysis = background_analysis[analysis_id].copy()
        
        # Datetime nesnelerini string'e çevir
        if 'start_time' in analysis:
            analysis['start_time'] = analysis['start_time'].isoformat()
        if 'end_time' in analysis:
            analysis['end_time'] = analysis['end_time'].isoformat()
            
        return jsonify(analysis)
    else:
        return jsonify({"error": "Analiz bulunamadı"}), 404

@app.route('/export')
def export_data():
    """Export data as JSON"""
    devices = scanner.get_devices()
    return jsonify({
        "export_date": datetime.now().isoformat(),
        "total_devices": len(devices),
        "devices": devices
    })

@app.route('/import', methods=['POST'])
def import_data():
    """Import data from JSON"""
    try:
        data = request.json
        if 'devices' in data:
            scanner.devices = data['devices']
            scanner.save_to_json()
            return jsonify({"message": f"{len(data['devices'])} cihaz import edildi"})
        return jsonify({"error": "Geçersiz veri formatı"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Configuration API endpoints
@app.route('/api/config/oui', methods=['GET', 'POST'])
def manage_oui_database():
    """Manage the OUI database"""
    if request.method == 'GET':
        return jsonify(oui_manager.export_database())
    
    elif request.method == 'POST':
        try:
            data = request.json
            oui_manager.import_database(data)
            return jsonify({"message": "OUI database güncellendi"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/api/oui/update', methods=['POST'])
def update_oui_database():
    """Update the OUI database from IEEE sources"""
    try:
        success = oui_manager.update_database()
        stats = oui_manager.get_stats()
        return jsonify({
            "success": success,
            "message": "OUI database güncellendi" if success else "Güncelleme başarısız",
            "stats": stats
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/oui/lookup/<mac>')
def lookup_oui(mac):
    """Look up vendor information from a MAC address"""
    try:
        vendor = oui_manager.get_vendor(mac)
        return jsonify({
            "mac": mac,
            "vendor": vendor
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/oui/search')
def search_oui():
    """Search the OUI database by vendor name"""
    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify({"error": "Query parameter required"}), 400
        
        results = oui_manager.search_vendor(query)
        return jsonify({
            "query": query,
            "results": results,
            "count": len(results)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/oui/stats')
def oui_stats():
    """OUI database statistics"""
    try:
        return jsonify(oui_manager.get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/config/device_types', methods=['GET', 'POST'])
def manage_device_types():
    """Manage device types"""
    config_manager = scanner.get_config_manager()
    
    if request.method == 'GET':
        return jsonify(config_manager.load_device_types())
    
    elif request.method == 'POST':
        try:
            data = request.json
            config_manager.save_device_types(data)
            scanner.load_config_settings()  # Ayarları yeniden yükle
            return jsonify({"message": "Cihaz tipleri güncellendi"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/api/config/settings', methods=['GET', 'POST'])
def manage_settings():
    """Manage general settings"""
    config_manager = scanner.get_config_manager()
    
    if request.method == 'GET':
        return jsonify({
            'scan_settings': config_manager.config.get('scan_settings', {}),
            'port_settings': config_manager.config.get('port_settings', {}),
            'detection_rules': config_manager.config.get('detection_rules', {})
        })
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Tüm bölümleri önce güncelle, sonra kaydet
            for section, settings in data.items():
                if section not in config_manager.config:
                    config_manager.config[section] = {}
                
                for key, value in settings.items():
                    config_manager.config[section][key] = value
            
            # Tek seferde kaydet
            config_manager.save_config()
            scanner.load_config_settings()  # Ayarları yeniden yükle
            
            return jsonify({"success": True, "message": "Ayarlar güncellendi"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/networks')
def get_available_networks():
    """Return available network interfaces"""
    try:
        networks = scanner.get_available_networks()
        # Mark the range that auto-detection would scan (the gateway's subnet),
        # so Settings can preselect it in the dropdown.
        detected = scanner.get_local_network()
        for n in networks:
            n['is_default'] = (n.get('network_range') == detected)
        return jsonify(networks)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/scan_history')
def get_scan_history():
    """Return scan history"""
    try:
        config_manager = scanner.get_config_manager()
        history = config_manager.load_scan_history()
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/version')
def get_app_version():
    """Return application version information"""
    try:
        return jsonify(get_version_info())
    except Exception as e:
        return jsonify({"error": str(e), "version": get_version()}), 400

@app.route('/api/sanitize_data', methods=['POST'])
def sanitize_device_data():
    """Sanitize device data by removing sensitive information"""
    try:
        sanitizer = DataSanitizer()
        devices_file = data_file('lan_devices.json')
        backup_file = data_file('lan_devices_backup.json')
        
        # Backup oluştur
        import shutil
        import os
        
        if os.path.exists(devices_file):
            shutil.copy2(devices_file, backup_file)
            
            # Dosyayı temizle
            if sanitizer.sanitize_file(devices_file):
                # Scanner'ın verilerini yeniden yükle
                scanner.load_from_json()
                
                return jsonify({
                    "success": True,
                    "message": "Cihaz verileri temizlendi",
                    "backup_created": backup_file
                })
            else:
                return jsonify({
                    "success": False,
                    "error": "Veri temizleme başarısız"
                }), 400
        else:
            return jsonify({
                "success": False,
                "error": "Cihaz verileri dosyası bulunamadı"
            }), 404
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/save_settings', methods=['POST'])
def save_settings():
    """Save settings for the config page"""
    try:
        data = request.json
        config_manager = scanner.get_config_manager()
        
        # Ayarları kaydet
        for key, value in data.items():
            config_manager.config[key] = value
        
        config_manager.save_config()
        scanner.load_config_settings()  # Ayarları yeniden yükle
        
        return jsonify({"success": True, "message": "Ayarlar kaydedildi"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/lookup_vendor/<mac>')
def lookup_vendor_api(mac):
    """Look up vendor information from a MAC address via API"""
    try:
        # MAC adresini normalize et
        clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac.upper())
        if len(clean_mac) < 6:
            return jsonify({"error": "Geçersiz MAC adresi"}), 400
        
        oui = clean_mac[:6]
        
        # Önce local database'den kontrol et
        config_manager = scanner.get_config_manager()
        oui_db = config_manager.load_oui_database()
        
        if oui in oui_db:
            return jsonify({
                "success": True,
                "vendor": oui_db[oui],
                "source": "local_database"
            })
        
        # Local database'de yoksa API'lerden dene
        api_endpoints = [
            f"https://api.macvendorlookup.com/v2/{mac}",
            f"https://api.maclookup.app/v2/macs/{mac}",
            f"https://macvendors.co/api/{mac}"
        ]
        
        for endpoint in api_endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # API response'una göre vendor adını çıkar
                    vendor = None
                    if isinstance(data, list) and len(data) > 0:
                        vendor = data[0].get('company') or data[0].get('vendor')
                    elif isinstance(data, dict):
                        vendor = data.get('company') or data.get('vendor') or data.get('result', {}).get('company')
                    
                    if vendor:
                        # Local database'e ekle
                        oui_db[oui] = vendor
                        config_manager.save_oui_database(oui_db)
                        
                        return jsonify({
                            "success": True,
                            "vendor": vendor,
                            "source": "api_lookup",
                            "api": endpoint
                        })
                        
            except Exception as e:
                continue  # Bir sonraki API'yi dene
        
        return jsonify({
            "success": False,
            "error": "Vendor bilgisi bulunamadı"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/download_ieee_oui')
def download_ieee_oui():
    """Download and process the IEEE OUI CSV file"""
    try:
        # IEEE OUI CSV dosyasını indir
        ieee_url = "https://standards-oui.ieee.org/oui/oui.csv"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Accept': 'text/csv,application/csv,text/plain,*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        response = requests.get(ieee_url, headers=headers, timeout=60, verify=False)
        if response.status_code == 200:
            # CSV dosyasını kaydet
            with open(config_file('oui_ieee.csv'), 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            # CSV'yi işle
            processed_count = process_ieee_csv(config_file('oui_ieee.csv'))
            
            return jsonify({
                "success": True,
                "message": f"IEEE OUI database güncellendi. {processed_count} kayıt işlendi.",
                "processed_count": processed_count
            })
        else:
            return jsonify({
                "success": False,
                "error": f"IEEE veritabanı indirilemedi. HTTP {response.status_code}"
            })
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })

def process_ieee_csv(csv_file):
    """Process the IEEE CSV file and add it to the OUI database"""
    try:
        config_manager = scanner.get_config_manager()
        oui_db = config_manager.load_oui_database()
        
        processed_count = 0
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                registry = row.get('Registry')
                assignment = row.get('Assignment')
                organization_name = row.get('Organization Name')
                
                if registry and assignment and organization_name:
                    # MAC prefix'i normalize et
                    mac_prefix = assignment.replace('-', '').upper()
                    if len(mac_prefix) == 6:  # 3-byte OUI
                        oui_db[mac_prefix] = organization_name.strip()
                        processed_count += 1
        
        # Güncellenmiş database'i kaydet
        config_manager.save_oui_database(oui_db)
        return processed_count
        
    except Exception as e:
        print(f"CSV işleme hatası: {e}")
        return 0
        

@app.route('/api/clear_history', methods=['POST'])
def clear_scan_history():
    """Clear scan history"""
    try:
        config_manager = scanner.get_config_manager()
        # History dosyasını temizle
        with open(config_manager.scan_history_file, 'w', encoding='utf-8') as f:
            json.dump([], f)
        return jsonify({"success": True, "message": "Tarihçe temizlendi"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/emojis', methods=['GET'])
def get_emojis():
    """Get emoji data from the CSV file"""
    try:
        emojis_file = os.path.join('config', 'emojis.csv')
        emojis_data = []
        categories = set()
        
        if os.path.exists(emojis_file):
            with open(emojis_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    emojis_data.append({
                        'emoji': row['emoji'],
                        'category': row['category'],
                        'description': row['description'],
                        'keywords': row['keywords']
                    })
                    categories.add(row['category'])
        
        return jsonify({
            'emojis': emojis_data,
            'categories': sorted(list(categories)),
            'total_count': len(emojis_data)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/emojis/categories')
def get_emoji_categories():
    """Get emoji categories"""
    try:
        emojis_file = os.path.join('config', 'emojis.csv')
        categories = set()
        
        if os.path.exists(emojis_file):
            with open(emojis_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    categories.add(row['category'])
        
        return jsonify(sorted(list(categories)))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/emojis/search')
def search_emojis():
    """Search emojis"""
    try:
        query = request.args.get('q', '').lower()
        category = request.args.get('category', '')
        
        emojis_file = os.path.join('config', 'emojis.csv')
        results = []
        
        if os.path.exists(emojis_file):
            with open(emojis_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Kategori filtresi
                    if category and row['category'] != category:
                        continue
                    
                    # Arama filtresi
                    if query:
                        searchable_text = f"{row['description']} {row['keywords']}".lower()
                        if query not in searchable_text:
                            continue
                    
                    results.append({
                        'emoji': row['emoji'],
                        'category': row['category'],
                        'description': row['description'],
                        'keywords': row['keywords']
                    })
        
        return jsonify({
            'results': results,
            'count': len(results),
            'query': query,
            'category': category
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/emojis', methods=['POST'])
def add_emoji():
    """Add a new emoji"""
    try:
        data = request.json
        emoji = data.get('emoji', '').strip()
        category = data.get('category', '').strip()
        description = data.get('description', '').strip()
        keywords = data.get('keywords', '').strip()
        
        if not all([emoji, category, description, keywords]):
            return jsonify({"error": "Tüm alanlar gereklidir"}), 400
        
        emojis_file = os.path.join('config', 'emojis.csv')
        
        # Mevcut emojileri kontrol et
        existing_emojis = set()
        if os.path.exists(emojis_file):
            with open(emojis_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    existing_emojis.add(row['emoji'])
        
        if emoji in existing_emojis:
            return jsonify({"error": "Bu emoji zaten mevcut"}), 400
        
        # Yeni emoji ekle
        with open(emojis_file, 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([emoji, category, description, keywords])
        
        return jsonify({"message": "Emoji başarıyla eklendi"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Docker API Endpoints
@app.route('/api/docker/networks')
def get_docker_networks():
    """Return Docker networks"""
    try:
        networks = docker_manager.get_docker_networks()
        return jsonify({
            "success": True,
            "networks": networks,
            "count": len(networks)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/docker/containers')
def get_docker_containers():
    """Return Docker containers"""
    try:
        containers = docker_manager.get_docker_containers()
        return jsonify({
            "success": True,
            "containers": containers,
            "count": len(containers)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/docker/scan_ranges')
def get_docker_scan_ranges():
    """Return scan ranges derived from Docker networks"""
    try:
        scan_ranges = docker_manager.get_docker_scan_ranges()
        return jsonify({
            "success": True,
            "scan_ranges": scan_ranges,
            "count": len(scan_ranges)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/docker/interfaces')
def get_docker_interfaces():
    """Return Docker virtual interfaces"""
    try:
        interfaces = docker_manager.get_docker_interface_info()
        return jsonify({
            "success": True,
            "interfaces": interfaces,
            "count": len(interfaces)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/docker/stats')
def get_docker_stats():
    """Return overall Docker statistics"""
    try:
        stats = docker_manager.get_docker_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({
            "available": False,
            "error": str(e)
        }), 400

@app.route('/device_access/<ip>', methods=['GET', 'POST'])
def device_access(ip):
    """Manage device access credentials"""
    global credential_manager
    
    # Credential manager'ın hazır olduğundan emin ol
    if not credential_manager:
        credential_manager = get_credential_manager()
    
    if request.method == 'GET':
        # Mevcut erişim bilgilerini getir (password'leri gizle)
        try:
            device_creds = credential_manager.get_device_credentials(ip) or {}
            # Password'leri gizle
            safe_creds = {}
            for access_type, creds in device_creds.items():
                safe_creds[access_type] = {
                    'username': creds.get('username'),
                    'port': creds.get('port'),
                    'additional_info': creds.get('additional_info', {}),
                    'created_at': creds.get('created_at'),
                    'has_password': bool(creds.get('password'))
                }
            return jsonify(safe_creds)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    
    elif request.method == 'POST':
        # Yeni erişim bilgilerini kaydet
        try:
            access_data = request.json
            access_type = access_data.get('access_type')
            username = access_data.get('username')
            password = access_data.get('password')
            port = access_data.get('port')
            additional_info = access_data.get('additional_info', {})
            keep_existing_password = access_data.get('keep_existing_password', False)
            
            # Eğer mevcut şifreyi koruma talebi varsa, eski şifreyi al
            if keep_existing_password:
                existing_creds = credential_manager.get_device_credentials(ip, access_type)
                if existing_creds and existing_creds.get('password'):
                    password = existing_creds.get('password')
            
            # Güvenli credential manager'a kaydet
            success = credential_manager.save_device_credentials(
                ip, access_type, username, password, port, additional_info
            )
            
            if success:
                # Enhanced analyzer'a bilgileri aktar
                scanner.enhanced_analyzer.set_device_credentials(
                    ip, access_type, username, password, port, additional_info
                )
                
                return jsonify({"success": True, "message": "Erişim bilgileri güvenli olarak kaydedildi"})
            else:
                return jsonify({"success": False, "error": "Credential kaydetme hatası"}), 400
                
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

@app.route('/test_device_access/<ip>', methods=['POST'])
def test_device_access(ip):
    """Test device access"""
    global credential_manager
    
    # Credential manager'ın hazır olduğundan emin ol
    if not credential_manager:
        credential_manager = get_credential_manager()
    
    try:
        access_data = request.json
        access_type = access_data.get('access_type')
        use_stored_credentials = access_data.get('use_stored_credentials', False)
        
        if use_stored_credentials:
            # Credential'ları güvenli depolama sisteminden al
            stored_creds = credential_manager.get_device_credentials(ip, access_type)
            if stored_creds:
                username = stored_creds.get('username')
                password = stored_creds.get('password')
                port = stored_creds.get('port')
            else:
                return jsonify({"success": False, "error": "Kayıtlı credential bulunamadı"}), 400
        else:
            # POST'tan gelen credential'ları kullan
            username = access_data.get('username')
            password = access_data.get('password')
            port = access_data.get('port')
            
            if not password:
                # Eğer şifre boşsa ve kayıtlı credential varsa onları kullan
                stored_creds = credential_manager.get_device_credentials(ip, access_type)
                if stored_creds and stored_creds.get('password'):
                    password = stored_creds.get('password')
        
        # Test için credentials oluştur
        test_credentials = {
            'username': username,
            'password': password,
            'port': int(port) if port else (22 if access_type == 'ssh' else 21 if access_type == 'ftp' else 23)
        }
        
        # Test sonuçları - geçici credential'lar ile test yap
        test_result = credential_manager._test_credentials_direct(ip, access_type, test_credentials)
        
        return jsonify(test_result)
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/enhanced_analysis/<ip>', methods=['POST'])
def enhanced_analysis(ip):
    """Start enhanced device analysis"""
    global enhanced_analysis_status
    
    try:
        # Status'u analyzing olarak ayarla
        enhanced_analysis_status[ip] = {
            "status": "analyzing", 
            "message": f"{ip} için gelişmiş analiz başlatılıyor...",
            "started_at": datetime.now().isoformat()
        }
        
        # Port-scan scope (fast|common|full) from the modal, default common.
        scope = (request.get_json(silent=True) or {}).get('scope', 'common')

        # Arkaplan thread'inde gelişmiş analiz çalıştır
        analysis_thread = threading.Thread(
            target=run_enhanced_analysis,
            args=(ip, scope)
        )
        analysis_thread.start()
        
        return jsonify({
            "success": True, 
            "message": f"{ip} için gelişmiş analiz başlatıldı"
        })
        
    except Exception as e:
        enhanced_analysis_status[ip] = {
            "status": "error",
            "message": str(e)
        }
        return jsonify({"success": False, "error": str(e)}), 400

def merge_enhanced_info(existing, new_info):
    """Mevcut enhanced info ile yeni bilgileri merge eder"""
    try:
        # Deep copy oluştur
        import copy
        merged = copy.deepcopy(existing)
        
        for key, new_value in new_info.items():
            if key in merged:
                if isinstance(merged[key], dict) and isinstance(new_value, dict):
                    # Dict ise recursive merge
                    merged[key] = merge_dict_recursive(merged[key], new_value)
                elif isinstance(merged[key], list) and isinstance(new_value, list):
                    # List ise birleştir ve unique tut
                    merged[key] = merge_lists_unique(merged[key], new_value)
                else:
                    # Diğer tiplerde yeni değeri al
                    merged[key] = new_value
            else:
                # Yeni key ise direkt ekle
                merged[key] = new_value
        
        return merged
    except Exception as e:
        print(f"Enhanced info merge hatası: {e}")
        return new_info

def merge_dict_recursive(dict1, dict2):
    """Recursively merge two dicts"""
    import copy
    result = copy.deepcopy(dict1)
    
    for key, value in dict2.items():
        if key in result:
            if isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = merge_dict_recursive(result[key], value)
            elif isinstance(result[key], list) and isinstance(value, list):
                result[key] = merge_lists_unique(result[key], value)
            else:
                result[key] = value
        else:
            result[key] = value
    
    return result

def merge_lists_unique(list1, list2):
    """Merge two lists, keeping unique items"""
    try:
        # JSON serialize ederek unique kontrolü yap
        import json
        seen = set()
        merged = []
        
        for item in list1 + list2:
            # JSON serialize et, hash olarak kullan
            try:
                item_hash = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else str(item)
                if item_hash not in seen:
                    seen.add(item_hash)
                    merged.append(item)
            except:
                # Serialize edilemezse direkt ekle
                merged.append(item)
        
        return merged
    except Exception as e:
        print(f"List merge hatası: {e}")
        return list1 + list2

def run_enhanced_analysis(ip, scope='common'):
    """Run enhanced analysis in a background thread"""
    global enhanced_analysis_status
    
    try:
        # Status güncelle
        enhanced_analysis_status[ip] = {
            "status": "analyzing",
            "message": f"{ip} cihaz bilgileri alınıyor..."
        }
        
        # Cihaz bilgilerini bul
        device = None
        for d in scanner.get_devices():
            if d.get('ip') == ip:
                device = d
                break
        
        if not device:
            enhanced_analysis_status[ip] = {
                "status": "error",
                "message": f"{ip} cihazı bulunamadı"
            }
            print(f"Enhanced analysis: {ip} cihazı bulunamadı")
            return
        
        # Status güncelle
        enhanced_analysis_status[ip] = {
            "status": "analyzing",
            "message": f"{ip} erişim bilgileri kontrol ediliyor..."
        }
        
        # Credential'ları güvenli depolamadan yükle ve enhanced analyzer'a aktar
        credentials_set = False
        device_creds = credential_manager.get_device_credentials(ip)
        if device_creds:
            for access_type, creds in device_creds.items():
                scanner.enhanced_analyzer.set_device_credentials(
                    ip, access_type, 
                    creds.get('username'), 
                    creds.get('password'), 
                    creds.get('port'),
                    creds.get('additional_info')
                )
                print(f"Enhanced analysis: {ip} için {access_type} credential'ları güvenli depolamadan yüklendi")
                credentials_set = True
        
        if credentials_set:
            enhanced_analysis_status[ip]["message"] = f"{ip} credential'lar ayarlandı, analiz başlatılıyor..."
        else:
            enhanced_analysis_status[ip]["message"] = f"{ip} credential bulunamadı, genel analiz yapılıyor..."
        
        # Progress tracking
        total_steps = 8  # Port scan, Web, SSH, FTP, SNMP, Hardware, IoT, Final
        current_step = 0
        
        # Progress callback
        def progress_callback(message):
            nonlocal current_step
            print(f"Enhanced analysis progress: {message}")
            
            # Mesaja göre adım numarasını güncelle
            if "Port Tarama:" in message or "🔌" in message:
                current_step = max(current_step, 1)
            elif "Web Servisleri" in message or "🌐" in message:
                current_step = max(current_step, 2)
            elif "SSH Analizi" in message or "🔐" in message:
                current_step = max(current_step, 3)
            elif "FTP Analizi" in message or "📁" in message:
                current_step = max(current_step, 4)
            elif "SNMP" in message or "📊" in message:
                current_step = max(current_step, 5)
            elif "Hardware" in message or "⚙️" in message:
                current_step = max(current_step, 6)
            elif "IoT" in message or "🏠" in message:
                current_step = max(current_step, 7)
            elif "sonuçları kaydediliyor" in message:
                current_step = 8
            
            # Progress percentage hesapla (5-95 arası)
            progress_percent = max(5, min(95, 5 + (current_step / total_steps) * 90))
            
            enhanced_analysis_status[ip] = {
                "status": "analyzing",
                "message": message,
                "progress": progress_percent,
                "step": current_step,
                "total_steps": total_steps
            }
        
        print(f"Enhanced analysis: {ip} için kapsamlı analiz başlatılıyor...")
        
        # Gelişmiş analiz yap
        enhanced_info = scanner.enhanced_analyzer.get_comprehensive_device_info(
            ip,
            device.get('mac', ''),
            device.get('hostname', ''),
            device.get('vendor', ''),
            progress_callback=progress_callback,
            scope=scope
        )
        
        # Status güncelle
        enhanced_analysis_status[ip] = {
            "status": "analyzing",
            "message": f"{ip} analiz sonuçları kaydediliyor..."
        }
        
        print(f"Enhanced analysis: {ip} analizi tamamlandı, sonuçlar kaydediliyor...")

        # Persist atomically: re-locate the device in the LIVE list and write +
        # save under the scanner lock. The `device` grabbed at the start of this
        # (minutes-long) run may have been orphaned by a scan that rebuilt
        # self.devices in the meantime - writing to it would never reach disk.
        scanner.apply_enhanced_analysis(
            ip,
            device.get('mac', ''),
            enhanced_info,
            discovered_ports=enhanced_info.get('discovered_ports', []),
        )
        print(f"Enhanced analysis: {ip} sonuçları kalıcı olarak kaydedildi")

        # Başarılı tamamlandı
        enhanced_analysis_status[ip] = {
            "status": "completed",
            "message": f"{ip} gelişmiş analizi başarıyla tamamlandı",
            "completed_at": datetime.now().isoformat()
        }
        
        print(f"Enhanced analysis: {ip} için gelişmiş analiz başarıyla tamamlandı")
        
    except Exception as e:
        enhanced_analysis_status[ip] = {
            "status": "error",
            "message": f"{ip} analiz hatası: {str(e)}",
            "error_at": datetime.now().isoformat()
        }
        print(f"Enhanced analysis hatası {ip}: {e}")
        import traceback
        traceback.print_exc()

@app.route('/enhanced_analysis_status/<ip>')
def enhanced_analysis_status_endpoint(ip):
    """Return enhanced-analysis status"""
    global enhanced_analysis_status
    
    if ip in enhanced_analysis_status:
        return jsonify(enhanced_analysis_status[ip])
    else:
        # Fallback: cihazda enhanced info var mı kontrol et
        devices = scanner.get_devices()
        for device in devices:
            if device.get('ip') == ip:
                if 'enhanced_comprehensive_info' in device:
                    return jsonify({
                        "status": "completed",
                        "message": f"{ip} gelişmiş analizi tamamlandı (daha önce)"
                    })
                else:
                    return jsonify({
                        "status": "idle",
                        "message": f"{ip} için gelişmiş analiz yapılmamış"
                    })
        
        return jsonify({
            "status": "error",
            "message": "Cihaz bulunamadı"
        })

@app.route('/stop_enhanced_analysis/<ip>', methods=['POST'])
def stop_enhanced_analysis(ip):
    """Stop enhanced analysis"""
    global enhanced_analysis_status
    
    if ip in enhanced_analysis_status:
        enhanced_analysis_status[ip] = {
            "status": "stopped",
            "message": f"{ip} analizi kullanıcı tarafından durduruldu",
            "stopped_at": datetime.now().isoformat()
        }
        return jsonify({"success": True, "message": f"{ip} analizi durduruldu"})
    else:
        return jsonify({"success": False, "message": "Aktif analiz bulunamadı"})

@app.route('/stop_bulk_analysis', methods=['POST'])
def stop_bulk_analysis():
    """Stop bulk analysis"""
    global bulk_analysis_status
    
    # Tüm aktif analizleri durdur
    bulk_analysis_status = {
        "status": "stopped",
        "message": "Toplu analiz kullanıcı tarafından durduruldu",
        "stopped_at": datetime.now().isoformat()
    }
    
    return jsonify({"success": True, "message": "Toplu analiz durduruldu"})

@app.route('/add_manual_device', methods=['POST'])
def add_manual_device():
    """Add a device manually"""
    try:
        data = request.json
        
        # Gerekli alanları kontrol et
        required_fields = ['ip', 'alias']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"success": False, "message": f"{field} alanı gereklidir"}), 400
        
        ip = data['ip'].strip()
        
        # IP format kontrolü
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, ip):
            return jsonify({"success": False, "message": "Geçersiz IP adresi formatı"}), 400
        
        # Mevcut cihazları kontrol et
        devices = scanner.get_devices()
        existing_device = None
        for device in devices:
            if device.get('ip') == ip:
                existing_device = device
                break
        
        if existing_device:
            return jsonify({"success": False, "message": f"Bu IP adresi zaten kayıtlı: {ip}"}), 400
        
        # Yeni cihaz oluştur
        new_device = {
            'ip': ip,
            'mac': data.get('mac', '').strip() or '',
            'hostname': data.get('hostname', '').strip() or '',
            'alias': data['alias'].strip(),
            'vendor': data.get('vendor', '').strip() or '',
            'device_type': data.get('device_type', '').strip() or 'Unknown',
            'notes': data.get('notes', '').strip() or '',
            'status': 'offline',  # Başlangıçta offline
            'last_seen': datetime.now().isoformat(),
            'open_ports': [],
            'manual_entry': True  # Manuel eklenen cihaz işareti
        }
        
        # Cihazı listeye ekle
        devices.append(new_device)
        
        # Dosyaya kaydet
        scanner.save_devices()
        
        print(f"Manuel cihaz eklendi: {ip} ({new_device['alias']})")
        
        return jsonify({
            "success": True, 
            "message": f"Cihaz başarıyla eklendi: {new_device['alias']}",
            "device": new_device
        })
        
    except Exception as e:
        print(f"Manuel cihaz ekleme hatası: {e}")
        return jsonify({"success": False, "message": f"Cihaz ekleme hatası: {str(e)}"}), 500

@app.route('/save_device', methods=['POST'])
def save_device():
    """Save or update a device"""
    try:
        data = request.json
        ip = data.get('ip')
        
        if not ip:
            return jsonify({"success": False, "message": "IP adresi gerekli"}), 400
        
        # Önce en güncel verileri yükle (credential manager'dan gelen değişiklikler dahil)
        scanner.load_from_json()
        devices = scanner.get_devices()
        
        # Mevcut cihazı bul
        device_found = False
        for i, device in enumerate(devices):
            if device.get('ip') == ip:
                # Cihazı güncelle (encrypted_credentials'ı koru!)
                updates = {
                    'mac': data.get('mac', device.get('mac', '')),
                    'alias': data.get('alias', device.get('alias', '')),
                    'hostname': data.get('hostname', device.get('hostname', '')),
                    'vendor': data.get('vendor', device.get('vendor', '')),
                    'device_type': data.get('device_type', device.get('device_type', '')),
                    'notes': data.get('notes', device.get('notes', '')),
                    'last_modified': datetime.now().isoformat()
                }

                # An alias the user typed here outranks the scanner's generated
                # one, and must survive every later scan.
                if 'alias' in data and data.get('alias') != device.get('alias'):
                    updates['alias_source'] = 'user'
                if 'device_type' in data and data.get('device_type') != device.get('device_type'):
                    updates['device_type_source'] = 'user'

                # Encrypted credentials'ı koru
                if 'encrypted_credentials' in device:
                    updates['encrypted_credentials'] = device['encrypted_credentials']
                
                device.update(updates)
                # Scanner'ın internal listesini de güncelle
                scanner.devices[i] = device
                device_found = True
                break
        
        if not device_found:
            # Yeni cihaz ekle
            new_device = {
                'ip': ip,
                'mac': data.get('mac', ''),
                'alias': data.get('alias', ''),
                'hostname': data.get('hostname', ''),
                'vendor': data.get('vendor', ''),
                'device_type': data.get('device_type', ''),
                'notes': data.get('notes', ''),
                'status': 'offline',
                'last_seen': datetime.now().isoformat(),
                'last_modified': datetime.now().isoformat(),
                'open_ports': []
            }
            devices.append(new_device)
        
        # Dosyaya kaydet
        scanner.save_devices()
        
        return jsonify({
            "success": True,
            "message": "Cihaz başarıyla kaydedildi"
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": f"Kaydetme hatası: {str(e)}"}), 500

@app.route('/delete_device/<ip>', methods=['DELETE'])
def delete_device(ip):
    """Delete a device"""
    try:
        devices = scanner.get_devices()
        device_found = False
        device_name = ip
        
        # Cihazı bul ve sil
        for i, device in enumerate(devices):
            if device.get('ip') == ip:
                device_name = device.get('alias') or device.get('hostname') or ip
                devices.pop(i)
                device_found = True
                break
        
        if not device_found:
            return jsonify({"success": False, "message": "Cihaz bulunamadı"}), 404
        
        # Dosyaya kaydet
        scanner.save_devices()
        
        print(f"Cihaz silindi: {ip} ({device_name})")
        
        return jsonify({
            "success": True, 
            "message": f"Cihaz başarıyla silindi: {device_name}"
        })
        
    except Exception as e:
        print(f"Cihaz silme hatası: {e}")
        return jsonify({"success": False, "message": f"Cihaz silme hatası: {str(e)}"}), 500


@app.route('/save_device_credentials', methods=['POST'])
def save_device_credentials():
    """Save device access credentials"""
    try:
        data = request.json
        ip = data.get('ip')
        access_type = data.get('access_type', 'ssh')
        
        if not ip:
            return jsonify({"error": "IP adresi gerekli"}), 400
        
        success = credential_manager.save_device_credentials(
            ip=ip,
            access_type=access_type,
            username=data.get('username', ''),
            password=data.get('password', ''),
            port=data.get('port', ''),
            additional_info={'notes': data.get('notes', '')}
        )
        
        if success:
            return jsonify({"success": True, "message": "Erişim bilgileri kaydedildi"})
        else:
            return jsonify({"error": "Kaydetme başarısız"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get_device_types')
def get_device_types():
    """Return device types"""
    try:
        return jsonify(scanner.device_types)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_device_credentials/<ip>')
def get_device_credentials(ip):
    """Get device access credentials"""
    try:
        if not credential_manager:
            return jsonify({"error": "Credential manager not initialized"}), 500
        
        access_type = request.args.get('access_type', 'ssh')
        credentials = credential_manager.get_device_credentials(ip, access_type)
        if credentials:
            return jsonify(credentials)
        else:
            return jsonify({}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_active_analyses')
def get_active_analyses():
    """Return active analysis jobs"""
    global enhanced_analysis_status, bulk_analysis_status
    
    active_analyses = {}
    
    # Tek cihaz analizleri
    for ip, status in enhanced_analysis_status.items():
        if status.get('status') == 'analyzing':
            active_analyses[ip] = {
                'type': 'single',
                'status': status.get('status'),
                'message': status.get('message'),
                'progress': status.get('progress', 0),
                'step': status.get('step', 0),
                'total_steps': status.get('total_steps', 8),
                'analysis_results': status.get('analysis_results', {}),
                'completed_steps': status.get('completed_steps', [])
            }
    
    # Toplu analiz
    if bulk_analysis_status.get('status') == 'analyzing':
        active_analyses['bulk'] = {
            'type': 'bulk',
            'status': bulk_analysis_status.get('status'),
            'message': bulk_analysis_status.get('message'),
            'progress': bulk_analysis_status.get('progress', 0),
            'current_device': bulk_analysis_status.get('current_device', ''),
            'completed_devices': bulk_analysis_status.get('completed_devices', [])
        }
    
    return jsonify(active_analyses)

@app.route('/save_analysis_temp', methods=['POST'])
def save_analysis_temp():
    """Save the analysis temp file"""
    try:
        data = request.json
        session_key = data.get('session_key')
        analysis_data = data.get('analysis_data', {})
        
        if not session_key:
            return jsonify({'error': 'Session key required'}), 400
        
        # Temp dosya dizini
        temp_dir = os.path.join('data', 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        
        # Dosya yolu
        temp_file = os.path.join(temp_dir, f'analysis_{session_key.replace(".", "_")}.json')
        
        # Kaydet
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, ensure_ascii=False, indent=2)
        
        return jsonify({'status': 'success'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/load_analysis_temp/<session_key>')
def load_analysis_temp(session_key):
    """Load the analysis temp file"""
    try:
        temp_dir = os.path.join('data', 'temp')
        temp_file = os.path.join(temp_dir, f'analysis_{session_key.replace(".", "_")}.json')
        
        if os.path.exists(temp_file):
            with open(temp_file, 'r', encoding='utf-8') as f:
                analysis_data = json.load(f)
            return jsonify(analysis_data)
        else:
            return jsonify({'error': 'Temp file not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/clear_analysis_temp/<session_key>', methods=['POST'])
def clear_analysis_temp(session_key):
    """Clear the analysis temp file"""
    try:
        temp_dir = os.path.join('data', 'temp')
        temp_file = os.path.join(temp_dir, f'analysis_{session_key.replace(".", "_")}.json')
        
        if os.path.exists(temp_file):
            os.remove(temp_file)
        
        return jsonify({'status': 'success'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/credentials/stats')
def get_credential_stats():
    """Return credential statistics"""
    global credential_manager
    try:
        stats = credential_manager.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def main():
    """Start the web UI. Entry point for `mynes` / `python -m mynes` / `app.py`."""
    scanner.load_from_json()

    host = os.environ.get('MYNES_HOST', '0.0.0.0')
    port = int(os.environ.get('MYNES_PORT') or os.environ.get('FLASK_PORT') or 5883)
    debug = os.environ.get('MYNES_DEBUG', '').lower() in ('1', 'true', 'yes')

    # Web push, service workers and the install prompt all require a secure
    # context, and http://<lan-ip> is not one - which is why "Notifications:
    # Unsupported" on an otherwise healthy LAN install. MYNES_TLS=adhoc serves
    # a self-signed cert (browsers warn once); MYNES_TLS_CERT/_KEY use your own.
    # ponytail: no cert management, no ACME. Point a reverse proxy at it if you
    # want a real certificate.
    ssl_context = None
    cert, key = os.environ.get('MYNES_TLS_CERT'), os.environ.get('MYNES_TLS_KEY')
    if cert and key:
        ssl_context = (cert, key)
    elif os.environ.get('MYNES_TLS', '').lower() in ('1', 'true', 'yes', 'adhoc'):
        ssl_context = 'adhoc'  # needs `cryptography`, already a hard dependency

    scheme = 'https' if ssl_context else 'http'
    print(f"MyNeS starting on {scheme}://localhost:{port}")
    app.run(debug=debug, host=host, port=port, ssl_context=ssl_context)


if __name__ == '__main__':
    main()
