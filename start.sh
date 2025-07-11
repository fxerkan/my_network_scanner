#!/bin/bash

# LAN Scanner Başlatma Scripti
# Bu script virtual environment'ı aktifleştirir ve uygulamayı başlatır

echo "🌐 LAN Scanner başlatılıyor..."

# Virtual environment'ın varlığını kontrol et
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment bulunamadı!"
    echo "Lütfen önce şu komutu çalıştırın: python3 -m venv .venv"
    exit 1
fi

# Virtual environment'ı aktifleştir
echo "📦 Virtual environment aktifleştiriliyor..."
source .venv/bin/activate

# Gerekli paketlerin kurulu olup olmadığını kontrol et
echo "🔍 Bağımlılıklar kontrol ediliyor..."
if ! python -c "import flask, nmap, netifaces, scapy" 2>/dev/null; then
    echo "📥 Eksik paketler kuruluyor..."
    pip install -r requirements.txt
fi

# Nmap'in kurulu olup olmadığını kontrol et
if ! command -v nmap &> /dev/null; then
    echo "❌ Nmap bulunamadı! Lütfen nmap'i kurun:"
    echo "macOS: brew install nmap"
    echo "Ubuntu: sudo apt-get install nmap"
    exit 1
fi

# Yetki kontrolü (macOS için)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🔐 macOS tespit edildi. Port taraması için yönetici yetkileri gerekebilir."
fi

echo "🚀 Uygulama başlatılıyor..."
echo "📱 Web arayüzü: http://localhost:5883"
echo "⏹️  Durdurmak için Ctrl+C kullanın"
echo ""

# Uygulamayı başlat
python app.py
