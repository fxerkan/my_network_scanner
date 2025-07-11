/**
 * History Page JavaScript Functions
 * Handles history data visualization, charts, and statistics
 */

let scanHistory = [];
let deviceTypes = {};

// Sayfa yüklendiğinde verileri getir
window.addEventListener('load', function() {
    loadDeviceTypes();
    loadScanHistory();
});

async function loadDeviceTypes() {
    try {
        const response = await fetch('/api/config/device_types');
        deviceTypes = await response.json();
    } catch (error) {
        console.error('Cihaz tipleri yüklenirken hata oluştu:', error);
    }
}

async function loadScanHistory() {
    try {
        const response = await fetch('/api/scan_history');
        scanHistory = await response.json();
        
        updateStatistics();
        updateDeviceTypeChart();
        updateVendorChart();
        updateTrendChart();
        updateHistoryTable();
        updateTimeline();
        
    } catch (error) {
        console.error('Tarihçe yüklenirken hata oluştu:', error);
    }
}

function updateStatistics() {
    const totalScans = scanHistory.length;
    
    // Get unique devices from the last scan, not total from all scans
    const lastScanDevices = scanHistory.length > 0 ? (scanHistory[scanHistory.length - 1].total_devices || 0) : 0;
    
    // Calculate average devices per scan
    const totalDevicesAllScans = scanHistory.reduce((sum, scan) => sum + (scan.total_devices || 0), 0);
    const avgDevices = totalScans > 0 ? Math.round(totalDevicesAllScans / totalScans) : 0;
    const lastScanDuration = scanHistory.length > 0 ? Math.round(scanHistory[scanHistory.length - 1].scan_duration || 0) : 0;

    document.getElementById('totalScans').textContent = totalScans;
    document.getElementById('totalDevices').textContent = lastScanDevices; // Show last scan's unique devices
    document.getElementById('avgDevices').textContent = avgDevices;
    document.getElementById('lastScanDuration').textContent = lastScanDuration + 's';
}

function updateDeviceTypeChart() {
    const deviceTypeChart = document.getElementById('deviceTypeChart');
    deviceTypeChart.innerHTML = '';

    if (scanHistory.length === 0) {
        deviceTypeChart.innerHTML = '<p style="text-align: center; color: #6c757d;">Henüz tarama verisi yok</p>';
        return;
    }

    const lastScan = scanHistory[scanHistory.length - 1];
    const scanDeviceTypes = lastScan.device_types || {};

    // Pie chart container oluştur
    const chartContainer = document.createElement('div');
    chartContainer.className = 'pie-chart-container';
    
    const pieChart = document.createElement('div');
    pieChart.className = 'pie-chart';
    pieChart.id = 'deviceTypePieChart';
    
    // Tooltip element
    const tooltip = document.createElement('div');
    tooltip.className = 'pie-tooltip';
    tooltip.id = 'pieTooltip';
    
    chartContainer.appendChild(pieChart);
    chartContainer.appendChild(tooltip);
    deviceTypeChart.appendChild(chartContainer);

    // Pie chart oluştur
    createDeviceTypePieChart(scanDeviceTypes);
}

function createDeviceTypePieChart(scanDeviceTypes) {
    const pieChart = document.getElementById('deviceTypePieChart');
    const tooltip = document.getElementById('pieTooltip');
    
    const total = Object.values(scanDeviceTypes).reduce((sum, count) => sum + count, 0);
    if (total === 0) {
        pieChart.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #6c757d;">Veri yok</div>';
        return;
    }

    // Renk paleti
    const colors = [
        '#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe',
        '#43e97b', '#38f9d7', '#ffecd2', '#fcb69f', '#a8edea', '#fed6e3',
        '#ff9a9e', '#fecfef', '#ffefd5', '#c471f5', '#fa71cd', '#667eea'
    ];

    let cumulativePercentage = 0;
    let colorIndex = 0;
    
    // SVG oluştur
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '250');
    svg.setAttribute('height', '250');
    svg.style.transform = 'rotate(-90deg)';

    // Cihaz tiplerini sayıya göre büyükten küçüğe sırala
    const sortedDeviceTypes = Object.entries(scanDeviceTypes).sort((a, b) => b[1] - a[1]);
    
    sortedDeviceTypes.forEach(([deviceType, count]) => {
        const percentage = (count / total) * 100;
        const circumference = 2 * Math.PI * 100; // radius = 100
        const strokeDasharray = `${(percentage / 100) * circumference} ${circumference}`;
        const strokeDashoffset = -cumulativePercentage * circumference / 100;
        
        // Circle element
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', '125');
        circle.setAttribute('cy', '125');
        circle.setAttribute('r', '100');
        circle.setAttribute('fill', 'transparent');
        circle.setAttribute('stroke', colors[colorIndex % colors.length]);
        circle.setAttribute('stroke-width', '50');
        circle.setAttribute('stroke-dasharray', strokeDasharray);
        circle.setAttribute('stroke-dashoffset', strokeDashoffset);
        circle.style.transition = 'all 0.3s ease';
        circle.style.cursor = 'pointer';
        
        // Hover effects
        circle.addEventListener('mouseenter', (e) => {
            circle.style.strokeWidth = '55';
            circle.style.filter = 'brightness(1.1)';
            
            const icon = getDeviceTypeIcon(deviceType);
            tooltip.innerHTML = `${icon} <strong>${deviceType}</strong><br>${count} cihaz (${percentage.toFixed(1)}%)`;
            tooltip.style.display = 'block';
        });
        
        circle.addEventListener('mousemove', (e) => {
            const rect = pieChart.getBoundingClientRect();
            tooltip.style.left = (e.clientX - rect.left + 10) + 'px';
            tooltip.style.top = (e.clientY - rect.top - 10) + 'px';
        });
        
        circle.addEventListener('mouseleave', () => {
            circle.style.strokeWidth = '50';
            circle.style.filter = 'none';
            tooltip.style.display = 'none';
        });
        
        svg.appendChild(circle);
        
        cumulativePercentage += percentage;
        colorIndex++;
    });
    
    pieChart.appendChild(svg);
}

function getDeviceTypeIcon(deviceTypeName) {
    // device_types.json'dan icon al
    if (deviceTypes[deviceTypeName] && deviceTypes[deviceTypeName].icon) {
        return deviceTypes[deviceTypeName].icon;
    }
    
    // Fallback iconlar
    const fallbackIcons = {
        'Unknown': '❓',
        'Router': '🌐',
        'Switch': '🔀',
        'Smartphone': '📱',
        'Tablet': '📃',
        'Laptop': '💻',
        'Desktop': '🖥️',
        'Printer': '🖨️',
        'IP Camera': '📹',
        'Smart TV': '📺',
        'Gaming Console': '🎮',
        'Smart Speaker': '🔊',
        'NAS': '💾',
        'IoT Device': '🔗'
    };
    
    return fallbackIcons[deviceTypeName] || '📦';
}

function updateVendorChart() {
    const vendorChart = document.getElementById('vendorChart');
    vendorChart.innerHTML = '';

    if (scanHistory.length === 0) {
        vendorChart.innerHTML = '<p style="text-align: center; color: #6c757d;">Henüz tarama verisi yok</p>';
        return;
    }

    const lastScan = scanHistory[scanHistory.length - 1];
    const vendors = lastScan.vendors || {};

    // Vendor'ları sayıya göre sırala
    const sortedVendors = Object.entries(vendors).sort((a, b) => b[1] - a[1]);
    const maxCount = Math.max(...Object.values(vendors));

    // İlk 15 vendor'ı göster
    sortedVendors.slice(0, 15).forEach(([vendor, count]) => {
        const vendorItem = document.createElement('div');
        vendorItem.className = 'vendor-item';
        
        const percentage = (count / maxCount) * 100;
        
        vendorItem.innerHTML = `
            <div class="vendor-name" title="${vendor}">${vendor}</div>
            <div class="vendor-bar">
                <div class="vendor-fill" style="width: ${percentage}%"></div>
            </div>
            <div class="vendor-count">${count}</div>
        `;
        
        vendorChart.appendChild(vendorItem);
    });
}

function updateTrendChart() {
    const trendChart = document.getElementById('trendChart');
    const controlsContainer = document.getElementById('trendChartControls');
    
    if (!trendChart || !controlsContainer) return;
    
    trendChart.innerHTML = '';
    controlsContainer.innerHTML = '';

    if (scanHistory.length === 0) {
        trendChart.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 60px;">Henüz tarama verisi yok</p>';
        return;
    }

    // Son 20 taramayı al
    const recentHistory = scanHistory.slice(-20);
    
    if (recentHistory.length < 2) {
        trendChart.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 60px;">Trend göstermek için en az 2 tarama gerekli</p>';
        return;
    }

    // Metrikler tanımı
    const metrics = [
        { key: 'total_devices', label: 'Toplam Cihaz', color: '#667eea', active: true },
        { key: 'online_devices', label: 'Online Cihaz', color: '#43e97b', active: true },
        { key: 'scan_duration', label: 'Tarama Süresi (s)', color: '#f5576c', active: false }
    ];

    // Kontrol butonlarını oluştur
    metrics.forEach((metric, index) => {
        const toggle = document.createElement('div');
        toggle.className = `metric-toggle ${metric.active ? 'active' : ''}`;
        toggle.innerHTML = `
            <span class="metric-color" style="background-color: ${metric.color}"></span>
            <span>${metric.label}</span>
        `;
        
        toggle.addEventListener('click', () => {
            metric.active = !metric.active;
            toggle.classList.toggle('active', metric.active);
            drawTrendChart(recentHistory, metrics);
        });
        
        controlsContainer.appendChild(toggle);
    });

    // Chart'ı çiz
    drawTrendChart(recentHistory, metrics);
}

function drawTrendChart(data, metrics) {
    const trendChart = document.getElementById('trendChart');
    const tooltip = document.getElementById('chartTooltip');
    
    trendChart.innerHTML = '';

    // SVG chart oluştur
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '380');
    svg.setAttribute('viewBox', '0 0 900 380');
    
    const margin = { top: 20, right: 30, bottom: 80, left: 70 };
    const width = 900 - margin.left - margin.right;
    const height = 380 - margin.top - margin.bottom;

    // Aktif metrikleri al
    const activeMetrics = metrics.filter(m => m.active);
    
    if (activeMetrics.length === 0) {
        trendChart.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 60px;">En az bir metrik seçin</p>';
        return;
    }

    // Her metrik için min/max değerleri hesapla (Y eksenini 0'dan başlat)
    const metricRanges = {};
    activeMetrics.forEach(metric => {
        const values = data.map(scan => scan[metric.key] || 0);
        metricRanges[metric.key] = {
            min: 0, // Y eksenini 0'dan başlat
            max: Math.max(...values),
            range: Math.max(...values) || 1
        };
    });

    // Grid çizgileri (sadece ilk metrik için)
    const primaryMetric = activeMetrics[0];
    const primaryRange = metricRanges[primaryMetric.key];
    
    for (let i = 0; i <= 5; i++) {
        const y = margin.top + (height * i / 5);
        const value = Math.round(primaryRange.max - (primaryRange.max * i / 5));
        
        // Yatay grid çizgisi
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', margin.left);
        line.setAttribute('y1', y);
        line.setAttribute('x2', margin.left + width);
        line.setAttribute('y2', y);
        line.setAttribute('stroke', '#f0f0f0');
        line.setAttribute('stroke-width', '1');
        svg.appendChild(line);
        
        // Y ekseni etiketi
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', margin.left - 10);
        text.setAttribute('y', y + 5);
        text.setAttribute('text-anchor', 'end');
        text.setAttribute('font-size', '11');
        text.setAttribute('fill', '#6c757d');
        text.textContent = value;
        svg.appendChild(text);
    }

    // Her aktif metrik için area chart çiz
    activeMetrics.forEach((metric) => {
        const range = metricRanges[metric.key];
        let pathData = '';
        let areaData = '';
        
        // Başlangıç noktası (sol alt köşe)
        const startX = margin.left;
        const baselineY = margin.top + height;
        areaData += `M ${startX} ${baselineY}`;
        
        // Data noktaları ve path
        data.forEach((scan, index) => {
            const x = margin.left + (width * index / (data.length - 1));
            const normalizedValue = scan[metric.key] / range.range;
            const y = margin.top + height - (normalizedValue * height);
            
            if (index === 0) {
                pathData += `M ${x} ${y}`;
                areaData += ` L ${x} ${y}`;
            } else {
                pathData += ` L ${x} ${y}`;
                areaData += ` L ${x} ${y}`;
            }
            
            // Data noktası
            const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', x);
            circle.setAttribute('cy', y);
            circle.setAttribute('r', '4');
            circle.setAttribute('fill', metric.color);
            circle.setAttribute('stroke', 'white');
            circle.setAttribute('stroke-width', '2');
            circle.style.cursor = 'pointer';
            
            // Hover effects
            circle.addEventListener('mouseenter', () => {
                circle.setAttribute('r', '6');
                
                // Tooltip içeriği
                const date = new Date(scan.timestamp).toLocaleDateString('tr-TR');
                let tooltipHtml = `<div class="tooltip-date">${date}</div>`;
                
                activeMetrics.forEach(m => {
                    const value = scan[m.key] || 0;
                    const unit = m.key === 'scan_duration' ? 's' : '';
                    tooltipHtml += `
                        <div class="tooltip-metric">
                            <div class="tooltip-metric-label">
                                <span class="tooltip-metric-color" style="background-color: ${m.color}"></span>
                                ${m.label}
                            </div>
                            <strong>${value}${unit}</strong>
                        </div>
                    `;
                });
                
                tooltip.innerHTML = tooltipHtml;
                tooltip.style.display = 'block';
            });
            
            circle.addEventListener('mousemove', (e) => {
                const rect = trendChart.getBoundingClientRect();
                tooltip.style.left = (e.clientX - rect.left + 10) + 'px';
                tooltip.style.top = (e.clientY - rect.top - 10) + 'px';
            });
            
            circle.addEventListener('mouseleave', () => {
                circle.setAttribute('r', '4');
                tooltip.style.display = 'none';
            });
            
            svg.appendChild(circle);
        });

        // Area path'ini kapat (sağ alt köşeye git)
        const endX = margin.left + width;
        areaData += ` L ${endX} ${baselineY} Z`;

        // Area (dolgu)
        const area = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        area.setAttribute('d', areaData);
        area.setAttribute('fill', metric.color);
        area.setAttribute('fill-opacity', '0.3');
        area.setAttribute('stroke', 'none');
        svg.appendChild(area);

        // Çizgi (area'nın üstüne)
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', pathData);
        path.setAttribute('stroke', metric.color);
        path.setAttribute('stroke-width', '3');
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke-linecap', 'round');
        path.setAttribute('stroke-linejoin', 'round');
        svg.appendChild(path);
    });

    // X ekseni etiketleri
    data.forEach((scan, index) => {
        if (index % 3 === 0 || index === data.length - 1) {
            const x = margin.left + (width * index / (data.length - 1));
            const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            text.setAttribute('x', x);
            text.setAttribute('y', margin.top + height + 20);
            text.setAttribute('text-anchor', 'middle');
            text.setAttribute('font-size', '10');
            text.setAttribute('fill', '#6c757d');
            text.setAttribute('transform', `rotate(-45, ${x}, ${margin.top + height + 20})`);
            const date = new Date(scan.timestamp).toLocaleDateString('tr-TR', { 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
            text.textContent = date;
            svg.appendChild(text);
        }
    });

    // Eksenleri çiz
    // Y ekseni
    const yAxis = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    yAxis.setAttribute('x1', margin.left);
    yAxis.setAttribute('y1', margin.top);
    yAxis.setAttribute('x2', margin.left);
    yAxis.setAttribute('y2', margin.top + height);
    yAxis.setAttribute('stroke', '#2c3e50');
    yAxis.setAttribute('stroke-width', '2');
    svg.appendChild(yAxis);

    // X ekseni
    const xAxis = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    xAxis.setAttribute('x1', margin.left);
    xAxis.setAttribute('y1', margin.top + height);
    xAxis.setAttribute('x2', margin.left + width);
    xAxis.setAttribute('y2', margin.top + height);
    xAxis.setAttribute('stroke', '#2c3e50');
    xAxis.setAttribute('stroke-width', '2');
    svg.appendChild(xAxis);

    trendChart.appendChild(svg);
}

function updateHistoryTable() {
    const historyTableBody = document.getElementById('historyTableBody');
    historyTableBody.innerHTML = '';

    if (scanHistory.length === 0) {
        historyTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6c757d;">Henüz tarama verisi yok</td></tr>';
        return;
    }

    // Son 20 taramayı göster, son tarihten eskiye doğru
    const recentHistory = scanHistory.slice(-20).reverse();

    recentHistory.forEach((scan, index) => {
        const date = new Date(scan.timestamp);
        const formattedDate = date.toLocaleString('tr-TR');
        
        // Trend hesapla (bir önceki tarama ile karşılaştır)
        let trendClass = 'trend-stable';
        let trendText = 'Stabil';
        
        if (index < recentHistory.length - 1) {
            const prevScan = recentHistory[index + 1];
            const currentDevices = scan.total_devices || 0;
            const prevDevices = prevScan.total_devices || 0;
            
            if (currentDevices > prevDevices) {
                trendClass = 'trend-up';
                trendText = `+${currentDevices - prevDevices}`;
            } else if (currentDevices < prevDevices) {
                trendClass = 'trend-down';
                trendText = `${currentDevices - prevDevices}`;
            }
        }

        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formattedDate}</td>
            <td>${scan.ip_range || 'N/A'}</td>
            <td>${scan.total_devices || 0}</td>
            <td>${scan.online_devices || 0}</td>
            <td>${Math.round(scan.scan_duration || 0)}s</td>
            <td><span class="trend-indicator ${trendClass}">${trendText}</span></td>
        `;
        
        historyTableBody.appendChild(row);
    });
}

function updateTimeline() {
    const scanTimeline = document.getElementById('scanTimeline');
    scanTimeline.innerHTML = '';

    if (scanHistory.length === 0) {
        scanTimeline.innerHTML = '<p style="text-align: center; color: #6c757d;">Henüz tarama verisi yok</p>';
        return;
    }

    // Son 10 taramayı timeline'da göster
    const recentHistory = scanHistory.slice(-10).reverse();

    recentHistory.forEach(scan => {
        const date = new Date(scan.timestamp);
        const formattedDate = date.toLocaleString('tr-TR');
        
        const timelineItem = document.createElement('div');
        timelineItem.className = 'timeline-item';
        
        // En çok bulunan cihaz tipi ve vendor
        const scanDeviceTypes = scan.device_types || {};
        const vendors = scan.vendors || {};
        
        const topDeviceType = Object.entries(scanDeviceTypes).sort((a, b) => b[1] - a[1])[0];
        const topVendor = Object.entries(vendors).sort((a, b) => b[1] - a[1])[0];
        
        timelineItem.innerHTML = `
            <div class="timeline-date">${formattedDate}</div>
            <div class="timeline-content">
                <div class="timeline-title">
                    ${scan.total_devices || 0} cihaz bulundu (${scan.online_devices || 0} online)
                </div>
                <div class="timeline-details">
                    <strong>IP Aralığı:</strong> ${scan.ip_range || 'N/A'}<br>
                    <strong>Tarama Süresi:</strong> ${Math.round(scan.scan_duration || 0)} saniye<br>
                    ${topDeviceType ? `<strong>En Çok Bulunan Tip:</strong> ${topDeviceType[0]} (${topDeviceType[1]} adet)<br>` : ''}
                    ${topVendor ? `<strong>En Çok Bulunan Marka:</strong> ${topVendor[0]} (${topVendor[1]} adet)` : ''}
                </div>
            </div>
        `;
        
        scanTimeline.appendChild(timelineItem);
    });
}

function exportHistory() {
    const dataStr = JSON.stringify(scanHistory, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `lan_scanner_history_${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

async function clearHistory() {
    if (confirm('Tüm tarama geçmişini silmek istediğinizden emin misiniz? Bu işlem geri alınamaz.')) {
        try {
            const response = await fetch('/api/clear_history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const result = await response.json();
            
            if (result.success) {
                scanHistory = [];
                updateStatistics();
                updateDeviceTypeChart();
                updateVendorChart();
                updateTrendChart();
                updateHistoryTable();
                updateTimeline();
                alert('Tarihçe temizlendi!');
            } else {
                alert('Tarihçe temizlenirken hata oluştu: ' + result.error);
            }
        } catch (error) {
            alert('Tarihçe temizlenirken hata oluştu: ' + error.message);
        }
    }
}

// Sayfa 30 saniyede bir otomatik olarak yenilensin
setInterval(loadScanHistory, 30000);