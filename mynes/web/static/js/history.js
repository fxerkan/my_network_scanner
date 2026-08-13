/**
 * History Page JavaScript Functions
 * Handles history data visualization, charts, and statistics
 */

let scanHistory = [];
let deviceTypes = {};

/** Dates used to be hardcoded to tr-TR, so the English page showed Turkish. */
function pageLocale() {
    const lang = document.documentElement.lang || 'en';
    return lang === 'tr' ? 'tr-TR' : 'en-GB';
}

// Sayfa yüklendiğinde verileri getir
window.addEventListener('load', function() {
    loadDeviceTypes();
    loadScanHistory();
    loadUptime();
});

// translations.js fetches its table asynchronously, so the first render can
// beat it and paint raw keys ("total_devices") into the chart legend.
window.addEventListener('translationsLoaded', function () {
    loadUptime();
    if (scanHistory.length) {
        updateDeviceTypeChart();
        updateTrendChart();
        updateHistoryTable();
        updateTimeline();
    }
});

async function loadDeviceTypes() {
    try {
        const response = await fetch('/api/config/device_types');
        deviceTypes = await response.json();
    } catch (error) {
        console.error('device types failed to load:', error);
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
        console.error('scan history failed to load:', error);
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
        deviceTypeChart.innerHTML = `<p class="chart-empty">${t('no_scan_data')}</p>`;
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
        pieChart.innerHTML = `<div class="chart-empty">${t('no_data')}</div>`;
        return;
    }

    // Eight tokens, cycled. Reading the slice colour off a CSS variable keeps
    // the chart on the same palette as the rest of the app in both themes.
    const styles = getComputedStyle(document.documentElement);
    const colorAt = i => styles.getPropertyValue(`--chart-${(i % 8) + 1}`).trim() || 'currentColor';

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 250 250');
    svg.setAttribute('class', 'donut-svg');

    const ring = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    ring.setAttribute('transform', 'rotate(-90 125 125)');
    svg.appendChild(ring);

    const sorted = Object.entries(scanDeviceTypes).sort((a, b) => b[1] - a[1]);
    const circumference = 2 * Math.PI * 100;
    let cumulative = 0;

    sorted.forEach(([deviceType, count], i) => {
        const percentage = (count / total) * 100;
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', '125');
        circle.setAttribute('cy', '125');
        circle.setAttribute('r', '100');
        circle.setAttribute('fill', 'transparent');
        circle.setAttribute('stroke', colorAt(i));
        circle.setAttribute('stroke-width', '46');
        circle.setAttribute('stroke-dasharray', `${(percentage / 100) * circumference} ${circumference}`);
        circle.setAttribute('stroke-dashoffset', -cumulative * circumference / 100);
        circle.classList.add('donut-slice');

        circle.addEventListener('mouseenter', () => {
            circle.setAttribute('stroke-width', '52');
            tooltip.innerHTML = `${getDeviceTypeIcon(deviceType)} <strong>${deviceType}</strong><br>${count} (${percentage.toFixed(1)}%)`;
            tooltip.style.display = 'block';
        });
        circle.addEventListener('mousemove', (e) => {
            const rect = pieChart.getBoundingClientRect();
            tooltip.style.left = (e.clientX - rect.left + 10) + 'px';
            tooltip.style.top = (e.clientY - rect.top - 10) + 'px';
        });
        circle.addEventListener('mouseleave', () => {
            circle.setAttribute('stroke-width', '46');
            tooltip.style.display = 'none';
        });

        ring.appendChild(circle);

        // Data label in the slice. Below ~7% the text does not fit an arc this
        // thick, so those are left to the legend rather than drawn overlapping.
        if (percentage >= 7) {
            const angle = ((cumulative + percentage / 2) / 100) * 2 * Math.PI - Math.PI / 2;
            const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', 125 + Math.cos(angle) * 100);
            label.setAttribute('y', 125 + Math.sin(angle) * 100 + 4);
            label.setAttribute('text-anchor', 'middle');
            label.setAttribute('class', 'donut-label');
            label.textContent = count;
            svg.appendChild(label);
        }

        cumulative += percentage;
    });

    const centreValue = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    centreValue.setAttribute('x', '125');
    centreValue.setAttribute('y', '120');
    centreValue.setAttribute('text-anchor', 'middle');
    centreValue.setAttribute('class', 'donut-total');
    centreValue.textContent = total;
    svg.appendChild(centreValue);

    const centreLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    centreLabel.setAttribute('x', '125');
    centreLabel.setAttribute('y', '140');
    centreLabel.setAttribute('text-anchor', 'middle');
    centreLabel.setAttribute('class', 'donut-total-label');
    centreLabel.textContent = t('devices');
    svg.appendChild(centreLabel);

    pieChart.appendChild(svg);

    const legend = document.createElement('ul');
    legend.className = 'donut-legend';
    legend.innerHTML = sorted.map(([deviceType, count], i) => `
        <li class="donut-legend__item">
            <span class="donut-legend__dot" style="background:${colorAt(i)}"></span>
            <span class="donut-legend__name" title="${deviceType}">${getDeviceTypeIcon(deviceType)} ${deviceType}</span>
            <span class="donut-legend__value">${count}</span>
            <span class="donut-legend__pct">${((count / total) * 100).toFixed(0)}%</span>
        </li>`).join('');
    pieChart.parentElement.appendChild(legend);
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
    
    if (deviceTypeName && /docker/i.test(deviceTypeName)) return '🐳';
    return fallbackIcons[deviceTypeName] || '📦';
}

function updateVendorChart() {
    const vendorChart = document.getElementById('vendorChart');
    vendorChart.innerHTML = '';

    if (scanHistory.length === 0) {
        vendorChart.innerHTML = `<p class="chart-empty">${t('no_scan_data')}</p>`;
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
            <div class="vendor-bar"><div class="vendor-fill" style="width: ${percentage}%"></div></div>
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
        trendChart.innerHTML = `<p class="chart-empty">${t('no_scan_data')}</p>`;
        return;
    }

    // Son 20 taramayı al
    const recentHistory = scanHistory.slice(-20);
    
    if (recentHistory.length < 2) {
        trendChart.innerHTML = `<p class="chart-empty">${t('trend_needs_two_scans')}</p>`;
        return;
    }

    // Labels were hardcoded Turkish, which showed up untranslated on the
    // English page; colours now come from the shared chart palette.
    const styles = getComputedStyle(document.documentElement);
    const token = name => styles.getPropertyValue(name).trim() || 'currentColor';
    const metrics = [
        { key: 'total_devices',  label: t('total_devices'),  color: token('--chart-1'), active: true },
        { key: 'online_devices', label: t('online_devices'), color: token('--chart-2'), active: true },
        { key: 'scan_duration',  label: t('scan_duration_seconds'),  color: token('--chart-4'), active: false }
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
        trendChart.innerHTML = `<p class="chart-empty">${t('select_a_metric')}</p>`;
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
        line.setAttribute('stroke', 'currentColor');
        line.setAttribute('class', 'trend-grid');
        line.setAttribute('stroke-width', '1');
        svg.appendChild(line);
        
        // Y ekseni etiketi
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', margin.left - 10);
        text.setAttribute('y', y + 5);
        text.setAttribute('text-anchor', 'end');
        text.setAttribute('font-size', '11');
        text.setAttribute('class', 'trend-axis');
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
                const date = new Date(scan.timestamp).toLocaleDateString(pageLocale());
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

            // Data label. Every point on a 20-point series would collide, so
            // only every other one is drawn once the series gets long.
            if (data.length <= 10 || index % 2 === 0 || index === data.length - 1) {
                const value = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                value.setAttribute('x', x);
                value.setAttribute('y', y - 12);
                value.setAttribute('text-anchor', 'middle');
                value.setAttribute('class', 'trend-value');
                value.setAttribute('fill', metric.color);
                value.textContent = scan[metric.key] || 0;
                svg.appendChild(value);
            }
        });

        // Area path'ini kapat (sağ alt köşeye git)
        const endX = margin.left + width;
        areaData += ` L ${endX} ${baselineY} Z`;

        // Area (dolgu)
        const area = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        area.setAttribute('d', areaData);
        area.setAttribute('fill', metric.color);
        area.setAttribute('fill-opacity', '0.16');
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
            const date = new Date(scan.timestamp).toLocaleDateString(pageLocale(), { 
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
        historyTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-tertiary);">' + t('no_scan_data') + '</td></tr>';
        return;
    }

    // Son 20 taramayı göster, son tarihten eskiye doğru
    const recentHistory = scanHistory.slice(-20).reverse();

    recentHistory.forEach((scan, index) => {
        const date = new Date(scan.timestamp);
        const formattedDate = date.toLocaleString(pageLocale());
        
        // Trend hesapla (bir önceki tarama ile karşılaştır)
        let trendClass = 'trend-stable';
        let trendText = t('trend_stable');
        
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
        scanTimeline.innerHTML = `<p class="chart-empty">${t('no_scan_data')}</p>`;
        return;
    }

    // Son 10 taramayı timeline'da göster
    const recentHistory = scanHistory.slice(-10).reverse();

    recentHistory.forEach(scan => {
        const date = new Date(scan.timestamp);
        const formattedDate = date.toLocaleString(pageLocale());
        
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
                    ${scan.total_devices || 0} ${t('devices')} (${scan.online_devices || 0} ${t('online')})
                </div>
                <div class="timeline-details">
                    <strong>${t('ip_range')}:</strong> ${scan.ip_range || 'N/A'}<br>
                    <strong>${t('scan_duration')}:</strong> ${Math.round(scan.scan_duration || 0)}s<br>
                    ${topDeviceType ? `<strong>${t('top_device_type')}:</strong> ${topDeviceType[0]} (${topDeviceType[1]})<br>` : ''}
                    ${topVendor ? `<strong>${t('top_vendor')}:</strong> ${topVendor[0]} (${topVendor[1]})` : ''}
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
                alert(t('history_cleared'));
            } else {
                alert(t('history_clear_error') + ': ' + result.error);
            }
        } catch (error) {
            alert(t('history_clear_error') + ': ' + error.message);
        }
    }
}

// Sayfa 30 saniyede bir otomatik olarak yenilensin
setInterval(loadScanHistory, 30000);

/*
 * Per-device availability strip. Only shown when scheduled scanning is on -
 * without it there is nothing sampling the network, so the cells would be a
 * misleading record of whenever somebody happened to press Scan.
 */
async function loadUptime() {
    const card = document.getElementById('uptimeCard');
    if (!card) return;

    let data;
    try {
        data = await (await fetch('/api/monitoring/uptime?limit=48')).json();
    } catch (error) {
        card.hidden = true;
        return;
    }

    if (!data.enabled || !data.devices || !data.devices.length) {
        card.hidden = true;
        return;
    }
    card.hidden = false;

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const icon = type => (typeof getDeviceTypeIcon === 'function' ? getDeviceTypeIcon(type) : '');

    const first = data.checks[0];
    const last = data.checks[data.checks.length - 1];
    const incidents = data.devices.reduce((sum, d) => sum + d.incidents, 0);
    document.getElementById('uptimeSummary').textContent = t('uptime_summary', {
        checks: data.checks.length,
        incidents: incidents,
        from: first ? new Date(first).toLocaleString(pageLocale()) : '—',
        to: last ? new Date(last).toLocaleString(pageLocale()) : '—'
    });

    // Sort by availability %, highest first (the always-on devices at the top,
    // the one-hit-wonder rotating-MAC noise at the bottom), then IP as tie-break.
    const ipParts = ip => (ip || '').split('.').map(n => parseInt(n, 10) || 0);
    const sorted = data.devices.slice().sort(function (a, b) {
        if ((b.uptime || 0) !== (a.uptime || 0)) return (b.uptime || 0) - (a.uptime || 0);
        if (!a.ip || !b.ip) {
            if (Boolean(a.ip) !== Boolean(b.ip)) return a.ip ? -1 : 1;
            return String(a.name || '').localeCompare(String(b.name || ''));
        }
        const pa = ipParts(a.ip), pb = ipParts(b.ip);
        for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
        return 0;
    });

    // Last non-null cell = the device's most recent known reachability.
    const lastState = d => [...d.cells].reverse().find(s => s) || null;

    const PAGE_SIZE = 60;   // rotating-MAC devices can push this into the hundreds
    let page = 0;

    const render = function () {
        const statusF = (document.getElementById('uptimeStatusFilter') || {}).value || 'all';
        const F = window.MynesFilters;
        const s = F ? F.get() : null;
        const rows = sorted.filter(function (d) {
            if (statusF === 'active' && lastState(d) !== 'up') return false;
            if (statusF === 'passive' && lastState(d) === 'up') return false;
            // Shared filters. Uptime rows carry device_type/ip/name but no
            // vendor, so the vendor dimension is intentionally skipped here.
            if (s) {
                if (!s.showContainers && F.isContainer(d)) return false;
                if (!s.showNoIp && F.isNoIp(d)) return false;
                if (!s.showBluetooth && F.isBluetooth(d)) return false;
                if (!s.showRandomMac && F.isRandomMac(d) && !F.isContainer(d)) return false;
                if (s.types.length && !s.types.includes(d.device_type)) return false;
                if (s.q) {
                    const hay = [d.name, d.ip, d.device_type].filter(Boolean).join(' ').toLowerCase();
                    if (!hay.includes(s.q.toLowerCase())) return false;
                }
            }
            return true;
        });
        const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
        if (page >= pageCount) page = pageCount - 1;
        const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
        document.getElementById('uptimeList').innerHTML = pageRows.map(function (d) {
            const cells = d.cells.map(function (state, i) {
                const stamp = data.checks[i] ? new Date(data.checks[i]).toLocaleString(pageLocale()) : '';
                const label = state ? t('uptime_' + state) : t('uptime_unknown');
                return '<i class="uptime-cell uptime-cell--' + (state || 'none') + '"' +
                       ' title="' + esc(stamp + ' — ' + label) + '"></i>';
            }).join('');
            const pctClass = d.uptime >= 99 ? '' : (d.uptime >= 90 ? ' is-degraded' : ' is-down');
            // Name/MAC links to the Devices page, which opens this device's edit
            // popup (?device=<ip|mac>). The rich edit modal lives on that page.
            const ident = d.ip || d.mac || '';
            // IP first (leftmost), then the name - list is IP-sorted, so the IP is the primary key.
            const inner = icon(d.device_type) +
                (d.ip ? '<span class="uptime-row__ip">' + esc(d.ip) + '</span>' : '') +
                '<span title="' + esc(d.name) + '">' + esc(d.name) + '</span>';
            const nameHtml = ident
                ? '<a class="uptime-row__link" href="/?device=' + encodeURIComponent(ident) +
                  '" title="' + esc(t('open_device_details')) + '">' + inner + '</a>'
                : inner;
            return '<div class="uptime-row">' +
                '<div class="uptime-row__name">' + nameHtml + '</div>' +
                '<div class="uptime-row__bars">' + cells + '</div>' +
                '<div class="uptime-row__pct' + pctClass + '">' + d.uptime + '%</div>' +
            '</div>';
        }).join('');
        renderPager(rows.length, pageCount);
    };

    // Prev / "page X of Y (N devices)" / Next. Only shown when it overflows one
    // page - a handful of devices needs no pager.
    function renderPager(total, pageCount) {
        const host = document.getElementById('uptimePager');
        if (!host) return;
        if (pageCount <= 1) { host.innerHTML = ''; return; }
        const info = t('uptime_page_of', { page: page + 1, pages: pageCount, total: total }) ||
            ((page + 1) + ' / ' + pageCount + ' (' + total + ')');
        host.innerHTML =
            '<button class="btn btn-small" id="uptimePrev"' + (page === 0 ? ' disabled' : '') + '>‹</button>' +
            '<span class="uptime-pager__info">' + esc(info) + '</span>' +
            '<button class="btn btn-small" id="uptimeNext"' + (page >= pageCount - 1 ? ' disabled' : '') + '>›</button>';
        const prev = document.getElementById('uptimePrev'), next = document.getElementById('uptimeNext');
        if (prev) prev.onclick = function () { if (page > 0) { page--; render(); } };
        if (next) next.onclick = function () { page++; render(); };
    }

    ['uptimeStatusFilter'].forEach(function (id) {
        const el = document.getElementById(id);
        if (el && !el.dataset.wired) { el.dataset.wired = '1'; el.addEventListener('change', function () { page = 0; render(); }); }
    });
    // Shared visibility toggles + re-render when any shared filter changes.
    if (window.MynesFilters && !card.dataset.filtersWired) {
        card.dataset.filtersWired = '1';
        MynesFilters.bindToggle(document.getElementById('toggleContainers'), 'showContainers');
        MynesFilters.bindToggle(document.getElementById('toggleNoIp'), 'showNoIp');
        MynesFilters.bindToggle(document.getElementById('toggleBluetooth'), 'showBluetooth');
        MynesFilters.bindToggle(document.getElementById('toggleRandomMac'), 'showRandomMac');
        // Same searchable Device Type multi-select as the Devices page, bound to
        // the shared 'types' filter the render above already honours. Options are
        // the types actually present in the uptime data.
        var typeEl = document.getElementById('uptimeTypeMulti');
        if (typeEl) MynesFilters.mountMulti(typeEl, {
            key: 'types', label: t('device_type'),
            options: function () {
                return [...new Set(data.devices.map(function (d) { return d.device_type; }).filter(Boolean))]
                    .sort().map(function (v) { return { value: v, label: v }; });
            }
        });
        document.addEventListener('mynes:filters', function () { page = 0; render(); });
    }
    render();
}
