// Enhanced Details Modal Management
// Gelişmiş Analiz Detayları Modal Yönetimi

let currentDevice = null;
let currentTab = 'overview';

// Enhanced Details Modal'ını açma fonksiyonu
function openEnhancedDetailsModal(device) {
    currentDevice = device;
    
    // Enhanced info'ya sahip olup olmadığını kontrol et
    // Keşif verisi de tek başına modalı açmaya yeter: gelişmiş analiz yapılmamış
    // bir cihazın SSDP/mDNS bilgisi olabilir.
    const hasEnhancedInfo = device.enhanced_comprehensive_info ||
                           device.advanced_scan_summary ||
                           device.enhanced_info ||
                           (device.discovery && (device.discovery.sources || []).length);
    
    if (!hasEnhancedInfo) {
        showToast(t('no_enhanced_info'), 'error');
        return;
    }
    
    // Modal title'ı güncelle
    document.getElementById('detailsDeviceTitle').innerHTML = 
        `🔬 ${device.ip} - ${device.alias || device.hostname || 'Bilinmeyen Cihaz'}`;
    
    // Modal'ı göster
    document.getElementById('enhancedDetailsModal').style.display = 'block';
    
    // İlk tab'ı aktif et
    switchDetailsTab('overview');
}

// Enhanced Details Modal'ını kapatma fonksiyonu
function closeEnhancedDetailsModal() {
    document.getElementById('enhancedDetailsModal').style.display = 'none';
    currentDevice = null;
    currentTab = 'overview';
}

// Tab geçiş fonksiyonu
function switchDetailsTab(tabName) {
    currentTab = tabName;
    
    // Tüm tab butonlarının active class'ını kaldır
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Aktif tab butonunu işaretle
    event?.target?.classList.add('active') || 
    document.querySelector(`[onclick="switchDetailsTab('${tabName}')"]`)?.classList.add('active');
    
    // İçeriği yükle
    loadTabContent(tabName);
}

// Tab içeriğini yükleme fonksiyonu
function loadTabContent(tabName) {
    if (!currentDevice) return;
    
    const contentDiv = document.getElementById('detailsContent');
    
    // Enhanced info'yu al
    const enhancedInfo = currentDevice.enhanced_comprehensive_info || 
                        currentDevice.advanced_scan_summary || 
                        currentDevice.enhanced_info || {};
    
    let content = '';
    
    switch (tabName) {
        case 'overview':
            content = generateOverviewContent(enhancedInfo, currentDevice);
            break;
        case 'network':
            content = generateNetworkContent(enhancedInfo);
            break;
        case 'ports':
            content = generatePortsContent(enhancedInfo);
            break;
        case 'system':
            content = generateSystemContent(enhancedInfo);
            break;
        case 'security':
            content = generateSecurityContent(enhancedInfo);
            break;
        case 'hardware':
            content = generateHardwareContent(enhancedInfo);
            break;
        case 'discovery':
            content = generateDiscoveryContent(currentDevice);
            break;
        case 'raw':
            content = generateRawContent(enhancedInfo);
            break;
        default:
            content = '<div class="details-no-data">Bilinmeyen tab</div>';
    }
    
    contentDiv.innerHTML = content;
}

// Genel Bakış içeriği
function generateOverviewContent(enhancedInfo, device) {
    const basicInfo = enhancedInfo.basic_info || {};
    const raspberryInfo = enhancedInfo.raspberry_pi_analysis || {};
    const iotInfo = enhancedInfo.iot_analysis || {};
    
    return `
        <div class="details-section">
            <h4>📊 Cihaz Özeti</h4>
            <div class="details-grid">
                <div class="details-card">
                    <h5>🔍 Temel Bilgiler</h5>
                    <ul class="details-list">
                        <li><span class="details-label">IP Adresi:</span><span class="details-value">${device.ip}</span></li>
                        <li><span class="details-label">MAC Adresi:</span><span class="details-value">${device.mac}</span></li>
                        <li><span class="details-label">Hostname:</span><span class="details-value">${device.hostname || 'N/A'}</span></li>
                        <li><span class="details-label">Alias:</span><span class="details-value">${device.alias || 'N/A'}</span></li>
                        <li><span class="details-label">Vendor:</span><span class="details-value">${device.vendor || 'N/A'}</span></li>
                        <li><span class="details-label">Durum:</span><span class="details-value">
                            <span class="status-badge status-${device.status}">${device.status}</span>
                        </span></li>
                        <li><span class="details-label">Son Görülme:</span><span class="details-value">${formatDate(device.last_seen)}</span></li>
                        ${device.last_enhanced_analysis ? 
                            `<li><span class="details-label">Son Analiz:</span><span class="details-value">${formatDate(device.last_enhanced_analysis)}</span></li>` : ''
                        }
                    </ul>
                </div>
                
                <div class="details-card">
                    <h5>🎯 Tespit Olasılıkları</h5>
                    ${generateDeviceTypeProbabilities(enhancedInfo)}
                </div>
            </div>
        </div>
        
        ${generateQuickStats(enhancedInfo, device)}
    `;
}

// Ağ Servisleri içeriği
function generateNetworkContent(enhancedInfo) {
    const webServices = enhancedInfo.web_services || {};
    const networkServices = enhancedInfo.network_services || {};
    const sshInfo = enhancedInfo.remote_access?.ssh || {};
    
    return `
        <div class="details-section">
            <h4>🌐 Web Servisleri</h4>
            ${Object.keys(webServices).length > 0 ? 
                generateWebServicesGrid(webServices) : 
                '<div class="details-no-data">Web servisi bulunamadı</div>'
            }
        </div>
        
        <div class="details-section">
            <h4>🔐 Uzaktan Erişim</h4>
            ${Object.keys(sshInfo).length > 0 ? 
                generateSSHInfo(sshInfo) : 
                '<div class="details-no-data">SSH bilgisi bulunamadı</div>'
            }
        </div>
        
        <div class="details-section">
            <h4>📡 SNMP ve Diğer Servisler</h4>
            ${Object.keys(networkServices).length > 0 ? 
                generateNetworkServicesInfo(networkServices) : 
                '<div class="details-no-data">Ağ servisi bilgisi bulunamadı</div>'
            }
        </div>
    `;
}

// Port Analizi içeriği
function generatePortsContent(enhancedInfo) {
    const detailedPorts = enhancedInfo.detailed_ports || {};
    
    if (detailedPorts.error) {
        return `
            <div class="details-section">
                <h4>🔌 Port Tarama Hatası</h4>
                <div class="vulnerability-item vulnerability-medium">
                    <strong>⚠️ Hata:</strong> ${detailedPorts.error}
                    <p style="margin-top: 10px; font-size: 14px;">
                        Port taraması için root yetkileri gerekli olabilir. 
                        Alternatif olarak temel port bilgileri cihaz listesinde mevcuttur.
                    </p>
                </div>
            </div>
        `;
    }
    
    return `
        <div class="details-section">
            <h4>🔌 Detaylı Port Analizi</h4>
            ${Object.keys(detailedPorts).length > 0 ? 
                generatePortsGrid(detailedPorts) : 
                '<div class="details-no-data">Port bilgisi bulunamadı</div>'
            }
        </div>
    `;
}

// Sistem Bilgileri içeriği
function generateSystemContent(enhancedInfo) {
    const systemId = enhancedInfo.system_identification || {};
    const osDetection = systemId.os_detection || {};
    const sshSystemInfo = enhancedInfo.remote_access?.ssh?.system_info || {};
    
    return `
        <div class="details-section">
            <h4>💻 İşletim Sistemi Tespiti</h4>
            ${Object.keys(osDetection).length > 0 ? 
                generateOSDetectionInfo(osDetection) : 
                '<div class="details-no-data">İşletim sistemi bilgisi bulunamadı</div>'
            }
        </div>
        
        <div class="details-section">
            <h4>🖥️ SSH Sistem Bilgileri</h4>
            ${Object.keys(sshSystemInfo).length > 0 ? 
                generateSSHSystemInfo(sshSystemInfo) : 
                '<div class="details-no-data">SSH sistem bilgisi bulunamadı (Erişim bilgileri gerekli)</div>'
            }
        </div>
    `;
}

// Güvenlik içeriği
function generateSecurityContent(enhancedInfo) {
    const securityAnalysis = enhancedInfo.security_analysis || {};
    
    return `
        <div class="details-section">
            <h4>🛡️ Güvenlik Analizi</h4>
            ${Object.keys(securityAnalysis).length > 0 ? 
                generateSecurityAnalysisInfo(securityAnalysis) : 
                '<div class="details-no-data">Güvenlik analizi bilgisi bulunamadı</div>'
            }
        </div>
    `;
}

// Donanım içeriği
function generateHardwareContent(enhancedInfo) {
    const raspberryInfo = enhancedInfo.raspberry_pi_analysis || {};
    const hardwareInfo = raspberryInfo.hardware || {};
    
    return `
        <div class="details-section">
            <h4>🔧 Donanım Bilgileri</h4>
            ${Object.keys(hardwareInfo).length > 0 ? 
                generateHardwareInfo(hardwareInfo) : 
                '<div class="details-no-data">Donanım bilgisi bulunamadı (SSH erişimi gerekli)</div>'
            }
        </div>
        
        <div class="details-section">
            <h4>🥧 Raspberry Pi Servisleri</h4>
            ${generateRaspberryPiServices(raspberryInfo)}
        </div>
    `;
}

// Ham Veri içeriği
// Protokol keşfi: SSDP description.xml, mDNS TXT kayıtları, DHCP hostname.
// Discovery sayfasındaki "Save to devices" bu veriyi cihaza yazar.
function generateDiscoveryContent(device) {
    const d = (device && device.discovery) || {};
    const esc = v => String(v == null ? '' : v).replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));

    if (!d.sources || !d.sources.length) {
        return '<div class="details-section"><h4>📡 Protokol Keşfi</h4>' +
            '<div class="details-no-data">Bu cihaz için keşif verisi yok. ' +
            'Discovery sayfasında bir sweep çalıştırıp "Save to devices" deyin.</div></div>';
    }

    // Her SSDP description.xml belgesi bir kart: üretici, model, seri no, servisler.
    const descriptions = ((d.attributes || {}).ssdp || {}).descriptions || {};
    const descCards = Object.entries(descriptions).map(([url, doc]) => `
        <div class="details-card">
            <h5>📄 ${esc(url)}</h5>
            <ul class="details-list">
                ${Object.entries(doc).map(([k, v]) => `<li>
                    <span class="details-label">${esc(k)}:</span>
                    <span class="details-value">${esc(Array.isArray(v) ? v.join(', ') : v)}</span></li>`).join('')}
            </ul>
        </div>`).join('');

    return `
        <div class="details-section">
            <h4>📡 Protokol Keşfi</h4>
            <ul class="details-list">
                <li><span class="details-label">Görüldüğü protokoller:</span><span class="details-value">${esc(d.sources.join(', '))}</span></li>
                <li><span class="details-label">Model:</span><span class="details-value">${esc(d.model || 'N/A')}</span></li>
                <li><span class="details-label">Servisler:</span><span class="details-value">${esc((d.services || []).join(', ') || 'N/A')}</span></li>
            </ul>
        </div>
        ${descCards ? `<div class="details-section"><h4>🧾 UPnP Cihaz Tanımı (description.xml)</h4>
            <div class="details-grid">${descCards}</div></div>` : ''}
        <div class="details-section">
            <h4>🗂️ Tüm Keşif Verisi</h4>
            <div class="details-code">${esc(JSON.stringify(d.attributes || {}, null, 2))}</div>
        </div>
    `;
}

function generateRawContent(enhancedInfo) {
    return `
        <div class="details-section">
            <h4>📄 Ham Veri (JSON)</h4>
            <div class="details-code">${JSON.stringify(enhancedInfo, null, 2)}</div>
        </div>
    `;
}

// Yardımcı fonksiyonlar
function getProbabilityClass(probability) {
    if (probability >= 0.7) return 'probability-high';
    if (probability >= 0.3) return 'probability-medium';
    return 'probability-low';
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('tr-TR');
}

function generateQuickStats(enhancedInfo, device) {
    const openPorts = device.open_ports ? device.open_ports.length : 0;
    const webServices = enhancedInfo.web_services ? Object.keys(enhancedInfo.web_services).length : 0;
    const securityIssues = enhancedInfo.security_analysis ? Object.keys(enhancedInfo.security_analysis).length : 0;
    
    return `
        <div class="details-section">
            <h4>📈 Hızlı İstatistikler</h4>
            <div class="details-grid">
                <div class="details-card" style="text-align: center;">
                    <h5>🚪 Açık Portlar</h5>
                    <div style="font-size: 32px; font-weight: bold; color: #28a745;">${openPorts}</div>
                </div>
                <div class="details-card" style="text-align: center;">
                    <h5>🌐 Web Servisleri</h5>
                    <div style="font-size: 32px; font-weight: bold; color: #007bff;">${webServices}</div>
                </div>
                <div class="details-card" style="text-align: center;">
                    <h5>🛡️ Güvenlik Kontrolü</h5>
                    <div style="font-size: 32px; font-weight: bold; color: #ffc107;">${securityIssues}</div>
                </div>
            </div>
        </div>
    `;
}

function generateWebServicesGrid(webServices) {
    let html = '<div class="details-grid">';
    
    for (const [service, data] of Object.entries(webServices)) {
        if (data.error) {
            html += `
                <div class="details-card">
                    <h5>${service}</h5>
                    <div class="vulnerability-item vulnerability-medium">
                        <strong>❌ Hata:</strong> ${data.error}
                    </div>
                </div>
            `;
        } else {
            html += `
                <div class="details-card">
                    <h5>${service}</h5>
                    <ul class="details-list">
                        <li><span class="details-label">Status:</span><span class="details-value">${data.status_code || 'N/A'}</span></li>
                        <li><span class="details-label">Title:</span><span class="details-value">${data.title || 'N/A'}</span></li>
                        <li><span class="details-label">Server:</span><span class="details-value">${data.server || 'N/A'}</span></li>
                        <li><span class="details-label">Content Type:</span><span class="details-value">${data.content_type || 'N/A'}</span></li>
                        ${data.technologies && data.technologies.length > 0 ? 
                            `<li><span class="details-label">Technologies:</span><span class="details-value">
                                <div class="port-list">
                                    ${data.technologies.map(tech => `<span class="port-tag">${tech}</span>`).join('')}
                                </div>
                            </span></li>` : ''
                        }
                    </ul>
                </div>
            `;
        }
    }
    
    html += '</div>';
    return html;
}

function generateSSHInfo(sshInfo) {
    return `
        <div class="details-card">
            <h5>🔐 SSH Service</h5>
            <ul class="details-list">
                <li><span class="details-label">Banner:</span><span class="details-value">${sshInfo.banner || 'N/A'}</span></li>
                <li><span class="details-label">Version:</span><span class="details-value">${sshInfo.version || 'N/A'}</span></li>
                ${sshInfo.connection_test ? `
                    <li><span class="details-label">Connection Test:</span><span class="details-value">
                        <span class="status-badge ${sshInfo.connection_test.success ? 'status-online' : 'status-error'}">
                            ${sshInfo.connection_test.success ? 'Başarılı' : 'Başarısız'}
                        </span>
                    </span></li>
                    ${sshInfo.connection_test.user ? `
                        <li><span class="details-label">User:</span><span class="details-value">${sshInfo.connection_test.user}</span></li>
                    ` : ''}
                ` : ''}
            </ul>
        </div>
    `;
}

function generatePortsGrid(detailedPorts) {
    let html = '<div class="details-grid">';
    
    for (const [port, data] of Object.entries(detailedPorts)) {
        if (typeof port === 'string' && !isNaN(port)) {
            html += `
                <div class="details-card">
                    <h5>Port ${port}</h5>
                    <ul class="details-list">
                        <li><span class="details-label">State:</span><span class="details-value">
                            <span class="port-tag ${data.state === 'open' ? 'open' : 'closed'}">${data.state}</span>
                        </span></li>
                        <li><span class="details-label">Service:</span><span class="details-value">${data.service || 'N/A'}</span></li>
                        <li><span class="details-label">Version:</span><span class="details-value">${data.version || 'N/A'}</span></li>
                        <li><span class="details-label">Product:</span><span class="details-value">${data.product || 'N/A'}</span></li>
                        ${data.extrainfo ? `<li><span class="details-label">Extra Info:</span><span class="details-value">${data.extrainfo}</span></li>` : ''}
                    </ul>
                </div>
            `;
        }
    }
    
    html += '</div>';
    return html;
}

function generateSecurityAnalysisInfo(securityAnalysis) {
    let html = '<div class="details-grid">';
    
    for (const [key, data] of Object.entries(securityAnalysis)) {
        if (key.includes('vulns')) {
            html += `
                <div class="details-card">
                    <h5>🔍 ${key}</h5>
                    ${typeof data === 'object' ? 
                        Object.entries(data).map(([vulnKey, vulnData]) => `
                            <div class="vulnerability-item">
                                <strong>${vulnKey}:</strong>
                                <div class="expandable-content">
                                    <pre style="white-space: pre-wrap; font-size: 12px;">${vulnData}</pre>
                                </div>
                            </div>
                        `).join('') :
                        `<div class="details-code">${data}</div>`
                    }
                </div>
            `;
        } else {
            html += `
                <div class="details-card">
                    <h5>${key}</h5>
                    <div class="details-code">${typeof data === 'object' ? JSON.stringify(data, null, 2) : data}</div>
                </div>
            `;
        }
    }
    
    html += '</div>';
    return html;
}

function generateHardwareInfo(hardwareInfo) {
    let html = '<div class="details-grid">';
    
    for (const [key, data] of Object.entries(hardwareInfo)) {
        html += `
            <div class="details-card">
                <h5>${formatHardwareKey(key)}</h5>
                <div class="details-code">${data}</div>
            </div>
        `;
    }
    
    html += '</div>';
    return html;
}

function formatHardwareKey(key) {
    const keyMap = {
        'cpu_info': '🖥️ CPU Bilgisi',
        'memory': '💾 Bellek',
        'disk': '💽 Disk',
        'temperature': '🌡️ Sıcaklık',
        'gpio': '🔌 GPIO',
        'os_release': '💻 OS Release',
        'kernel': '⚙️ Kernel',
        'packages': '📦 Paketler'
    };
    return keyMap[key] || key;
}

function generateRaspberryPiServices(raspberryInfo) {
    let html = '<div class="details-grid">';
    
    for (const [key, data] of Object.entries(raspberryInfo)) {
        if (key.startsWith('service_')) {
            html += `
                <div class="details-card">
                    <h5>Port ${key.replace('service_', '')}</h5>
                    <ul class="details-list">
                        <li><span class="details-label">Status:</span><span class="details-value">
                            <span class="status-badge status-online">${data.status}</span>
                        </span></li>
                        <li><span class="details-label">Type:</span><span class="details-value">${data.indicator}</span></li>
                        <li><span class="details-label">Title:</span><span class="details-value">${data.title || 'N/A'}</span></li>
                    </ul>
                </div>
            `;
        }
    }
    
    if (html === '<div class="details-grid">') {
        return '<div class="details-no-data">Raspberry Pi servisi bulunamadı</div>';
    }
    
    html += '</div>';
    return html;
}

function generateNetworkServicesInfo(networkServices) {
    let html = '<div class="details-grid">';
    
    for (const [service, data] of Object.entries(networkServices)) {
        html += `
            <div class="details-card">
                <h5>${service.toUpperCase()}</h5>
                ${Object.keys(data).length > 0 ? 
                    `<div class="details-code">${JSON.stringify(data, null, 2)}</div>` :
                    '<div class="details-no-data">Veri bulunamadı</div>'
                }
            </div>
        `;
    }
    
    html += '</div>';
    return html;
}

function generateSSHSystemInfo(systemInfo) {
    let html = '<div class="details-grid">';
    
    for (const [key, data] of Object.entries(systemInfo)) {
        html += `
            <div class="details-card">
                <h5>${formatSystemKey(key)}</h5>
                <div class="details-code">${data}</div>
            </div>
        `;
    }
    
    html += '</div>';
    return html;
}

function formatSystemKey(key) {
    const keyMap = {
        'hostname': '🏠 Hostname',
        'uptime': '⏰ Uptime',
        'users': '👥 Users',
        'processes': '⚙️ Processes',
        'network': '🌐 Network',
        'services': '🔧 Services',
        'mounted': '💽 Mounted',
        'last_login': '🔐 Last Login'
    };
    return keyMap[key] || key;
}

function generateOSDetectionInfo(osDetection) {
    let html = '<div class="details-grid">';
    
    if (osDetection.os_matches && osDetection.os_matches.length > 0) {
        html += `
            <div class="details-card">
                <h5>🎯 OS Matches</h5>
                ${osDetection.os_matches.map(match => `
                    <div style="margin-bottom: 15px; padding: 10px; background: #f8f9fa; border-radius: 6px;">
                        <strong>${match.name}</strong>
                        <div style="margin-top: 5px;">
                            <span class="details-label">Accuracy:</span> ${match.accuracy}%
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    if (osDetection.os_classes && osDetection.os_classes.length > 0) {
        html += `
            <div class="details-card">
                <h5>📂 OS Classes</h5>
                ${osDetection.os_classes.map(osClass => `
                    <ul class="details-list">
                        <li><span class="details-label">Type:</span><span class="details-value">${osClass.type}</span></li>
                        <li><span class="details-label">Vendor:</span><span class="details-value">${osClass.vendor}</span></li>
                        <li><span class="details-label">OS Family:</span><span class="details-value">${osClass.osfamily}</span></li>
                        <li><span class="details-label">Accuracy:</span><span class="details-value">${osClass.accuracy}%</span></li>
                    </ul>
                `).join('')}
            </div>
        `;
    }
    
    if (html === '<div class="details-grid">') {
        html += '<div class="details-no-data">İşletim sistemi tespit edilemedi</div>';
    }
    
    html += '</div>';
    return html;
}

function generateDeviceTypeProbabilities(enhancedInfo) {
    const deviceTypeAnalysis = enhancedInfo.device_type_analysis || {};
    const probabilities = deviceTypeAnalysis.device_probabilities || {};
    const indicators = deviceTypeAnalysis.indicators || {};
    
    // Cihaz tipi simgeleri ve isimleri
    const deviceTypes = {
        'camera': { icon: '📹', name: 'IP Camera' },
        'smart_tv': { icon: '📺', name: 'Smart TV' },
        'air_conditioner': { icon: '❄️', name: 'Air Conditioner' },
        'apple_device': { icon: '🍎', name: 'Apple Device' },
        'gaming_console': { icon: '🎮', name: 'Game Console' },
        'pet_device': { icon: '🐕', name: 'Pet Device' },
        'router': { icon: '🌐', name: 'Router' },
        'printer': { icon: '🖨️', name: 'Printer' },
        'nas': { icon: '💾', name: 'NAS' },
        'smartphone': { icon: '📱', name: 'Smartphone' },
        'iot_device': { icon: '🔗', name: 'IoT Device' }
    };
    
    // Fallback: Eğer yeni analiz yoksa eski verileri kullan
    if (Object.keys(probabilities).length === 0) {
        const raspberryInfo = enhancedInfo.raspberry_pi_analysis || {};
        const iotInfo = enhancedInfo.iot_analysis || {};
        
        return `
            <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span>🥧 Raspberry Pi</span>
                    <span>${Math.round((raspberryInfo.raspberry_pi_probability || 0) * 100)}%</span>
                </div>
                <div class="probability-bar">
                    <div class="probability-fill ${getProbabilityClass(raspberryInfo.raspberry_pi_probability)}" 
                         style="width: ${(raspberryInfo.raspberry_pi_probability || 0) * 100}%">
                    </div>
                </div>
            </div>

             <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span>💾 NAS</span>
                    <span>${Math.round((iotInfo.iot_probability || 0) * 100)}%</span>
                </div>
                <div class="probability-bar">
                    <div class="probability-fill ${getProbabilityClass(iotInfo.iot_probability)}" 
                         style="width: ${(iotInfo.iot_probability || 0) * 100}%">
                    </div>
                </div>
            </div>

            <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span>❄️ Air Conditioner</span>
                    <span>${Math.round((iotInfo.iot_probability || 0) * 100)}%</span>
                </div>
                <div class="probability-bar">
                    <div class="probability-fill ${getProbabilityClass(iotInfo.iot_probability)}" 
                         style="width: ${(iotInfo.iot_probability || 0) * 100}%">
                    </div>
                </div>
            </div>

            <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span>🍎 Apple Device</span>
                    <span>${Math.round((iotInfo.iot_probability || 0) * 100)}%</span>
                </div>
                <div class="probability-bar">
                    <div class="probability-fill ${getProbabilityClass(iotInfo.iot_probability)}" 
                         style="width: ${(iotInfo.iot_probability || 0) * 100}%">
                    </div>
                </div>
            </div>

            <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span>📹 IP Camera</span>
                    <span>${Math.round((iotInfo.iot_probability || 0) * 100)}%</span>
                </div>
                <div class="probability-bar">
                    <div class="probability-fill ${getProbabilityClass(iotInfo.iot_probability)}" 
                         style="width: ${(iotInfo.iot_probability || 0) * 100}%">
                    </div>
                </div>
            </div>
            
        `;
    }
    
    let html = '';
    
    // Tüm cihaz tiplerini olasılık sırasına göre sırala
    const sortedTypes = Object.entries(probabilities)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 6); // En yüksek 6 tanesini göster
    
    for (const [deviceType, probability] of sortedTypes) {
        const typeInfo = deviceTypes[deviceType];
        if (!typeInfo) continue;
        
        const percentage = Math.round(probability * 100);
        const deviceIndicators = indicators[deviceType] || [];
        
        html += `
            <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span>${typeInfo.icon} ${typeInfo.name}</span>
                    <span>${percentage}%</span>
                </div>
                <div class="probability-bar">
                    <div class="probability-fill ${getProbabilityClass(probability)}" 
                         style="width: ${percentage}%">
                    </div>
                </div>
                ${deviceIndicators.length > 0 ? `
                    <div style="margin-top: 8px;">
                        <div class="port-list">
                            ${deviceIndicators.map(indicator => 
                                `<span class="port-tag" style="font-size: 11px;">${formatIndicator(indicator)}</span>`
                            ).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    // Eğer hiç sonuç yoksa
    if (html === '') {
        html = '<div style="color: #666; font-style: italic;">Cihaz tipi analizi yapılmadı</div>';
    }
    
    return html;
}

function formatIndicator(indicator) {
    // Gösterge isimlerini daha okunaklı hale getir
    const indicatorMap = {
        'camera_hostname': 'Camera Hostname',
        'rtsp_service': 'RTSP Service',
        'camera_vendor': 'Camera Vendor',
        'camera_web_interface': 'Web Interface',
        'tv_hostname': 'TV Hostname',
        'tv_ports': 'TV Ports',
        'tv_vendor': 'TV Vendor',
        'ac_hostname': 'AC Hostname',
        'modbus_protocol': 'Modbus',
        'ac_vendor': 'AC Vendor',
        'apple_hostname': 'Apple Hostname',
        'apple_vendor': 'Apple Vendor',
        'apple_services': 'Apple Services',
        'console_hostname': 'Console Hostname',
        'console_vendor': 'Console Vendor',
        'gaming_ports': 'Gaming Ports',
        'pet_hostname': 'Pet Hostname',
        'pet_vendor': 'Pet Vendor',
        'hardware_detected': 'Hardware',
        'web_interface': 'Web UI',
        'jupyter': 'Jupyter'
    };
    
    return indicatorMap[indicator] || indicator;
}

// Modal dışına tıklandığında kapat
window.addEventListener('click', function(event) {
    const modal = document.getElementById('enhancedDetailsModal');
    if (event.target === modal) {
        closeEnhancedDetailsModal();
    }
});

// Klavye kısayolları
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape' && document.getElementById('enhancedDetailsModal').style.display === 'block') {
        closeEnhancedDetailsModal();
    }
});