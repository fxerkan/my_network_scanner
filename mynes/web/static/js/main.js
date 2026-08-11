// My Network Scanner (MNS) - Ana JavaScript Dosyası

let devices = [];
let deviceTypes = {};
let translatedDeviceTypes = {};
let currentEditingIp = null;
let bulkAnalysisResults = {};
let bulkAnalysisRunning = false;
let backgroundAnalysisIndicator = null;
let lastAnalysisMessage = null;

// Tablo sıralama değişkenleri
let currentSortColumn = null;
let currentSortDirection = 'asc';

// Progress tracking için global değişken
let progressInterval = null;

// Language management
async function changeLanguage(languageCode) {
    try {
        const response = await fetch('/api/language/set', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ language: languageCode })
        });
        
        const result = await response.json();
        if (result.success) {
            // Reload the page to apply the new language
            window.location.reload();
        } else {
            console.error('Failed to change language:', result.error);
        }
    } catch (error) {
        console.error('Error changing language:', error);
    }
}

// Sayfa yüklendiğinde verileri getir
window.addEventListener('load', async function() {
    // Wait for translations to load
    await translationManager.loadTranslations();
    
    await loadDeviceTypes();
    // Make the device-type / connected-via dropdowns sorted + searchable, like
    // the Filters panel. Native <select>s stay as the value holders.
    ['enhancedEditDeviceType', 'enhancedEditUplink', 'addDeviceType', 'editDeviceType']
        .forEach(id => MynesFilters.enhanceSelect(document.getElementById(id)));
    await loadDevices(true); // İlk yüklemede filtreleri güncelle
    openDeviceFromQuery();   // deep link from the availability page (?device=)
    initializeTableSorting();
    
    // Scan durumunu kontrol et ve buton durumlarını ayarla
    await checkScanStatus();
    
    // Versiyon bilgisini yükle
    await loadVersion();
    
    // Aktif analiz işlemlerini restore et
    await restoreActiveAnalyses();
    
    // startProgressUpdates(); - Bu satırı kaldırdık, sadece tarama başladığında çalışacak
});

// Tablo sıralama başlatma
function initializeTableSorting() {
    const sortableHeaders = document.querySelectorAll('.sortable');
    sortableHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const column = this.getAttribute('data-column');
            const type = this.getAttribute('data-type');
            sortTable(column, type);
        });
    });
    
    // Başlangıçta hiçbir sıralama gösterme, sadece IP'ye göre sırala (arka planda)
    currentSortColumn = null; // Hiçbir sütun seçili değil
    currentSortDirection = 'asc';
}

// Tablo sıralama fonksiyonu
function sortTable(column, type) {
    // Aynı kolona tıklanırsa yönü değiştir
    if (currentSortColumn === column) {
        currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        currentSortColumn = column;
        currentSortDirection = 'asc';
    }
    
    updateSortIndicators();
    displayDevices();
}

// Sıralama göstergelerini güncelle
function updateSortIndicators() {
    const headers = document.querySelectorAll('.sortable');
    headers.forEach(header => {
        header.classList.remove('asc', 'desc');
        const indicator = header.querySelector('.sort-indicator');
        if (indicator) {
            indicator.innerHTML = '';
        }
    });
    
    const activeHeader = document.querySelector(`[data-column="${currentSortColumn}"]`);
    if (activeHeader) {
        activeHeader.classList.add(currentSortDirection);
        const indicator = activeHeader.querySelector('.sort-indicator');
        if (indicator) {
            indicator.innerHTML = currentSortDirection === 'asc' ? ' ↑' : ' ↓';
        }
    }
}

// Cihazları sırala
function sortDevices(devicesArray) {
    let sortColumn = currentSortColumn || 'ip'; // Eğer hiçbir sütun seçili değilse IP kullan
    let sortDirection = currentSortColumn ? currentSortDirection : 'asc'; // Varsayılan artan

    return [...devicesArray].sort((a, b) => {
        let aValue, bValue;

        switch (sortColumn) {
            case 'ip': {
                // Radio-only devices (BLE) have no IP - keep them grouped after
                // the IP devices instead of letting NaN scatter them.
                if (!a.ip || !b.ip) {
                    if (a.ip === b.ip) return (a.hostname || a.mac || '').localeCompare(b.hostname || b.mac || '');
                    return a.ip ? -1 : 1;
                }
                const aIP = a.ip.split('.').map(num => parseInt(num));
                const bIP = b.ip.split('.').map(num => parseInt(num));

                for (let i = 0; i < 4; i++) {
                    if (aIP[i] !== bIP[i]) {
                        const result = aIP[i] - bIP[i];
                        return sortDirection === 'asc' ? result : -result;
                    }
                }
                return 0;
            }
            case 'alias':
                aValue = (a.alias || '').toLowerCase();
                bValue = (b.alias || '').toLowerCase();
                break;
            case 'vendor':
                aValue = (a.vendor || '').toLowerCase();
                bValue = (b.vendor || '').toLowerCase();
                break;
            case 'device_type':
                aValue = (a.device_type || '').toLowerCase();
                bValue = (b.device_type || '').toLowerCase();
                break;
            case 'mac':
                aValue = (a.mac || '').toLowerCase();
                bValue = (b.mac || '').toLowerCase();
                break;
            case 'open_ports':
                aValue = a.open_ports ? a.open_ports.length : 0;
                bValue = b.open_ports ? b.open_ports.length : 0;
                break;
            case 'last_seen':
                aValue = new Date(a.last_seen || 0);
                bValue = new Date(b.last_seen || 0);
                break;
            default:
                return 0;
        }

        // Tarih sıralaması
        if (sortColumn === 'last_seen') {
            const result = aValue - bValue;
            return sortDirection === 'asc' ? result : -result;
        }
        
        // Port sayısı sıralaması
        if (sortColumn === 'open_ports') {
            const result = aValue - bValue;
            return sortDirection === 'asc' ? result : -result;
        }
        
        // Metin sıralaması
        if (aValue < bValue) {
            return sortDirection === 'asc' ? -1 : 1;
        }
        if (aValue > bValue) {
            return sortDirection === 'asc' ? 1 : -1;
        }
        return 0;
    });
}

async function loadDevices(updateFiltersFlag = false) {
    try {
        const response = await fetch('/devices');
        const newDevices = await response.json();
        
        // Sadece cihaz listesi değiştiyse veya açıkça istendiğinde filtreleri güncelle
        let shouldUpdateFilters = updateFiltersFlag;
        
        // Eğer açıkça filtre güncellemesi istenmemişse, cihaz listesinin değişip değişmediğini kontrol et
        if (!updateFiltersFlag) {
            const oldDevicesStr = JSON.stringify(devices.map(d => ({
                ip: d.ip, 
                device_type: d.device_type, 
                vendor: d.vendor, 
                alias: d.alias,
                open_ports: d.open_ports
            })).sort((a, b) => a.ip.localeCompare(b.ip)));
            
            const newDevicesStr = JSON.stringify(newDevices.map(d => ({
                ip: d.ip, 
                device_type: d.device_type, 
                vendor: d.vendor, 
                alias: d.alias,
                open_ports: d.open_ports
            })).sort((a, b) => a.ip.localeCompare(b.ip)));
            
            shouldUpdateFilters = oldDevicesStr !== newDevicesStr;
        }
        
        devices = newDevices;
        // filterDevices() (not displayDevices()) so any persisted shared filter
        // - e.g. "hide containers" set in Settings - applies on first paint too.
        filterDevices();

        if (shouldUpdateFilters) {
            updateFilters();
        }
    } catch (error) {
        console.error(t('device_loading_error'), error);
    }
}

async function loadDeviceTypes() {
    try {
        // Çevirili device types'ı yükle
        const response = await fetch('/api/device-types/translated');
        deviceTypes = await response.json();
        
        // Device type dropdowns'ını güncelle
        populateDeviceTypeDropdowns();
    } catch (error) {
        console.error(t('device_types_loading_error'), error);
    }
}

function getTranslatedDeviceType(deviceType) {
    if (!deviceType) return t('unknown');
    
    // Check if we have a translation for this device type
    if (deviceTypes && deviceTypes[deviceType] && deviceTypes[deviceType].name) {
        return deviceTypes[deviceType].name;
    }
    
    // Fallback to original device type
    return deviceType;
}

function populateDeviceTypeDropdowns() {
    // Edit modal dropdown'ını güncelle
    const editDeviceTypeSelect = document.getElementById('editDeviceType');
    if (editDeviceTypeSelect && deviceTypes) {
        editDeviceTypeSelect.innerHTML = `<option value="">${t('select_device_type')}</option>`;
        Object.keys(deviceTypes).sort().forEach(typeName => {
            const option = document.createElement('option');
            option.value = typeName;
            option.textContent = `${deviceTypes[typeName].icon} ${deviceTypes[typeName].name}`;
            editDeviceTypeSelect.appendChild(option);
        });
    }
    
    // Add device modal dropdown'ını güncelle
    const addDeviceTypeSelect = document.getElementById('addDeviceType');
    if (addDeviceTypeSelect && deviceTypes) {
        addDeviceTypeSelect.innerHTML = `<option value="">${t('select_device_type')}</option>`;
        Object.keys(deviceTypes).sort().forEach(typeName => {
            const option = document.createElement('option');
            option.value = typeName;
            option.textContent = `${deviceTypes[typeName].icon} ${typeName}`;
            addDeviceTypeSelect.appendChild(option);
        });
    }
}

function getDeviceIcon(deviceType) {
    if (!deviceType) return '❓';
    if (deviceTypes[deviceType]?.icon) return deviceTypes[deviceType].icon;
    // The scanner mints qualified names at runtime ("Local Machine (Docker)",
    // "Desktop/Laptop (WiFi)") that no config file can enumerate. Fall back to
    // the base name before giving up, so those rows are not the only iconless
    // entries in every dropdown.
    const base = deviceType.replace(/\s*\(.*\)\s*$/, '').trim();
    if (deviceTypes[base]?.icon) return deviceTypes[base].icon;
    // Containers were the last iconless class - show the Docker whale instead
    // of a bare "?" for any docker-qualified type.
    if (/docker/i.test(deviceType)) return '🐳';
    return '❓';
}

async function checkScanStatus() {
    try {
        const response = await fetch('/progress');
        const progress = await response.json();
        
        // Scan durumuna göre buton durumlarını ayarla
        if (progress.status === 'scanning') {
            setScanUiState(true);
            document.getElementById('progressContainer').style.display = 'block';
            // Progress tracking'i başlat
            startProgressUpdates();
        } else {
            // Idle, completed, error, stopped durumları
            setScanUiState(false);
            document.getElementById('progressContainer').style.display = 'none';
        }
    } catch (error) {
        console.error(t('scan_status_error'), error);
        // Hata durumunda güvenli taraf için butonları normal duruma getir
        setScanUiState(false);
        document.getElementById('progressContainer').style.display = 'none';
    }
}

// One button drives the whole scan: it opens the scan menu when idle and
// becomes a red "Stop Scan" while a scan runs, so a second scan can't be
// launched over a running one. setScanUiState flips its look; the click router
// picks the action from the current state.
function setScanUiState(scanning) {
    const trig = document.getElementById('toolsDropdown');
    if (!trig) return;
    trig.classList.toggle('btn-danger', scanning);
    trig.classList.toggle('btn-primary', !scanning);
    trig.dataset.scanning = scanning ? '1' : '';
    const label = trig.querySelector('.scan-trigger__label');
    const icon = trig.querySelector('.scan-trigger__icon use');
    const caret = trig.querySelector('.actions-menu__caret');
    if (label) label.textContent = scanning ? t('stop_scan') : t('scan');
    if (icon) icon.setAttribute('href', scanning ? '#i-stop' : '#i-search');
    if (caret) caret.style.display = scanning ? 'none' : '';
    if (scanning) closeToolsDropdown();
}

function onScanTriggerClick() {
    const trig = document.getElementById('toolsDropdown');
    if (trig && trig.dataset.scanning) {
        stopScan();
    } else {
        toggleToolsDropdown();
    }
}

// Localize a progress step from the structured fields the scanner emits; the
// scanner thread has no session locale, so it sends stage+data and we render.
function progressLabel(p) {
    switch (p.stage) {
        case 'scanning': return t('scanning_ip', {ip: p.current_ip, scanned: p.scanned, total: p.total});
        case 'finding': return t('scan_finding', {total: p.total});
        case 'onvif': return t('scan_onvif');
        case 'completed': return t('scan_completed_count', {count: p.devices_found});
        case 'stopped': return t('scan_stopped');
        case 'error': return t('error') + ': ' + (p.message || '');
        default: return p.message || '';
    }
}

function toggleToolsDropdown() {
    const dropdown = document.getElementById('toolsDropdownMenu');
    const open = !(dropdown.style.display === 'none' || dropdown.style.display === '');
    dropdown.style.display = open ? 'none' : 'block';
    document.getElementById('toolsDropdown')?.setAttribute('aria-expanded', String(!open));
}

function closeToolsDropdown() {
    document.getElementById('toolsDropdownMenu').style.display = 'none';
    document.getElementById('toolsDropdown')?.setAttribute('aria-expanded', 'false');
}

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
    const dropdown = document.getElementById('toolsDropdownMenu');
    const button = document.getElementById('toolsDropdown');
    
    if (dropdown && button && !dropdown.contains(event.target) && !button.contains(event.target)) {
        dropdown.style.display = 'none';
    }
});

async function loadVersion() {
    try {
        const response = await fetch('/api/version');
        const versionInfo = await response.json();
        
        // Version bilgisini footer'da güncelle
        const versionElement = document.getElementById('appVersion');
        if (versionElement && versionInfo.version) {
            versionElement.textContent = `v${versionInfo.version}`;
            
            // Tooltip olarak detaylı bilgi ekle
            if (versionInfo.commit_hash || versionInfo.build_time) {
                let tooltip = [];
                if (versionInfo.commit_hash) {
                    tooltip.push(`Commit: ${versionInfo.commit_hash}`);
                }
                if (versionInfo.commit_count !== null) {
                    tooltip.push(`Commits: ${versionInfo.commit_count}`);
                }
                if (versionInfo.build_time) {
                    const buildDate = new Date(versionInfo.build_time).toLocaleDateString();
                    tooltip.push(`Built: ${buildDate}`);
                }
                if (versionInfo.is_dirty) {
                    tooltip.push('Modified');
                }
                
                versionElement.title = tooltip.join(' | ');
            }
        }
    } catch (error) {
        console.error(t('version_loading_error'), error);
        // Hata durumunda default version'u koru
    }
}

function displayDevices() {
    // Aktif görünüme göre ilgili display fonksiyonunu çağır
    switch (currentView) {
        case 'table':
            displayDevicesTable();
            return;
        case 'graph':
        case 'topology':
        case 'home':
            // views.js owns these; it reads the same (already filtered) `devices`.
            if (window.MynesViews) window.MynesViews.render(currentView, devices);
            return;
        default:
            // Card view (varsayılan)
            displayDevicesCard();
            return;
    }
}

function displayDevicesCard() {
    const container = document.getElementById('devicesContainer');
    
    if (devices.length === 0) {
        container.innerHTML = `
            <div class="no-devices">
                <i>📡</i>
                <h3>${t('no_devices_message')}</h3>
                <p>${t('scan_to_start')}</p>
            </div>
        `;
        return;
    }

    // Sıralama fonksiyonunu kullan
    const sortedDevices = sortDevices(devices);

    container.innerHTML = sortedDevices.map(device => `
        <div class="device-card">
            <div class="device-header">
                <div class="device-icon">${getDeviceIcon(device.device_type)}</div>
                <div class="device-main-info">
                    ${device.ip
                        ? `<div class="device-ip" onclick="openDevice('${device.ip}')">${device.ip}</div>`
                        : `<div class="device-ip device-ip--none" title="${t('discovery_only')}">${device.hostname || device.mac || '—'}</div>`}
                    <div class="device-type">${getTranslatedDeviceType(device.device_type)}</div>
                </div>
                <div class="device-status">
                    ${device.status === 'online' ? '🟢' : '🔴'}
                </div>
            </div>

            ${device.alias ? `<div class="device-alias"><svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-info"/></svg> ${device.alias}</div>` : ''}
            
            ${device.notes ? `<div class="device-notes">📝 ${device.notes.replace(/\n/g, '<br>')}</div>` : ''}

            ${(device.trust_status && device.trust_status !== 'unknown') || device.location ? `
                <div class="device-meta-row">
                    ${device.trust_status && device.trust_status !== 'unknown'
                        ? `<span class="trust-badge trust-badge--${device.trust_status}">${t('trust_' + device.trust_status)}</span>` : ''}
                    ${device.location
                        ? `<span class="device-location"><svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-home"/></svg> ${escHtml(device.location)}</span>` : ''}
                </div>` : ''}

            <div class="device-details">
                <div class="detail-row">
                    <span class="detail-label">MAC:</span>
                    <span class="detail-value">
                        ${device.mac && device.mac !== 'N/A' ? `
                            <div class="mac-container">
                                <span class="mac-address">${device.mac}</span>
                                <button class="copy-mac-btn" onclick="copyMacAddress('${device.mac}', this); event.stopPropagation();" title="${t('copy_mac_address')}" aria-label="${t('copy_mac_address')}"><svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-copy"/></svg></button>
                            </div>
                        ` : 'N/A'}
                    </span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Hostname:</span>
                    <span class="detail-value">${device.hostname || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">${t('manufacturer')}:</span>
                    <span class="detail-value">${device.vendor || t('unknown')}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">${t('last_seen')}:</span>
                    <span class="detail-value">${formatDate(device.last_seen)}</span>
                </div>
            </div>

            ${device.open_ports && device.open_ports.length > 0 ? `
                <div class="ports-container">
                    <div class="ports-title"><svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-plug"/></svg> ${t('open_ports')}</div>
                    <div class="ports-list">
                        ${device.open_ports.map(port => {
                            if (typeof port === 'object') {
                                return `<a href="#" class="port-badge" onclick="openPort('${device.ip}', ${port.port}, '${port.description || port.service || ''}')" title="${port.description || port.service || ''}">
                                    ${port.port}
                                </a>`;
                            } else {
                                return `<a href="#" class="port-badge" onclick="openPort('${device.ip}', ${port}, '')" title="Port ${port}">
                                    ${port}
                                </a>`;
                            }
                        }).join('')}
                    </div>
                </div>
            ` : ''}

            <div class="device-actions">
                ${device.ip || device.mac ? `<button class="btn btn-primary btn-small" onclick="openEnhancedEditModal('${device.ip || device.mac}')"><svg class="ds-icon" aria-hidden="true"><use href="#i-wrench"/></svg> ${t('edit')}</button>` : ''}
                ${device.ip ? `<button class="btn btn-warning btn-small" onclick="openSingleDeviceAnalysisPage('${device.ip}')" title="${t('detailed_analysis')}" aria-label="${t('detailed_analysis')}"><svg class="ds-icon" aria-hidden="true"><use href="#i-microscope"/></svg> ${t('detailed_analysis')}</button>` : ''}
                ${hasEnhancedInfo(device) ?
                    `<button class="btn btn-success btn-small" onclick="openEnhancedDetailsModal(${JSON.stringify(device).replace(/"/g, '&quot;')})" title="${t('details')}"><svg class="ds-icon" aria-hidden="true"><use href="#i-graph"/></svg> ${t('details')}</button>` : 
                    ''
                }
            </div>
        </div>
    `).join('');
}

// Enhanced info kontrol fonksiyonu
function hasEnhancedInfo(device) {
    return device.enhanced_comprehensive_info || 
           device.advanced_scan_summary || 
           device.enhanced_info;
}

function filterDevices() {
    // Keep the toolbar search box in sync with the shared store so the same
    // text query applies on every page. Guard the elements: this runs on pages
    // that don't have the alias/port selects.
    const searchEl = document.getElementById('searchInput');
    if (searchEl && window.MynesFilters) {
        const cur = MynesFilters.get().q || '';
        if (searchEl.value !== cur) MynesFilters.set({ q: searchEl.value });
    }
    const aliasFilter = (document.getElementById('aliasFilter') || {}).value || '';
    const portFilter = (document.getElementById('portFilter') || {}).value || '';
    const trustFilter = (document.getElementById('trustFilter') || {}).value || '';

    const filteredDevices = devices.filter(device => {
        // Type/vendor/status/text/visibility all live in the shared store.
        if (window.MynesFilters && !MynesFilters.match(device)) return false;

        // Unset trust reads as "unknown" so that filter still catches legacy devices.
        if (trustFilter && (device.trust_status || 'unknown') !== trustFilter) return false;

        // Alias + port stay page-local (single-select, rarely reused elsewhere).
        const matchesAlias = !aliasFilter || device.alias === aliasFilter;
        const matchesPort = !portFilter || (device.open_ports &&
            device.open_ports.some(port => {
                const portNumber = typeof port === 'object' ? port.port : port;
                return portNumber.toString() === portFilter;
            }));
        return matchesAlias && matchesPort;
    });

    // Geçici olarak filtrelenmiş cihazları göster
    const originalDevices = devices;
    devices = filteredDevices;
    displayDevices();
    updateStats();
    devices = originalDevices;

    // Reflect the active-filter count on the panel badge.
    const badge = document.getElementById('activeFilterCount');
    if (badge && window.MynesFilters) {
        const n = MynesFilters.activeCount() + (aliasFilter ? 1 : 0) + (portFilter ? 1 : 0) + (trustFilter ? 1 : 0);
        badge.textContent = n;
        badge.hidden = n === 0;
    }
}

/* Mount the shared searchable multi-selects + visibility toggles once, then let
 * filters.js drive re-renders through the mynes:filters event. Called from init
 * and re-run when the device list changes (to refresh the option lists). */
let _filterUiMounted = false;
function setupSharedFilters() {
    if (!window.MynesFilters) return;
    const F = window.MynesFilters;

    if (!_filterUiMounted) {
        const typeEl = document.getElementById('typeFilterMulti');
        const vendorEl = document.getElementById('vendorFilterMulti');
        const statusEl = document.getElementById('statusFilterMulti');
        if (typeEl) window._typeMulti = F.mountMulti(typeEl, {
            key: 'types', label: t('device_type'),
            options: () => [...new Set(devices.map(d => d.device_type).filter(Boolean))].sort()
                .map(v => ({ value: v, label: getTranslatedDeviceType(v), icon: getDeviceIcon(v) })),
        });
        if (vendorEl) window._vendorMulti = F.mountMulti(vendorEl, {
            key: 'vendors', label: t('vendor'),
            options: () => [...new Set(devices.map(d => F.vendorOf(d)).filter(Boolean))].sort()
                .map(v => ({ value: v, label: v })),
        });
        if (statusEl) window._statusMulti = F.mountMulti(statusEl, {
            key: 'statuses', label: t('status'),
            options: () => [{ value: 'online', label: t('online') }, { value: 'offline', label: t('offline') }],
        });
        F.bindToggle(document.getElementById('toggleContainers'), 'showContainers');
        F.bindToggle(document.getElementById('toggleNoIp'), 'showNoIp');
        F.bindToggle(document.getElementById('toggleBluetooth'), 'showBluetooth');

        // Any change to the shared store re-applies the filter to the view.
        document.addEventListener('mynes:filters', () => {
            const searchEl = document.getElementById('searchInput');
            if (searchEl) { const q = F.get().q || ''; if (searchEl.value !== q) searchEl.value = q; }
            filterDevices();
        });
        _filterUiMounted = true;
    }
    // Refresh option lists against the current device set.
    [window._typeMulti, window._vendorMulti, window._statusMulti].forEach(m => m && m.refresh());
}

// Filtre güncelleme durumlarını takip etmek için değişken
let filtersUpdateScheduled = false;

function updateFilters() {
    // Eğer bir güncelleme zaten zamanlanmışsa, tekrar zamanla
    if (filtersUpdateScheduled) {
        return;
    }
    
    filtersUpdateScheduled = true;
    
    // Bir sonraki frame'de çalıştır (DOM güncellemelerinin tamamlanması için)
    requestAnimationFrame(() => {
        performFiltersUpdate();
        filtersUpdateScheduled = false;
    });
}

function performFiltersUpdate() {
    // Type/vendor/status now live in the shared searchable multi-selects; just
    // refresh their option lists against the current device set.
    setupSharedFilters();

    // Mevcut seçili değerleri sakla
    const currentAlias = (document.getElementById('aliasFilter') || {}).value || '';
    const currentPort = (document.getElementById('portFilter') || {}).value || '';

    // Alias filter - A-Z sıralı, boş olmayanlar
    const aliasFilter = document.getElementById('aliasFilter');
    if (!aliasFilter) return;
    const aliasOptions = [...new Set(devices.map(d => d.alias).filter(alias => alias && alias.trim() !== ''))].sort();
    aliasFilter.innerHTML = `<option value="">${t('all')}</option>` + 
        aliasOptions.map(alias => `<option value="${alias}">${alias}</option>`).join('');
    
    // Seçili değeri geri yükle (sadece hala mevcut ise)
    if (aliasOptions.includes(currentAlias) || currentAlias === '') {
        aliasFilter.value = currentAlias;
    }

    // Port filter - Hem otomatik hem manuel portları dahil et
    const portFilter = document.getElementById('portFilter');
    const allPorts = new Set();
    
    // Varsayılan portları ekle
    ['22', '80', '443', '8080', '3389', '554', '631'].forEach(port => allPorts.add(port));
    
    // Cihazlardaki tüm portları topla
    devices.forEach(device => {
        if (device.open_ports && Array.isArray(device.open_ports)) {
            device.open_ports.forEach(port => {
                const portNumber = typeof port === 'object' ? port.port : port;
                if (portNumber) {
                    allPorts.add(portNumber.toString());
                }
            });
        }
    });
    
    // Port listesini oluştur
    const sortedPorts = Array.from(allPorts).sort((a, b) => parseInt(a) - parseInt(b));
    const portOptions = sortedPorts.map(port => {
        const portNum = parseInt(port);
        let serviceName = '';
        
        // Bilinen port isimlerini ekle
        const knownPorts = {
            22: 'SSH',
            80: 'HTTP', 
            443: 'HTTPS',
            8080: 'HTTP-Alt',
            3389: 'RDP',
            554: 'RTSP',
            631: 'Printer'
        };
        
        serviceName = knownPorts[portNum] || 'Port';
        return `<option value="${port}">${serviceName} (${port})</option>`;
    }).join('');
    
    portFilter.innerHTML = `<option value="">${t('all')}</option>` + portOptions;
    
    // Seçili değeri geri yükle (sadece hala mevcut ise)
    if (Array.from(allPorts).includes(currentPort) || currentPort === '') {
        portFilter.value = currentPort;
    }
}

// Vendor isimlerini normalize eden fonksiyon
function normalizeVendor(vendor) {
    if (!vendor) return vendor;
    
    // TP-Link varyasyonlarını birleştir
    if (vendor.toLowerCase().includes('tp-link')) {
        return 'TP-Link Systems Inc.';
    }
    
    // Diğer yaygın normalize işlemleri
    return vendor.trim();
}

function updateStats() {
    const totalDevices = devices.length;
    const onlineDevices = devices.filter(d => d.status === 'online').length;
    const deviceTypeCount = new Set(devices.map(d => d.device_type).filter(Boolean)).size;
    const vendorCount = new Set(devices.map(d => d.vendor).filter(Boolean)).size;

    document.getElementById('totalDevices').textContent = totalDevices;
    document.getElementById('onlineDevices').textContent = onlineDevices;
    document.getElementById('deviceTypes').textContent = deviceTypeCount;
    document.getElementById('vendors').textContent = vendorCount;
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('tr-TR');
}

function openDevice(ip) {
    // IP adresine tıklandığında yeni sekmede aç
    window.open(`http://${ip}`, '_blank');
}

function openPort(ip, port, service) {
    // Port'a tıklandığında uygun protokolde aç
    let url = `http://${ip}:${port}`;
    
    if (port === 443 || port === 8443) {
        url = `https://${ip}:${port}`;
    } else if (port === 22) {
        alert(`SSH ${t('connection')}: ssh user@${ip}`);
        return;
    } else if (port === 3389) {
        alert(`RDP ${t('connection')}: ${ip}:${port}`);
        return;
    }
    
    window.open(url, '_blank');
}

function editDevice(ip) {
    const device = devices.find(d => d.ip === ip);
    if (!device) return;

    currentEditingIp = ip;
    
    // Set current values
    document.getElementById('editIpAddress').value = device.ip || '';
    document.getElementById('editMacAddress').value = device.mac || '';
    document.getElementById('editAlias').value = device.alias || '';
    document.getElementById('editHostname').value = device.hostname || '';
    document.getElementById('editVendor').value = device.vendor || '';
    const editTypeSel = document.getElementById('editDeviceType');
    editTypeSel.value = device.device_type || '';
    editTypeSel._ds?.refresh();
    document.getElementById('editNotes').value = device.notes || '';
    
    // Manuel portları yükle
    loadManualPorts(device);
    
    document.getElementById('editModal').style.display = 'block';
}

function closeEditModal() {
    document.getElementById('editModal').style.display = 'none';
    currentEditingIp = null;
}

async function saveDevice() {
    if (!currentEditingIp) return;

    // Manuel portları topla
    const manualPorts = [];
    const portEntries = document.querySelectorAll('#manualPortsContainer .port-entry');
    portEntries.forEach(entry => {
        const portInput = entry.querySelector('.port-input');
        const descInput = entry.querySelector('.port-desc-input');
        
        if (portInput.value && portInput.value.trim() !== '') {
            manualPorts.push({
                port: parseInt(portInput.value),
                description: descInput.value.trim() || 'Manuel Port'
            });
        }
    });

    const data = {
        ip: document.getElementById('editIpAddress').value,
        mac: document.getElementById('editMacAddress').value.toLowerCase(),
        alias: document.getElementById('editAlias').value,
        hostname: document.getElementById('editHostname').value,
        vendor: document.getElementById('editVendor').value,
        device_type: document.getElementById('editDeviceType').value,
        notes: document.getElementById('editNotes').value,
        manual_ports: manualPorts
    };

    try {
        const response = await fetch(`/update_device/${currentEditingIp}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            closeEditModal();
            loadDevices(true); // Cihaz güncellendiğinde filtreleri de güncelle
            alert(t('device_info_updated'));
        } else {
            const error = await response.json();
            alert(t('error') + ': ' + error.error);
        }
    } catch (error) {
        alert(t('save_error') + ': ' + error.message);
    }
}

let currentAnalysisId = null;
let analysisInterval = null;

async function analyzeDevice(ip) {
    document.getElementById('analysisModal').style.display = 'block';
    document.getElementById('analysisContent').innerHTML = `
        <div class="analysis-controls" style="margin-bottom: 20px; display: flex; gap: 10px; justify-content: center;">
            <button id="closeAnalysisBtn" class="btn btn-secondary" onclick="closeAnalysisModal()">❌ Kapat</button>
            <button id="backgroundBtn" class="btn btn-info" onclick="continueInBackground()" disabled>${t('continue_in_background')}</button>
        </div>
        <div class="analysis-progress">
            <div class="progress-container">
                <div class="progress-bar">
                    <div id="analysisProgressFill" class="progress-fill" style="width: 0%;"></div>
                </div>
                <div id="analysisProgressText" class="progress-text">${t('analysis_starting')}</div>
            </div>
        </div>
        <div id="analysisDetails" class="analysis-details" style="margin-top: 20px;">
            <div class="analysis-log">
                <h4>📋 İşlem Geçmişi</h4>
                <div id="commandLog" style="background: #f8f9fa; padding: 15px; border-radius: 8px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 0.9em;">
                    <div>⏱️ ${new Date().toLocaleTimeString()} - ${t('analysis_starting')}</div>
                </div>
            </div>
        </div>
    `;

    try {
        // Arkaplan analizi başlat
        const response = await fetch(`/analyze_device_background/${ip}`);
        const result = await response.json();

        if (response.ok) {
            currentAnalysisId = result.analysis_id;
            document.getElementById('backgroundBtn').disabled = false;
            
            // Progress takibi başlat
            analysisInterval = setInterval(() => {
                updateAnalysisProgress();
            }, 1000);
            
        } else {
            displayAnalysisError(result.error);
        }
    } catch (error) {
        displayAnalysisError(error.message);
    }
}

async function updateAnalysisProgress() {
    if (!currentAnalysisId) return;

    try {
        const response = await fetch(`/analysis_status/${currentAnalysisId}`);
        const status = await response.json();

        if (response.ok) {
            // Progress bar güncelle
            document.getElementById('analysisProgressFill').style.width = status.progress + '%';
            document.getElementById('analysisProgressText').textContent = status.message;

            // Komut geçmişini güncelle
            const commandLog = document.getElementById('commandLog');
            if (status.commands) {
                let logContent = `<div>⏱️ ${new Date(status.start_time).toLocaleTimeString()} - Analiz başlatıldı</div>`;
                
                status.commands.forEach(cmd => {
                    const statusIcon = cmd.return_code === 0 ? '✅' : '❌';
                    logContent += `
                        <div style="margin-top: 10px; padding: 10px; background: white; border-radius: 4px;">
                            <div><strong>${statusIcon} ${cmd.name}</strong> (${cmd.duration}s)</div>
                            <div style="color: #6c757d; font-size: 0.8em;">${cmd.command}</div>
                            ${cmd.output ? `<div style="color: #28a745; margin-top: 5px;">${cmd.output.substring(0, 200)}${cmd.output.length > 200 ? '...' : ''}</div>` : ''}
                            ${cmd.error && cmd.error !== 'Timeout' ? `<div style="color: #dc3545; margin-top: 5px;">${cmd.error}</div>` : ''}
                        </div>
                    `;
                });
                
                if (status.current_command) {
                    logContent += `<div style="margin-top: 10px; color: #667eea;"><strong>🔄 Çalışıyor: ${status.current_command}</strong></div>`;
                }
                
                commandLog.innerHTML = logContent;
                commandLog.scrollTop = commandLog.scrollHeight;
            }

            // Analiz tamamlandı
            if (status.status === 'completed') {
                clearInterval(analysisInterval);
                analysisInterval = null;
                
                if (status.result) {
                    displayAnalysisResults(status.result, status);
                }
                
                document.getElementById('backgroundBtn').textContent = t('completed');
                document.getElementById('backgroundBtn').disabled = true;
            } else if (status.status === 'error') {
                clearInterval(analysisInterval);
                analysisInterval = null;
                displayAnalysisError(status.error || status.message);
            }
        } else {
            displayAnalysisError('Analiz durumu alınamadı');
        }
    } catch (error) {
        displayAnalysisError('Bağlantı hatası: ' + error.message);
    }
}

function continueInBackground() {
    if (analysisInterval) {
        clearInterval(analysisInterval);
        analysisInterval = null;
    }
    
    closeAnalysisModal();
    
    // Bildirim göster
    showAlert('Analiz arkaplanda devam ediyor. Sonuçları görmek için tekrar "Detaylı Analiz" butonuna tıklayabilirsiniz.', 'info');
}

function displayAnalysisError(error) {
    document.getElementById('analysisContent').innerHTML = `
        <div style="color: #e74c3c; text-align: center; padding: 20px;">
            ❌ ${t('analysis_error')}: ${error}
        </div>
        <div style="text-align: center; margin-top: 15px;">
            <button class="btn btn-secondary" onclick="closeAnalysisModal()">${t('close')}</button>
        </div>
    `;
}

function displayAnalysisResults(analysis, statusInfo) {
    const startTime = statusInfo ? new Date(statusInfo.start_time) : new Date();
    const endTime = statusInfo ? new Date(statusInfo.end_time) : new Date();
    const duration = Math.round((endTime - startTime) / 1000);
    
    const content = `
        <div class="analysis-controls" style="margin-bottom: 20px; display: flex; gap: 10px; justify-content: center;">
            <button class="btn btn-secondary" onclick="closeAnalysisModal()">❌ ${t('close')}</button>
            <button class="btn btn-success">✅ ${t('analysis_completed_duration', { duration })}</button>
        </div>
        
        <div class="analysis-container">
            <div class="analysis-section">
                <div class="analysis-title">📊 Analiz Özeti</div>
                <div class="analysis-result">
                    <strong>Başlangıç:</strong> ${startTime.toLocaleString('tr-TR')}<br>
                    <strong>Bitiş:</strong> ${endTime.toLocaleString('tr-TR')}<br>
                    <strong>Süre:</strong> ${duration} saniye<br>
                    <strong>Çalıştırılan Komut:</strong> ${statusInfo?.commands?.length || 0} adet
                </div>
            </div>

            <div class="analysis-section">
                <div class="analysis-title">🏓 Ping Testi</div>
                <div class="analysis-result">
                    ${analysis.ping_test?.success ? 
                        `✅ Başarılı\n${analysis.ping_test.output}` : 
                        `❌ Başarısız: ${analysis.ping_test?.error || 'Bilinmeyen hata'}`
                    }
                </div>
            </div>

            <div class="analysis-section">
                <div class="analysis-title">🗺️ Traceroute</div>
                <div class="analysis-result">
                    ${analysis.traceroute?.success ? 
                        analysis.traceroute.output : 
                        `❌ Başarısız: ${analysis.traceroute?.error || 'Bilinmeyen hata'}`
                    }
                </div>
            </div>

            <div class="analysis-section">
                <div class="analysis-title">🔍 Servis Tespiti</div>
                <div class="analysis-result">
                    ${Array.isArray(analysis.service_detection) ? 
                        analysis.service_detection.map(service => 
                            `Port ${service.port}: ${service.service} ${service.product} ${service.version}`
                        ).join('\n') || 'Servis bulunamadı' :
                        `❌ Hata: ${analysis.service_detection?.error || 'Servis tespiti yapılamadı'}`
                    }
                </div>
            </div>

            <div class="analysis-section">
                <div class="analysis-title">💻 İşletim Sistemi Tespiti</div>
                <div class="analysis-result">
                    ${analysis.os_detection?.name ? 
                        `${analysis.os_detection.name} (${analysis.os_detection.accuracy}% doğruluk)\nAile: ${analysis.os_detection.family}` :
                        analysis.os_detection?.error ? 
                            `❌ Hata: ${analysis.os_detection.error}` :
                            'İşletim sistemi tespit edilemedi'
                    }
                </div>
            </div>
            
            ${statusInfo?.commands ? `
            <div class="analysis-section">
                <div class="analysis-title">📋 Çalıştırılan Komutlar</div>
                <div class="analysis-result">
                    ${statusInfo.commands.map(cmd => `
                        <div style="margin-bottom: 15px; padding: 10px; background: #f8f9fa; border-radius: 6px;">
                            <div><strong>${cmd.return_code === 0 ? '✅' : '❌'} ${cmd.name}</strong> (${cmd.duration}s)</div>
                            <div style="font-family: monospace; font-size: 0.8em; color: #6c757d; margin-top: 5px;">${cmd.command}</div>
                            ${cmd.output ? `<div style="max-height: 100px; overflow-y: auto; margin-top: 8px; padding: 8px; background: white; border-radius: 4px;"><pre style="margin: 0; white-space: pre-wrap;">${cmd.output}</pre></div>` : ''}
                            ${cmd.error && cmd.error !== 'Timeout' ? `<div style="color: #dc3545; margin-top: 5px;">${cmd.error}</div>` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
            ` : ''}
        </div>
    `;

    document.getElementById('analysisContent').innerHTML = content;
}

function closeAnalysisModal() {
    if (analysisInterval) {
        clearInterval(analysisInterval);
        analysisInterval = null;
    }
    currentAnalysisId = null;
    document.getElementById('analysisModal').style.display = 'none';
}

async function startScan() {
    try {
        const response = await fetch('/scan');
        const result = await response.json();
        
        if (response.ok) {
            setScanUiState(true);
            document.getElementById('progressContainer').style.display = 'block';
            // Toast bildirimi göster
            showToast(t('scanning_network'), 'info');
            // Progress tracking'i başlat
            startProgressUpdates();
        } else {
            alert(t('scan_start_error') + ': ' + result.error);
        }
    } catch (error) {
        alert(t('scan_start_error') + ': ' + error.message);
    }
}

async function stopScan() {
    try {
        const response = await fetch('/stop_scan');
        const result = await response.json();

        setScanUiState(false);
        document.getElementById('progressContainer').style.display = 'none';
        
        // Progress interval'ını durdur
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        
        // Toast bildirimi göster
        showToast(t('scan_stopped'), 'warning');
    } catch (error) {
        showToast(t('scan_stop_error') + ': ' + error.message, 'error');
    }
}

function startProgressUpdates() {
    // Eğer zaten çalışan bir interval varsa, önce onu durdur
    if (progressInterval) {
        clearInterval(progressInterval);
    }
    
    progressInterval = setInterval(async () => {
        try {
            const response = await fetch('/progress');
            const progress = await response.json();
            
            document.getElementById('progressText').textContent = progressLabel(progress);

            if (progress.status === 'scanning') {
                // Real fraction when the scanner reports one, else the old 50%.
                const pct = (progress.total ? Math.round(100 * progress.scanned / progress.total) : 50);
                document.getElementById('progressFill').style.width = pct + '%';
            } else if (progress.status === 'completed') {
                document.getElementById('progressFill').style.width = '100%';
                setScanUiState(false);
                
                // Interval'ı durdur
                clearInterval(progressInterval);
                progressInterval = null;
                
                // Toast bildirimi göster
                showToast(t('scan_complete'), 'success');
                
                setTimeout(() => {
                    document.getElementById('progressContainer').style.display = 'none';
                    // Tarama tamamlandığında cihazları ve filtreleri yükle
                    loadDevices(true);
                }, 2000);
            } else if (progress.status === 'error') {
                document.getElementById('progressFill').style.width = '0%';
                setScanUiState(false);
                document.getElementById('progressContainer').style.display = 'none';
                
                // Toast bildirimi göster
                showToast(t('error') + ': ' + progress.message, 'error');
                
                // Interval'ı durdur
                clearInterval(progressInterval);
                progressInterval = null;
            } else if (progress.status === 'idle') {
                // Eğer durum idle ise ve progress çalışıyorsa, interval'ı durdur
                clearInterval(progressInterval);
                progressInterval = null;
            }
            
        } catch (error) {
            console.error(t('error'), error);
        }
    }, 1000);
}

async function exportData() {
    try {
        const response = await fetch('/export');
        const data = await response.json();
        
        const dataStr = JSON.stringify(data, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `lan_devices_${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        URL.revokeObjectURL(url);
    } catch (error) {
        alert(t('export_error') + ': ' + error.message);
    }
}

/* CSV of the device list. Exports what the user is currently looking at (the
   shared filter applied), which is what "export the list" almost always means. */
function exportDevicesCsv() {
    const rows = (window.MynesFilters ? MynesFilters.apply(devices) : devices);
    const cols = ['ip', 'mac', 'hostname', 'alias', 'vendor', 'device_type', 'status', 'last_seen'];
    const cell = v => {
        const s = String(v == null ? '' : v);
        return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const ports = d => (d.open_ports || [])
        .map(p => (typeof p === 'object' ? p.port : p)).filter(Boolean).join(' ');
    const header = [...cols, 'open_ports'].join(',');
    const body = rows.map(d => [...cols.map(c => cell(d[c])), cell(ports(d))].join(',')).join('\n');
    const blob = new Blob([header + '\n' + body], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `lan_devices_${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
}

function importData() {
    const file = document.getElementById('importFile').files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = async function(e) {
            try {
                const importedData = JSON.parse(e.target.result);
                
                const response = await fetch('/import', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(importedData)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    alert(result.message);
                    loadDevices(true); // Import sonrası filtreleri de güncelle
                } else {
                    alert(t('import_error') + ': ' + result.error);
                }
            } catch (error) {
                alert(t('file_read_error') + ': ' + error.message);
            }
        };
        reader.readAsText(file);
    }
}

async function sanitizeData() {
    // Kullanıcıdan onay al
    if (!confirm(t('confirm_data_clean'))) {
        return;
    }
    
    try {
        showToast(t('data_cleaning_in_progress'), 'info');
        
        const response = await fetch('/api/sanitize_data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast(t('data_cleaned_success') + ': ' + result.backup_created, 'success');
            // Verileri yeniden yükle
            await loadDevices(true);
        } else {
            showToast(t('data_clean_error') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

// Modal dışına tıklandığında kapat
window.onclick = function(event) {
    const editModal = document.getElementById('editModal');
    const analysisModal = document.getElementById('analysisModal');
    
    if (event.target === editModal) {
        closeEditModal();
    }
    if (event.target === analysisModal) {
        closeAnalysisModal();
    }
}

async function startBulkAnalysis() {
    if (devices.length === 0) {
        showToast(t('no_devices_to_analyze'), 'warning');
        return;
    }
    
    if (bulkAnalysisRunning) {
        showToast(t('bulk_analysis_running'), 'warning');
        return;
    }
    
    // Unified modal'da çağrılıyorsa, doğrudan analizi başlat
    if (window.unifiedAnalysisMode) {
        await startBulkAnalysisActual();
        return;
    }
    
    // Birleşik modal'ı kullan
    if (typeof showBulkAnalysisModal === 'function') {
        showBulkAnalysisModal();
    } else {
        // Fallback: eski sistem
        startBulkAnalysisFallback();
    }
}

async function startBulkAnalysisActual() {
    try {
        bulkAnalysisRunning = true;
        
        // UI durumunu güncelle
        updateBulkAnalysisButtons(true);
        
        // Yeni API'yi kullanarak toplu detaylı analizi başlat
        const response = await fetch('/detailed_analysis');
        const result = await response.json();
        
        if (response.ok) {
            showToast(t('bulk_analysis_started'), 'success');
            
            // Progress tracking başlat
            monitorDetailedAnalysisStatus();
            
        } else {
            throw new Error(result.error || 'Bilinmeyen hata');
        }
    } catch (error) {
        bulkAnalysisRunning = false;
        updateBulkAnalysisButtons(false);
        showToast(t('analysis_error') + ': ' + error.message, 'error');
    }
}

function updateBulkAnalysisButtons(isRunning) {
    // Unified modal içindeki butonları güncelle
    const sessionKey = 'bulk';
    const startBtn = document.getElementById(`startBtn_${sessionKey}`);
    const stopBtn = document.getElementById(`stopBtn_${sessionKey}`);
    const minimizeBtn = document.getElementById(`minimizeBtn_${sessionKey}`);
    
    if (startBtn) {
        startBtn.disabled = isRunning;
        startBtn.style.display = isRunning ? 'none' : 'inline-block';
    }
    
    if (stopBtn) {
        stopBtn.style.display = isRunning ? 'inline-block' : 'none';
    }
    
    if (minimizeBtn) {
        minimizeBtn.style.display = isRunning ? 'inline-block' : 'none';
    }
    
    // Progress bölümünü göster/gizle
    const progressDiv = document.getElementById('analysisProgress');
    if (progressDiv) {
        progressDiv.style.display = isRunning ? 'block' : 'none';
    }
}

async function startBulkAnalysisFallback() {
    try {
        // Yeni API'yi kullanarak toplu detaylı analizi başlat
        const response = await fetch('/detailed_analysis');
        const result = await response.json();
        
        if (response.ok) {
            bulkAnalysisRunning = true;
            showToast(t('bulk_analysis_started'), 'success');
            
            // Progress modal göster
            document.getElementById('analysisModal').style.display = 'block';
            document.getElementById('analysisContent').innerHTML = `
                <div class="analysis-controls" style="margin-bottom: 20px; display: flex; gap: 10px; justify-content: center;">
                    <button class="btn btn-info" onclick="hideBulkAnalysisModal()">📱 ${t('continue_in_background')}</button>
                    <button class="btn btn-success" onclick="loadDevices(true)">🔄 Verileri Yenile</button>
                </div>
                <div class="analysis-progress">
                    <div class="progress-container">
                        <div class="progress-bar">
                            <div id="bulkAnalysisProgressFill" class="progress-fill" style="width: 0%;"></div>
                        </div>
                        <div id="bulkAnalysisProgressText" class="progress-text">Detaylı analiz başlatılıyor...</div>
                    </div>
                </div>
                <div id="bulkAnalysisDetails" class="analysis-details" style="margin-top: 20px;">
                    <div class="analysis-log">
                        <h4>📋 Detaylı Analiz Durumu</h4>
                        <div id="bulkAnalysisLog" style="background: #f8f9fa; padding: 15px; border-radius: 8px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 0.9em;">
                            <div>⏱️ ${new Date().toLocaleTimeString()} - Toplu detaylı analiz başlatıldı</div>
                        </div>
                    </div>
                </div>
            `;
            
            // Analiz durumunu takip et
            monitorDetailedAnalysisStatus();
            
        } else {
            showToast(t('error') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

function updateBulkAnalysisProgress(percentage, message) {
    // Legacy modal
    const progressFill = document.getElementById('bulkAnalysisProgressFill');
    const progressText = document.getElementById('bulkAnalysisProgressText');
    
    if (progressFill) progressFill.style.width = percentage + '%';
    if (progressText) progressText.textContent = message;
    
    // Unified modal
    const unifiedProgressBar = document.getElementById('progressBar');
    const unifiedProgressText = document.getElementById('progressText');
    
    if (unifiedProgressBar) {
        unifiedProgressBar.style.width = percentage + '%';
        unifiedProgressBar.textContent = Math.round(percentage) + '%';
    }
    if (unifiedProgressText) {
        unifiedProgressText.textContent = message;
    }
}

function updateBulkAnalysisLog(message) {
    // Legacy modal
    const log = document.getElementById('bulkAnalysisLog');
    if (log) {
        const timeStamp = new Date().toLocaleTimeString();
        const newLine = document.createElement('div');
        newLine.textContent = `⏱️ ${timeStamp} - ${message}`;
        log.appendChild(newLine);
        log.scrollTop = log.scrollHeight;
    }
    
    // Unified modal - device-access.js'deki addVerboseLog fonksiyonunu kullan
    if (typeof addVerboseLog === 'function') {
        addVerboseLog(message, 'bulk');
    }
}

async function monitorBulkAnalysisResults() {
    const checkInterval = setInterval(async () => {
        if (!bulkAnalysisRunning) {
            clearInterval(checkInterval);
            return;
        }
        
        let allCompleted = true;
        let completedCount = 0;
        let totalCount = Object.keys(bulkAnalysisResults).length;
        
        for (const [ip, analyzeData] of Object.entries(bulkAnalysisResults)) {
            if (analyzeData.status === 'running') {
                try {
                    const response = await fetch(`/analysis_status/${analyzeData.analysis_id}`);
                    const status = await response.json();
                    
                    if (status.status === 'completed') {
                        bulkAnalysisResults[ip].status = 'completed';
                        bulkAnalysisResults[ip].result = status;
                        completedCount++;
                        updateBulkAnalysisLog(`✅ ${ip} analizi tamamlandı`);
                    } else if (status.status === 'error') {
                        bulkAnalysisResults[ip].status = 'error';
                        bulkAnalysisResults[ip].error = status.error;
                        completedCount++;
                        updateBulkAnalysisLog(`❌ ${ip} analiz hatası: ${status.error}`);
                    } else {
                        allCompleted = false;
                    }
                } catch (error) {
                    bulkAnalysisResults[ip].status = 'error';
                    bulkAnalysisResults[ip].error = error.message;
                    completedCount++;
                    updateBulkAnalysisLog(`❌ ${ip} durum kontrolü hatası: ${error.message}`);
                }
            } else {
                completedCount++;
            }
        }
        
        updateBulkAnalysisProgress((completedCount / totalCount) * 100, `${completedCount}/${totalCount} analiz tamamlandı`);
        
        if (allCompleted) {
            clearInterval(checkInterval);
            bulkAnalysisRunning = false;
            updateBulkAnalysisLog(`🎉 Toplu analiz tamamlandı! ${completedCount} cihaz analiz edildi.`);
            updateBulkAnalysisProgress(100, 'Toplu analiz tamamlandı');
            
            // Toast bildirimi göster
            showToast(t('bulk_analysis_completed') + '! ' + completedCount + ' ' + t('devices_analyzed'), 'success');
        }
    }, 3000); // Her 3 saniyede kontrol et
}

function monitorDetailedAnalysisStatus() {
    const checkInterval = setInterval(async () => {
        try {
            const response = await fetch('/detailed_analysis_status');
            const status = await response.json();
            
            if (status.status === 'analyzing') {
                // Yeni mesaj varsa logla
                if (status.message !== lastAnalysisMessage) {
                    updateBulkAnalysisLog(`🔄 ${status.message}`);
                    lastAnalysisMessage = status.message;
                }
                
                // Arkaplan göstergesi güncelle
                updateBackgroundIndicator(status.message);
                
                // Progress simülasyonu (gerçek progress backend'den gelse daha iyi olur)
                const currentProgress = document.getElementById('bulkAnalysisProgressFill')?.style.width || '0%';
                const progressValue = parseFloat(currentProgress.replace('%', '')) || 0;
                if (progressValue < 90) {
                    updateBulkAnalysisProgress(progressValue + 2, status.message);
                }
            } else if (status.status === 'completed') {
                clearInterval(checkInterval);
                bulkAnalysisRunning = false;
                updateBulkAnalysisLog(`🎉 ${status.message}`);
                updateBulkAnalysisProgress(100, 'Detaylı analiz tamamlandı');
                showToast(t('bulk_analysis_completed'), 'success');
                hideBackgroundIndicator();
                
                // Unified modal butonlarını güncelle
                updateBulkAnalysisButtons(false);
                if (typeof updateUnifiedAnalysisButtons === 'function') {
                    updateUnifiedAnalysisButtons('bulk', false);
                }
                
                // Cihaz listesini yenile
                await loadDevices(true);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                bulkAnalysisRunning = false;
                updateBulkAnalysisLog(`❌ ${status.message}`);
                showToast(t('analysis_error') + ': ' + status.message, 'error');
                hideBackgroundIndicator();
                
                // Unified modal butonlarını güncelle
                updateBulkAnalysisButtons(false);
                if (typeof updateUnifiedAnalysisButtons === 'function') {
                    updateUnifiedAnalysisButtons('bulk', false);
                }
            }
        } catch (error) {
            console.error('Analiz durumu kontrol hatası:', error);
        }
    }, 1500); // Daha sık kontrol et (1.5 saniye)
}

function stopBulkAnalysis() {
    bulkAnalysisRunning = false;
    updateBulkAnalysisLog(`⏹️ Toplu analiz durduruldu`);
    showToast(t('bulk_analysis_stopped'), 'warning');
}

function hideBulkAnalysisModal() {
    document.getElementById('analysisModal').style.display = 'none';
    
    // Arkaplan analizin devam edip etmediğini kontrol et
    if (bulkAnalysisRunning) {
        showBackgroundIndicator();
    }
}

// Detaylı Cihaz Analizi sayfasını aç - device-access.js ile uyumlu
function openSingleDeviceAnalysisPage(ip) {
    // device-access.js'teki showSingleDeviceAnalysisModal fonksiyonunu çağır
    if (typeof showSingleDeviceAnalysisModal === 'function') {
        showSingleDeviceAnalysisModal(ip);
    } else {
        // Fallback: eski analiz fonksiyonunu kullan
        analyzeSingleDeviceFallback(ip);
    }
}

async function analyzeSingleDeviceFallback(ip) {
    try {
        // Enhanced analysis endpoint'ini kullan
        const response = await fetch(`/enhanced_analysis/${ip}`, {
            method: 'POST'
        });
        const result = await response.json();
        
        if (response.ok) {
            showToast(`🔬 ${ip} ${t('detailed_analysis_started')}`, 'success');
            
            // Progress indicator göster
            updateBackgroundIndicator('Gelişmiş analiz yapılıyor...', true);
            
            // Analiz durumunu takip et
            const checkInterval = setInterval(async () => {
                try {
                    const statusResponse = await fetch(`/enhanced_analysis_status/${ip}`);
                    const status = await statusResponse.json();
                    
                    if (status.status === 'completed') {
                        clearInterval(checkInterval);
                        updateBackgroundIndicator('Gelişmiş analiz tamamlandı', false);
                        showToast(`🎉 ${ip} ${t('detailed_analysis_completed')}`, 'success');
                        await loadDevices(true); // Cihaz listesini yenile
                    } else if (status.status === 'error') {
                        clearInterval(checkInterval);
                        updateBackgroundIndicator('Analiz hatası', false);
                        showToast(`❌ ${ip} ${t('analysis_error')}: ${status.message}`, 'error');
                    } else if (status.status === 'analyzing' && status.message) {
                        // Progress mesajını güncelle
                        updateBackgroundIndicator(status.message, true);
                    }
                } catch (error) {
                    console.error('Tek cihaz analiz durumu kontrol hatası:', error);
                }
            }, 2000);
            
        } else {
            showToast(t('error') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

function addPortEntry() {
    const container = document.getElementById('manualPortsContainer');
    const newEntry = document.createElement('div');
    newEntry.className = 'port-entry';
    newEntry.innerHTML = `
        <input type="number" placeholder="Port (örn: 80)" class="port-input" min="1" max="65535">
        <input type="text" placeholder="Açıklama (örn: HTTP)" class="port-desc-input">
        <button type="button" class="btn btn-danger btn-small" onclick="removePortEntry(this)">🗑️</button>
    `;
    container.appendChild(newEntry);
}

function removePortEntry(button) {
    const container = document.getElementById('manualPortsContainer');
    if (container.children.length > 1) {
        button.parentElement.remove();
    }
}

function showAlert(message, type = 'info') {
    // Basit alert gösterimi - daha gelişmiş notification sistemi eklenebilir
    alert(message);
}

function loadManualPorts(device) {
    const container = document.getElementById('manualPortsContainer');
    
    // Container'ı temizle (sadece ilk entry'yi bırak)
    container.innerHTML = `
        <div class="port-entry">
            <input type="number" placeholder="Port (örn: 80)" class="port-input" min="1" max="65535">
            <input type="text" placeholder="Açıklama (örn: HTTP)" class="port-desc-input">
            <button type="button" class="btn btn-danger btn-small" onclick="removePortEntry(this)">🗑️</button>
        </div>
    `;
    
    // Mevcut manuel portları yükle
    if (device.open_ports && Array.isArray(device.open_ports)) {
        const manualPorts = device.open_ports.filter(port => {
            return typeof port === 'object' && port.manual === true;
        });
        
        if (manualPorts.length > 0) {
            // İlk manuel port için mevcut entry'yi kullan
            const firstEntry = container.querySelector('.port-entry');
            const firstPort = manualPorts[0];
            firstEntry.querySelector('.port-input').value = firstPort.port;
            firstEntry.querySelector('.port-desc-input').value = firstPort.description || '';
            
            // Kalan portlar için yeni entry'ler ekle
            for (let i = 1; i < manualPorts.length; i++) {
                const port = manualPorts[i];
                addPortEntry();
                const newEntry = container.lastElementChild;
                newEntry.querySelector('.port-input').value = port.port;
                newEntry.querySelector('.port-desc-input').value = port.description || '';
            }
        }
    }
}

// View Management - Görünüm yönetimi
let currentView = 'card'; // Varsayılan görünüm

function switchView(view) {
    // Önceki aktif butondan active class'ını kaldır (hem eski hem yeni butonlar için)
    document.querySelectorAll('.view-btn, .view-btn-vertical').forEach(btn => {
        btn.classList.remove('active');
        if (btn.hasAttribute('aria-pressed')) btn.setAttribute('aria-pressed', 'false');
    });

    // Yeni aktif butona active class'ı ekle
    const activeBtn = document.getElementById(`view${view.charAt(0).toUpperCase() + view.slice(1)}`);
    activeBtn.classList.add('active');
    if (activeBtn.hasAttribute('aria-pressed')) activeBtn.setAttribute('aria-pressed', 'true');
    
    // Görünümleri gizle/göster
    const containers = {
        card: ['devicesContainer', 'grid'],
        table: ['tableContainer', 'block'],
        graph: ['graphContainer', 'block'],
        topology: ['topologyContainer', 'block'],
        home: ['homeContainer', 'block'],
    };
    Object.entries(containers).forEach(([name, [id, display]]) => {
        const node = document.getElementById(id);
        if (node) node.style.display = name === view ? display : 'none';
    });

    currentView = view;

    // Seçilen görünüme göre verileri yükle
    displayDevices();
}

// The Table view is owned by static/js/table-view.js (MynesTable). It reads the
// same already-filtered `devices` global and renders header/body/toolbar itself.
function displayDevicesTable() {
    if (window.MynesTable) window.MynesTable.render();
}

function truncateText(text, maxLength) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

function formatRelativeTime(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffMins < 1) return 'Az önce';
    if (diffMins < 60) return `${diffMins}dk önce`;
    if (diffHours < 24) return `${diffHours}sa önce`;
    if (diffDays < 7) return `${diffDays}g önce`;
    
    return date.toLocaleDateString('tr-TR');
}

// Toast Notification Sistemi
function createToastContainer() {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    return container;
}

function showToast(message, type = 'info', duration = 5000) {
    const container = createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="removeToast(this.parentElement)">&times;</button>
    `;
    
    container.appendChild(toast);
    
    // Otomatik kaldırma
    setTimeout(() => {
        removeToast(toast);
    }, duration);
    
    return toast;
}

function removeToast(toast) {
    if (toast && toast.parentElement) {
        toast.classList.add('hiding');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.parentElement.removeChild(toast);
            }
        }, 300);
    }
}

// MAC Address Copy Functionality
async function copyMacAddress(macAddress, buttonElement) {
    try {
        // Modern browsers - clipboard API kullan
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(macAddress);
        } else {
            // Fallback - eski tarayıcılar için
            const textArea = document.createElement('textarea');
            textArea.value = macAddress;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
        }
        
        // Visual feedback
        const originalText = buttonElement.innerHTML;
        buttonElement.classList.add('copied');
        buttonElement.innerHTML = '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-check"/></svg>';
        
        // Toast notification
        showToast(`${t('mac_copied')}: ${macAddress}`, 'success', 2000);
        
        // Reset button after 1.5 seconds
        setTimeout(() => {
            buttonElement.classList.remove('copied');
            buttonElement.innerHTML = originalText;
        }, 1500);
        
    } catch (error) {
        console.error(t('mac_copy_error'), error);
        showToast(t('mac_copy_error'), 'error', 3000);
        
        // Error visual feedback
        const originalText = buttonElement.innerHTML;
        buttonElement.style.background = '#dc3545';
        buttonElement.innerHTML = '<svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-x"/></svg>';
        
        setTimeout(() => {
            buttonElement.style.background = '';
            buttonElement.innerHTML = originalText;
        }, 1500);
    }
}

// Arkaplan analiz göstergesi fonksiyonları
function showBackgroundIndicator() {
    if (backgroundAnalysisIndicator) return; // Zaten gösteriliyor
    
    // Arkaplan göstergesi oluştur
    backgroundAnalysisIndicator = document.createElement('div');
    backgroundAnalysisIndicator.id = 'backgroundAnalysisIndicator';
    backgroundAnalysisIndicator.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: linear-gradient(45deg, #007bff, #0056b3);
        color: white;
        padding: 15px 20px;
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0,123,255,0.3);
        z-index: 10000;
        cursor: pointer;
        animation: pulse 2s infinite;
        font-family: Arial, sans-serif;
        font-size: 14px;
        font-weight: bold;
        transition: transform 0.3s ease;
        max-width: 280px;
    `;
    
    backgroundAnalysisIndicator.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 8px; height: 8px; background: #28a745; border-radius: 50%; animation: blink 1s infinite;"></div>
            <span>🔬 Detaylı Analiz Devam Ediyor</span>
            <small style="opacity: 0.8; font-size: 12px;">Açmak için tıklayın</small>
        </div>
    `;
    
    // Tıklandığında modal'ı aç
    backgroundAnalysisIndicator.addEventListener('click', () => {
        document.getElementById('analysisModal').style.display = 'block';
        hideBackgroundIndicator();
    });
    
    // Hover efekti
    backgroundAnalysisIndicator.addEventListener('mouseenter', () => {
        backgroundAnalysisIndicator.style.transform = 'scale(1.05)';
    });
    
    backgroundAnalysisIndicator.addEventListener('mouseleave', () => {
        backgroundAnalysisIndicator.style.transform = 'scale(1)';
    });
    
    document.body.appendChild(backgroundAnalysisIndicator);
    
    // CSS animasyonları ekle
    if (!document.getElementById('backgroundIndicatorStyles')) {
        const styles = document.createElement('style');
        styles.id = 'backgroundIndicatorStyles';
        styles.textContent = `
            @keyframes pulse {
                0% { box-shadow: 0 4px 12px rgba(0,123,255,0.3); }
                50% { box-shadow: 0 6px 20px rgba(0,123,255,0.5); }
                100% { box-shadow: 0 4px 12px rgba(0,123,255,0.3); }
            }
            @keyframes blink {
                0%, 50% { opacity: 1; }
                51%, 100% { opacity: 0.3; }
            }
        `;
        document.head.appendChild(styles);
    }
}

function hideBackgroundIndicator() {
    if (backgroundAnalysisIndicator) {
        backgroundAnalysisIndicator.remove();
        backgroundAnalysisIndicator = null;
    }
}

function updateBackgroundIndicator(message) {
    if (backgroundAnalysisIndicator) {
        const messageDiv = backgroundAnalysisIndicator.querySelector('span');
        if (messageDiv) {
            // IP adresini vurgula
            const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
            if (ipMatch) {
                messageDiv.innerHTML = `🔬 Analiz: <strong>${ipMatch[0]}</strong>`;
            } else {
                messageDiv.textContent = '🔬 Detaylı Analiz Devam Ediyor';
            }
        }
    }
}

// Cihaz Yönetimi Modal Fonksiyonları
function showDeviceManagementModal() {
    document.getElementById('deviceManagementModal').style.display = 'block';
    // Device type dropdowns'ını güncelle
    populateDeviceTypeDropdowns();
    // Cihaz listesini yükle
    loadDevicesForManagement();
}

function closeDeviceManagementModal() {
    document.getElementById('deviceManagementModal').style.display = 'none';
}

function switchDeviceManagementTab(tab) {
    // Tab butonlarını güncelle
    const tabButtons = document.querySelectorAll('.device-management-tabs .tab-button');
    tabButtons.forEach(btn => btn.classList.remove('active'));
    
    // Aktif tab butonunu işaretle
    event.target.classList.add('active');
    
    // Tab içeriklerini gizle/göster
    const addTab = document.getElementById('addDeviceTab');
    const manageTab = document.getElementById('manageDeviceTab');
    
    if (tab === 'add') {
        addTab.style.display = 'block';
        manageTab.style.display = 'none';
    } else if (tab === 'manage') {
        addTab.style.display = 'none';
        manageTab.style.display = 'block';
        loadDevicesForManagement();
    }
}

// Cihaz ekleme formu submit
document.addEventListener('DOMContentLoaded', function() {
    const addDeviceForm = document.getElementById('addDeviceForm');
    if (addDeviceForm) {
        addDeviceForm.addEventListener('submit', function(e) {
            e.preventDefault();
            addManualDevice();
        });
    }
});

async function addManualDevice() {
    const formData = {
        ip: document.getElementById('addDeviceIP').value.trim(),
        mac: document.getElementById('addDeviceMAC').value.trim(),
        hostname: document.getElementById('addDeviceHostname').value.trim(),
        alias: document.getElementById('addDeviceAlias').value.trim(),
        vendor: document.getElementById('addDeviceVendor').value.trim(),
        device_type: document.getElementById('addDeviceType').value,
        notes: document.getElementById('addDeviceNotes').value.trim()
    };
    
    // Validation
    if (!formData.ip) {
        showToast(t('ip_required'), 'error');
        return;
    }
    
    if (!formData.alias) {
        showToast(t('alias_required'), 'error');
        return;
    }
    
    // IP format kontrolü
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipPattern.test(formData.ip)) {
        showToast(t('invalid_ip_format'), 'error');
        return;
    }
    
    try {
        const response = await fetch('/add_manual_device', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast(t('device_added_success') + ': ' + formData.alias, 'success');
            clearAddDeviceForm();
            // Ana listede güncelleme yap
            loadDevices(true);
            // Yönetim listesini güncelle
            loadDevicesForManagement();
        } else {
            showToast(t('device_add_error') + ': ' + result.message, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

function clearAddDeviceForm() {
    document.getElementById('addDeviceIP').value = '';
    document.getElementById('addDeviceMAC').value = '';
    document.getElementById('addDeviceHostname').value = '';
    document.getElementById('addDeviceAlias').value = '';
    document.getElementById('addDeviceVendor').value = '';
    document.getElementById('addDeviceType').value = '';
    document.getElementById('addDeviceNotes').value = '';
}

function loadDevicesForManagement() {
    const tableBody = document.getElementById('deviceTableBody');
    if (!tableBody) return;
    
    tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">📡 Cihazlar yükleniyor...</td></tr>';
    
    // Ana devices listesini kullan
    if (devices && devices.length > 0) {
        let html = '';
        devices.forEach(device => {
            const isOnline = device.status === 'online';
            const statusIcon = isOnline ? '🟢' : '🔴';
            const statusText = isOnline ? 'Çevrimiçi' : 'Çevrimdışı';
            
            html += `
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.ip}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.alias || device.hostname || '-'}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${getTranslatedDeviceType(device.device_type)}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.vendor || '-'}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${statusIcon}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">
                        <button class="btn btn-primary" onclick="editDeviceFromManagement('${device.ip}')" title="Düzenle" style="margin-right: 5px; padding: 4px 8px; font-size: 12px;">
                            ✏️
                        </button>
                        <button class="btn btn-danger" onclick="confirmDeleteDevice('${device.ip}')" title="Sil" style="padding: 4px 8px; font-size: 12px;">
                            🗑️
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html || '<tr><td colspan="6" style="text-align: center; padding: 20px;">Henüz cihaz bulunamadı.</td></tr>';
    } else {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">Henüz cihaz bulunamadı.</td></tr>';
    }
}

function filterDevicesForManagement() {
    const searchInput = document.getElementById('deviceSearchInput');
    if (!searchInput) return;
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    const tableBody = document.getElementById('deviceTableBody');
    if (!tableBody) return;
    
    // Eğer arama terimi yoksa tüm cihazları göster
    if (!searchTerm) {
        loadDevicesForManagement();
        return;
    }
    
    // Arama terimine göre cihazları filtrele
    const filteredDevices = devices.filter(device => {
        const ip = (device.ip || '').toLowerCase();
        const alias = (device.alias || '').toLowerCase();
        const hostname = (device.hostname || '').toLowerCase();
        const vendor = (device.vendor || '').toLowerCase();
        const deviceType = (device.device_type || '').toLowerCase();
        
        return ip.includes(searchTerm) || 
               alias.includes(searchTerm) || 
               hostname.includes(searchTerm) || 
               vendor.includes(searchTerm) || 
               deviceType.includes(searchTerm);
    });
    
    // Filtrelenmiş sonuçları göster
    if (filteredDevices.length > 0) {
        let html = '';
        filteredDevices.forEach(device => {
            const isOnline = device.status === 'online';
            const statusIcon = isOnline ? '🟢' : '🔴';
            const statusText = isOnline ? 'Çevrimiçi' : 'Çevrimdışı';
            
            html += `
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.ip}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.alias || device.hostname || '-'}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${getTranslatedDeviceType(device.device_type)}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.vendor || '-'}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${statusIcon} ${statusText}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">
                        <button class="btn btn-primary" onclick="editDeviceFromManagement('${device.ip}')" title="Düzenle" style="margin-right: 5px; padding: 4px 8px; font-size: 12px;">
                            ✏️
                        </button>
                        <button class="btn btn-danger" onclick="confirmDeleteDevice('${device.ip}')" title="Sil" style="padding: 4px 8px; font-size: 12px;">
                            🗑️
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
    } else {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">🔍 Arama kriterlerine uygun cihaz bulunamadı.</td></tr>';
    }
}

// Edit butonuna tıklandığında mevcut edit modal'ını aç
function editDeviceFromManagement(ip) {
    const device = devices.find(d => d.ip === ip);
    if (!device) {
        showToast(t('device_not_found'), 'error');
        return;
    }
    
    // Cihaz yönetimi modal'ını kapat
    closeDeviceManagementModal();
    
    // Ana sayfa edit modal'ını aç (main.js'deki mevcut editDevice fonksiyonunu kullan)
    editDevice(ip);
}

function confirmDeleteDevice(ip) {
    const device = devices.find(d => d.ip === ip);
    const deviceName = device ? (device.alias || device.hostname || ip) : ip;
    
    if (confirm(`"${deviceName}" ${t('confirm_delete_device')}`)) {
        deleteDevice(ip);
    }
}

async function deleteDevice(ip) {
    try {
        const response = await fetch(`/delete_device/${ip}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast(t('device_deleted_success'), 'success');
            // Ana listede güncelleme yap
            await loadDevices(true);
            // Yönetim listesini güncelle
            loadDevicesForManagement();
        } else {
            showToast(t('device_delete_error') + ': ' + result.message, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

// Aktif analiz işlemlerini restore et
async function restoreActiveAnalyses() {
    try {
        const response = await fetch('/get_active_analyses');
        const activeAnalyses = await response.json();
        
        if (response.ok && Object.keys(activeAnalyses).length > 0) {
            console.log('Aktif analiz işlemleri tespit edildi, restore ediliyor:', activeAnalyses);
            
            for (const [sessionKey, analysisInfo] of Object.entries(activeAnalyses)) {
                if (analysisInfo.type === 'single') {
                    // Tek cihaz analizi restore et
                    await restoreSingleDeviceAnalysis(sessionKey, analysisInfo);
                } else if (analysisInfo.type === 'bulk') {
                    // Toplu analiz restore et
                    await restoreBulkAnalysis(analysisInfo);
                }
            }
            
            showToast(t('active_analysis_restored'), 'info');
        }
    } catch (error) {
        console.error('Aktif analiz restore hatası:', error);
    }
}

// Tek cihaz analizini restore et
async function restoreSingleDeviceAnalysis(ip, analysisInfo) {
    // device-access.js yüklü mü kontrol et
    if (typeof showUnifiedAnalysisModal !== 'function') {
        console.warn('device-access.js yüklenmemiş, analiz restore edilemiyor');
        return;
    }
    
    // Modal'ı oluştur ve minimize et
    showUnifiedAnalysisModal(ip, 'single');
    
    // Kısa bir bekleme sonrası minimize et
    setTimeout(() => {
        if (typeof minimizeAnalysisModal === 'function') {
            minimizeAnalysisModal(ip);
            
            // Toaster'da progress göster
            if (typeof updateToasterProgress === 'function') {
                const progress = analysisInfo.progress || 0;
                const message = analysisInfo.message || 'Analiz devam ediyor...';
                updateToasterProgress(ip, progress, message);
            }
            
            // Monitoring'i yeniden başlat
            if (typeof monitorSingleDeviceAnalysis === 'function') {
                monitorSingleDeviceAnalysis(ip);
            }
        }
    }, 500);
}

// Toplu analizi restore et
async function restoreBulkAnalysis(analysisInfo) {
    // device-access.js yüklü mü kontrol et
    if (typeof showUnifiedAnalysisModal !== 'function') {
        console.warn('device-access.js yüklenmemiş, bulk analiz restore edilemiyor');
        return;
    }
    
    // Modal'ı oluştur ve minimize et
    showUnifiedAnalysisModal(null, 'bulk');
    
    // Kısa bir bekleme sonrası minimize et
    setTimeout(() => {
        if (typeof minimizeAnalysisModal === 'function') {
            minimizeAnalysisModal('bulk');
            
            // Toaster'da progress göster
            if (typeof updateToasterProgress === 'function') {
                const progress = analysisInfo.progress || 0;
                const message = analysisInfo.message || 'Toplu analiz devam ediyor...';
                updateToasterProgress('bulk', progress, message);
            }
            
            // Monitoring'i yeniden başlat
            if (typeof monitorBulkAnalysis === 'function') {
                monitorBulkAnalysis();
            }
        }
    }, 500);
}

// Enhanced Edit Modal Functions
let currentEnhancedEditingIp = null;

/* Deep link from the availability page: /?device=<ip|mac> opens that device's
   edit popup (or the details modal for a radio device with no IP). */
function openDeviceFromQuery() {
    const raw = new URLSearchParams(window.location.search).get('device');
    if (!raw) return;
    const want = decodeURIComponent(raw).toLowerCase();
    const dev = devices.find(d =>
        (d.ip && d.ip.toLowerCase() === want) || (d.mac && d.mac.toLowerCase() === want));
    // Clean the URL so a refresh doesn't keep reopening the modal.
    try { history.replaceState({}, '', window.location.pathname); } catch (_) { /* ignore */ }
    if (!dev) return;
    if (dev.ip) openEnhancedEditModal(dev.ip);
    else if (typeof openEnhancedDetailsModal === 'function') openEnhancedDetailsModal(dev);
}

// A device's edit key is its IP, or its MAC when it has no IP - Bluetooth and
// other radio-only discovery devices are keyed by MAC alone. Look one up by
// either, so the edit modal works for both.
function deviceByKey(key) {
    if (!key) return null;
    const k = String(key).toLowerCase();
    return devices.find(d => (d.ip && d.ip === key) ||
                             (d.mac && d.mac.toLowerCase() === k)) || null;
}

function openEnhancedEditModal(ip) {
    const device = deviceByKey(ip);
    if (!device) {
        showToast(t('device_not_found'), 'error');
        return;
    }

    // Key by MAC for IP-less (Bluetooth/radio) devices, else by IP.
    currentEnhancedEditingIp = device.ip || device.mac;

    // Title always names the device (alias/hostname/mac + IP), not a generic
    // "Advanced Device Edit" - you always know which device you're editing.
    const titleEl = document.getElementById('enhancedEditTitle');
    if (titleEl) {
        const label = device.alias || device.hostname || device.mac || device.ip || t('advanced_device_edit');
        const ipPart = device.ip ? ` · ${device.ip}` : '';
        titleEl.textContent = `${label}${ipPart}`;
    }

    // Load device data to all tabs
    loadDeviceToEnhancedModal(device);
    loadUplinkField(device);

    // "Identify with AI" header action: only for devices that have NOT been
    // AI-identified yet - once a result exists it lives in the Details modal's
    // AI tab, so the shortcut here would be redundant.
    const aiBtn = document.getElementById('enhancedEditAiBtn');
    if (aiBtn) {
        const identified = typeof getAiIdentification === 'function' && getAiIdentification(device, null);
        aiBtn.style.display = (device.ip && !identified) ? '' : 'none';
    }

    // Radio-only discovery devices (Bluetooth/Zigbee - no IP) can be given an
    // alias/name and have logs, but ports/access/tools/security all need an IP
    // to probe. Hide those tabs (and the uplink field) so the modal only offers
    // what actually works for them.
    applyEditTabVisibility(device);

    // Show modal
    document.getElementById('enhancedEditModal').style.display = 'block';

    // Switch to first tab
    switchEditTab('device');
}

// Tabs that need a reachable IP; hidden for IP-less discovery devices.
const IP_ONLY_EDIT_TABS = ['ports', 'access', 'tools', 'security'];

function applyEditTabVisibility(device) {
    const ipLess = !device.ip;
    document.querySelectorAll('#enhancedEditModal .tab-button[data-tab]').forEach(btn => {
        const hide = ipLess && IP_ONLY_EDIT_TABS.includes(btn.dataset.tab);
        btn.style.display = hide ? 'none' : '';
    });
    const uplink = document.getElementById('enhancedEditUplinkGroup');
    if (uplink) uplink.style.display = ipLess ? 'none' : '';
}

/*
 * "Connected via" - the same manual uplink the topology view sets, offered
 * here too because this is where people already come to correct a device. A
 * bridged switch is invisible at layer 3, so this is the only way to record it.
 */
async function loadUplinkField(device) {
    const select = document.getElementById('enhancedEditUplink');
    if (!select) return;

    const others = devices.filter(d => d.ip && d.ip !== device.ip);
    const infraRe = /router|switch|access point|extender|repeater|modem|gateway/i;
    const isInfra = d => infraRe.test(d.device_type || '') || d.ip.endsWith('.1');
    const option = d => `<option value="${d.ip}">${getDeviceIcon(d.device_type)} ${d.alias || d.hostname || d.ip} — ${d.ip}</option>`;

    select.innerHTML = `<option value="">${t('uplink_auto')}</option>`
        + `<optgroup label="${t('network_gear')}">${others.filter(isInfra).map(option).join('')}</optgroup>`
        + `<optgroup label="${t('other_devices')}">${others.filter(d => !isInfra(d)).map(option).join('')}</optgroup>`;

    try {
        const topo = await (await fetch('/api/topology')).json();
        select.value = (topo.uplinks || {})[device.ip] || '';
    } catch (_) {
        select.value = '';
    }
    select._ds?.refresh();
}

function closeEnhancedEditModal() {
    document.getElementById('enhancedEditModal').style.display = 'none';
    currentEnhancedEditingIp = null;
}

/*
 * Logs tab: everything we already know about this one device, assembled - no new
 * logging. Availability + last-scan facts come from the uptime series and the
 * device record; the activity timeline is this device's slice of the alert
 * history (online/offline, IP/MAC change, ports opening/closing, battery, ...).
 * Alerts can carry attacker-chosen text (a hostname), so everything is escaped.
 */
const LOG_RULE_LABELS = {
    new_device: 'New device', device_online: 'Came online', device_offline: 'Went offline',
    ip_changed: 'IP changed', mac_changed: 'MAC changed', new_port: 'Port opened',
    port_closed: 'Port closed', high_latency: 'High latency', low_battery: 'Low battery',
    low_voltage: 'Low voltage', weak_signal: 'Weak signal', risky_port: 'Risky port open',
};

// Match a device to its entry in a uptime/alerts list by identity (MAC first,
// then IP) - the same key the backend uses.
function _sameDevice(x, device) {
    const ident = (device.mac || device.ip || '').toLowerCase();
    return (x.device_id || x.id || '').toLowerCase() === ident ||
        (device.ip && x.ip === device.ip) ||
        (device.mac && (x.mac || '').toLowerCase() === device.mac.toLowerCase());
}

/*
 * Device tab footer: a traffic-light online/offline light, the last ~20 checks
 * as green/red cells (same idea as the availability strip), and the scan facts.
 * Open ports are deliberately omitted - the Ports tab already owns those.
 */
async function loadDeviceStatus() {
    const box = document.getElementById('deviceStatusFooter');
    if (!box) return;
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) { box.innerHTML = ''; return; }

    const uptime = await fetch('/api/monitoring/uptime?limit=48').then(r => r.json()).catch(() => ({ devices: [] }));
    const u = (uptime.devices || []).find(x => _sameDevice(x, device));

    const online = device.status === 'online';
    const light = `<span class="device-status__light ${online ? 'is-online' : 'is-offline'}"></span>
        <span class="device-status__state">${online ? (t('online') || 'Online') : (t('offline') || 'Offline')}</span>`;

    const cells = u ? u.cells.slice(-20).map(s =>
        `<i class="device-status__cell is-${s || 'none'}"></i>`).join('') : '';

    const a = device.analysis_data || {};
    const fmt = ts => ts ? new Date(ts).toLocaleString() : '—';
    const facts = [
        [t('availability') || 'Availability', u ? `${u.uptime}% · ${u.incidents} ${t('incidents') || 'incidents'} · ${u.checks} ${t('checks') || 'checks'}` : '—'],
        [t('last_seen') || 'Last seen', fmt(device.last_seen)],
        [t('last_scan') || 'Last scan', fmt(a.last_normal_scan)],
        [t('last_deep_analysis') || 'Last deep analysis', fmt(a.last_enhanced_analysis)],
    ];

    box.innerHTML = `
        <div class="device-status__row">
            <span class="device-status__badge">${light}</span>
            <span class="device-status__strip">${cells}</span>
        </div>
        <div class="device-logs__facts">
            ${facts.map(([k, v]) => `<div class="device-logs__fact"><dt>${escHtml(k)}</dt><dd>${escHtml(v)}</dd></div>`).join('')}
        </div>`;
}

// Logs tab: just this device's activity timeline (alert history), newest first.
async function loadLogsTab() {
    const box = document.getElementById('deviceLogsResult');
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) { box.innerHTML = `<p class="details-no-data">${t('no_data')}</p>`; return; }
    box.innerHTML = `<p class="details-no-data">${t('loading')}</p>`;

    const alertsRes = await fetch('/api/alerts?limit=500').then(r => r.json()).catch(() => ({ alerts: [] }));
    const fmt = ts => ts ? new Date(ts).toLocaleString() : '—';
    const mine = (alertsRes.alerts || []).filter(al => _sameDevice(al, device));

    // The alert history is only half the story: a device that was scanned or
    // deep-analysed but never triggered an alert would show "no events". Fold in
    // the device's own analysis timestamps so the timeline reflects what ran.
    const a = device.analysis_data || {};
    const ai = (device.enhanced_comprehensive_info || {}).ai_identification ||
               (a.enhanced_analysis_info || {}).ai_identification;
    const aiMeta = ai && ai._meta ? [ai._meta.provider, ai._meta.model].filter(Boolean).join(' · ') : '';
    const activity = [
        { timestamp: a.last_normal_scan, severity: 'info', rule: 'scan',
          message: t('log_normal_scan') || 'Normal scan' },
        { timestamp: a.last_enhanced_analysis || device.last_enhanced_analysis, severity: 'info', rule: 'deep',
          message: t('log_deep_analysis') || 'Detailed analysis' },
        ai ? { timestamp: a.last_enhanced_analysis || device.last_enhanced_analysis, severity: 'info', rule: 'ai',
               message: (t('log_ai_identify') || 'AI identification') + (aiMeta ? ` — ${aiMeta}` : '') } : null,
    ].filter(e => e && e.timestamp);

    const events = [...mine, ...activity].sort((x, y) =>
        new Date(y.timestamp || 0) - new Date(x.timestamp || 0));

    const sev = s => ({ critical: 'is-down', warning: 'is-degraded', info: '' }[s] || '');
    const timeline = events.length ? events.map(al => `
        <div class="device-logs__event">
            <span class="device-logs__dot ${sev(al.severity)}"></span>
            <span class="device-logs__time">${escHtml(fmt(al.timestamp))}</span>
            <span class="device-logs__rule">${escHtml(LOG_RULE_LABELS[al.rule] || al.rule || '')}</span>
            <span class="device-logs__msg">${escHtml(al.message || al.title || '')}</span>
        </div>`).join('') : `<p class="details-no-data">${t('no_events') || 'No recorded events for this device yet.'}</p>`;

    // Scan-vs-your-edits: fields the user set by hand where a later scan saw a
    // different value. The edit always wins; this is the stored breadcrumb of
    // what the scan found, shown as raw JSON so nothing is hidden. See
    // models.merge_device_data (scan_log).
    const scanLog = device.scan_log || [];
    const overrides = scanLog.length ? `
        <h4 class="device-logs__heading">${t('scan_vs_edits') || 'Scan vs. your edits'}</h4>
        <pre class="device-logs__json">${escHtml(JSON.stringify(scanLog, null, 2))}</pre>` : '';

    box.innerHTML = `
        <h4 class="device-logs__heading">${t('activity_log') || 'Activity log'}</h4>
        <div class="device-logs__timeline">${timeline}</div>
        ${overrides}`;
}

/*
 * Network Tools tab: on-demand ping/traceroute/DNS/port-probe for whichever
 * device is open in the edit modal - see core/diagnostics.py and
 * /api/diagnostics/<ip>/*. A DNS/traceroute answer can contain attacker-
 * chosen text (a malicious PTR record, a hop's rDNS), so everything here is
 * escaped before it reaches innerHTML.
 */
function escHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function runDeviceDiagnostic(tool) {
    if (!currentEnhancedEditingIp) return;
    const box = document.getElementById('netToolsResult');
    box.innerHTML = `<p class="details-no-data">${t('tool_running')}</p>`;
    try {
        const res = await fetch(`/api/diagnostics/${encodeURIComponent(currentEnhancedEditingIp)}/${tool}`);
        box.innerHTML = renderDiagnosticResult(tool, await res.json());
    } catch (error) {
        box.innerHTML = `<p class="details-no-data">${t('tool_error')}: ${escHtml(error)}</p>`;
    }
}

async function runDevicePortProbe() {
    if (!currentEnhancedEditingIp) return;
    const box = document.getElementById('netToolsResult');
    const portsEl = document.getElementById('netToolsPortsInput');
    const ports = ((portsEl.value || portsEl.placeholder || '')
        .split(',').map(s => s.trim()).filter(Boolean));
    if (!ports.length) { showToast(t('tool_port_probe_ports'), 'error'); return; }

    box.innerHTML = `<p class="details-no-data">${t('tool_running')}</p>`;
    try {
        const res = await fetch(`/api/diagnostics/${encodeURIComponent(currentEnhancedEditingIp)}/ports`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ports }),
        });
        box.innerHTML = renderDiagnosticResult('ports', await res.json());
    } catch (error) {
        box.innerHTML = `<p class="details-no-data">${t('tool_error')}: ${escHtml(error)}</p>`;
    }
}

async function runDeviceWakeOnLan() {
    if (!currentEnhancedEditingIp) return;
    const device = deviceByKey(currentEnhancedEditingIp);
    const mac = device && device.mac;
    const box = document.getElementById('netToolsResult');
    if (!mac || mac === 'N/A') {
        box.innerHTML = `<p class="details-no-data">${t('wol_no_mac')}</p>`;
        return;
    }
    box.innerHTML = `<p class="details-no-data">${t('tool_running')}</p>`;
    try {
        const res = await fetch(`/api/diagnostics/${encodeURIComponent(currentEnhancedEditingIp)}/wol`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac }),
        });
        const data = await res.json();
        if (data.success) {
            box.innerHTML = `<div class="net-tools__summary"><span class="ds-badge ds-badge--success">✓</span> ${t('wol_sent', { mac })}</div>`;
            showToast(t('wol_sent', { mac }), 'success');
        } else {
            box.innerHTML = `<div class="net-tools__summary net-tools__summary--fail">${t('tool_error')}${data.error ? ': ' + escHtml(data.error) : ''}</div>`;
        }
    } catch (error) {
        box.innerHTML = `<p class="details-no-data">${t('tool_error')}: ${escHtml(error)}</p>`;
    }
}

// Delete the device being edited, from the modal footer. Reuses the existing
// deleteDevice() + /delete_device endpoint; just adds the confirm + modal close.
function deleteDeviceFromEditModal() {
    if (!currentEnhancedEditingIp) return;
    const device = deviceByKey(currentEnhancedEditingIp);
    const name = (device && (device.alias || device.hostname || device.ip || device.mac)) || currentEnhancedEditingIp;
    if (!confirm(`"${name}" ${t('confirm_delete_device')}`)) return;
    const key = currentEnhancedEditingIp;
    closeEnhancedEditModal();
    deleteDevice(key);
}

function renderDiagnosticResult(tool, data) {
    if (tool === 'ping') {
        if (!data.success) {
            return `<div class="net-tools__summary net-tools__summary--fail">${t('tool_ping_failed')}${data.error ? ': ' + escHtml(data.error) : ''}</div>`;
        }
        return `<div class="net-tools__summary">
            <span class="ds-badge ds-badge--success">${data.received}/${data.sent} ${t('tool_ping_received')}</span>
            <span>${t('tool_loss')}: ${data.loss_pct}%</span>
            ${data.avg_ms != null ? `<span>${t('tool_avg')}: ${data.avg_ms} ms</span>` : ''}
            ${data.ttl != null ? `<span>TTL: ${data.ttl}</span>` : ''}
        </div>`;
    }
    if (tool === 'traceroute') {
        if (!data.hop_count) {
            return `<div class="net-tools__summary net-tools__summary--fail">${t('tool_traceroute_failed')}${data.error ? ': ' + escHtml(data.error) : ''}</div>`;
        }
        const rows = data.hops.map(h => `<tr>
            <td>${h.hop}</td>
            <td>${h.timed_out ? '*' : escHtml(h.ip || '?')}</td>
            <td>${h.rtt_ms != null ? h.rtt_ms + ' ms' : '-'}</td>
        </tr>`).join('');
        return `<table class="ds-table"><thead><tr><th>#</th><th>IP</th><th>RTT</th></tr></thead><tbody>${rows}</tbody></table>`;
    }
    if (tool === 'dns') {
        if (!data.success) {
            // No PTR record is a normal state for most LAN devices, not a tool
            // failure - show it as a neutral note so it does not read as broken.
            return `<div class="net-tools__summary">${t('tool_dns_failed')}</div>`;
        }
        const aliases = (data.aliases || []).filter(a => a && a !== data.hostname);
        return `<div class="net-tools__summary"><strong>${escHtml(data.hostname)}</strong>${aliases.length ? '<br>' + escHtml(aliases.join(', ')) : ''}</div>`;
    }
    if (tool === 'ports') {
        if (!data.checked || !data.checked.length) return `<p class="details-no-data">${t('tool_port_probe_ports')}</p>`;
        const open = new Set(data.open || []);
        const chips = data.checked.map(p =>
            `<span class="ds-badge ${open.has(p) ? 'ds-badge--success' : 'ds-badge--info'}">${p} ${open.has(p) ? '✓' : '✕'}</span>`
        ).join(' ');
        return `<div class="net-tools__summary">${chips}</div>`;
    }
    return `<pre>${escHtml(JSON.stringify(data, null, 2))}</pre>`;
}

/*
 * Security tab: curated CVE-pattern matching + attack-surface risk scoring
 * against the device's already-known fingerprint (services/banners) - see
 * security/cve.py and /api/security/vulnerabilities/<ip>. Pattern matches
 * against open-source vulnerability databases, not a live feed.
 */
async function runDeviceVulnScan() {
    const box = document.getElementById('securityScanResult');
    // A radio device (no IP) can't be assessed - the assessment keys off the
    // fingerprint an IP scan collected. Say so instead of fetching an empty IP,
    // which would hit Flask's HTML 404 and blow up JSON.parse().
    if (!currentEnhancedEditingIp) {
        box.innerHTML = `<p class="details-no-data">${t('security_no_ip')}</p>`;
        return;
    }
    box.innerHTML = `<p class="details-no-data">${t('tool_running')}</p>`;
    try {
        const res = await fetch(`/api/security/vulnerabilities/${encodeURIComponent(currentEnhancedEditingIp)}`);
        // Never JSON.parse an error page: surface the server's message cleanly.
        if (!res.ok) {
            let msg = t('tool_error');
            try { const j = await res.json(); if (j && j.error) msg += ': ' + j.error; }
            catch (_) { msg += ` (HTTP ${res.status})`; }
            box.innerHTML = `<p class="details-no-data">${escHtml(msg)}</p>`;
            return;
        }
        box.innerHTML = renderVulnScanResult(await res.json());
    } catch (error) {
        box.innerHTML = `<p class="details-no-data">${t('tool_error')}: ${escHtml(error)}</p>`;
    }
}

function renderVulnScanResult(data) {
    const riskClass = { critical: 'ds-badge--critical', high: 'ds-badge--critical',
                        medium: 'ds-badge--warning', low: 'ds-badge--info',
                        none: 'ds-badge--success' }[data.risk_level] || 'ds-badge--info';
    const header = `<div class="net-tools__summary">
        <span class="ds-badge ${riskClass}">${t('security_risk_' + (data.risk_level || 'none'))}</span>
        <span>${t('security_score')}: ${data.risk_score ?? 0}/100</span>
    </div>`;

    const findingRows = (data.findings || []).map(f => `
        <div class="ds-disclosure">
            <details>
                <summary>
                    <span class="ds-badge ${riskClass2(f.severity)}">${escHtml((f.severity || '').toUpperCase())}</span>
                    ${escHtml(f.title)}
                    ${f.cve_id ? `<code>${escHtml(f.cve_id)}</code>` : ''}
                </summary>
                <p>${escHtml(f.description)}</p>
                ${f.reference ? `<a href="${escHtml(f.reference)}" target="_blank" rel="noopener noreferrer">${escHtml(f.reference)}</a>` : ''}
            </details>
        </div>`).join('');

    const exposureRows = (data.exposures || []).map(e => `
        <div class="ds-disclosure">
            <details>
                <summary>
                    <span class="ds-badge ${riskClass2(e.severity)}">${escHtml((e.severity || '').toUpperCase())}</span>
                    ${escHtml(e.title)}
                </summary>
                <p>${escHtml(e.description)}</p>
            </details>
        </div>`).join('');

    if (!findingRows && !exposureRows) {
        return header + `<p class="details-no-data">${t('security_no_findings')}</p>`;
    }
    return header + findingRows + exposureRows;
}

function riskClass2(severity) {
    return { critical: 'ds-badge--critical', high: 'ds-badge--critical',
            medium: 'ds-badge--warning', low: 'ds-badge--info' }[severity] || 'ds-badge--info';
}

function switchEditTab(tabName) {
    // Hide all tab panes
    const tabPanes = document.querySelectorAll('.tab-pane');
    tabPanes.forEach(pane => pane.classList.remove('active'));
    
    // Remove active class from all buttons
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => button.classList.remove('active'));
    
    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Activate selected button - find button by onclick attribute
    const activeButton = document.querySelector(`[onclick*="switchEditTab('${tabName}')"]`);
    if (activeButton) {
        activeButton.classList.add('active');
    }
    
    // Load tab-specific data
    if (tabName === 'device') {
        loadDeviceStatus();
    } else if (tabName === 'ports') {
        loadPortsTab();
    } else if (tabName === 'access') {
        loadAccessTab();
    } else if (tabName === 'logs') {
        loadLogsTab();
    } else if (tabName === 'raw') {
        loadRawJsonTab();
    }
}

/*
 * Raw JSON tab: the whole device record from lan_devices.json, editable. On
 * save we diff against the original and send only the CHANGED top-level keys to
 * /update_device, so update_device records exactly those as user-owned (never
 * the untouched analysis_data/ports). Diff-and-update also means a field the
 * editor doesn't show (e.g. encrypted_credentials) can never be dropped.
 */
let _rawJsonOriginal = null;

function loadRawJsonTab() {
    const device = deviceByKey(currentEnhancedEditingIp);
    const editor = document.getElementById('rawJsonEditor');
    const err = document.getElementById('rawJsonError');
    if (!device || !editor) return;
    err.textContent = '';
    // Hide the encrypted-credentials blob - it's an opaque secret, not something
    // to hand-edit. Omitting it also means the diff-save never touches it.
    const { encrypted_credentials, ...shown } = device;
    _rawJsonOriginal = shown;
    editor.value = JSON.stringify(shown, null, 2);
    syncRawJsonHl();
}

// Overlay-editör senkronu: textarea içeriğini renklendirip arkadaki <pre>'ye bas
// ve kaydırmayı hizala. mynesHighlightJson enhanced-details.js'te tanımlı.
function syncRawJsonHl() {
    const ta = document.getElementById('rawJsonEditor');
    const code = document.getElementById('rawJsonHl');
    if (!ta || !code || typeof mynesHighlightJson !== 'function') return;
    code.innerHTML = mynesHighlightJson(ta.value) + '\n';
    syncRawJsonScroll();
}
function syncRawJsonScroll() {
    const ta = document.getElementById('rawJsonEditor');
    const pre = ta && ta.parentElement.querySelector('.code-editor__hl');
    if (pre) { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; }
}

// Editör içeriğini .json dosyası olarak indir (mynesDownloadJson enhanced-details.js'te).
function downloadRawJson() {
    const editor = document.getElementById('rawJsonEditor');
    if (!editor) return;
    const name = `mynes-${(currentEnhancedEditingIp || 'device')}.json`;
    if (typeof mynesDownloadJson === 'function') mynesDownloadJson(editor.value, name);
}

async function saveRawJson() {
    const editor = document.getElementById('rawJsonEditor');
    const err = document.getElementById('rawJsonError');
    if (!editor || !currentEnhancedEditingIp) return;
    err.textContent = '';

    let edited;
    try {
        edited = JSON.parse(editor.value);
    } catch (e) {
        err.textContent = (t('invalid_json') || 'Invalid JSON') + ': ' + e.message;
        return;
    }
    if (!edited || typeof edited !== 'object' || Array.isArray(edited)) {
        err.textContent = t('invalid_json') || 'Invalid JSON';
        return;
    }

    // Only send keys whose value actually changed (compared structurally).
    const orig = _rawJsonOriginal || {};
    const changed = {};
    for (const [k, v] of Object.entries(edited)) {
        if (JSON.stringify(v) !== JSON.stringify(orig[k])) changed[k] = v;
    }
    if (Object.keys(changed).length === 0) {
        showToast(t('no_changes') || 'No changes', 'info');
        return;
    }

    try {
        const res = await fetch(`/update_device/${currentEnhancedEditingIp}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(changed),
        });
        const result = await res.json().catch(() => ({}));
        if (res.ok) {
            showToast(t('device_updated_success'), 'success');
            closeEnhancedEditModal();
            await loadDevices();
        } else {
            err.textContent = (t('update_error') || 'Update error') + ': ' + (result.error || res.status);
        }
    } catch (e) {
        err.textContent = (t('connection_error') || 'Connection error') + ': ' + e.message;
    }
}

function loadDeviceToEnhancedModal(device) {
    // Load device tab data
    document.getElementById('enhancedEditIpAddress').value = device.ip || '';
    document.getElementById('enhancedEditMacAddress').value = device.mac || '';
    document.getElementById('enhancedEditAlias').value = device.alias || '';
    document.getElementById('enhancedEditHostname').value = device.hostname || '';
    document.getElementById('enhancedEditVendor').value = device.vendor || '';
    document.getElementById('enhancedEditNotes').value = device.notes || '';
    const trustEl = document.getElementById('enhancedEditTrust');
    if (trustEl) { trustEl.value = device.trust_status || 'unknown'; trustEl._ds?.refresh(); }
    const locEl = document.getElementById('enhancedEditLocation');
    if (locEl) locEl.value = device.location || '';
    
    // Load device types to dropdown first, then set selected value
    loadDeviceTypesToEnhancedModal().then(() => {
        const sel = document.getElementById('enhancedEditDeviceType');
        sel.value = device.device_type || '';
        sel._ds?.refresh();
    });
}

async function loadDeviceTypesToEnhancedModal() {
    try {
        const response = await fetch('/api/device-types/translated');
        const types = await response.json();
        
        const select = document.getElementById('enhancedEditDeviceType');
        select.innerHTML = `<option value="">${t('select_device_type')}</option>`;
        
        Object.keys(types)
            .sort((a, b) => (types[a].name || a).localeCompare(types[b].name || b))
            .forEach(type => {
                const option = document.createElement('option');
                option.value = type;
                const icon = types[type].icon || '📱';
                const translatedName = types[type].name || type;
                option.textContent = `${icon} ${translatedName}`;
                select.appendChild(option);
            });
    } catch (error) {
        console.error('Device types yüklenemedi:', error);
    }
}

function loadPortsTab() {
    if (!currentEnhancedEditingIp) return;
    
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    const tableBody = document.getElementById('portsTableBody');
    tableBody.innerHTML = '';
    
    if (device.open_ports && device.open_ports.length > 0) {
        // Sort ports by port number
        const sortedPorts = [...device.open_ports].sort((a, b) => a.port - b.port);
        
        sortedPorts.forEach(port => {
            const row = createPortTableRow(port);
            tableBody.appendChild(row);
        });
    } else {
        tableBody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted" style="padding: 30px;">
                    Henüz port bulunamadı. "➕ Yeni Port Ekle" ile port ekleyebilirsiniz.
                </td>
            </tr>
        `;
    }
}

function createPortTableRow(port) {
    const row = document.createElement('tr');
    const isManual = port.manual || false;
    
    row.innerHTML = `
        <td>
            <span class="port-number">${port.port}</span>
        </td>
        <td>
            ${isManual ? 
                `<input type="text" class="editable-field" value="${port.service || ''}" onchange="updatePortField(${port.port}, 'service', this.value)">` :
                `${port.service || 'Bilinmeyen'}`
            }
        </td>
        <td>
            ${isManual ? 
                `<input type="text" class="editable-field" value="${port.description || ''}" onchange="updatePortField(${port.port}, 'description', this.value)">` :
                `${port.description || port.version || '-'}`
            }
        </td>
        <td>
            <span class="port-type ${isManual ? 'manual' : 'auto'}">
                ${isManual ? 'Manuel' : 'Otomatik'}
            </span>
        </td>
        <td>
            <div class="port-actions">
                ${isManual ? `
                    <button class="port-btn delete" onclick="deletePortFromTable(${port.port})" title="Sil">🗑️</button>
                ` : `
                    <button class="port-btn convert" onclick="convertToManualInTable(${port.port})" title="Manuel Moda Geçir">📝</button>
                `}
            </div>
        </td>
    `;
    return row;
}

function addNewPortInline() {
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    const tableBody = document.getElementById('portsTableBody');
    
    // Remove empty message if exists
    const emptyRow = tableBody.querySelector('td[colspan="5"]');
    if (emptyRow) {
        emptyRow.parentElement.remove();
    }
    
    // Create new row for editing
    const newRow = document.createElement('tr');
    newRow.style.background = '#fff3cd';
    newRow.innerHTML = `
        <td>
            <input type="number" class="editable-field" placeholder="Port No" min="1" max="65535" id="newPortNumber" required>
        </td>
        <td>
            <input type="text" class="editable-field" placeholder="Servis adı" id="newPortService">
        </td>
        <td>
            <input type="text" class="editable-field" placeholder="Açıklama" id="newPortDescription">
        </td>
        <td>
            <span class="port-type manual">Manuel</span>
        </td>
        <td>
            <div class="port-actions">
                <button class="port-btn edit" onclick="saveNewPort()" title="Kaydet">💾</button>
                <button class="port-btn delete" onclick="cancelNewPort()" title="İptal">❌</button>
            </div>
        </td>
    `;
    
    tableBody.appendChild(newRow);
    document.getElementById('newPortNumber').focus();
}

function saveNewPort() {
    const portNumber = document.getElementById('newPortNumber').value;
    const portService = document.getElementById('newPortService').value;
    const portDescription = document.getElementById('newPortDescription').value;
    
    if (!portNumber || isNaN(portNumber) || portNumber < 1 || portNumber > 65535) {
        showToast(t('invalid_port_number'), 'error');
        return;
    }
    
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    if (!device.open_ports) device.open_ports = [];
    
    // Check if port already exists
    if (device.open_ports.some(p => p.port == portNumber)) {
        showToast(t('port_already_exists'), 'error');
        return;
    }
    
    device.open_ports.push({
        port: parseInt(portNumber),
        service: portService,
        description: portDescription,
        state: 'open',
        manual: true,
        last_verified: new Date().toISOString()
    });
    
    loadPortsTab();
    showToast(t('port_added_success'), 'success');
}

function cancelNewPort() {
    loadPortsTab(); // Reload to remove the editing row
}

function updatePortField(portNumber, field, value) {
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    const port = device.open_ports.find(p => p.port == portNumber);
    if (!port) return;
    
    port[field] = value;
    showToast(t('port_updated_success'), 'success');
}

function deletePortFromTable(portNumber) {
    if (!confirm(t('confirm_delete_port'))) return;
    
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    device.open_ports = device.open_ports.filter(p => p.port != portNumber);
    
    loadPortsTab();
    showToast(t('port_deleted_success'), 'success');
}

function convertToManualInTable(portNumber) {
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    const port = device.open_ports.find(p => p.port == portNumber);
    if (!port) return;
    
    port.manual = true;
    loadPortsTab();
    showToast(t('port_manual_mode'), 'success');
}

function editPort(portNumber) {
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    const port = device.open_ports.find(p => p.port == portNumber);
    if (!port) return;
    
    const newService = prompt('Servis adı:', port.service || '') || '';
    const newDescription = prompt('Açıklama:', port.description || '') || '';
    
    port.service = newService;
    port.description = newDescription;
    
    loadPortsTab();
    showToast(t('port_updated_success'), 'success');
}

function deletePort(portNumber) {
    if (!confirm(t('confirm_delete_port'))) return;
    
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    device.open_ports = device.open_ports.filter(p => p.port != portNumber);
    
    loadPortsTab();
    showToast(t('port_deleted_success'), 'success');
}

function convertToManual(portNumber) {
    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;
    
    const port = device.open_ports.find(p => p.port == portNumber);
    if (!port) return;
    
    port.manual = true;
    loadPortsTab();
    showToast(t('port_manual_mode'), 'success');
}

function refreshDetectedPorts() {
    showToast(t('port_scan_starting'), 'info');
    // This would trigger a port scan for the specific device
    // Implementation depends on backend API
}

function loadAccessTab() {
    // Load existing access credentials
    updateEnhancedAccessForm();
    loadExistingAccessCredentials();
}

async function loadExistingAccessCredentials() {
    if (!currentEnhancedEditingIp) return;
    
    try {
        const accessType = document.getElementById('enhancedAccessType').value || 'ssh';
        const response = await fetch(`/get_device_credentials/${currentEnhancedEditingIp}?access_type=${accessType}`);
        if (response.ok) {
            const credentials = await response.json();
            if (credentials && Object.keys(credentials).length > 0) {
                document.getElementById('enhancedAccessType').value = accessType;
                document.getElementById('enhancedAccessPort').value = credentials.port || '';
                document.getElementById('enhancedAccessUsername').value = credentials.username || '';
                document.getElementById('enhancedAccessPassword').value = credentials.password || '';
                document.getElementById('enhancedAccessNotes').value = credentials.additional_info?.notes || '';
                // Don't call updateEnhancedAccessForm() here to avoid recursion
                updateEnhancedAccessHints();
            } else {
                // Clear fields if no credentials found
                clearAccessFields();
            }
        } else {
            // Clear fields if request failed
            clearAccessFields();
        }
    } catch (error) {
        console.log('Mevcut erişim bilgileri yüklenemedi:', error);
        clearAccessFields();
    }
}

function clearAccessFields() {
    document.getElementById('enhancedAccessPort').value = '';
    document.getElementById('enhancedAccessUsername').value = '';
    document.getElementById('enhancedAccessPassword').value = '';
    document.getElementById('enhancedAccessNotes').value = '';
}

function updateEnhancedAccessForm() {
    const accessType = document.getElementById('enhancedAccessType').value;
    const portField = document.getElementById('enhancedAccessPort');
    const hintsDiv = document.getElementById('enhancedAccessHints');
    
    // Auto-set default ports
    const defaultPorts = {
        'ssh': 22,
        'ftp': 21,
        'telnet': 23,
        'http': 80,
        'snmp': 161,
        'api': ''
    };
    
    if (defaultPorts[accessType]) {
        portField.value = defaultPorts[accessType];
    } else {
        portField.value = '';
    }
    
    // Reload credentials for this access type
    loadExistingAccessCredentials();
    
    // Update hints
    updateEnhancedAccessHints();
}

function updateEnhancedAccessHints() {
    const accessType = document.getElementById('enhancedAccessType').value;
    const hintsDiv = document.getElementById('enhancedAccessHints');
    
    // Update hints (reuse existing hints from device-access.js)
    const hints = {
        'ssh': `
            <div class="hint">
                <strong>SSH:</strong> Linux/Unix sistemler için. 
                <br>• Raspberry Pi: kullanıcı <code>pi</code>, port <code>22</code>
                <br>• Ubuntu/Debian: kullanıcı <code>ubuntu</code> veya <code>admin</code>
                <br>• Router'lar: kullanıcı <code>admin</code> veya <code>root</code>
            </div>
        `,
        'ftp': `
            <div class="hint">
                <strong>FTP:</strong> Dosya transferi için.
                <br>• Anonymous erişim: kullanıcı <code>anonymous</code>, şifre boş
                <br>• NAS cihazları: genellikle <code>admin</code> veya <code>guest</code>
            </div>
        `,
        'telnet': `
            <div class="hint">
                <strong>Telnet:</strong> Eski cihazlar ve router'lar için.
                <br>• Router'lar: <code>admin/admin</code>, <code>root/admin</code>
                <br>⚠️ Güvenli değil, SSH tercih edin
            </div>
        `,
        'http': `
            <div class="hint">
                <strong>HTTP Auth:</strong> Web arayüzü erişimi için.
                <br>• Router'lar: <code>admin/admin</code>, <code>admin/password</code>
                <br>• IP Kameralar: <code>admin/admin</code>, <code>admin/123456</code>
                <br>• IoT Cihazlar: <code>admin</code> veya cihaz modeline özel
            </div>
        `,
        'snmp': `
            <div class="hint">
                <strong>SNMP:</strong> Sistem izleme için.
                <br>• Community String: genellikle <code>public</code> (kullanıcı adı alanına)
                <br>• SNMP v3 için kullanıcı adı ve parola gerekli
                <br>• Port: genellikle <code>161</code>
            </div>
        `,
        'api': `
            <div class="hint">
                <strong>API Token:</strong> REST API erişimi için.
                <br>• Token'ı Parola alanına girin
                <br>• Kullanıcı adı genellikle gerekli değil
                <br>• Ek Bilgiler'e API endpoint'lerini ekleyin
            </div>
        `
    };
    
    hintsDiv.innerHTML = hints[accessType] || '';
}

async function testEnhancedAccess() {
    if (!currentEnhancedEditingIp) return;
    
    const accessData = {
        ip: currentEnhancedEditingIp,
        access_type: document.getElementById('enhancedAccessType').value,
        port: document.getElementById('enhancedAccessPort').value,
        username: document.getElementById('enhancedAccessUsername').value,
        password: document.getElementById('enhancedAccessPassword').value
    };
    
    if (!accessData.username || !accessData.password) {
        showToast(t('username_password_required'), 'error');
        return;
    }
    
    showToast(t('connection_test_starting'), 'info');
    
    try {
        const response = await fetch(`/test_device_access/${currentEnhancedEditingIp}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accessData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast('✅ ' + t('connection_successful'), 'success');
        } else {
            showToast(`❌ ${t('connection_failed')}: ${result.error || t('unknown_error')}`, 'error');
        }
    } catch (error) {
        showToast(`❌ ${t('test_error')}: ${error.message}`, 'error');
    }
}

async function saveEnhancedAccess() {
    if (!currentEnhancedEditingIp) return;
    
    const accessData = {
        ip: currentEnhancedEditingIp,
        access_type: document.getElementById('enhancedAccessType').value,
        port: document.getElementById('enhancedAccessPort').value,
        username: document.getElementById('enhancedAccessUsername').value,
        password: document.getElementById('enhancedAccessPassword').value,
        notes: document.getElementById('enhancedAccessNotes').value
    };
    
    if (!accessData.username) {
        showToast(t('username_required'), 'error');
        return;
    }
    
    showToast(t('access_info_saving'), 'info');
    
    try {
        const response = await fetch('/save_device_credentials', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accessData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast('✅ ' + t('access_info_saved'), 'success');
        } else {
            showToast(`❌ ${t('save_failed')}: ${result.error || t('unknown_error')}`, 'error');
        }
    } catch (error) {
        showToast(`❌ ${t('save_error')}: ${error.message}`, 'error');
    }
}


async function saveEnhancedDevice() {
    if (!currentEnhancedEditingIp) return;

    const device = deviceByKey(currentEnhancedEditingIp);
    if (!device) return;

    // Collect data from all tabs
    const deviceData = {
        ip: document.getElementById('enhancedEditIpAddress').value,
        mac: document.getElementById('enhancedEditMacAddress').value,
        alias: document.getElementById('enhancedEditAlias').value,
        hostname: document.getElementById('enhancedEditHostname').value,
        vendor: document.getElementById('enhancedEditVendor').value,
        device_type: document.getElementById('enhancedEditDeviceType').value,
        notes: document.getElementById('enhancedEditNotes').value,
        trust_status: document.getElementById('enhancedEditTrust').value,
        location: document.getElementById('enhancedEditLocation').value,
        open_ports: device.open_ports || []
    };

    try {
        const response = await fetch(`/update_device/${currentEnhancedEditingIp}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(deviceData)
        });

        const result = await response.json();

        if (response.ok) {
            const uplink = document.getElementById('enhancedEditUplink');
            if (uplink) {
                await fetch('/api/topology/uplinks', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uplinks: { [currentEnhancedEditingIp]: uplink.value || null } })
                }).catch(() => { /* the device itself saved; the uplink is a nicety */ });
            }
            showToast(t('device_updated_success'), 'success');
            closeEnhancedEditModal();
            await loadDevices(); // Reload devices
        } else {
            showToast(t('update_error') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}
