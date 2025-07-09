/**
 * Config Page JavaScript Functions
 * Handles configuration management, OUI database, device types, and detection rules
 */

// Global variables
let currentOuiDatabase = {};
let currentDeviceTypes = {};
let currentSettings = {};

// Page initialization
window.addEventListener('load', function() {
    loadAllSettings();
});

/**
 * Tab Management
 */
function switchTab(tabName) {
    // Tab butonlarını güncelle
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
    
    // Tab içeriklerini güncelle
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
    
    // Seçilen tab'a göre özel yükleme işlemleri
    if (tabName === 'networks') {
        loadNetworks();
    } else if (tabName === 'docker') {
        loadDockerInfo();
    }
}

/**
 * Alert System
 */
function showAlert(message, type = 'success') {
    const alertContainer = document.getElementById('alertContainer');
    const alertClass = type === 'error' ? 'alert-error' : 'alert-success';
    alertContainer.innerHTML = `<div class="alert ${alertClass}">${message}</div>`;
    
    setTimeout(() => {
        alertContainer.innerHTML = '';
    }, 5000);
}

/**
 * Data Loading Functions
 */
async function loadAllSettings() {
    try {
        // OUI database
        const ouiResponse = await fetch('/api/config/oui');
        currentOuiDatabase = await ouiResponse.json();
        displayOuiDatabase();

        // Device types
        const deviceTypesResponse = await fetch('/api/config/device_types');
        currentDeviceTypes = await deviceTypesResponse.json();
        displayDeviceTypes();

        // General settings
        const settingsResponse = await fetch('/api/config/settings');
        currentSettings = await settingsResponse.json();
        displayGeneralSettings();
        displayDetectionRules();
        displayDevicePortRules();
        
        // Update selects with device types
        updateDetectionRuleSelects();

    } catch (error) {
        showAlert('Ayarlar yüklenirken hata oluştu: ' + error.message, 'error');
    }
}

/**
 * General Settings Display
 */
function displayGeneralSettings() {
    const scanSettings = currentSettings.scan_settings || {};
    const portSettings = currentSettings.port_settings || {};

    const defaultIpRange = document.getElementById('defaultIpRange');
    const timeout = document.getElementById('timeout');
    const maxThreads = document.getElementById('maxThreads');
    const includeOffline = document.getElementById('includeOffline');
    const defaultPorts = document.getElementById('defaultPorts');

    if (defaultIpRange) defaultIpRange.value = scanSettings.default_ip_range || '';
    if (timeout) timeout.value = scanSettings.timeout || '';
    if (maxThreads) maxThreads.value = scanSettings.max_threads || '';
    if (includeOffline) includeOffline.checked = scanSettings.include_offline === true;
    if (defaultPorts) defaultPorts.value = (portSettings.default_ports || []).join(',');

    // Device specific ports - sadece currentDevicePortRules div'ini güncelle
    displayDevicePortRules();
}

/**
 * OUI Database Management
 */
function displayOuiDatabase() {
    const ouiList = document.getElementById('ouiList');
    if (!ouiList) return;
    
    ouiList.innerHTML = '';
    
    const sortedOuis = Object.entries(currentOuiDatabase).sort(([a], [b]) => a.localeCompare(b));
    
    sortedOuis.forEach(([oui, vendor]) => {
        const div = document.createElement('div');
        div.className = 'oui-item';
        div.style.cssText = 'background: #f8f9fa; padding: 10px; border-radius: 6px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;';
        
        const macExample = `${oui.substring(0,2)}:${oui.substring(2,4)}:${oui.substring(4,6)}:XX:XX:XX`;
        
        div.innerHTML = `
            <div style="flex: 1;">
                <div style="display: flex; align-items: center; gap: 15px;">
                    <strong style="font-family: monospace; color: #495057;">${oui}</strong>
                    <span style="color: #6c757d; font-size: 0.9em;">${macExample}</span>
                    <span style="flex: 1; color: #212529;">${vendor}</span>
                </div>
            </div>
            <div style="display: flex; gap: 5px;">
                <button class="btn btn-warning btn-small" onclick="editOuiEntry('${oui}', '${vendor.replace(/'/g, "\\'")}')" title="Düzenle">✏️</button>
                <button class="btn btn-danger btn-small" onclick="removeOuiEntry('${oui}')" title="Sil">🗑️</button>
            </div>
        `;
        ouiList.appendChild(div);
    });
    
    // Toplam sayısını göster
    const totalCount = document.createElement('div');
    totalCount.style.cssText = 'text-align: center; margin-top: 10px; color: #6c757d; font-size: 0.9em;';
    totalCount.textContent = `Toplam ${sortedOuis.length} OUI kaydı`;
    ouiList.appendChild(totalCount);
}

function addOuiEntry() {
    const oui = document.getElementById('newOui').value.trim().toUpperCase();
    const vendor = document.getElementById('newVendor').value.trim();
    
    if (!oui || !vendor) {
        showAlert('OUI ve Vendor alanları boş olamaz!', 'error');
        return;
    }
    
    if (oui.length !== 6) {
        showAlert('OUI 6 karakter olmalıdır (örnek: 001122)', 'error');
        return;
    }
    
    currentOuiDatabase[oui] = vendor;
    displayOuiDatabase();
    
    document.getElementById('newOui').value = '';
    document.getElementById('newVendor').value = '';
    
    showAlert('OUI kaydı eklendi!');
}

function removeOuiEntry(oui) {
    if (confirm(`${oui} kaydını silmek istediğinizden emin misiniz?`)) {
        delete currentOuiDatabase[oui];
        displayOuiDatabase();
        showAlert('OUI kaydı silindi!');
    }
}

function editOuiEntry(oui, vendor) {
    const newVendor = prompt(`OUI ${oui} için yeni vendor adı:`, vendor);
    if (newVendor && newVendor.trim() !== '' && newVendor !== vendor) {
        currentOuiDatabase[oui] = newVendor.trim();
        displayOuiDatabase();
        showAlert('OUI kaydı güncellendi!');
    }
}

function filterOuiList() {
    const searchInput = document.getElementById('ouiSearchInput');
    if (!searchInput) return;
    
    const searchTerm = searchInput.value.toLowerCase();
    const ouiItems = document.querySelectorAll('.oui-item');
    
    ouiItems.forEach(item => {
        const text = item.textContent.toLowerCase();
        if (text.includes(searchTerm)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
}

/**
 * Device Types Management
 */
function displayDeviceTypes() {
    const deviceTypesList = document.getElementById('deviceTypesList');
    if (!deviceTypesList) return;
    
    deviceTypesList.innerHTML = '';
    
    for (const [typeName, typeInfo] of Object.entries(currentDeviceTypes)) {
        const div = document.createElement('div');
        div.className = 'device-type-edit';
        div.innerHTML = `
            <div class="device-type-edit-form">
                <button type="button" class="btn btn-small" onclick="openEmojiPicker('deviceIcon_${typeName.replace(/[^a-zA-Z0-9]/g, '_')}'); this.nextElementSibling.id = 'deviceIcon_${typeName.replace(/[^a-zA-Z0-9]/g, '_')}';">📋</button>
                <input type="text" class="device-icon-input" data-device-type="${typeName}" value="${typeInfo.icon}" style="text-align: center; font-size: 1.2em;" maxlength="2">
                <input type="text" class="device-name-input" data-device-type="${typeName}" value="${typeName}" style="font-weight: bold;">
                <select class="device-category-select" data-device-type="${typeName}">
                    <option value="unknown" ${typeInfo.category === 'unknown' ? 'selected' : ''}>Unknown</option>
                    <option value="tech" ${typeInfo.category === 'tech' ? 'selected' : ''}>Technology</option>
                    <option value="network" ${typeInfo.category === 'network' ? 'selected' : ''}>Network</option>
                    <option value="smart" ${typeInfo.category === 'smart' ? 'selected' : ''}>Smart Home</option>
                    <option value="media" ${typeInfo.category === 'media' ? 'selected' : ''}>Media</option>
                    <option value="security" ${typeInfo.category === 'security' ? 'selected' : ''}>Security</option>
                    <option value="transport" ${typeInfo.category === 'transport' ? 'selected' : ''}>Transport</option>
                    <option value="office" ${typeInfo.category === 'office' ? 'selected' : ''}>Office</option>
                    <option value="mobile" ${typeInfo.category === 'mobile' ? 'selected' : ''}>Mobile</option>
                    <option value="computer" ${typeInfo.category === 'computer' ? 'selected' : ''}>Computer</option>
                    <option value="peripheral" ${typeInfo.category === 'peripheral' ? 'selected' : ''}>Peripheral</option>
                    <option value="entertainment" ${typeInfo.category === 'entertainment' ? 'selected' : ''}>Entertainment</option>
                    <option value="appliance" ${typeInfo.category === 'appliance' ? 'selected' : ''}>Appliance</option>
                    <option value="iot" ${typeInfo.category === 'iot' ? 'selected' : ''}>IoT Device</option>
                    <option value="storage" ${typeInfo.category === 'storage' ? 'selected' : ''}>Storage</option>
                    <option value="gaming" ${typeInfo.category === 'gaming' ? 'selected' : ''}>Gaming</option>
                    <option value="medical" ${typeInfo.category === 'medical' ? 'selected' : ''}>Medical</option>
                    <option value="industrial" ${typeInfo.category === 'industrial' ? 'selected' : ''}>Industrial</option>
                </select>
                <button class="btn btn-danger btn-small device-remove-btn" data-device-type="${typeName}">🗑️</button>
            </div>
        `;
        deviceTypesList.appendChild(div);
    }
    
    // Add event listeners after creating the elements
    attachDeviceTypeEventListeners();
}

function attachDeviceTypeEventListeners() {
    // Icon input event listeners - using polling to detect changes
    const iconInputs = document.querySelectorAll('.device-icon-input');
    
    iconInputs.forEach(input => {
        const deviceType = input.getAttribute('data-device-type');
        
        // Store initial value and monitor for changes
        let lastValue = input.value;
        setInterval(() => {
            if (input.value !== lastValue) {
                updateDeviceTypeIcon(deviceType, input.value);
                lastValue = input.value;
            }
        }, 200);
        
        // Also try standard events as backup
        ['input', 'change', 'blur'].forEach(eventType => {
            input.addEventListener(eventType, function() {
                updateDeviceTypeIcon(deviceType, this.value);
            });
        });
    });
    
    // Name input event listeners
    document.querySelectorAll('.device-name-input').forEach(input => {
        input.addEventListener('change', function() {
            const oldName = this.getAttribute('data-device-type');
            const newName = this.value;
            updateDeviceTypeName(oldName, newName);
        });
    });
    
    // Category select event listeners
    document.querySelectorAll('.device-category-select').forEach(select => {
        select.addEventListener('change', function() {
            const deviceType = this.getAttribute('data-device-type');
            const newCategory = this.value;
            updateDeviceTypeCategory(deviceType, newCategory);
        });
    });
    
    // Remove button event listeners
    document.querySelectorAll('.device-remove-btn').forEach(button => {
        button.addEventListener('click', function() {
            const deviceType = this.getAttribute('data-device-type');
            removeDeviceType(deviceType);
        });
    });
}

function updateDeviceTypeIcon(oldName, newIcon) {
    if (currentDeviceTypes[oldName]) {
        currentDeviceTypes[oldName].icon = newIcon;
    }
}

function updateDeviceTypeName(oldName, newName) {
    if (oldName !== newName && currentDeviceTypes[oldName]) {
        currentDeviceTypes[newName] = {...currentDeviceTypes[oldName]};
        delete currentDeviceTypes[oldName];
        displayDeviceTypes();
    }
}

function updateDeviceTypeCategory(typeName, newCategory) {
    if (currentDeviceTypes[typeName]) {
        currentDeviceTypes[typeName].category = newCategory;
    }
}

function addDeviceType() {
    const typeName = document.getElementById('newDeviceType').value.trim();
    const icon = document.getElementById('newDeviceIcon').value.trim();
    const category = document.getElementById('newDeviceCategory').value;
    
    if (!typeName || !icon) {
        showAlert('Cihaz tipi adı ve ikon alanları boş olamaz!', 'error');
        return;
    }
    
    currentDeviceTypes[typeName] = {
        icon: icon,
        category: category
    };
    
    displayDeviceTypes();
    
    document.getElementById('newDeviceType').value = '';
    document.getElementById('newDeviceIcon').value = '';
    document.getElementById('newDeviceCategory').value = 'unknown';
    
    showAlert('Cihaz tipi eklendi!');
}

function removeDeviceType(typeName) {
    if (confirm(`${typeName} cihaz tipini silmek istediğinizden emin misiniz?`)) {
        delete currentDeviceTypes[typeName];
        displayDeviceTypes();
        showAlert('Cihaz tipi silindi!');
    }
}

/**
 * Detection Rules Management
 */
function displayDetectionRules() {
    const hostnamePatterns = document.getElementById('hostnamePatterns');
    const vendorPatterns = document.getElementById('vendorPatterns');
    
    if (!hostnamePatterns || !vendorPatterns) return;
    
    hostnamePatterns.innerHTML = '';
    vendorPatterns.innerHTML = '';
    
    const detectionRules = currentSettings.detection_rules || {};
    
    // Hostname patterns
    const hostPatterns = detectionRules.hostname_patterns || [];
    hostPatterns.forEach((rule, index) => {
        const div = document.createElement('div');
        div.style.cssText = 'background: #f8f9fa; padding: 10px; border-radius: 6px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;';
        div.innerHTML = `
            <span><strong>${rule.type}:</strong> ${rule.pattern}</span>
            <button class="btn btn-danger btn-small" onclick="removeHostnamePattern(${index})">🗑️</button>
        `;
        hostnamePatterns.appendChild(div);
    });
    
    // Vendor patterns
    const vendPatterns = detectionRules.vendor_patterns || [];
    vendPatterns.forEach((rule, index) => {
        const div = document.createElement('div');
        div.style.cssText = 'background: #f8f9fa; padding: 10px; border-radius: 6px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;';
        div.innerHTML = `
            <span><strong>${rule.type}:</strong> ${rule.pattern}</span>
            <button class="btn btn-danger btn-small" onclick="removeVendorPattern(${index})">🗑️</button>
        `;
        vendorPatterns.appendChild(div);
    });
}

function addHostnamePattern() {
    const pattern = document.getElementById('newHostnamePattern').value.trim();
    const deviceType = document.getElementById('newHostnameDeviceType').value;
    
    if (!pattern || !deviceType) {
        showAlert('Pattern ve cihaz tipi alanları dolu olmalıdır!', 'error');
        return;
    }
    
    if (!currentSettings.detection_rules) {
        currentSettings.detection_rules = {};
    }
    if (!currentSettings.detection_rules.hostname_patterns) {
        currentSettings.detection_rules.hostname_patterns = [];
    }
    
    currentSettings.detection_rules.hostname_patterns.push({
        pattern: pattern,
        type: deviceType
    });
    
    document.getElementById('newHostnamePattern').value = '';
    document.getElementById('newHostnameDeviceType').value = '';
    displayDetectionRules();
    showAlert('Hostname pattern eklendi!');
}

function addVendorPattern() {
    const pattern = document.getElementById('newVendorPattern').value.trim();
    const deviceType = document.getElementById('newVendorDeviceType').value;
    
    if (!pattern || !deviceType) {
        showAlert('Pattern ve cihaz tipi alanları dolu olmalıdır!', 'error');
        return;
    }
    
    if (!currentSettings.detection_rules) {
        currentSettings.detection_rules = {};
    }
    if (!currentSettings.detection_rules.vendor_patterns) {
        currentSettings.detection_rules.vendor_patterns = [];
    }
    
    currentSettings.detection_rules.vendor_patterns.push({
        pattern: pattern,
        type: deviceType
    });
    
    document.getElementById('newVendorPattern').value = '';
    document.getElementById('newVendorDeviceType').value = '';
    displayDetectionRules();
    showAlert('Vendor pattern eklendi!');
}

function removeHostnamePattern(index) {
    if (currentSettings.detection_rules && currentSettings.detection_rules.hostname_patterns) {
        currentSettings.detection_rules.hostname_patterns.splice(index, 1);
        displayDetectionRules();
        showAlert('Hostname pattern silindi!');
    }
}

function removeVendorPattern(index) {
    if (currentSettings.detection_rules && currentSettings.detection_rules.vendor_patterns) {
        currentSettings.detection_rules.vendor_patterns.splice(index, 1);
        displayDetectionRules();
        showAlert('Vendor pattern silindi!');
    }
}

function saveDetectionRules() {
    fetch('/api/save_settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(currentSettings)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('Tanıma kuralları kaydedildi!');
        } else {
            showAlert('Kaydetme hatası: ' + data.error, 'error');
        }
    })
    .catch(error => {
        showAlert('Kaydetme hatası: ' + error, 'error');
    });
}

/**
 * Port Management
 */
function displayDevicePortRules() {
    const container = document.getElementById('currentDevicePortRules');
    if (!container) return;
    
    container.innerHTML = '';
    
    const deviceSpecificPorts = currentSettings.port_settings?.device_specific_ports || {};
    if (Object.keys(deviceSpecificPorts).length > 0) {
        for (const [deviceType, ports] of Object.entries(deviceSpecificPorts)) {
            const div = document.createElement('div');
            div.style.cssText = 'background: #f8f9fa; padding: 10px; border-radius: 6px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;';
            div.innerHTML = `
                <span><strong>${deviceType}:</strong> ${ports.join(', ')}</span>
                <button class="btn btn-danger btn-small" onclick="removeDevicePortRule('${deviceType}')">🗑️</button>
            `;
            container.appendChild(div);
        }
    }
}

function addDeviceTypePorts() {
    const deviceType = document.getElementById('deviceTypePortSelect').value;
    const ports = document.getElementById('deviceTypePorts').value.trim();
    
    if (!deviceType || !ports) {
        showAlert('Cihaz tipi ve port alanları dolu olmalıdır!', 'error');
        return;
    }
    
    if (!currentSettings.port_settings) {
        currentSettings.port_settings = {};
    }
    if (!currentSettings.port_settings.device_specific_ports) {
        currentSettings.port_settings.device_specific_ports = {};
    }
    
    currentSettings.port_settings.device_specific_ports[deviceType] = ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    
    document.getElementById('deviceTypePorts').value = '';
    document.getElementById('deviceTypePortSelect').value = '';
    
    displayDevicePortRules();
    showAlert('Cihaz tipi port kuralı eklendi!');
}

function removeDevicePortRule(deviceType) {
    if (currentSettings.port_settings?.device_specific_ports) {
        delete currentSettings.port_settings.device_specific_ports[deviceType];
        displayDevicePortRules();
        showAlert('Port kuralı silindi!');
    }
}

/**
 * Network Management
 */
async function loadNetworks() {
    try {
        const response = await fetch('/api/networks');
        const networks = await response.json();
        
        const networksList = document.getElementById('networksList');
        if (!networksList) return;
        
        networksList.innerHTML = '';
        
        networks.forEach(network => {
            const div = document.createElement('div');
            div.className = 'network-item';
            div.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h4>${network.interface}</h4>
                    <span class="network-type">${network.type}</span>
                </div>
                <p><strong>IP:</strong> ${network.ip}</p>
                <p><strong>Netmask:</strong> ${network.netmask}</p>
                <p><strong>Network:</strong> ${network.network_range}</p>
            `;
            networksList.appendChild(div);
        });
        
    } catch (error) {
        showAlert('Ağ bilgileri yüklenirken hata oluştu: ' + error.message, 'error');
    }
}

function refreshNetworks() {
    loadNetworks();
    showAlert('Ağ bilgileri yenilendi!');
}

/**
 * Save Functions
 */
async function saveGeneralSettings() {
    try {
        const defaultIpRangeEl = document.getElementById('defaultIpRange');
        const timeoutEl = document.getElementById('timeout');
        const maxThreadsEl = document.getElementById('maxThreads');
        const includeOfflineEl = document.getElementById('includeOffline');
        const defaultPortsEl = document.getElementById('defaultPorts');
        
        if (!defaultIpRangeEl || !timeoutEl || !maxThreadsEl || !includeOfflineEl || !defaultPortsEl) {
            showAlert('Form elementleri bulunamadı!', 'error');
            return;
        }
        
        const defaultPorts = defaultPortsEl.value.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
        
        const settingsData = {
            scan_settings: {
                default_ip_range: defaultIpRangeEl.value || '192.168.1.0/24',
                timeout: parseInt(timeoutEl.value) || 3,
                max_threads: parseInt(maxThreadsEl.value) || 50,
                include_offline: includeOfflineEl.checked
            },
            port_settings: {
                default_ports: defaultPorts,
                device_specific_ports: currentSettings.port_settings?.device_specific_ports || {}
            }
        };
        
        const response = await fetch('/api/config/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settingsData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showAlert('Genel ayarlar kaydedildi!');
            currentSettings = {...currentSettings, ...settingsData};
            await loadAllSettings();
        } else {
            showAlert('Hata: ' + (result.error || result.message || 'Bilinmeyen hata'), 'error');
        }
        
    } catch (error) {
        showAlert('Ayarlar kaydedilirken hata oluştu: ' + error.message, 'error');
    }
}

async function saveOuiDatabase() {
    try {
        const response = await fetch('/api/config/oui', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(currentOuiDatabase)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert('OUI database kaydedildi!');
        } else {
            showAlert('Hata: ' + result.error, 'error');
        }
        
    } catch (error) {
        showAlert('OUI database kaydedilirken hata oluştu: ' + error.message, 'error');
    }
}

async function saveDeviceTypes() {
    try {
        const response = await fetch('/api/config/device_types', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(currentDeviceTypes)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert('Cihaz tipleri kaydedildi!');
        } else {
            showAlert('Hata: ' + result.error, 'error');
        }
        
    } catch (error) {
        showAlert('Cihaz tipleri kaydedilirken hata oluştu: ' + error.message, 'error');
    }
}

/**
 * Import/Export Functions
 */
function exportOuiDatabase() {
    const dataStr = JSON.stringify(currentOuiDatabase, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'oui_database.json';
    link.click();
    URL.revokeObjectURL(url);
}

function importOuiDatabase() {
    const file = document.getElementById('ouiImportFile').files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const importedData = JSON.parse(e.target.result);
                currentOuiDatabase = {...currentOuiDatabase, ...importedData};
                displayOuiDatabase();
                showAlert(`${Object.keys(importedData).length} OUI kaydı import edildi!`);
            } catch (error) {
                showAlert('Import hatası: Geçersiz JSON dosyası', 'error');
            }
        };
        reader.readAsText(file);
    }
}

/**
 * OUI API Functions
 */
async function downloadIEEEDatabase() {
    const btn = document.getElementById('downloadIEEEBtn');
    const originalText = btn.textContent;
    
    btn.disabled = true;
    btn.textContent = '📥 İndiriliyor...';
    
    try {
        const response = await fetch('/api/download_ieee_oui');
        const result = await response.json();
        
        if (result.success) {
            showAlert(`IEEE OUI database başarıyla güncellendi! ${result.processed_count} kayıt işlendi.`);
            loadAllSettings();
        } else {
            showAlert('IEEE database indirme hatası: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('Bağlantı hatası: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function lookupVendorAPI() {
    const oui = document.getElementById('newOui').value.trim();
    
    if (!oui || oui.length !== 6) {
        showAlert('Geçerli bir 6 haneli OUI girin (örnek: 001122)', 'error');
        return;
    }
    
    const btn = document.getElementById('apiLookupBtn');
    const originalText = btn.textContent;
    
    btn.disabled = true;
    btn.textContent = '🔍 Aranıyor...';
    
    try {
        const testMac = oui + '123456';
        
        const response = await fetch(`/api/lookup_vendor/${testMac}`);
        const result = await response.json();
        
        if (result.success) {
            document.getElementById('newVendor').value = result.vendor;
            showAlert(`Vendor bulundu: ${result.vendor} (Kaynak: ${result.source})`);
        } else {
            showAlert('Vendor bilgisi bulunamadı: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('API arama hatası: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

/**
 * Helper Functions
 */
function updateDetectionRuleSelects() {
    const hostnameSelect = document.getElementById('newHostnameDeviceType');
    const vendorSelect = document.getElementById('newVendorDeviceType');
    const devicePortSelect = document.getElementById('deviceTypePortSelect');
    
    if (!hostnameSelect || !vendorSelect || !devicePortSelect) return;
    
    hostnameSelect.innerHTML = '<option value="">Cihaz Tipi Seç</option>';
    vendorSelect.innerHTML = '<option value="">Cihaz Tipi Seç</option>';
    devicePortSelect.innerHTML = '<option value="">Port tanımı eklemek için cihaz tipi seçin</option>';
    
    for (const typeName of Object.keys(currentDeviceTypes)) {
        const option1 = document.createElement('option');
        option1.value = typeName;
        option1.textContent = typeName;
        hostnameSelect.appendChild(option1);
        
        const option2 = document.createElement('option');
        option2.value = typeName;
        option2.textContent = typeName;
        vendorSelect.appendChild(option2);
        
        const option3 = document.createElement('option');
        option3.value = typeName;
        option3.textContent = typeName;
        devicePortSelect.appendChild(option3);
    }
}

// Initialize OUI input validation
document.addEventListener('DOMContentLoaded', function() {
    const ouiInput = document.getElementById('newOui');
    const apiBtn = document.getElementById('apiLookupBtn');
    
    if (ouiInput && apiBtn) {
        ouiInput.addEventListener('input', function() {
            const value = this.value.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
            this.value = value;
            
            apiBtn.disabled = value.length !== 6;
        });
    }
});

/**
 * Docker Management Functions
 */
async function loadDockerInfo() {
    try {
        await Promise.all([
            loadDockerStatus(),
            loadDockerNetworks(),
            loadDockerContainers(),
            loadDockerScanRanges()
        ]);
    } catch (error) {
        showAlert('Docker bilgileri yüklenirken hata oluştu: ' + error.message, 'error');
    }
}

async function loadDockerStatus() {
    try {
        const response = await fetch('/api/docker/stats');
        const data = await response.json();
        
        const statusContainer = document.getElementById('dockerStatus');
        if (!statusContainer) return;
        
        let statusHtml = '';
        
        if (data.available) {
            statusHtml = `
                <div class="docker-status-item" style="background: #d4edda; color: #155724; padding: 15px; border-radius: 6px; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 1.5em;">✅</span>
                        <div>
                            <strong>Docker Aktif</strong>
                            <div style="font-size: 0.9em; opacity: 0.8;">
                                ${data.networks_count} network, ${data.containers_count} container, ${data.scan_ranges_count} tarama aralığı
                            </div>
                        </div>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
                    <div class="stat-item">
                        <div class="stat-number">${data.networks_count}</div>
                        <div class="stat-label">Docker Networks</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">${data.containers_count}</div>
                        <div class="stat-label">Aktif Containers</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">${data.scan_ranges_count}</div>
                        <div class="stat-label">Tarama Aralıkları</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">${data.socket_available ? '✅' : '❌'}</div>
                        <div class="stat-label">Socket Access</div>
                    </div>
                </div>
            `;
        } else {
            statusHtml = `
                <div class="docker-status-item" style="background: #f8d7da; color: #721c24; padding: 15px; border-radius: 6px;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 1.5em;">❌</span>
                        <div>
                            <strong>Docker Kullanılamıyor</strong>
                            <div style="font-size: 0.9em; opacity: 0.8;">
                                ${data.error || 'Docker kurulu değil veya çalışmıyor'}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        statusContainer.innerHTML = statusHtml;
        
    } catch (error) {
        const statusContainer = document.getElementById('dockerStatus');
        if (statusContainer) {
            statusContainer.innerHTML = `
                <div style="background: #f8d7da; color: #721c24; padding: 15px; border-radius: 6px;">
                    ❌ Docker durumu kontrol edilemedi: ${error.message}
                </div>
            `;
        }
    }
}

async function loadDockerNetworks() {
    try {
        const response = await fetch('/api/docker/networks');
        const data = await response.json();
        
        const networksContainer = document.getElementById('dockerNetworksList');
        if (!networksContainer) return;
        
        if (!data.success || !data.networks || data.networks.length === 0) {
            networksContainer.innerHTML = '<div style="text-align: center; color: #6c757d; padding: 20px;">Docker network bulunamadı</div>';
            return;
        }
        
        let networksHtml = '';
        data.networks.forEach(network => {
            const containerCount = network.containers ? network.containers.length : 0;
            const subnetDisplay = network.subnets && network.subnets.length > 0 ? network.subnets.join(', ') : 'N/A';
            
            networksHtml += `
                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                                <strong style="color: #0066cc;">${network.name}</strong>
                                <span style="background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em;">${network.driver}</span>
                                ${network.internal ? '<span style="background: #dc3545; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em;">Internal</span>' : ''}
                            </div>
                            <div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;">
                                <strong>ID:</strong> ${network.id}
                            </div>
                            <div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;">
                                <strong>Subnet:</strong> ${subnetDisplay}
                            </div>
                            ${network.gateway ? `<div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;"><strong>Gateway:</strong> ${network.gateway}</div>` : ''}
                            <div style="font-size: 0.9em; color: #6c757d;">
                                <strong>Containers:</strong> ${containerCount} adet
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        networksContainer.innerHTML = networksHtml;
        
    } catch (error) {
        const networksContainer = document.getElementById('dockerNetworksList');
        if (networksContainer) {
            networksContainer.innerHTML = `<div style="color: #dc3545; padding: 20px; text-align: center;">❌ Docker networks yüklenemedi: ${error.message}</div>`;
        }
    }
}

async function loadDockerContainers() {
    try {
        const response = await fetch('/api/docker/containers');
        const data = await response.json();
        
        const containersContainer = document.getElementById('dockerContainersList');
        if (!containersContainer) return;
        
        if (!data.success || !data.containers || data.containers.length === 0) {
            containersContainer.innerHTML = '<div style="text-align: center; color: #6c757d; padding: 20px;">Çalışan Docker container bulunamadı</div>';
            return;
        }
        
        let containersHtml = '';
        data.containers.forEach(container => {
            const ipAddresses = container.ip_addresses || [];
            const networks = container.networks || [];
            
            containersHtml += `
                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                                <strong style="color: #0066cc;">${container.name}</strong>
                                <span style="background: #28a745; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em;">Running</span>
                            </div>
                            <div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;">
                                <strong>ID:</strong> ${container.id}
                            </div>
                            <div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;">
                                <strong>Image:</strong> ${container.image}
                            </div>
                            <div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;">
                                <strong>Networks:</strong> ${networks.join(', ') || 'N/A'}
                            </div>
                            ${ipAddresses.length > 0 ? `
                                <div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;">
                                    <strong>IP Addresses:</strong>
                                    ${ipAddresses.map(ip => `<span style="background: #e9ecef; padding: 2px 6px; border-radius: 4px; margin-right: 5px;">${ip.ipv4} (${ip.network})</span>`).join('')}
                                </div>
                            ` : ''}
                            ${container.ports ? `<div style="font-size: 0.9em; color: #6c757d;"><strong>Ports:</strong> ${container.ports}</div>` : ''}
                        </div>
                    </div>
                </div>
            `;
        });
        
        containersContainer.innerHTML = containersHtml;
        
    } catch (error) {
        const containersContainer = document.getElementById('dockerContainersList');
        if (containersContainer) {
            containersContainer.innerHTML = `<div style="color: #dc3545; padding: 20px; text-align: center;">❌ Docker containers yüklenemedi: ${error.message}</div>`;
        }
    }
}

async function loadDockerScanRanges() {
    try {
        const response = await fetch('/api/docker/scan_ranges');
        const data = await response.json();
        
        const scanRangesContainer = document.getElementById('dockerScanRangesList');
        if (!scanRangesContainer) return;
        
        if (!data.success || !data.scan_ranges || data.scan_ranges.length === 0) {
            scanRangesContainer.innerHTML = '<div style="text-align: center; color: #6c757d; padding: 20px;">Docker tarama aralığı bulunamadı</div>';
            return;
        }
        
        let scanRangesHtml = '';
        data.scan_ranges.forEach(range => {
            scanRangesHtml += `
                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                                <strong style="color: #0066cc;">${range.network_name}</strong>
                                <span style="background: #17a2b8; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em;">${range.driver}</span>
                            </div>
                            <div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;">
                                <strong>Subnet:</strong> ${range.subnet}
                            </div>
                            <div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;">
                                <strong>Scan Range:</strong> <code style="background: #e9ecef; padding: 2px 6px; border-radius: 4px;">${range.scan_range}</code>
                            </div>
                            ${range.gateway ? `<div style="font-size: 0.9em; color: #6c757d; margin-bottom: 5px;"><strong>Gateway:</strong> ${range.gateway}</div>` : ''}
                            <div style="font-size: 0.9em; color: #6c757d;">
                                <strong>Containers:</strong> ${range.container_count} adet
                            </div>
                        </div>
                        <div>
                            <button class="btn btn-small" onclick="addToScanRange('${range.scan_range}', '${range.network_name}')" style="background: #28a745; color: white;">
                                ➕ Taramaya Ekle
                            </button>
                        </div>
                    </div>
                </div>
            `;
        });
        
        scanRangesContainer.innerHTML = scanRangesHtml;
        
    } catch (error) {
        const scanRangesContainer = document.getElementById('dockerScanRangesList');
        if (scanRangesContainer) {
            scanRangesContainer.innerHTML = `<div style="color: #dc3545; padding: 20px; text-align: center;">❌ Docker scan ranges yüklenemedi: ${error.message}</div>`;
        }
    }
}

// Refresh functions
async function refreshDockerNetworks() {
    const networksContainer = document.getElementById('dockerNetworksList');
    if (networksContainer) {
        networksContainer.innerHTML = '<div class="loading">Network bilgileri yenileniyor...</div>';
    }
    await loadDockerNetworks();
    showAlert('Docker networks yenilendi!');
}

async function refreshDockerContainers() {
    const containersContainer = document.getElementById('dockerContainersList');
    if (containersContainer) {
        containersContainer.innerHTML = '<div class="loading">Container bilgileri yenileniyor...</div>';
    }
    await loadDockerContainers();
    showAlert('Docker containers yenilendi!');
}

async function refreshDockerScanRanges() {
    const scanRangesContainer = document.getElementById('dockerScanRangesList');
    if (scanRangesContainer) {
        scanRangesContainer.innerHTML = '<div class="loading">Tarama aralıkları yenileniyor...</div>';
    }
    await loadDockerScanRanges();
    showAlert('Docker tarama aralıkları yenilendi!');
}

function addToScanRange(subnet, networkName) {
    // Genel ayarlar sekmesine geç ve IP aralığına ekle
    switchTab('general');
    
    setTimeout(() => {
        const defaultIpRangeInput = document.getElementById('defaultIpRange');
        if (defaultIpRangeInput) {
            const currentValue = defaultIpRangeInput.value;
            const newValue = currentValue ? `${currentValue},${subnet}` : subnet;
            defaultIpRangeInput.value = newValue;
            showAlert(`${networkName} network'ü (${subnet}) tarama aralığına eklendi!`);
        }
    }, 100);
}