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

// Cleanup when page is unloaded
window.addEventListener('beforeunload', function() {
    cleanupDeviceTypeListeners();
});

// Cleanup when navigating away
window.addEventListener('pagehide', function() {
    cleanupDeviceTypeListeners();
});

window.addEventListener('translationsLoaded', function () {
    // translations.js fetches its table after this file has already rendered,
    // so the first paint showed raw keys like "category_network".
    if (Object.keys(currentDeviceTypes || {}).length) displayDeviceTypes();
    if (currentSettings && currentSettings.detection_rules) displayDetectionRules();
    if (Object.keys(currentOuiDatabase || {}).length) displayOuiDatabase();
    updateDetectionRuleSelects();
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
    } else if (tabName === 'oui') {
        ensureOuiLoaded();
    }
}

/*
 * The OUI database is 1.5 MB of JSON. Fetching and parsing it during page load
 * blocked every other tab behind it, which is why Settings took seconds to
 * become usable. It is now loaded the first time its own tab is opened.
 */
let ouiLoadPromise = null;

function ensureOuiLoaded() {
    if (ouiLoadPromise) return ouiLoadPromise;
    const list = document.getElementById('ouiList');
    if (list) list.innerHTML = `<div class="oui-count">${t('loading')}</div>`;
    ouiLoadPromise = fetch('/api/config/oui')
        .then(r => r.json())
        .then(data => {
            currentOuiDatabase = data;
            displayOuiDatabase();
        })
        .catch(error => {
            ouiLoadPromise = null;              // let the next visit retry
            showAlert(t('settings_load_error') + error.message, 'error');
        });
    return ouiLoadPromise;
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
        // The OUI database is loaded lazily - see ensureOuiLoaded().

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
        showAlert(t('settings_load_error') + error.message, 'error');
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
/*
 * The IEEE database is ~40,000 entries. The old renderer built one styled DOM
 * node for every one of them on load, and the search box then walked all
 * 40,000 nodes on each keystroke - that is the freeze. Now the list renders
 * only what matches, capped, and search re-renders from the data.
 */
const OUI_PAGE_SIZE = 100;
let ouiPage = 0;

function displayOuiDatabase() {
    const ouiList = document.getElementById('ouiList');
    if (!ouiList) return;

    const term = (document.getElementById('ouiSearchInput')?.value || '').trim().toLowerCase();
    const all = Object.entries(currentOuiDatabase);
    const matches = term
        ? all.filter(([oui, vendor]) => oui.toLowerCase().includes(term) || String(vendor).toLowerCase().includes(term))
        : all;
    matches.sort(([a], [b]) => a.localeCompare(b));

    const pages = Math.max(1, Math.ceil(matches.length / OUI_PAGE_SIZE));
    ouiPage = Math.min(Math.max(0, ouiPage), pages - 1);
    const start = ouiPage * OUI_PAGE_SIZE;
    const shown = matches.slice(start, start + OUI_PAGE_SIZE);

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    ouiList.innerHTML = shown.map(([oui, vendor]) => `
        <div class="oui-item">
            <span class="oui-item__code" title="${esc(oui.substring(0,2))}:${esc(oui.substring(2,4))}:${esc(oui.substring(4,6))}:XX:XX:XX">${esc(oui)}</span>
            <span class="oui-item__vendor" title="${esc(vendor)}">${esc(vendor)}</span>
            <span class="oui-item__actions">
                <button type="button" class="icon-btn" data-oui-edit="${esc(oui)}" title="${t('edit')}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-wrench"/></svg>
                </button>
                <button type="button" class="icon-btn icon-btn--danger" data-oui-remove="${esc(oui)}" title="${t('delete')}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
                </button>
            </span>
        </div>`).join('') || `<div class="oui-count">${t('no_results')}</div>`;

    ouiList.querySelectorAll('[data-oui-edit]').forEach(btn =>
        btn.addEventListener('click', () => editOuiEntry(btn.dataset.ouiEdit, currentOuiDatabase[btn.dataset.ouiEdit])));
    ouiList.querySelectorAll('[data-oui-remove]').forEach(btn =>
        btn.addEventListener('click', () => removeOuiEntry(btn.dataset.ouiRemove)));

    renderOuiPager(matches.length, pages, start, shown.length);
}

/* Pagination rather than one endless list: 40,000 entries is far past what a
   scroll bar can address usefully. */
function renderOuiPager(total, pages, start, count) {
    const host = document.getElementById('ouiPager');
    if (!host) return;
    const from = count ? start + 1 : 0;
    host.innerHTML = `
        <button type="button" class="icon-btn" id="ouiFirst" ${ouiPage === 0 ? 'disabled' : ''} title="${t('first_page')}">«</button>
        <button type="button" class="icon-btn" id="ouiPrev" ${ouiPage === 0 ? 'disabled' : ''} title="${t('previous_page')}">‹</button>
        <span class="oui-pager__label">
            ${t('showing_range', { from: from, to: start + count, total: total })}
            <span class="oui-pager__page">${t('page_x_of_y', { page: ouiPage + 1, pages: pages })}</span>
        </span>
        <button type="button" class="icon-btn" id="ouiNext" ${ouiPage >= pages - 1 ? 'disabled' : ''} title="${t('next_page')}">›</button>
        <button type="button" class="icon-btn" id="ouiLast" ${ouiPage >= pages - 1 ? 'disabled' : ''} title="${t('last_page')}">»</button>`;

    const go = (page) => { ouiPage = page; displayOuiDatabase(); document.getElementById('ouiList').scrollTop = 0; };
    host.querySelector('#ouiFirst').addEventListener('click', () => go(0));
    host.querySelector('#ouiPrev').addEventListener('click', () => go(ouiPage - 1));
    host.querySelector('#ouiNext').addEventListener('click', () => go(ouiPage + 1));
    host.querySelector('#ouiLast').addEventListener('click', () => go(pages - 1));
}

function addOuiEntry() {
    const oui = document.getElementById('newOui').value.trim().toUpperCase();
    const vendor = document.getElementById('newVendor').value.trim();
    
    if (!oui || !vendor) {
        showAlert(t('oui_fields_required'), 'error');
        return;
    }
    
    if (oui.length !== 6) {
        showAlert(t('oui_must_be_six'), 'error');
        return;
    }
    
    currentOuiDatabase[oui] = vendor;
    displayOuiDatabase();
    
    document.getElementById('newOui').value = '';
    document.getElementById('newVendor').value = '';
    
    showAlert(t('oui_added'));
}

function removeOuiEntry(oui) {
    if (confirm(t('confirm_delete_oui', { oui: oui }))) {
        delete currentOuiDatabase[oui];
        displayOuiDatabase();
        showAlert(t('oui_removed'));
    }
}

function editOuiEntry(oui, vendor) {
    const newVendor = prompt(t('prompt_new_vendor', { oui: oui }), vendor);
    if (newVendor && newVendor.trim() !== '' && newVendor !== vendor) {
        currentOuiDatabase[oui] = newVendor.trim();
        displayOuiDatabase();
        showAlert(t('oui_updated'));
    }
}

let ouiFilterTimer = null;

function filterOuiList() {
    // Debounced, and back to page 1 - staying on page 40 of a two-page result
    // would look like the search found nothing.
    clearTimeout(ouiFilterTimer);
    ouiFilterTimer = setTimeout(() => { ouiPage = 0; displayOuiDatabase(); }, 150);
}

/**
 * Device Types Management
 */

const DEVICE_CATEGORIES = [
    'unknown', 'tech', 'network', 'smart', 'media', 'security', 'transport',
    'office', 'mobile', 'computer', 'peripheral', 'entertainment', 'appliance',
    'iot', 'storage', 'gaming', 'medical', 'industrial',
];

function categoryOptions(selected) {
    return DEVICE_CATEGORIES.map(key =>
        `<option value="${key}"${key === selected ? ' selected' : ''}>${t('category_' + key)}</option>`).join('');
}

function displayDeviceTypes() {
    const deviceTypesList = document.getElementById('deviceTypesList');
    if (!deviceTypesList) return;

    cleanupDeviceTypeListeners();
    deviceTypesList.className = 'device-types-grid';

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    deviceTypesList.innerHTML = Object.entries(currentDeviceTypes).map(([typeName, typeInfo]) => {
        const slug = typeName.replace(/[^a-zA-Z0-9]/g, '_');
        return `
        <div class="device-type-card">
            <button type="button" class="device-type-card__icon" id="deviceIcon_${slug}"
                    data-icon-picker="deviceIcon_${slug}" data-device-type="${esc(typeName)}"
                    title="${t('icon_emoji')}">${esc(typeInfo.icon)}</button>
            <input type="text" class="device-type-card__name device-name-input"
                   data-device-type="${esc(typeName)}" value="${esc(typeName)}"
                   aria-label="${t('device_type_name')}">
            <div class="device-type-card__row">
                <select class="form-select device-category-select" data-device-type="${esc(typeName)}"
                        aria-label="${t('category')}">${categoryOptions(typeInfo.category)}</select>
                <button type="button" class="icon-btn icon-btn--danger device-remove-btn"
                        data-device-type="${esc(typeName)}" title="${t('delete')}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
                </button>
            </div>
            <input type="hidden" class="device-icon-input" data-device-type="${esc(typeName)}" value="${esc(typeInfo.icon)}">
        </div>`;
    }).join('');

    // The icon tile is the picker trigger; it writes into the hidden input the
    // save path already reads, so nothing downstream had to change.
    deviceTypesList.querySelectorAll('[data-icon-picker]').forEach(tile => {
        tile.addEventListener('click', () => {
            const hidden = tile.parentElement.querySelector('.device-icon-input');
            hidden.id = tile.dataset.iconPicker + '_value';
            openEmojiPicker(hidden.id);
            const sync = () => { tile.textContent = hidden.value; };
            hidden.addEventListener('change', sync);
            hidden.addEventListener('input', sync);
        });
    });

    attachDeviceTypeEventListeners();
}

// Global array to track active intervals for cleanup
let activeIntervals = [];

// Cleanup function to clear all intervals and event listeners
function cleanupDeviceTypeListeners() {
    // Clear all active intervals
    activeIntervals.forEach(intervalId => {
        clearInterval(intervalId);
    });
    activeIntervals = [];
    
    // Remove existing event listeners by replacing elements
    const elementsToClean = [
        '.device-icon-input',
        '.device-name-input', 
        '.device-category-select',
        '.device-remove-btn'
    ];
    
    elementsToClean.forEach(selector => {
        document.querySelectorAll(selector).forEach(element => {
            const newElement = element.cloneNode(true);
            element.parentNode.replaceChild(newElement, element);
        });
    });
}

function attachDeviceTypeEventListeners() {
    // Clean up previous listeners and intervals
    cleanupDeviceTypeListeners();
    
    // Icon input event listeners - improved without polling
    const iconInputs = document.querySelectorAll('.device-icon-input');
    
    iconInputs.forEach(input => {
        const deviceType = input.getAttribute('data-device-type');
        
        // Use proper event delegation instead of polling
        const handleIconChange = function() {
            updateDeviceTypeIcon(deviceType, this.value);
        };
        
        // Attach events with proper cleanup tracking
        input.addEventListener('input', handleIconChange, { passive: true });
        input.addEventListener('change', handleIconChange, { passive: true });
        input.addEventListener('blur', handleIconChange, { passive: true });
        
        // Special handling for emoji picker updates
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'attributes' && mutation.attributeName === 'value') {
                    updateDeviceTypeIcon(deviceType, input.value);
                } else if (mutation.type === 'characterData' || 
                          (mutation.type === 'childList' && input.value !== input.defaultValue)) {
                    updateDeviceTypeIcon(deviceType, input.value);
                }
            });
        });
        
        observer.observe(input, {
            attributes: true,
            attributeFilter: ['value'],
            characterData: true,
            childList: true,
            subtree: true
        });
        
        // Store observer for cleanup
        input._observer = observer;
    });
    
    // Name input event listeners
    document.querySelectorAll('.device-name-input').forEach(input => {
        input.addEventListener('change', function() {
            const oldName = this.getAttribute('data-device-type');
            const newName = this.value;
            updateDeviceTypeName(oldName, newName);
        }, { passive: true });
    });
    
    // Category select event listeners
    document.querySelectorAll('.device-category-select').forEach(select => {
        select.addEventListener('change', function() {
            const deviceType = this.getAttribute('data-device-type');
            const newCategory = this.value;
            updateDeviceTypeCategory(deviceType, newCategory);
        }, { passive: true });
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
        updateDetectionRuleSelects();
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
        showAlert(t('device_type_name_icon_required'), 'error');
        return;
    }
    
    currentDeviceTypes[typeName] = {
        icon: icon,
        category: category
    };
    
    displayDeviceTypes();
    updateDetectionRuleSelects();
    
    document.getElementById('newDeviceType').value = '';
    document.getElementById('newDeviceIcon').value = '';
    document.getElementById('newDeviceCategory').value = 'unknown';
    
    showAlert(t('device_type_added'));
}

function removeDeviceType(typeName) {
    if (confirm(t('confirm_delete_device_type', {type: typeName}))) {
        delete currentDeviceTypes[typeName];
        displayDeviceTypes();
        updateDetectionRuleSelects();
        showAlert(t('device_type_deleted'));
    }
}

/**
 * Detection Rules Management
 */
function deviceTypeOptions(selected) {
    return Object.entries(currentDeviceTypes)
        .map(([name, info]) => `<option value="${name}"${name === selected ? ' selected' : ''}>${info.icon || ''} ${name}</option>`)
        .join('');
}

/*
 * Each rule is "this regex means this device type". The type used to be
 * printed as plain text, so there was no way to see it as a choice or fix a
 * wrong one without deleting the rule and retyping the pattern.
 */
function renderPatternRules(container, rules, kind) {
    if (!rules.length) {
        container.innerHTML = `<div class="pattern-empty">${t('no_patterns_yet')}</div>`;
        return;
    }
    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    container.innerHTML = rules.map((rule, index) => `
        <div class="pattern-item">
            <input type="text" class="form-input pattern-item__pattern" value="${esc(rule.pattern)}"
                   data-pattern-index="${index}" spellcheck="false"
                   aria-label="${t('pattern')}" title="${esc(rule.pattern)}">
            <select class="form-select pattern-item__type" data-rule-kind="${kind}" data-rule-index="${index}"
                    aria-label="${t('device_type')}">${deviceTypeOptions(rule.type)}</select>
            <button type="button" class="icon-btn icon-btn--danger" data-remove-kind="${kind}" data-remove-index="${index}"
                    title="${t('delete')}">
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
            </button>
        </div>`).join('');

    // The pattern is a regex the scanner will compile, so a typo here silently
    // stops matching. Validate on edit and say so rather than saving garbage.
    container.querySelectorAll('[data-pattern-index]').forEach(input => {
        const commit = () => {
            const value = input.value.trim();
            const rule = rules[Number(input.dataset.patternIndex)];
            if (!value) {
                input.value = rule.pattern;
                input.classList.remove('is-invalid');
                return;
            }
            try {
                new RegExp(value, 'i');
            } catch (e) {
                input.classList.add('is-invalid');
                input.title = t('invalid_regex') + ' ' + e.message;
                return;
            }
            input.classList.remove('is-invalid');
            input.title = value;
            if (rule.pattern !== value) {
                rule.pattern = value;
                showAlert(t('detection_rule_updated'));
            }
        };
        input.addEventListener('change', commit);
        input.addEventListener('blur', commit);
        input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); input.blur(); } });
    });

    container.querySelectorAll('[data-rule-kind]').forEach(select => {
        select.addEventListener('change', () => {
            rules[Number(select.dataset.ruleIndex)].type = select.value;
            showAlert(t('detection_rule_updated'));
        });
    });
    container.querySelectorAll('[data-remove-kind]').forEach(btn => {
        btn.addEventListener('click', () => {
            const i = Number(btn.dataset.removeIndex);
            if (btn.dataset.removeKind === 'hostname') removeHostnamePattern(i);
            else removeVendorPattern(i);
        });
    });
}

/**
 * Combined rules: vendor AND hostname, both required.
 *
 * A single-signal rule cannot separate a MacBook from an iPhone - the vendor
 * is "Apple" either way - which is why a laptop kept coming back as a generic
 * "Apple Device". These are evaluated before every heuristic the scanner has.
 */
function renderCombinedRules(container, rules) {
    if (!rules.length) {
        container.innerHTML = `<div class="pattern-empty">${t('no_patterns_yet')}</div>`;
        return;
    }
    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    container.innerHTML = rules.map((rule, index) => `
        <div class="pattern-item pattern-item--combined">
            <input type="text" class="form-input pattern-item__pattern" value="${esc(rule.vendor || '')}"
                   data-combined-index="${index}" data-combined-field="vendor" spellcheck="false"
                   placeholder="${t('vendor')}" aria-label="${t('vendor')}">
            <span class="pattern-item__and">${t('and')}</span>
            <input type="text" class="form-input pattern-item__pattern" value="${esc(rule.hostname || '')}"
                   data-combined-index="${index}" data-combined-field="hostname" spellcheck="false"
                   placeholder="${t('hostname')}" aria-label="${t('hostname')}">
            <select class="form-select pattern-item__type" data-combined-type="${index}"
                    aria-label="${t('device_type')}">${deviceTypeOptions(rule.type)}</select>
            <button type="button" class="icon-btn icon-btn--danger" data-combined-remove="${index}"
                    title="${t('delete')}">
                <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
            </button>
        </div>`).join('');

    container.querySelectorAll('[data-combined-index]').forEach(input => {
        const commit = () => {
            const value = input.value.trim();
            const rule = rules[Number(input.dataset.combinedIndex)];
            const field = input.dataset.combinedField;
            // An empty side means "any", which is what `.*` does in the scanner.
            if (value) {
                try {
                    new RegExp(value, 'i');
                } catch (e) {
                    input.classList.add('is-invalid');
                    input.title = t('invalid_regex') + ' ' + e.message;
                    return;
                }
            }
            input.classList.remove('is-invalid');
            input.title = value;
            if (rule[field] !== value) {
                rule[field] = value;
                showAlert(t('detection_rule_updated'));
            }
        };
        input.addEventListener('change', commit);
        input.addEventListener('blur', commit);
        input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); input.blur(); } });
    });

    container.querySelectorAll('[data-combined-type]').forEach(select => {
        select.addEventListener('change', () => {
            rules[Number(select.dataset.combinedType)].type = select.value;
            showAlert(t('detection_rule_updated'));
        });
    });
    container.querySelectorAll('[data-combined-remove]').forEach(btn => {
        btn.addEventListener('click', () => {
            rules.splice(Number(btn.dataset.combinedRemove), 1);
            displayDetectionRules();
            showAlert(t('detection_rule_removed'));
        });
    });
}

function addCombinedRule() {
    const vendor = document.getElementById('newCombinedVendor').value.trim();
    const hostname = document.getElementById('newCombinedHostname').value.trim();
    const deviceType = document.getElementById('newCombinedDeviceType').value;

    // One of the two may be blank ("any Raspberry Pi"), but not both - a rule
    // that matches everything would swallow the whole device list.
    if ((!vendor && !hostname) || !deviceType) {
        showAlert(t('pattern_fields_required'), 'error');
        return;
    }

    if (!currentSettings.detection_rules) currentSettings.detection_rules = {};
    if (!currentSettings.detection_rules.combined_rules) currentSettings.detection_rules.combined_rules = [];
    currentSettings.detection_rules.combined_rules.push({ vendor, hostname, type: deviceType });

    document.getElementById('newCombinedVendor').value = '';
    document.getElementById('newCombinedHostname').value = '';
    document.getElementById('newCombinedDeviceType').value = '';
    displayDetectionRules();
    showAlert(t('detection_rule_added'));
}

function displayDetectionRules() {
    const hostnamePatterns = document.getElementById('hostnamePatterns');
    const vendorPatterns = document.getElementById('vendorPatterns');
    if (!hostnamePatterns || !vendorPatterns) return;

    const detectionRules = currentSettings.detection_rules || {};
    const combined = document.getElementById('combinedRules');
    if (combined) renderCombinedRules(combined, detectionRules.combined_rules || []);
    renderPatternRules(hostnamePatterns, detectionRules.hostname_patterns || [], 'hostname');
    renderPatternRules(vendorPatterns, detectionRules.vendor_patterns || [], 'vendor');
}

function addHostnamePattern() {
    const pattern = document.getElementById('newHostnamePattern').value.trim();
    const deviceType = document.getElementById('newHostnameDeviceType').value;
    
    if (!pattern || !deviceType) {
        showAlert(t('pattern_fields_required'), 'error');
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
    showAlert(t('hostname_pattern_added'));
}

function addVendorPattern() {
    const pattern = document.getElementById('newVendorPattern').value.trim();
    const deviceType = document.getElementById('newVendorDeviceType').value;
    
    if (!pattern || !deviceType) {
        showAlert(t('pattern_fields_required'), 'error');
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
    showAlert(t('vendor_pattern_added'));
}

function removeHostnamePattern(index) {
    if (currentSettings.detection_rules && currentSettings.detection_rules.hostname_patterns) {
        currentSettings.detection_rules.hostname_patterns.splice(index, 1);
        displayDetectionRules();
        showAlert(t('hostname_pattern_removed'));
    }
}

function removeVendorPattern(index) {
    if (currentSettings.detection_rules && currentSettings.detection_rules.vendor_patterns) {
        currentSettings.detection_rules.vendor_patterns.splice(index, 1);
        displayDetectionRules();
        showAlert(t('vendor_pattern_removed'));
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
            showAlert(t('detection_rules_saved'));
        } else {
            showAlert(t('save_error') + data.error, 'error');
        }
    })
    .catch(error => {
        showAlert(t('save_error') + error, 'error');
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
            div.className = 'port-rule';
            div.innerHTML = `
                <span><strong>${deviceType}:</strong> ${ports.join(', ')}</span>
                <button type="button" class="icon-btn icon-btn--danger" onclick="removeDevicePortRule('${deviceType}')" title="${t('delete')}">
                    <svg class="ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-trash"/></svg>
                </button>`;
            container.appendChild(div);
        }
    }
}

function addDeviceTypePorts() {
    const deviceType = document.getElementById('deviceTypePortSelect').value;
    const ports = document.getElementById('deviceTypePorts').value.trim();
    
    if (!deviceType || !ports) {
        showAlert(t('device_ports_required'), 'error');
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
    showAlert(t('device_port_rule_added'));
}

function removeDevicePortRule(deviceType) {
    if (currentSettings.port_settings?.device_specific_ports) {
        delete currentSettings.port_settings.device_specific_ports[deviceType];
        displayDevicePortRules();
        showAlert(t('device_port_rule_removed'));
    }
}

/**
 * Network Management
 */
/**
 * Interfaces grouped by the network range they sit on.
 *
 * A flat list hid the one fact that matters on a multi-homed box: end0 and
 * wlan0 are two doors into the *same* 192.168.1.0/24, while every br-* is its
 * own island. Grouping by range says that at a glance; the old list made you
 * compare CIDRs by eye down a page of identical cards.
 */
function renderNetworkGroups(host, networks) {
    const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    const groups = new Map();
    (networks || []).forEach(n => {
        const key = n.network_range || n.ip || '?';
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(n);
    });

    if (!groups.size) {
        host.innerHTML = `<div class="pattern-empty">${t('no_networks_found')}</div>`;
        return;
    }

    // Shared ranges first - those are the ones worth a second look.
    const ordered = [...groups.entries()].sort((a, b) =>
        b[1].length - a[1].length || a[0].localeCompare(b[0]));

    host.innerHTML = ordered.map(([range, members]) => `
        <section class="net-group">
            <header class="net-group__head">
                <div>
                    <span class="net-group__range mono">${esc(range)}</span>
                    <span class="net-group__count">${members.length} ${t(members.length === 1 ? 'interface' : 'interfaces')}</span>
                </div>
                ${members.length > 1
                    ? `<span class="ds-badge ds-badge--info">${t('shared_segment')}</span>` : ''}
            </header>
            <div class="net-group__body">
                ${members.map(n => `
                    <article class="net-iface">
                        <div class="net-iface__name mono">${esc(n.interface)}</div>
                        <span class="network-type">${esc(n.type)}</span>
                        <dl class="net-iface__facts">
                            <div><dt>IP</dt><dd class="mono">${esc(n.ip)}</dd></div>
                            <div><dt>${t('netmask')}</dt><dd class="mono">${esc(n.netmask)}</dd></div>
                            ${n.description ? `<div><dt>${t('description')}</dt><dd>${esc(n.description)}</dd></div>` : ''}
                        </dl>
                    </article>`).join('')}
            </div>
        </section>`).join('');
}

async function loadNetworks() {
    try {
        const response = await fetch('/api/networks');
        const networks = await response.json();
        
        const networksList = document.getElementById('networksList');
        if (!networksList) return;
        
        renderNetworkGroups(networksList, networks);
    } catch (error) {
        showAlert(t('networks_load_error') + error.message, 'error');
    }
}

function refreshNetworks() {
    loadNetworks();
    showAlert(t('networks_refreshed'));
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
            showAlert(t('form_elements_missing'), 'error');
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
        showAlert(t('settings_save_error') + error.message, 'error');
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
        showAlert(t('oui_save_error') + error.message, 'error');
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
        showAlert(t('device_types_save_error') + error.message, 'error');
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
                showAlert(t('oui_imported', { count: Object.keys(importedData).length }));
            } catch (error) {
                showAlert(t('import_invalid_json'), 'error');
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
    btn.textContent = t('downloading');
    
    try {
        const response = await fetch('/api/download_ieee_oui');
        const result = await response.json();
        
        if (result.success) {
            showAlert(t('ieee_updated', { count: result.processed_count }));
            loadAllSettings();
        } else {
            showAlert(t('ieee_download_error') + result.error, 'error');
        }
    } catch (error) {
        showAlert(t('connection_error') + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function lookupVendorAPI() {
    const oui = document.getElementById('newOui').value.trim();
    
    if (!oui || oui.length !== 6) {
        showAlert(t('oui_must_be_six'), 'error');
        return;
    }
    
    const btn = document.getElementById('apiLookupBtn');
    const originalText = btn.textContent;
    
    btn.disabled = true;
    btn.textContent = t('searching');
    
    try {
        const testMac = oui + '123456';
        
        const response = await fetch(`/api/lookup_vendor/${testMac}`);
        const result = await response.json();
        
        if (result.success) {
            document.getElementById('newVendor').value = result.vendor;
            showAlert(`Vendor bulundu: ${result.vendor} (Kaynak: ${result.source})`);
        } else {
            showAlert(t('vendor_not_found') + result.error, 'error');
        }
    } catch (error) {
        showAlert(t('api_lookup_error') + error.message, 'error');
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
    const combinedSelect = document.getElementById('newCombinedDeviceType');

    if (!hostnameSelect || !vendorSelect || !devicePortSelect) return;

    // Leading placeholder: without it the picker silently pre-selects whatever
    // sorts first, and "Add" quietly files the rule under Access Point.
    if (combinedSelect) {
        combinedSelect.innerHTML =
            `<option value="">${t('select_device_type')}</option>` + deviceTypeOptions('');
    }
    hostnameSelect.innerHTML = `<option value="">${t('select_device_type')}</option>`;
    vendorSelect.innerHTML = `<option value="">${t('select_device_type')}</option>`;
    devicePortSelect.innerHTML = `<option value="">${t('select_device_type_for_ports')}</option>`;
    
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

    ['dockerSearch', 'dockerStackFilter', 'dockerNetworkFilter'].forEach(id => {
        const node = document.getElementById(id);
        if (node) node.addEventListener('input', renderDocker);
    });
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
        showAlert(t('docker_load_error') + error.message, 'error');
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
                                ${data.networks_count} ${t('docker_networks')}, ${data.containers_count} ${t('docker_containers')}, ${data.scan_ranges_count} ${t('scan_ranges')}
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
                        <div class="stat-label">${t('scan_ranges')}</div>
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
                            <strong>${t('docker_unavailable')}</strong>
                            <div style="font-size: 0.9em; opacity: 0.8;">
                                ${data.error || t('docker_unavailable')}
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

/*
 * Docker tab: one filter bar over both lists.
 *
 * Networks and containers were two unrelated walls of cards, each written with
 * hardcoded hex colours. They are now filtered together by text / stack /
 * network, because "which containers are in the telegram stack" was a question
 * you could only answer by scrolling.
 */
const dockerState = { networks: [], containers: [] };

function dockerEsc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function dockerFilters() {
    const value = id => (document.getElementById(id) || {}).value || '';
    return {
        text: value('dockerSearch').trim().toLowerCase(),
        stack: value('dockerStackFilter'),
        network: value('dockerNetworkFilter'),
    };
}

function containerMatches(c, f) {
    if (f.stack && (c.stack || '') !== f.stack) return false;
    if (f.network && !(c.networks || []).includes(f.network)) return false;
    if (!f.text) return true;
    return [c.name, c.image, c.stack, c.service, c.id, (c.networks || []).join(' ')]
        .join(' ').toLowerCase().includes(f.text);
}

function networkMatches(n, f) {
    if (f.network && n.name !== f.network) return false;
    // A stack filter narrows networks to the ones its containers actually use.
    if (f.stack) {
        const used = dockerState.containers
            .filter(c => (c.stack || '') === f.stack)
            .some(c => (c.networks || []).includes(n.name));
        if (!used) return false;
    }
    if (!f.text) return true;
    return [n.name, n.driver, n.id, (n.subnets || []).join(' ')]
        .join(' ').toLowerCase().includes(f.text);
}

/** Rebuild the two selects from whatever the daemon currently reports. */
function refreshDockerFilterOptions() {
    const stacks = [...new Set(dockerState.containers.map(c => c.stack).filter(Boolean))].sort();
    const nets = [...new Set([
        ...dockerState.networks.map(n => n.name),
        ...dockerState.containers.flatMap(c => c.networks || []),
    ].filter(Boolean))].sort();

    const fill = (id, values, allLabel) => {
        const select = document.getElementById(id);
        if (!select) return;
        const previous = select.value;
        select.innerHTML = `<option value="">${allLabel}</option>` +
            values.map(v => `<option value="${dockerEsc(v)}">${dockerEsc(v)}</option>`).join('');
        if (values.includes(previous)) select.value = previous;
    };
    fill('dockerStackFilter', stacks, t('all_stacks'));
    fill('dockerNetworkFilter', nets, t('all_networks'));
}

function renderDockerNetworks() {
    const host = document.getElementById('dockerNetworksList');
    if (!host) return;
    const shown = dockerState.networks.filter(n => networkMatches(n, dockerFilters()));
    if (!shown.length) {
        host.innerHTML = `<div class="pattern-empty">${t('no_docker_networks')}</div>`;
        return;
    }
    host.innerHTML = shown.map(n => {
        const count = (n.containers || []).length;
        const subnets = (n.subnets || []).length ? n.subnets.join(', ') : '—';
        return `
            <article class="docker-card">
                <header class="docker-card__head">
                    <span class="docker-card__name mono">${dockerEsc(n.name)}</span>
                    <span class="network-type">${dockerEsc(n.driver)}</span>
                    ${n.internal ? `<span class="ds-badge ds-badge--critical">${t('internal')}</span>` : ''}
                </header>
                <dl class="docker-card__facts">
                    <div><dt>ID</dt><dd class="mono">${dockerEsc(n.id)}</dd></div>
                    <div><dt>${t('subnet')}</dt><dd class="mono">${dockerEsc(subnets)}</dd></div>
                    ${n.gateway ? `<div><dt>Gateway</dt><dd class="mono">${dockerEsc(n.gateway)}</dd></div>` : ''}
                    <div><dt>${t('docker_containers')}</dt><dd>${count}</dd></div>
                </dl>
            </article>`;
    }).join('');
}

function renderDockerContainers() {
    const host = document.getElementById('dockerContainersList');
    if (!host) return;
    const shown = dockerState.containers.filter(c => containerMatches(c, dockerFilters()));
    if (!shown.length) {
        host.innerHTML = `<div class="pattern-empty">${t('no_docker_containers')}</div>`;
        return;
    }

    // Grouped by stack: a compose project is the unit people think in, and
    // loose `docker run` containers collect under one "no stack" heading.
    const byStack = new Map();
    shown.forEach(c => {
        const key = c.stack || '';
        if (!byStack.has(key)) byStack.set(key, []);
        byStack.get(key).push(c);
    });
    const ordered = [...byStack.entries()].sort((a, b) =>
        (a[0] ? 0 : 1) - (b[0] ? 0 : 1) || a[0].localeCompare(b[0]));

    host.innerHTML = ordered.map(([stack, list]) => `
        <section class="net-group">
            <header class="net-group__head">
                <div>
                    <span class="net-group__range">${dockerEsc(stack || t('no_stack'))}</span>
                    <span class="net-group__count">${list.length}</span>
                </div>
            </header>
            <div class="net-group__body">
                ${list.map(c => `
                    <article class="docker-card">
                        <header class="docker-card__head">
                            <span class="docker-card__name mono">${dockerEsc(c.name)}</span>
                            <span class="ds-badge ds-badge--success">${t('running')}</span>
                        </header>
                        <dl class="docker-card__facts">
                            <div><dt>${t('docker_image')}</dt><dd>${dockerEsc(c.image)}</dd></div>
                            ${c.service ? `<div><dt>${t('service')}</dt><dd>${dockerEsc(c.service)}</dd></div>` : ''}
                            <div><dt>${t('docker_network')}</dt><dd class="mono">${dockerEsc((c.networks || []).join(', ') || '—')}</dd></div>
                            <div><dt>IP</dt><dd class="mono">${dockerEsc((c.ip_addresses || []).map(a => a.ipv4).filter(Boolean).join(', ') || '—')}</dd></div>
                            <div><dt>${t('status')}</dt><dd>${dockerEsc(c.status)}</dd></div>
                        </dl>
                    </article>`).join('')}
            </div>
        </section>`).join('');
}

function renderDocker() {
    renderDockerNetworks();
    renderDockerContainers();
}

async function loadDockerNetworks() {
    const host = document.getElementById('dockerNetworksList');
    try {
        const data = await (await fetch('/api/docker/networks')).json();
        dockerState.networks = (data.success && data.networks) || [];
        refreshDockerFilterOptions();
        renderDockerNetworks();
    } catch (error) {
        if (host) host.innerHTML = `<div class="pattern-empty">Docker networks: ${dockerEsc(error.message)}</div>`;
    }
}

async function loadDockerContainers() {
    const host = document.getElementById('dockerContainersList');
    try {
        const data = await (await fetch('/api/docker/containers')).json();
        dockerState.containers = (data.success && data.containers) || [];
        refreshDockerFilterOptions();
        renderDockerContainers();
    } catch (error) {
        if (host) host.innerHTML = `<div class="pattern-empty">Docker containers: ${dockerEsc(error.message)}</div>`;
    }
}

async function loadDockerScanRanges() {
    try {
        const response = await fetch('/api/docker/scan_ranges');
        const data = await response.json();
        
        const scanRangesContainer = document.getElementById('dockerScanRangesList');
        if (!scanRangesContainer) return;
        
        if (!data.success || !data.scan_ranges || data.scan_ranges.length === 0) {
            scanRangesContainer.innerHTML = `<div class="pattern-empty">${t('no_docker_ranges')}</div>`;
            return;
        }
        
        let scanRangesHtml = '';
        data.scan_ranges.forEach(range => {
            scanRangesHtml += `
                <div style="background: var(--bg-surface-sunken); padding: 15px; border-radius: 6px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                                <strong style="color: #0066cc;">${range.network_name}</strong>
                                <span style="background: #17a2b8; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em;">${range.driver}</span>
                            </div>
                            <div style="font-size: 0.9em; color: var(--text-tertiary); margin-bottom: 5px;">
                                <strong>Subnet:</strong> ${range.subnet}
                            </div>
                            <div style="font-size: 0.9em; color: var(--text-tertiary); margin-bottom: 5px;">
                                <strong>Scan Range:</strong> <code style="background: #e9ecef; padding: 2px 6px; border-radius: 4px;">${range.scan_range}</code>
                            </div>
                            ${range.gateway ? `<div style="font-size: 0.9em; color: var(--text-tertiary); margin-bottom: 5px;"><strong>Gateway:</strong> ${range.gateway}</div>` : ''}
                            <div style="font-size: 0.9em; color: var(--text-tertiary);">
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
            scanRangesContainer.innerHTML = `<div class="pattern-empty">Docker scan ranges: ${error.message}</div>`;
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
        scanRangesContainer.innerHTML = `<div class="loading">${t('scan_ranges_loading')}</div>`;
    }
    await loadDockerScanRanges();
    showAlert(t('docker_ranges_refreshed'));
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
            showAlert(t('docker_range_added', { network: networkName, subnet: subnet }));
        }
    }, 100);
}
/* ---------------- Access control (login gate) ----------------------------
   Kept at the end of config.js so it does not disturb the existing settings
   code. Credentials themselves live in .env and are never sent from here. */
(function () {
  'use strict';

  function esc(v) { var d = document.createElement('div'); d.textContent = v == null ? '' : String(v); return d.innerHTML; }

  function render(s) {
    var box = document.getElementById('loginRequired');
    var badge = document.getElementById('authBadge');
    var hint = document.getElementById('authHint');
    if (!box) return;

    box.checked = !!s.login_required;
    // Cannot enable a gate with no key: that locks everyone out of a LAN app.
    box.disabled = !s.credentials_configured && !s.login_required;

    badge.textContent = s.active ? t('auth_sign_in_required') : t('auth_open_to_network');
    badge.className = 'ds-badge ' + (s.active ? 'ds-badge--success' : 'ds-badge--warning');

    if (!s.credentials_configured) {
      // A container has no .env the user can edit, so telling them to go add
      // one made this switch permanently dead exactly where it matters most.
      // Set the credentials here; the server stores a PBKDF2 hash.
      hint.innerHTML =
        '<div class="ds-alert ds-alert--warning">' +
          '<svg class="ds-alert__icon ds-icon ds-icon--sm" aria-hidden="true"><use href="#i-alert"/></svg>' +
          '<div style="flex:1">' + t('auth_no_credentials') +
            '<div class="ds-row" style="margin-top:var(--space-3)">' +
              '<input class="ds-input" id="authUser" autocomplete="username" ' +
                'placeholder="' + t('auth_username_placeholder') + '">' +
              '<input class="ds-input" id="authPass" type="password" autocomplete="new-password" ' +
                'placeholder="' + t('auth_password_placeholder') + '">' +
              '<button class="ds-btn ds-btn--primary" id="authSave" type="button">' +
                t('auth_save_credentials') + '</button>' +
            '</div>' +
            '<div class="ds-dim" style="margin-top:var(--space-2)">' + t('auth_env_alternative') +
              ' <code>MYNES_AUTH_USERNAME</code> / <code>MYNES_AUTH_PASSWORD</code></div>' +
          '</div></div>';
      var save = document.getElementById('authSave');
      if (save) save.addEventListener('click', saveCredentials);
    } else {
      hint.innerHTML =
        '<div class="ds-dim">' + t('auth_signed_in_as', { user: esc(s.username) }) +
        (s.active ? ' <a href="/logout">' + t('auth_sign_out') + '</a>.' : '') + '</div>';
    }
  }

  function load() {
    return fetch('/api/auth/status').then(function (r) { return r.json(); }).then(render);
  }

  function saveCredentials() {
    var user = (document.getElementById('authUser') || {}).value || '';
    var pass = (document.getElementById('authPass') || {}).value || '';
    return fetch('/api/auth/credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass })
    })
      .then(function (r) { return r.json(); })
      .then(function (r) {
        if (!r.ok) {
          if (window.MyNeS) window.MyNeS.toast(r.error, 'critical');
          else window.alert(r.error);
          return;
        }
        if (window.MyNeS) window.MyNeS.toast(t('auth_credentials_saved'), 'success');
        return load();
      });
  }

  function init() {
    var box = document.getElementById('loginRequired');
    if (!box) return;

    box.addEventListener('change', function () {
      fetch('/api/auth/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login_required: box.checked })
      })
        .then(function (r) { return r.json(); })
        .then(function (r) {
          if (!r.ok) {
            box.checked = !box.checked;
            if (window.MyNeS) window.MyNeS.toast(r.error, 'critical');
            else window.alert(r.error);
            return;
          }
          if (window.MyNeS) {
            window.MyNeS.toast(r.login_required ? t('auth_enabled_toast') : t('auth_disabled_toast'),
              r.login_required ? 'success' : 'warning');
          }
          return load();
        });
    });

    load();
    // Same race as the rest of this page: translations.js fetches its table
    // after we have already painted, so re-render once it lands.
    window.addEventListener('translationsLoaded', load);
  }

  // Guard on readyState: if this file is served from cache after the document
  // has already parsed, a bare DOMContentLoaded listener never fires.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
