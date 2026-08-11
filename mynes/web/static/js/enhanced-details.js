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
        `🔬 ${device.ip} - ${device.alias || device.hostname || t('det_unknown_device')}`;
    
    // Modal'ı göster
    document.getElementById('enhancedDetailsModal').style.display = 'block';

    // İlk tab'ı aktif et.
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

    // Enhanced info'yu al ve normal-scan/AI verisinden eksik bölümleri türet.
    const rawInfo = currentDevice.enhanced_comprehensive_info ||
                    currentDevice.advanced_scan_summary ||
                    currentDevice.enhanced_info || {};
    const enhancedInfo = deriveEnhancedInfo(currentDevice, rawInfo);

    let content = '';
    
    switch (tabName) {
        case 'overview':
            content = generateOverviewContent(enhancedInfo, currentDevice);
            break;
        case 'ai':
            content = generateAIContent(currentDevice, enhancedInfo);
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
            content = `<div class="details-no-data">${t('det_no_data')}</div>`;
    }
    
    contentDiv.innerHTML = content;
}

// Comprehensive-scan yapılmamış olsa bile normal tarama + AI zaten çok şey
// biliyor (açık portlar, SSH banner'ı, OS ailesi, cihaz-tipi skorları). Bu
// veriyi tabların beklediği bölüm şekline dönüştür ki sekmeler "veri yok"
// yerine gerçek bilgiyi göstersin. Yalnızca EKSİK bölümleri doldururuz;
// gerçek comprehensive-scan sonucu her zaman kazanır.
function deriveEnhancedInfo(device, rawInfo) {
    const info = { ...(rawInfo || {}) };
    const ai = getAiIdentification(device, rawInfo) || {};
    const ad = device.analysis_data || {};
    const nsi = ad.normal_scan_info || {};
    const idres = nsi.identification_result || {};
    const sys = idres.system_info || {};
    const ports = (device.open_ports || []).filter(p => p && p.port);
    const isRpi = /raspberry/i.test((ai.brand || '') + (ai.manufacturer || '') + (device.vendor || ''));

    const isWeb = p => /http|web/i.test(p.service || '') ||
        [80, 443, 8000, 8008, 8080, 8443, 8888, 5000].includes(p.port);
    const isSsh = p => p.port === 22 || /ssh/i.test(p.service || '');

    // Port Analysis: açık port listesinden doğrudan.
    if (!info.detailed_ports || !Object.keys(info.detailed_ports).length) {
        const dp = {};
        for (const p of ports) dp[String(p.port)] = {
            state: p.state || 'open', service: p.service || '',
            version: p.version || '', product: p.product || ''
        };
        if (Object.keys(dp).length) info.detailed_ports = dp;
    }

    // System Information: OS ailesi + SSH banner + TTL (normal taramadan).
    info.system_identification = info.system_identification || {};
    if (!Object.keys(info.system_identification.os_detection || {}).length &&
        (sys.os || sys.ssh_banner || ai.what_it_is)) {
        info.system_identification.os_detection = {
            basic: {
                os_family: sys.os || '', ttl: sys.ttl,
                ssh_banner: sys.ssh_banner || '', ssh_version: sys.ssh_version || '',
                identified: [ai.brand, ai.model].filter(Boolean).join(' ')
            }
        };
    }

    // Network Services: SSH banner'ı + kalan açık servisler.
    info.remote_access = info.remote_access || {};
    if (!Object.keys(info.remote_access.ssh || {}).length && (sys.ssh_banner || ports.some(isSsh))) {
        info.remote_access.ssh = { banner: sys.ssh_banner || '', version: sys.ssh_version || '' };
    }
    if (!info.web_services || !Object.keys(info.web_services).length) {
        const web = {};
        for (const p of ports.filter(isWeb)) web[`${(p.service || 'http').toUpperCase()} :${p.port}`] =
            { status_code: 'open', title: p.product || t('det_from_portscan') || 'Detected via port scan', server: p.version || '' };
        if (Object.keys(web).length) info.web_services = web;
    }
    if (!info.network_services || !Object.keys(info.network_services).length) {
        const net = {};
        for (const p of ports.filter(p => !isWeb(p) && !isSsh(p)))
            net[`${p.service || 'service'} (${p.port})`] = { port: p.port, state: p.state || 'open', product: p.product || '' };
        if (Object.keys(net).length) info.network_services = net;
    }

    // Hardware: AI'nın bulduğu donanım özelliklerini yüzeye çıkar.
    if (isRpi && (ai.key_features || []).length) {
        info.raspberry_pi_analysis = info.raspberry_pi_analysis || {};
        if (!Object.keys(info.raspberry_pi_analysis.hardware || {}).length) {
            const hw = {};
            if (ai.model) hw['🧩 Model'] = ai.model;
            (ai.key_features || []).forEach((f, i) => { hw[`• ${i + 1}`] = f; });
            info.raspberry_pi_analysis.hardware = hw;
        }
    }

    // Security: gerçek CVE verisi yoksa AI güvenlik notunu göster.
    const sec = info.security_analysis || {};
    if (!(sec.findings || []).length && !(sec.exposures || []).length && !sec.risk_level && ai.security_notes) {
        info.security_analysis = {
            risk_level: 'info', risk_score: 0,
            exposures: [{ title: t('ai_security') === 'ai_security' ? 'AI security note' : t('ai_security'),
                          description: ai.security_notes, severity: 'info' }]
        };
    }

    // Overview cihaz-tipi olasılıkları: normal-tarama skorları (max'a göre
    // normalize) + AI'nın kimliği. 0% yerine gerçek sinyali göster.
    const scores = idres.scores || {};
    const probs = {};
    const maxScore = Math.max(1, ...Object.values(scores).map(Number));
    for (const [k, v] of Object.entries(scores)) probs[k] = Math.min(1, (Number(v) || 0) / maxScore);
    if (ai.confidence) {
        const conf = Number(ai.confidence) || 0;
        if (isRpi) probs.raspberry_pi = Math.max(probs.raspberry_pi || 0, conf);
        if (/comput|server|sbc|single.board/i.test((ai.category || '') + (ai.product_type || '')))
            probs.computer = Math.max(probs.computer || 0, conf);
    }
    if (Object.keys(probs).length &&
        !Object.keys((info.device_type_analysis || {}).device_probabilities || {}).length) {
        info.device_type_analysis = { device_probabilities: probs, indicators: {} };
    }

    return info;
}

// Genel Bakış içeriği
function generateOverviewContent(enhancedInfo, device) {
    const basicInfo = enhancedInfo.basic_info || {};
    const raspberryInfo = enhancedInfo.raspberry_pi_analysis || {};
    const iotInfo = enhancedInfo.iot_analysis || {};
    
    return `
        <div class="details-section">
            <h4>📊 ${t('det_summary')}</h4>
            <div class="details-grid">
                <div class="details-card">
                    <h5>🔍 ${t('det_basic_info')}</h5>
                    <ul class="details-list">
                        <li><span class="details-label">IP Adresi:</span><span class="details-value">${device.ip}</span></li>
                        <li><span class="details-label">MAC Adresi:</span><span class="details-value">${device.mac}</span></li>
                        <li><span class="details-label">Hostname:</span><span class="details-value">${device.hostname || 'N/A'}</span></li>
                        <li><span class="details-label">Alias:</span><span class="details-value">${device.alias || 'N/A'}</span></li>
                        <li><span class="details-label">Vendor:</span><span class="details-value">${device.vendor || 'N/A'}</span></li>
                        <li><span class="details-label">${t('status')}:</span><span class="details-value">
                            <span class="status-badge status-${device.status}">${device.status}</span>
                        </span></li>
                        <li><span class="details-label">${t('last_seen')}:</span><span class="details-value">${formatDate(device.last_seen)}</span></li>
                        ${device.last_enhanced_analysis ?
                            `<li><span class="details-label">${t('det_last_analysis') || 'Last Analysis'}:</span><span class="details-value">${formatDate(device.last_enhanced_analysis)}</span></li>` : ''
                        }
                    </ul>
                </div>

                <div class="details-card">
                    <h5>🎯 ${t('det_type_probs')}</h5>
                    ${generateDeviceTypeProbabilities(enhancedInfo)}
                </div>
            </div>
        </div>
        
        ${generateQuickStats(enhancedInfo, device)}
    `;
}

// Ağ Servisleri içeriği. A web service that only produced a connection error
// means the port is closed - we render those quietly, not as a scary traceback.
function generateNetworkContent(enhancedInfo) {
    const webServices = enhancedInfo.web_services || {};
    const networkServices = enhancedInfo.network_services || {};
    const sshInfo = enhancedInfo.remote_access?.ssh || {};

    const reachableWeb = Object.entries(webServices).filter(([, d]) => !d || !d.error);

    return `
        <div class="details-section">
            <h4>🌐 ${t('det_web_services')}</h4>
            ${reachableWeb.length > 0 ?
                generateWebServicesGrid(Object.fromEntries(reachableWeb)) :
                `<div class="details-no-data">${t('det_no_web')}</div>`
            }
        </div>

        <div class="details-section">
            <h4>🔐 ${t('det_remote_access')}</h4>
            ${Object.keys(sshInfo).length > 0 ?
                generateSSHInfo(sshInfo) :
                `<div class="details-no-data">${t('det_no_ssh')}</div>`
            }
        </div>

        <div class="details-section">
            <h4>📡 ${t('det_snmp_other')}</h4>
            ${Object.keys(networkServices).length > 0 ?
                generateNetworkServicesInfo(networkServices) :
                `<div class="details-no-data">${t('det_no_netsvc')}</div>`
            }
        </div>
    `;
}

// Port Analizi içeriği
function generatePortsContent(enhancedInfo) {
    const detailedPorts = enhancedInfo.detailed_ports || {};
    
    // A scan error (usually "needs root") is not something to alarm the user
    // with - the basic port list is on the device card regardless.
    if (detailedPorts.error) {
        return `
            <div class="details-section">
                <h4>🔌 ${t('det_port_analysis')}</h4>
                <div class="details-no-data">${t('det_no_ports')}</div>
            </div>
        `;
    }

    return `
        <div class="details-section">
            <h4>🔌 ${t('det_port_analysis')}</h4>
            ${Object.keys(detailedPorts).length > 0 ?
                generatePortsGrid(detailedPorts) :
                `<div class="details-no-data">${t('det_no_ports')}</div>`
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
            <h4>💻 ${t('det_os_detection')}</h4>
            ${Object.keys(osDetection).length > 0 ?
                generateOSDetectionInfo(osDetection) :
                `<div class="details-no-data">${t('det_no_os')}</div>`
            }
        </div>

        <div class="details-section">
            <h4>🖥️ ${t('det_ssh_sysinfo')}</h4>
            ${Object.keys(sshSystemInfo).length > 0 ?
                generateSSHSystemInfo(sshSystemInfo) :
                `<div class="details-no-data">${t('det_no_ssh_sys')}</div>`
            }
        </div>
    `;
}

// Güvenlik içeriği. The security step now returns the CVE-database assessment
// (findings + attack-surface exposures + risk) - the same source as the
// Security page - instead of a separate ad-hoc scan.
function generateSecurityContent(enhancedInfo) {
    const sec = enhancedInfo.security_analysis || {};
    const findings = sec.findings || [];
    const exposures = sec.exposures || [];

    if (sec.error || (!findings.length && !exposures.length && !sec.risk_level)) {
        return `<div class="details-section"><h4>🛡️ ${t('det_security')}</h4>
            <div class="details-no-data">${t('det_no_security')}</div></div>`;
    }

    const item = (f, isFinding) => `
        <div class="details-card">
            <h5>${escSec(isFinding ? (f.cve_id || f.title) : f.title)}
                <span class="status-badge status-${(f.severity || 'info')}">${escSec(f.severity || 'info')}</span></h5>
            <div class="details-value" style="color: var(--text-secondary);">${escSec(f.description || f.title || '')}</div>
        </div>`;

    return `
        <div class="details-section">
            <h4>🛡️ ${t('det_security')} — ${escSec((sec.risk_level || '').toUpperCase())} (${sec.risk_score ?? 0})</h4>
            ${findings.length ? `<div class="details-grid">${findings.map(f => item(f, true)).join('')}</div>`
                              : `<div class="details-no-data">${t('det_no_security')}</div>`}
            ${exposures.length ? `<div class="details-grid" style="margin-top:8px;">${exposures.map(e => item(e, false)).join('')}</div>` : ''}
        </div>
    `;
}

function escSec(v) {
    return String(v == null ? '' : v).replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));
}

// ---------------------------------------------------------------------------
// AI identification tab: the result the AI agent researched on the web, plus a
// button to (re)run it. Result lands under enhanced_*.ai_identification once the
// backend's apply_enhanced_analysis merges it in.
// ---------------------------------------------------------------------------

function getAiIdentification(device, enhancedInfo) {
    return (enhancedInfo && enhancedInfo.ai_identification)
        || (device.enhanced_comprehensive_info || {}).ai_identification
        || (((device.analysis_data || {}).enhanced_analysis_info || {}).ai_identification)
        || null;
}

let aiIdentifyPolling = null;

function generateAIContent(device, enhancedInfo) {
    const ai = getAiIdentification(device, enhancedInfo);
    const ip = device.ip;

    if (!ai) {
        return `
            <div class="details-section ai-section">
                <div class="ai-empty">
                    <svg class="ds-icon ai-empty-icon" aria-hidden="true"><use href="#i-sparkles"/></svg>
                    <p>${t('ai_empty') === 'ai_empty' ? 'No AI identification yet. The AI agent searches the web (manuals, OUI databases, support pages) to work out exactly what this device is.' : t('ai_empty')}</p>
                    <button class="btn-ai-run" onclick="runAiIdentify('${escSec(ip)}')">
                        <svg class="ds-icon" aria-hidden="true"><use href="#i-sparkles"/></svg>
                        <span>${t('ai_run') === 'ai_run' ? 'Identify with AI' : t('ai_run')}</span>
                    </button>
                    <div id="aiIdentifyStatus" class="ai-status"></div>
                </div>
            </div>`;
    }

    const conf = Math.round((Number(ai.confidence) || 0) * 100);
    const confClass = conf >= 75 ? 'probability-high' : conf >= 45 ? 'probability-medium' : 'probability-low';
    const confLvl = conf >= 75 ? 'ai-conf-high' : conf >= 45 ? 'ai-conf-medium' : 'ai-conf-low';
    const what = ai.product_type || ai.category || t('det_unknown_device');
    const title = [ai.brand || ai.manufacturer, ai.model].filter(Boolean).join(' ') || what;
    const chips = (arr, cls) => (arr || []).map(x => `<span class="ai-chip ${cls || ''}">${escSec(x)}</span>`).join('');
    const meta = ai._meta || {};

    const kv = (label, value) => value ? `<li><span class="details-label">${label}:</span><span class="details-value">${escSec(value)}</span></li>` : '';

    // Olası cihaz tipleri (AI + normal-tarama skorları), her biri bir MyNeS
    // Device Type'ına eşlenir; kullanıcı birini seçip cihaza uygular.
    const candidates = buildAiCandidates(device, ai, enhancedInfo);
    const icon = mt => (typeof deviceTypes === 'object' && deviceTypes && deviceTypes[mt] && deviceTypes[mt].icon) || '🏷️';
    const name = mt => (typeof deviceTypes === 'object' && deviceTypes && deviceTypes[mt] && deviceTypes[mt].name) || mt;
    const candRow = c => `
        <div class="ai-candidate${c.primary ? ' ai-candidate-primary' : ''}">
            <span class="ai-candidate-type">${icon(c.type)} ${escSec(name(c.type))}</span>
            <span class="ai-candidate-pct">${c.pct}%</span>
            <button class="btn-ai-run btn-sm" onclick="applyDeviceType('${escSec(ip)}','${escSec(c.type)}',${c.primary ? 'true' : 'false'})">
                ${t('ai_use_this') === 'ai_use_this' ? 'Use this' : t('ai_use_this')}
            </button>
        </div>`;

    return `
        <div class="details-section ai-section">
            <div class="ai-hero">
                <div class="ai-hero-head">
                    <svg class="ds-icon ai-hero-icon" aria-hidden="true"><use href="#i-sparkles"/></svg>
                    <div>
                        <div class="ai-hero-title">${escSec(title)}</div>
                        <div class="ai-hero-sub">${escSec(ai.product_type || '')}${ai.category ? ' · ' + escSec(ai.category) : ''}</div>
                    </div>
                    <div class="ai-hero-actions">
                        <button class="btn-ai-run" onclick="saveAiToDevice('${escSec(ip)}')">
                            <svg class="ds-icon" aria-hidden="true"><use href="#i-check"/></svg>
                            <span>${t('ai_save') === 'ai_save' ? 'Save to device' : t('ai_save')}</span>
                        </button>
                        <div id="aiIdentifyStatus" class="ai-status"></div>
                    </div>
                </div>
                ${ai.what_it_is ? `<p class="ai-lead">${escSec(ai.what_it_is)}</p>` : ''}
                <div class="ai-conf">
                    <div class="ai-conf-kpi ${confLvl}">
                        <div class="ai-conf-big">${conf}%</div>
                        <div class="ai-conf-kpi-label">${t('ai_conf_label') === 'ai_conf_label' ? 'confidence' : t('ai_conf_label')}</div>
                    </div>
                    <div class="ai-conf-text">
                        <div class="ai-conf-line">${t('ai_conf_is') === 'ai_conf_is' ? 'confident this is a' : t('ai_conf_is')} <b>${escSec(what)}</b></div>
                        <div class="probability-bar"><div class="probability-fill ${confClass}" style="width:${conf}%"></div></div>
                        <div class="ai-conf-caption">${t('ai_conf_caption') === 'ai_conf_caption' ? "AI's confidence in the identification above" : t('ai_conf_caption')}</div>
                    </div>
                </div>
            </div>

            ${candidates.length ? `<div class="details-card ai-block">
                <h5>${t('ai_candidates') === 'ai_candidates' ? 'Possible device types — pick one to apply' : t('ai_candidates')}</h5>
                <div class="ai-candidates">${candidates.map(candRow).join('')}</div>
            </div>` : ''}

            <div class="details-grid">
                <div class="details-card">
                    <h5>${t('ai_identity') === 'ai_identity' ? 'Identity' : t('ai_identity')}</h5>
                    <ul class="details-list">
                        ${kv(t('ai_manufacturer') === 'ai_manufacturer' ? 'Manufacturer' : t('ai_manufacturer'), ai.manufacturer)}
                        ${kv('Brand', ai.brand)}
                        ${kv('Model', ai.model)}
                        ${kv(t('ai_category') === 'ai_category' ? 'Category' : t('ai_category'), ai.category)}
                    </ul>
                </div>
                <div class="details-card">
                    <h5>${t('ai_what') === 'ai_what' ? 'What it does' : t('ai_what')}</h5>
                    <div class="details-value" style="text-align:left; color: var(--text-secondary);">${escSec(ai.what_it_does || '—')}</div>
                </div>
            </div>

            ${(ai.key_features || []).length ? `<div class="details-card ai-block">
                <h5>${t('ai_features') === 'ai_features' ? 'Key features' : t('ai_features')}</h5>
                <div class="ai-chips">${chips(ai.key_features)}</div></div>` : ''}

            ${((ai.typical_protocols || []).length || (ai.typical_ports || []).length) ? `<div class="details-card ai-block">
                <h5>${t('ai_protocols') === 'ai_protocols' ? 'Protocols & ports' : t('ai_protocols')}</h5>
                <div class="ai-chips">${chips(ai.typical_protocols)}${chips((ai.typical_ports || []).map(String), 'ai-chip-port')}</div></div>` : ''}

            ${ai.setup_notes ? `<div class="details-card ai-block"><h5>${t('ai_setup') === 'ai_setup' ? 'Setup' : t('ai_setup')}</h5>
                <div class="details-value" style="text-align:left; color: var(--text-secondary);">${escSec(ai.setup_notes)}</div></div>` : ''}

            ${ai.security_notes ? `<div class="details-card ai-block ai-security">
                <h5><svg class="ds-icon" aria-hidden="true"><use href="#i-shield"/></svg> ${t('ai_security') === 'ai_security' ? 'Security notes' : t('ai_security')}</h5>
                <div class="details-value" style="text-align:left;">${escSec(ai.security_notes)}</div></div>` : ''}

            ${ai.reasoning ? `<div class="details-card ai-block"><h5>${t('ai_reasoning') === 'ai_reasoning' ? 'Reasoning' : t('ai_reasoning')}</h5>
                <div class="details-value" style="text-align:left; color: var(--text-tertiary);">${escSec(ai.reasoning)}</div></div>` : ''}

            ${(ai.sources || []).length ? `<div class="details-card ai-block"><h5>${t('ai_sources') === 'ai_sources' ? 'Sources' : t('ai_sources')}</h5>
                <ul class="ai-sources">${(ai.sources || []).map(s => `<li><a href="${escSec(s.url)}" target="_blank" rel="noopener noreferrer">${escSec(s.title || s.url)}</a></li>`).join('')}</ul></div>` : ''}

            <div class="ai-footer">
                <span class="ai-meta">${escSec(meta.provider || '')}${meta.model ? ' · ' + escSec(meta.model) : ''}</span>
            </div>
        </div>`;
}

// Serbest metin / iç skor anahtarını GEÇERLİ bir MyNeS Device Type'ına eşle.
// AI'nın önerdiği her tip mutlaka mevcut bir tipe karşılık gelir; eşleşme
// bulunamazsa "IoT Device"a düşer. Global deviceTypes yüklüyse doğrulanır.
function mynesTypeFor(label) {
    if (!label) return '';
    const s = String(label).toLowerCase();
    const rules = [
        [/raspberry|\brpi\b/, 'Raspberry Pi Server'],
        [/\bnas\b|network.attached|storage/, 'NAS'],
        [/ip.?camera|\bcamera\b|webcam|cctv|surveillance/, 'IP Camera'],
        [/access.?point|\bap\b/, 'Access Point'],
        [/router|gateway/, 'Router'],
        [/\bmodem\b/, 'Modem'],
        [/network.?switch|\bswitch\b/, 'Switch'],
        [/printer/, 'Printer'],
        [/scanner/, 'Scanner'],
        [/air.?condition|\bhvac\b/, 'Air Conditioner'],
        [/air.?puri/, 'Air Purifier'],
        [/thermostat/, 'Smart Thermostat'],
        [/smart.?light|\bbulb\b|\blight\b/, 'Smart Light'],
        [/smart.?lock|door.?lock/, 'Smart Lock'],
        [/smart.?speaker|echo|alexa|google.?home|homepod/, 'Smart Speaker'],
        [/smart.?tv|television|\btv\b/, 'Smart TV'],
        [/stream|chromecast|roku|fire.?tv|apple.?tv/, 'Streaming Device'],
        [/vacuum|roomba|robot.?clean/, 'Vacuum Cleaner'],
        [/refrigerator|fridge/, 'Refrigerator'],
        [/dishwasher/, 'Dishwasher'],
        [/washing.?machine|washer/, 'Washing Machine'],
        [/game|console|playstation|xbox|nintendo/, 'Game Console'],
        [/airtag/, 'Apple AirTag'],
        [/apple|iphone|ipad|mac(book)?|\bios\b/, 'Apple Device'],
        [/smart.?watch/, 'Smart Watch'],
        [/wearable/, 'Wearable'],
        [/headphone|earbud|airpods/, 'Headphones'],
        [/tablet/, 'Tablet'],
        [/laptop|notebook/, 'Laptop'],
        [/desktop|workstation/, 'Desktop'],
        [/smartphone|\bphone\b|android|mobile/, 'Smartphone'],
        [/pet.?feeder/, 'Pet Feeder'],
        [/pet.?camera/, 'Pet Camera'],
        [/\bpet\b|animal/, 'Pet Tracker'],
        [/beacon/, 'Beacon'],
        [/zigbee/, 'Zigbee Device'],
        [/z.?wave/, 'Z-Wave Device'],
        [/bluetooth|\bble\b/, 'Bluetooth Device'],
        [/sensor/, 'Sensor'],
        [/docker|container/, 'Docker Container'],
        [/security.?system|alarm/, 'Security System'],
        [/smart.?home|home.?automation|\bhub\b/, 'Smart Home'],
        [/server|\bsbc\b|single.?board/, 'Server'],
        [/comput/, 'Desktop'],
        [/\biot\b|module|microcontroller|esp32|esp8266/, 'IoT Device'],
    ];
    for (const [re, mt] of rules) if (re.test(s)) return validMynesType(mt);
    return validMynesType('IoT Device');
}

function validMynesType(mt) {
    if (typeof deviceTypes === 'object' && deviceTypes && Object.keys(deviceTypes).length) {
        return deviceTypes[mt] ? mt : (deviceTypes['IoT Device'] ? 'IoT Device' : mt);
    }
    return mt;
}

// AI'nın birincil tahmini + alternatifleri + normal-tarama skorlarını tek bir
// aday listesine indir; her biri bir MyNeS tipine eşlenir, orana göre sıralı.
function buildAiCandidates(device, ai, enhancedInfo) {
    const map = {};
    const add = (label, pct, primary) => {
        const mt = mynesTypeFor(label);
        if (!mt) return;
        pct = Math.round(pct);
        const cur = map[mt];
        map[mt] = { type: mt, pct: Math.max(pct, cur ? cur.pct : 0), primary: primary || (cur && cur.primary) };
    };
    add(ai.product_type || ai.category, (Number(ai.confidence) || 0) * 100, true);
    (ai.alternatives || []).forEach(a =>
        add(a.product_type || a.category || a.label || a.device_type, (Number(a.confidence) || 0) * 100, false));
    const probs = (enhancedInfo.device_type_analysis || {}).device_probabilities || {};
    Object.entries(probs).forEach(([k, v]) => add(k, (Number(v) || 0) * 100, false));
    return Object.values(map)
        .sort((a, b) => (b.primary ? 1 : 0) - (a.primary ? 1 : 0) || b.pct - a.pct)
        .slice(0, 6);
}

// Bir aday tipi (ve "Cihaza Kaydet"te AI model/vendor'ını) cihaza kalıcı yaz.
async function applyDeviceType(ip, mynesType, includeAiFields) {
    const setStatus = (msg, cls) => { const el = document.getElementById('aiIdentifyStatus'); if (el) el.innerHTML = `<span class="ai-status-${cls || 'info'}">${msg}</span>`; };
    const updates = {};
    if (mynesType) updates.device_type = mynesType;
    if (includeAiFields) {
        const ai = getAiIdentification(currentDevice, null) || {};
        if (ai.model) updates.model = ai.model;
        if (ai.brand || ai.manufacturer) updates.vendor = ai.brand || ai.manufacturer;
    }
    if (!Object.keys(updates).length) { setStatus('Nothing to save', 'error'); return; }
    try {
        const r = await fetch(`/update_device/${ip}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updates)
        });
        if (!r.ok) { const b = await r.json().catch(() => ({})); setStatus(escSec(b.error || 'save failed'), 'error'); return; }
        Object.assign(currentDevice, updates);
        if (typeof showToast === 'function') showToast(t('ai_saved') === 'ai_saved' ? 'Saved to device' : t('ai_saved'), 'success');
        if (typeof refreshDevicesAfterAnalysis === 'function') refreshDevicesAfterAnalysis(ip);
        setStatus('✓', 'success');
    } catch (e) {
        setStatus(escSec(String(e)), 'error');
    }
}

// "Cihaza Kaydet" (üst çubuk): AI'nın birincil kimliğini uygula.
function saveAiToDevice(ip) {
    const ai = getAiIdentification(currentDevice, null);
    if (!ai) return;
    return applyDeviceType(ip, mynesTypeFor(ai.product_type || ai.category), true);
}

let aiTimerCycle = null;

// Toggle the "working" visuals: a spinner + live elapsed-seconds counter in the
// status line, a pulsing hero/empty icon, and a disabled button. The counter is
// the honest signal that something is happening - we get no step-by-step
// progress from the single POST, so we show elapsed time rather than fake steps.
function setAiWorking(on, startedAt) {
    document.querySelectorAll('.ai-section .btn-ai-run').forEach(b => {
        b.disabled = on; b.classList.toggle('is-loading', on);
    });
    document.querySelectorAll('.ai-empty-icon, .ai-hero-icon').forEach(i => i.classList.toggle('is-loading', on));
    if (aiTimerCycle) { clearInterval(aiTimerCycle); aiTimerCycle = null; }
    const el = document.getElementById('aiIdentifyStatus');
    if (!on || !el) return;
    const base = t('ai_running') === 'ai_running' ? 'Researching on the web…' : t('ai_running');
    const render = () => {
        const secs = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
        el.innerHTML = `<span class="ai-working"><span class="ai-spinner"></span>` +
            `<span class="ai-status-info">${escSec(base)} <span class="ai-elapsed">(${secs}s)</span></span></span>`;
    };
    render();
    aiTimerCycle = setInterval(render, 1000);
}

async function runAiIdentify(ip) {
    const setStatus = (msg, cls) => { const el = document.getElementById('aiIdentifyStatus'); if (el) el.innerHTML = `<span class="ai-status-${cls || 'info'}">${msg}</span>`; };
    const stopWork = () => setAiWorking(false);
    if (aiIdentifyPolling) { clearInterval(aiIdentifyPolling); aiIdentifyPolling = null; }

    try {
        const start = await fetch(`/api/devices/${ip}/ai-identify`, { method: 'POST' });
        const body = await start.json();
        if (!start.ok) { stopWork(); setStatus(escSec(body.error || 'error'), 'error'); return; }
        setAiWorking(true, Date.now());

        aiIdentifyPolling = setInterval(async () => {
            let st;
            try { st = await fetch(`/api/devices/${ip}/ai-identify/status`).then(r => r.json()); }
            catch (e) { return; }
            if (st.status === 'completed') {
                clearInterval(aiIdentifyPolling); aiIdentifyPolling = null; stopWork();
                // Stash the fresh result on the open device so the tab re-renders it,
                // and refresh the card list so the change sticks in the UI.
                if (currentDevice) {
                    currentDevice.enhanced_comprehensive_info = currentDevice.enhanced_comprehensive_info || {};
                    currentDevice.enhanced_comprehensive_info.ai_identification = st.result;
                }
                if (typeof showToast === 'function') showToast(t('ai_done') === 'ai_done' ? 'AI identification complete' : t('ai_done'), 'success');
                if (typeof refreshDevicesAfterAnalysis === 'function') refreshDevicesAfterAnalysis(ip);
                if (currentTab === 'ai') loadTabContent('ai');
            } else if (st.status === 'error') {
                clearInterval(aiIdentifyPolling); aiIdentifyPolling = null; stopWork();
                setStatus(escSec(st.error || 'error'), 'error');
            }
        }, 2500);
    } catch (e) {
        stopWork(); setStatus(escSec(String(e)), 'error');
    }
}

// Entry point from the Device Edit popup's "Identify with AI" button. Opens the
// Details modal straight onto the AI tab and, if the device has no result yet,
// kicks off the identify run so the user watches it happen and sees the result.
function openAiIdentify(ip) {
    const device = (typeof deviceByKey === 'function' && deviceByKey(ip)) || null;
    if (!device) { if (typeof showToast === 'function') showToast(t('device_not_found'), 'error'); return; }
    currentDevice = device;

    const titleEl = document.getElementById('detailsDeviceTitle');
    if (titleEl) titleEl.textContent = `${device.ip || device.mac} — ${device.alias || device.hostname || t('det_unknown_device')}`;
    document.getElementById('enhancedDetailsModal').style.display = 'block';
    switchDetailsTab('ai');

    if (!getAiIdentification(device, null)) {
        runAiIdentify(device.ip);
    }
}

// Called by the header button in the Edit popup: close the edit modal, then run
// AI identification for the device being edited.
function startEditAiIdentify() {
    const ip = (typeof currentEnhancedEditingIp !== 'undefined' && currentEnhancedEditingIp) || null;
    if (!ip) return;
    if (typeof closeEnhancedEditModal === 'function') closeEnhancedEditModal();
    openAiIdentify(ip);
}

// Donanım içeriği
function generateHardwareContent(enhancedInfo) {
    const raspberryInfo = enhancedInfo.raspberry_pi_analysis || {};
    const hardwareInfo = raspberryInfo.hardware || {};
    
    return `
        <div class="details-section">
            <h4>🔧 ${t('det_hardware')}</h4>
            ${Object.keys(hardwareInfo).length > 0 ?
                generateHardwareInfo(hardwareInfo) :
                `<div class="details-no-data">${t('det_no_hardware')}</div>`
            }
        </div>

        <div class="details-section">
            <h4>🥧 ${t('det_rpi_services')}</h4>
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
        return `<div class="details-section"><h4>📡 ${t('det_protocol_discovery')}</h4>` +
            `<div class="details-no-data">${t('det_no_data')}</div></div>`;
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
            <h4>📡 ${t('det_protocol_discovery')}</h4>
            <ul class="details-list">
                <li><span class="details-label">Görüldüğü protokoller:</span><span class="details-value">${esc(d.sources.join(', '))}</span></li>
                <li><span class="details-label">Model:</span><span class="details-value">${esc(d.model || 'N/A')}</span></li>
                <li><span class="details-label">Servisler:</span><span class="details-value">${esc((d.services || []).join(', ') || 'N/A')}</span></li>
            </ul>
        </div>
        ${descCards ? `<div class="details-section"><h4>🧾 UPnP (description.xml)</h4>
            <div class="details-grid">${descCards}</div></div>` : ''}
        <div class="details-section">
            <h4>🗂️ Tüm Keşif Verisi</h4>
            <div class="details-code">${esc(JSON.stringify(d.attributes || {}, null, 2))}</div>
        </div>
    `;
}

function generateRawContent(enhancedInfo) {
    const ip = (currentDevice && currentDevice.ip) || 'device';
    return `
        <div class="details-section">
            <h4>📄 ${t('det_raw_json')}
                <button class="btn-ai-run btn-sm json-dl-btn" onclick="downloadEnhancedJson()">
                    <svg class="ds-icon" aria-hidden="true"><use href="#i-download"/></svg>
                    <span>${t('json_download') === 'json_download' ? 'Download JSON' : t('json_download')}</span>
                </button>
            </h4>
            <pre class="details-code json-view">${mynesHighlightJson(enhancedInfo)}</pre>
        </div>
    `;
}

// Küçük regex tabanlı JSON syntax highlighter (kütüphane yok). Girdi önce
// escape edilir, sonra token'lar renklendirilir.
function mynesHighlightJson(obj) {
    let json;
    try { json = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2); }
    catch (e) { json = String(obj); }
    json = json.replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));
    return json.replace(
        /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
        (m) => {
            let cls = 'jn';                         // number
            if (/^"/.test(m)) cls = /:$/.test(m) ? 'jk' : 'js';   // key / string
            else if (/true|false/.test(m)) cls = 'jb';            // boolean
            else if (/null/.test(m)) cls = 'jz';                  // null
            return `<span class="${cls}">${m}</span>`;
        });
}

// Açık cihazın ham analiz JSON'unu indir (Raw Data sekmesindeki buton).
function downloadEnhancedJson() {
    const d = currentDevice || {};
    const raw = d.enhanced_comprehensive_info || d.advanced_scan_summary || d.enhanced_info || {};
    mynesDownloadJson(raw, `mynes-${d.ip || 'device'}-analysis.json`);
}

// JSON'ı dosya olarak indir (Blob + geçici <a>). Kütüphane yok.
function mynesDownloadJson(obj, filename) {
    try {
        const text = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
        const blob = new Blob([text], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename || 'data.json';
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
        if (typeof showToast === 'function') showToast('Download failed', 'error');
    }
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
    // Follow the selected UI language, not a hardcoded Turkish locale.
    const lang = (typeof translationManager !== 'undefined' && translationManager.getCurrentLanguage)
        ? translationManager.getCurrentLanguage() : 'en';
    return date.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-GB');
}

function generateQuickStats(enhancedInfo, device) {
    const openPorts = device.open_ports ? device.open_ports.length : 0;
    // Count only what the tabs actually render, so the KPI can't claim 11 web
    // services when the Network tab shows 2 reachable, or 5 "security checks"
    // that are really just dict keys with zero findings.
    const webServices = Object.values(enhancedInfo.web_services || {})
        .filter(d => d && !d.error).length;
    const sec = enhancedInfo.security_analysis || {};
    const securityIssues = (sec.findings || []).length + (sec.exposures || []).length;
    
    return `
        <div class="details-section">
            <h4>📈 ${t('det_quick_stats')}</h4>
            <div class="details-grid">
                <div class="details-card" style="text-align: center;">
                    <h5>🚪 ${t('det_open_ports')}</h5>
                    <div style="font-size: 32px; font-weight: bold; color: var(--severity-ok-fg, #28a745);">${openPorts}</div>
                </div>
                <div class="details-card" style="text-align: center;">
                    <h5>🌐 ${t('det_web_services')}</h5>
                    <div style="font-size: 32px; font-weight: bold; color: var(--accent-fg, #007bff);">${webServices}</div>
                </div>
                <div class="details-card" style="text-align: center;">
                    <h5>🛡️ ${t('det_security_checks')}</h5>
                    <div style="font-size: 32px; font-weight: bold; color: var(--severity-warn-fg, #ffc107);">${securityIssues}</div>
                </div>
            </div>
        </div>
    `;
}

function generateWebServicesGrid(webServices) {
    let html = '<div class="details-grid">';
    
    for (const [service, data] of Object.entries(webServices)) {
        if (data.error) {
            // A connection error just means the port is closed. Show a quiet
            // "closed" chip instead of dumping the raw Python exception at the user.
            html += `
                <div class="details-card">
                    <h5>${service}</h5>
                    <div class="details-no-data">${t('det_service_closed')}</div>
                </div>
            `;
        } else {
            // Many embedded/IoT devices answer 200 but send no <title> and no
            // Server header - so Title/Server alone made this card look empty
            // even though the scan captured a full set of response headers.
            // Surface those (Content-Length, ETag, security headers, ...) so a
            // reachable service always shows the evidence it actually collected.
            const headers = data.headers || {};
            const hdrEntries = Object.entries(headers);
            const secHdrs = ['x-frame-options', 'content-security-policy', 'strict-transport-security',
                             'x-content-type-options', 'x-xss-protection', 'referrer-policy'];
            html += `
                <div class="details-card">
                    <h5>${service}</h5>
                    <ul class="details-list">
                        <li><span class="details-label">Status:</span><span class="details-value">${data.status_code || 'N/A'}</span></li>
                        <li><span class="details-label">Title:</span><span class="details-value">${data.title || 'N/A'}</span></li>
                        <li><span class="details-label">Server:</span><span class="details-value">${data.server || 'N/A'}</span></li>
                        <li><span class="details-label">Content Type:</span><span class="details-value">${data.content_type || 'N/A'}</span></li>
                        ${data.content_length != null ? `<li><span class="details-label">Content Length:</span><span class="details-value">${data.content_length}</span></li>` : ''}
                        ${data.redirect_url ? `<li><span class="details-label">Redirect:</span><span class="details-value">${escSec(data.redirect_url)}</span></li>` : ''}
                        ${data.technologies && data.technologies.length > 0 ?
                            `<li><span class="details-label">Technologies:</span><span class="details-value">
                                <div class="port-list">
                                    ${data.technologies.map(tech => `<span class="port-tag">${escSec(tech)}</span>`).join('')}
                                </div>
                            </span></li>` : ''
                        }
                    </ul>
                    ${hdrEntries.length ? `
                        <div class="details-label" style="margin-top:8px;">${t('det_http_headers') === 'det_http_headers' ? 'HTTP Headers' : t('det_http_headers')}</div>
                        <ul class="details-list">
                            ${hdrEntries.map(([k, v]) => `<li>
                                <span class="details-label">${escSec(k)}${secHdrs.includes(k.toLowerCase()) ? ' 🛡️' : ''}:</span>
                                <span class="details-value">${escSec(v)}</span></li>`).join('')}
                        </ul>` : ''}
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
                            ${sshInfo.connection_test.success ? t('det_success') : t('det_failed')}
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
        return `<div class="details-no-data">${t('det_no_rpi')}</div>`;
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
                    `<div class="details-no-data">${t('det_no_data')}</div>`
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

    // Normal taramadan türetilmiş temel OS bilgisi (nmap os_matches yoksa).
    const b = osDetection.basic;
    if (b && (b.os_family || b.ssh_banner || b.identified)) {
        html += `
            <div class="details-card">
                <h5>💻 ${b.identified || b.os_family || 'OS'}</h5>
                <ul class="details-list">
                    ${b.os_family ? `<li><span class="details-label">OS Family:</span><span class="details-value">${escSec(b.os_family)}</span></li>` : ''}
                    ${b.ttl != null ? `<li><span class="details-label">TTL:</span><span class="details-value">${escSec(b.ttl)}</span></li>` : ''}
                    ${b.ssh_version ? `<li><span class="details-label">SSH Version:</span><span class="details-value">${escSec(b.ssh_version)}</span></li>` : ''}
                    ${b.ssh_banner ? `<li><span class="details-label">SSH Banner:</span><span class="details-value">${escSec(b.ssh_banner)}</span></li>` : ''}
                </ul>
            </div>
        `;
    }

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
        'iot_device': { icon: '🔗', name: 'IoT Device' },
        'computer': { icon: '💻', name: 'Computer' },
        'raspberry_pi': { icon: '🥧', name: 'Raspberry Pi' }
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
        html = `<div class="details-no-data">${t('det_no_data')}</div>`;
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