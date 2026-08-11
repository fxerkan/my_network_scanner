// Device Access Management - Cihaz Erişim Yönetimi

let currentAccessDevice = null;

// Modal açma fonksiyonu
function openDeviceAccessModal(ip) {
    currentAccessDevice = ip;
    document.getElementById('accessDeviceIP').value = ip;
    document.getElementById('deviceAccessModal').style.display = 'block';
    
    // Mevcut erişim bilgilerini yükle
    loadExistingAccessInfo(ip);
    updateAccessForm();
}

// Modal kapatma fonksiyonu
function closeDeviceAccessModal() {
    document.getElementById('deviceAccessModal').style.display = 'none';
    currentAccessDevice = null;
    clearAccessForm();
}

// Erişim türüne göre formu güncelle
function updateAccessForm() {
    const accessType = document.getElementById('accessType').value;
    const hintsDiv = document.getElementById('accessHints');
    
    // Port'u otomatik ayarla
    const portField = document.getElementById('accessPort');
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
    
    // Hint'leri güncelle
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

// Formu temizle
function clearAccessForm() {
    document.getElementById('accessUsername').value = '';
    document.getElementById('accessPassword').value = '';
    document.getElementById('accessPort').value = '';
    document.getElementById('accessNotes').value = '';
    document.getElementById('accessType').value = 'ssh';
}

// Mevcut erişim bilgilerini yükle
async function loadExistingAccessInfo(ip) {
    try {
        console.log(`Loading existing access info for ${ip}`);
        const response = await fetch(`/device_access/${ip}`);
        console.log(`Response status: ${response.status}`);
        
        if (response.ok) {
            const accessInfo = await response.json();
            console.log(`Access info received:`, accessInfo);
            
            if (accessInfo && Object.keys(accessInfo).length > 0) {
                // İlk erişim türünü yükle
                const firstType = Object.keys(accessInfo)[0];
                const firstAccess = accessInfo[firstType];
                
                document.getElementById('accessType').value = firstType;
                document.getElementById('accessUsername').value = firstAccess.username || '';
                
                // Şifreyi gizle - eğer var ise placeholder göster
                const passwordField = document.getElementById('accessPassword');
                if (firstAccess.has_password) {
                    passwordField.placeholder = '••••••••';
                    passwordField.value = '';
                    passwordField.setAttribute('data-has-existing', 'true');
                } else {
                    passwordField.placeholder = t('access_password_enter');
                    passwordField.value = '';
                    passwordField.removeAttribute('data-has-existing');
                }
                
                document.getElementById('accessPort').value = firstAccess.port || '';
                document.getElementById('accessNotes').value = 
                    JSON.stringify(firstAccess.additional_info || {}, null, 2);
                
                updateAccessForm();
            }
        }
    } catch (error) {
        console.error('Erişim bilgileri yüklenirken hata:', error);
    }
}

// Cihaz erişim bilgilerini kaydet
async function saveDeviceAccess() {
    if (!currentAccessDevice) {
        showToast(t('access_invalid_device'), 'error');
        return;
    }
    
    console.log(`Saving device access for ${currentAccessDevice}`);
    
    const passwordField = document.getElementById('accessPassword');
    const accessData = {
        access_type: document.getElementById('accessType').value,
        username: document.getElementById('accessUsername').value,
        password: passwordField.value,
        port: document.getElementById('accessPort').value || null,
        additional_info: {}
    };
    
    // Eğer şifre alanı boş ve mevcut şifre varsa, şifreyi güncellememe
    if (!passwordField.value && passwordField.getAttribute('data-has-existing') === 'true') {
        accessData.keep_existing_password = true;
        console.log('Keeping existing password');
    }
    
    console.log('Access data to save:', { ...accessData, password: accessData.password ? '***HIDDEN***' : 'EMPTY' });
    
    // Ek bilgileri parse et
    const notes = document.getElementById('accessNotes').value.trim();
    if (notes) {
        try {
            accessData.additional_info = JSON.parse(notes);
        } catch (e) {
            accessData.additional_info = { notes: notes };
        }
    }
    
    try {
        console.log('Sending POST request to save credentials...');
        const response = await fetch(`/device_access/${currentAccessDevice}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accessData)
        });
        
        console.log(`Save response status: ${response.status}`);
        const result = await response.json();
        console.log('Save response result:', result);
        
        if (response.ok) {
            showToast(t('access_saved'), 'success');
            console.log('Credentials saved successfully');
        } else {
            console.error('Save error:', result.error);
            showToast(t('access_save_error', {error: result.error}), 'error');
        }
    } catch (error) {
        console.error('Save connection error:', error);
        showToast(t('access_connection_error', {error: error.message}), 'error');
    }
}

// Erişim testi
async function testDeviceAccess() {
    if (!currentAccessDevice) {
        showToast(t('access_invalid_device'), 'error');
        return;
    }
    
    const passwordField = document.getElementById('accessPassword');
    const accessData = {
        access_type: document.getElementById('accessType').value,
        username: document.getElementById('accessUsername').value,
        password: passwordField.value,
        port: document.getElementById('accessPort').value || null
    };
    
    // Eğer şifre alanı boş ve mevcut şifre varsa, kayıtlı credential'ları kullan
    if (!passwordField.value && passwordField.getAttribute('data-has-existing') === 'true') {
        accessData.use_stored_credentials = true;
        console.log('Using stored credentials for test');
    }
    
    console.log('Test access data:', { ...accessData, password: accessData.password ? '***HIDDEN***' : 'EMPTY' });
    
    // Test butonunu devre dışı bırak
    const testBtn = event.target;
    const originalText = testBtn.innerHTML;
    testBtn.disabled = true;
    testBtn.innerHTML = '🔄 ' + t('access_testing');
    
    try {
        console.log('Sending test request...');
        const response = await fetch(`/test_device_access/${currentAccessDevice}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accessData)
        });
        
        console.log(`Test response status: ${response.status}`);
        const result = await response.json();
        console.log('Test response result:', result);
        
        if (response.ok) {
            if (result.success) {
                console.log('Test successful:', result);
                showToast(`✅ ${t('access_test_success')} ${result.details || ''}`, 'success');
            } else {
                console.error('Test failed:', result.error);
                showToast(`❌ ${t('access_test_failed', {error: result.error})}`, 'error');
            }
        } else {
            console.error('Test error response:', result.error);
            showToast(t('access_test_error', {error: result.error}), 'error');
        }
    } catch (error) {
        console.error('Test connection error:', error);
        showToast(t('access_connection_error', {error: error.message}), 'error');
    } finally {
        // Test butonunu tekrar aktif et
        testBtn.disabled = false;
        testBtn.innerHTML = originalText;
    }
}

// Gelişmiş analiz çalıştır - artık Detaylı Cihaz Analizi sayfasını açar
async function runEnhancedAnalysis() {
    if (!currentAccessDevice) {
        showToast(t('access_invalid_device'), 'error');
        return;
    }
    
    // IP'yi kaydet (modal kapanmadan önce)
    const deviceIP = currentAccessDevice;
    
    // Önce erişim bilgilerini kaydet
    await saveDeviceAccess();
    
    showToast(t('access_saved_opening_analysis'), 'success');
    
    // Modal'ı kapat
    closeDeviceAccessModal();
    
    // Detaylı Cihaz Analizi sayfasını açmak için kaydedilen IP'yi kullan
    openSingleDeviceAnalysisPage(deviceIP);
}

// Detaylı Cihaz Analizi sayfasını aç
function openSingleDeviceAnalysisPage(ip) {
    // Yeni bir sayfa oluştur veya mevcut sayfada göster
    const analysisUrl = `/single_device_analysis/${ip}`;
    
    // Eğer single device analysis sayfası mevcut değilse, modal olarak göster
    showSingleDeviceAnalysisModal(ip);
}

// Global değişkenler - çoklu analiz desteği
let activeAnalysisSessions = new Map(); // IP -> {isMinimized, type, toasterId}
let analysisToasters = new Map(); // Minimize edilmiş analiz toaster'ları
let isAnalysisMinimized = false; // Analysis modal minimize durumu
let analysisToasterCount = 0;

// Unified modal'dan bulk analysis başlat
async function startUnifiedBulkAnalysis(sessionKey) {
    window.unifiedAnalysisMode = true;
    
    // UI durumunu güncelle
    updateUnifiedAnalysisButtons(sessionKey, true);
    
    try {
        // main.js'deki fonksiyonu çağır
        await startBulkAnalysisActual();
    } catch (error) {
        updateUnifiedAnalysisButtons(sessionKey, false);
    }
}

// Unified modal buton durumlarını güncelle
function updateUnifiedAnalysisButtons(sessionKey, isRunning) {
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
    
    // Verbose logs bölümünü göster
    const verboseSection = document.getElementById('verboseLogsSection');
    if (verboseSection && isRunning) {
        verboseSection.style.display = 'block';
    }
}

// Birleşik Gelişmiş Analiz modal'ını göster
function showSingleDeviceAnalysisModal(ip) {
    showUnifiedAnalysisModal(ip, 'single');
}

// Toplu analiz için birleşik modal'ı göster
function showBulkAnalysisModal() {
    showUnifiedAnalysisModal(null, 'bulk');
}

// Birleşik Gelişmiş Analiz Modal'ı
function showUnifiedAnalysisModal(targetIP = null, analysisType = 'single') {
    // Çoklu oturum desteği
    const sessionKey = analysisType === 'bulk' ? 'bulk' : targetIP;
    
    // Eğer zaten aktif bir analiz varsa, o modal'ı göster
    if (activeAnalysisSessions.has(sessionKey)) {
        const session = activeAnalysisSessions.get(sessionKey);
        if (session.isMinimized) {
            maximizeAnalysisModal(sessionKey);
        }
        return;
    }
    
    const isSingleDevice = analysisType === 'single';
    const title = isSingleDevice ? `${t('an_title')} — ${targetIP}` : t('an_title_bulk');
    const buttonText = isSingleDevice ? t('an_start') : t('an_start_bulk');
    const startFunction = isSingleDevice ? `startSingleDeviceAnalysis('${targetIP}')` : `startUnifiedBulkAnalysis('${sessionKey}')`;
    const descriptionText = isSingleDevice ? t('an_desc_single', { ip: targetIP }) : t('an_desc_bulk');

    // Benzersiz modal ID'si oluştur
    const modalId = `unifiedAnalysisModal_${sessionKey.replace(/\./g, '_')}`;
    const sk = sessionKey.replace(/\./g, '_');

    // Session'ı kaydet
    activeAnalysisSessions.set(sessionKey, {
        isMinimized: false,
        type: analysisType,
        modalId: modalId,
        targetIP: targetIP
    });

    // Minimalist modal: design tokens, one concise description, and a port-scan
    // scope picker so the user is not forced to wait out a full sweep.
    const modalHtml = `
        <div id="${modalId}" class="modal" style="display: block;">
            <div class="modal-content" style="width: 92%; max-width: 640px; max-height: 88vh; overflow-y: auto;">
                <div class="modal-header">
                    <h2 style="font-size: var(--text-lg, 1.15rem);">🔬 ${title}</h2>
                    <div class="modal-controls">
                        <span class="close" onclick="handleModalClose('${sessionKey}')">&times;</span>
                    </div>
                </div>
                <div class="modal-body">
                    <p style="margin: 0 0 var(--space-3, 12px); color: var(--text-secondary);">${descriptionText}</p>

                    <div class="form-group" style="margin-bottom: var(--space-3, 12px);">
                        <label class="form-label" for="scanScope_${sk}">${t('an_scope_label')}</label>
                        <select class="ds-select" id="scanScope_${sk}" style="max-width: 340px;">
                            <option value="fast">${t('an_scope_fast')}</option>
                            <option value="common" selected>${t('an_scope_common')}</option>
                            <option value="full">${t('an_scope_full')}</option>
                        </select>
                        <p class="card-hint" style="margin-top: 4px;">${t('an_scope_hint')}</p>
                    </div>

                    <div id="unifiedAnalysisContent">
                        <div class="analysis-section" style="display:flex; gap: var(--space-2, 8px); flex-wrap: wrap;">
                            <button id="startBtn_${sk}" onclick="${startFunction}" class="btn btn-primary">${buttonText}</button>
                            <button id="stopBtn_${sk}" onclick="stopAnalysis('${sessionKey}')" class="btn btn-danger" style="display: none;">${t('an_stop')}</button>
                            <button id="minimizeBtn_${sk}" onclick="minimizeAnalysisModal('${sessionKey}')" class="btn btn-secondary" style="display: none;">${t('an_minimize')}</button>
                        </div>
                        <div id="analysisProgress" style="display: none; margin-top: var(--space-3, 12px);">
                            <div class="progress-bar" style="background: var(--bg-surface-sunken, #e9ecef); height: 8px; border-radius: 999px; overflow: hidden;">
                                <div id="progressBar" style="width: 0%; background: var(--accent-bg, #007bff); height: 100%; transition: width 0.4s;"></div>
                            </div>
                            <div id="progressText" style="margin-top: 8px; color: var(--text-secondary); font-size: var(--text-sm, .9em);">${t('an_starting')}</div>
                        </div>

                        <div class="verbose-logs-section" id="verboseLogsSection" style="display: none; margin-top: var(--space-3, 12px);">
                            <div style="border: 1px solid var(--border-default, #ddd); border-radius: var(--radius-md, 6px); overflow: hidden;">
                                <div style="background: var(--bg-surface-sunken, #e9ecef); padding: 8px 10px; border-bottom: 1px solid var(--border-default, #ddd); font-weight: 600; font-size: var(--text-sm, .9em);">${t('an_logs')}</div>
                                <div id="verboseLogs" style="height: 240px; overflow-y: auto; padding: 10px; font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-size: 12px; line-height: 1.5; background: var(--bg-surface, #fff);"></div>
                            </div>
                        </div>

                        <div class="analysis-results" id="analysisResults" style="display: none; margin-top: var(--space-3, 12px);">
                            <h3 style="font-size: var(--text-base, 1rem);">${t('an_results')}</h3>
                            <div id="analysisResultsContent"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Modal'ı sayfaya ekle
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}

/** Read the chosen port-scan scope for a session's modal (default "common"). */
function getAnalysisScope(sessionKey) {
    const el = document.getElementById('scanScope_' + String(sessionKey).replace(/\./g, '_'));
    return el ? el.value : 'common';
}

// Modal kapama işlemini yönet (aktif analiz varsa minimize et)
function handleModalClose(sessionKey) {
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) {
        closeUnifiedAnalysisModal(sessionKey);
        return;
    }
    
    // Analiz durumunu kontrol et
    const modal = document.getElementById(session.modalId);
    if (!modal) {
        closeUnifiedAnalysisModal(sessionKey);
        return;
    }
    
    // Progress gösteriliyor mu kontrol et
    const progressDiv = modal.querySelector('#analysisProgress');
    const isAnalysisActive = progressDiv && progressDiv.style.display !== 'none';
    
    if (isAnalysisActive) {
        // Aktif analiz varsa minimize et
        minimizeAnalysisModal(sessionKey);
    } else {
        // Analiz yoksa normal kapat
        closeUnifiedAnalysisModal(sessionKey);
    }
}

// Birleşik Analiz modal'ını kapat (geriye dönük uyumluluk için de fonksiyon)
function closeSingleDeviceAnalysisModal() {
    // Eski sistem için fallback
    const oldModal = document.getElementById('singleDeviceAnalysisModal');
    if (oldModal) {
        oldModal.remove();
        return;
    }
    
    // Yeni sistem - ilk session'ı kapat
    if (activeAnalysisSessions.size > 0) {
        const firstKey = activeAnalysisSessions.keys().next().value;
        closeUnifiedAnalysisModal(firstKey);
    }
}

// Birleşik Analiz modal'ını kapat
function closeUnifiedAnalysisModal(sessionKey) {
    if (!sessionKey) {
        // Eski sistem fallback
        const modal = document.getElementById('unifiedAnalysisModal') || document.getElementById('singleDeviceAnalysisModal');
        if (modal) {
            modal.remove();
        }
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    const modal = document.getElementById(session.modalId);
    if (modal) {
        modal.remove();
    }
    
    // İlgili toaster'ı temizle
    const toaster = document.getElementById(`analysisToaster_${sessionKey.replace(/\./g, '_')}`);
    if (toaster) {
        toaster.remove();
    }
    
    // Session'ı sil
    activeAnalysisSessions.delete(sessionKey);

    // Analiz penceresi kapatılınca kart listesini tazele ki "Details" butonu
    // (ve güncel portlar) görünsün.
    if (typeof loadDevices === 'function') loadDevices(true);
}

// Modal'ı minimize et
function minimizeAnalysisModal(sessionKey) {
    if (!sessionKey) {
        // Eski sistem fallback
        const modal = document.getElementById('unifiedAnalysisModal') || document.getElementById('singleDeviceAnalysisModal');
        if (modal) {
            modal.style.display = 'none';
            showAnalysisToaster();
        }
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    const modal = document.getElementById(session.modalId);
    if (modal) {
        modal.style.display = 'none';
        session.isMinimized = true;
        isAnalysisMinimized = true;
        showAnalysisToaster(sessionKey);
    }
}

// Modal'ı maximize et
function maximizeAnalysisModal(sessionKey) {
    if (!sessionKey) {
        // Eski sistem fallback
        const modal = document.getElementById('unifiedAnalysisModal') || document.getElementById('singleDeviceAnalysisModal');
        const toaster = document.getElementById('analysisToaster');
        
        if (modal) {
            modal.style.display = 'block';
        }
        
        if (toaster) {
            toaster.remove();
        }
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) {
        // Session yoksa yeniden oluştur
        restoreSessionFromServer(sessionKey);
        return;
    }
    
    const modal = document.getElementById(session.modalId);
    const toaster = document.getElementById(`analysisToaster_${sessionKey.replace(/\./g, '_')}`);
    
    if (modal) {
        modal.style.display = 'block';
        session.isMinimized = false;
        isAnalysisMinimized = false;
        
        // Eğer analiz devam ediyorsa, UI durumunu restore et
        if (typeof bulkAnalysisRunning !== 'undefined' && bulkAnalysisRunning) {
            updateUnifiedAnalysisButtons(sessionKey, true);
            
            // Verbose logs bölümünü göster
            const verboseSection = document.getElementById('verboseLogsSection');
            if (verboseSection) {
                verboseSection.style.display = 'block';
            }
        } else if (sessionKey === 'bulk') {
            // Bulk analiz için server durumunu kontrol et
            checkBulkAnalysisStatusAndRestoreUI(sessionKey);
        }
        
        // Temp dosyasından analiz sonuçlarını yükle
        loadAnalysisFromTemp(sessionKey);
        
        // Modal butonlarını aktif analiz durumuna göre güncelle
        updateModalButtonsForActiveAnalysis(sessionKey);
    }
    
    if (toaster) {
        toaster.remove();
    }
}

// Server'dan session'ı restore et
async function restoreSessionFromServer(sessionKey) {
    try {
        const response = await fetch('/get_active_analyses');
        const activeAnalyses = await response.json();
        
        if (activeAnalyses[sessionKey]) {
            const analysisInfo = activeAnalyses[sessionKey];
            
            if (analysisInfo.type === 'single') {
                await restoreSingleDeviceAnalysis(sessionKey, analysisInfo);
            } else if (analysisInfo.type === 'bulk') {
                await restoreBulkAnalysis(analysisInfo);
            }
            
            // Modal'ı göster
            const session = activeAnalysisSessions.get(sessionKey);
            if (session) {
                const modal = document.getElementById(session.modalId);
                if (modal) {
                    modal.style.display = 'block';
                    session.isMinimized = false;
                }
            }
        }
    } catch (error) {
        console.error('Session restore hatası:', error);
        showToast('❌ ' + t('analysis_session_restore_failed'), 'error');
    }
}

// Temp dosyasından analiz sonuçlarını yükle
async function loadAnalysisFromTemp(sessionKey) {
    try {
        const response = await fetch(`/load_analysis_temp/${sessionKey}`);
        if (response.ok) {
            const tempData = await response.json();
            const session = activeAnalysisSessions.get(sessionKey);
            
            if (session && tempData.analysis_results) {
                const modal = document.getElementById(session.modalId);
                const resultsDiv = modal.querySelector('.analysis-results');
                
                if (resultsDiv && tempData.analysis_results) {
                    resultsDiv.innerHTML = tempData.analysis_results;
                }
                
                // Progress güncelle
                if (tempData.progress !== undefined) {
                    const progressBar = modal.querySelector('.progress-bar-fill');
                    const progressText = modal.querySelector('.progress-text');
                    
                    if (progressBar) {
                        progressBar.style.width = tempData.progress + '%';
                    }
                    
                    if (progressText && tempData.message) {
                        progressText.textContent = tempData.message;
                    }
                }
            }
        }
    } catch (error) {
        console.warn('Temp dosya yükleme hatası:', error);
    }
}

// Modal butonlarını aktif analiz durumuna göre güncelle
async function updateModalButtonsForActiveAnalysis(sessionKey) {
    try {
        const response = await fetch('/get_active_analyses');
        const activeAnalyses = await response.json();
        const isActive = activeAnalyses[sessionKey] && activeAnalyses[sessionKey].status === 'analyzing';
        
        const session = activeAnalysisSessions.get(sessionKey);
        if (!session) return;
        
        const modal = document.getElementById(session.modalId);
        if (!modal) return;
        
        // Butonları bul
        const startBtn = modal.querySelector('[onclick*="startSingleDeviceAnalysis"], [onclick*="startBulkAnalysis"]');
        const stopBtn = modal.querySelector('[onclick*="stopAnalysis"]');
        const minimizeBtn = modal.querySelector(`#minimizeBtn_${sessionKey.replace(/\./g, '_')}`);
        
        if (isActive) {
            // Aktif analiz varsa
            if (startBtn) {
                startBtn.disabled = true;
                startBtn.style.opacity = '0.5';
                startBtn.style.cursor = 'not-allowed';
            }
            
            if (stopBtn) {
                stopBtn.disabled = false;
                stopBtn.style.opacity = '1';
                stopBtn.style.cursor = 'pointer';
                stopBtn.style.display = 'inline-block';
            }
            
            if (minimizeBtn) {
                minimizeBtn.disabled = false;
                minimizeBtn.style.display = 'inline-block';
            }
        } else {
            // Aktif analiz yoksa
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.style.opacity = '1';
                startBtn.style.cursor = 'pointer';
            }
            
            if (stopBtn) {
                stopBtn.style.display = 'none';
            }
            
            if (minimizeBtn) {
                minimizeBtn.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Buton güncelleme hatası:', error);
    }
}

// Analiz toaster'ını göster
function showAnalysisToaster(sessionKey) {
    if (!sessionKey) {
        // Eski sistem fallback
        const existingToaster = document.getElementById('analysisToaster');
        if (existingToaster) {
            existingToaster.remove();
        }
        
        const toasterHtml = `
            <div id="analysisToaster" style="
                position: fixed;
                bottom: 20px;
                right: 20px;
                width: 300px;
                background: linear-gradient(135deg, #007bff, #0056b3);
                color: white;
                padding: 15px;
                border-radius: 10px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                z-index: 10000;
                cursor: pointer;
                transition: all 0.3s ease;
            " onclick="maximizeAnalysisModal()">
                <div style="display: flex; align-items: center; margin-bottom: 8px;">
                    <div style="font-weight: bold; flex: 1;">
                        🔬 Analiz Devam Ediyor
                    </div>
                    <div onclick="event.stopPropagation(); closeSingleDeviceAnalysisModal();" style="
                        background: rgba(255,255,255,0.2);
                        border-radius: 50%;
                        width: 20px;
                        height: 20px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        font-size: 12px;
                        cursor: pointer;
                    ">&times;</div>
                </div>
                <div id="toasterProgressText" style="font-size: 12px; opacity: 0.9;">
                    Analiz işlemi devam ediyor...
                </div>
                <div style="background: rgba(255,255,255,0.2); height: 4px; border-radius: 2px; margin-top: 8px; overflow: hidden;">
                    <div id="toasterProgressBar" style="background: white; height: 100%; width: 0%; transition: width 0.5s;"></div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', toasterHtml);
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    const toasterId = `analysisToaster_${sessionKey.replace(/\./g, '_')}`;
    const existingToaster = document.getElementById(toasterId);
    if (existingToaster) {
        existingToaster.remove();
    }
    
    // Toaster konumunu hesapla (birden fazla toaster için)
    const toasterPosition = calculateToasterPosition();
    const displayName = session.type === 'bulk' ? 'Toplu Analiz' : `Analiz - ${session.targetIP}`;
    
    const toasterHtml = `
        <div id="${toasterId}" style="
            position: fixed;
            bottom: ${toasterPosition.bottom}px;
            right: ${toasterPosition.right}px;
            width: 280px;
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            padding: 12px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            z-index: 10000;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 13px;
        " onclick="maximizeAnalysisModal('${sessionKey}')">
            <div style="display: flex; align-items: center; margin-bottom: 6px;">
                <div style="font-weight: bold; flex: 1;">
                    🔬 ${displayName}
                </div>
                <div onclick="event.stopPropagation(); handleToasterClose('${sessionKey}');" style="
                    background: rgba(255,255,255,0.2);
                    border-radius: 50%;
                    width: 18px;
                    height: 18px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 11px;
                    cursor: pointer;
                ">&times;</div>
            </div>
            <div id="toasterProgressText_${sessionKey.replace(/\./g, '_')}" style="font-size: 11px; opacity: 0.9;">
                Analiz işlemi devam ediyor...
            </div>
            <div style="background: rgba(255,255,255,0.2); height: 3px; border-radius: 2px; margin-top: 6px; overflow: hidden;">
                <div id="toasterProgressBar_${sessionKey.replace(/\./g, '_')}" style="background: white; height: 100%; width: 0%; transition: width 0.5s;"></div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', toasterHtml);
}

// Toaster konumunu hesapla (birden fazla toaster için)
function calculateToasterPosition() {
    const existingToasters = document.querySelectorAll('[id^="analysisToaster_"]');
    const baseBottom = 20;
    const baseRight = 20;
    const toasterHeight = 80; // Yaklaşık toaster yüksekliği
    const margin = 10;
    
    return {
        bottom: baseBottom + (existingToasters.length * (toasterHeight + margin)),
        right: baseRight
    };
}

// Toaster progress güncelle
// state: 'running' (default) | 'success' | 'error' — toaster rengini duruma göre değiştirir
function updateToasterProgress(sessionKey, progressPercent, message, state = 'running') {
    if (!sessionKey) {
        console.warn('updateToasterProgress called without sessionKey');
        return;
    }

    const id = sessionKey.replace(/\./g, '_');
    const toaster = document.getElementById(`analysisToaster_${id}`);
    const toasterProgressBar = document.getElementById(`toasterProgressBar_${id}`);
    const toasterProgressText = document.getElementById(`toasterProgressText_${id}`);

    const gradients = {
        running: 'linear-gradient(135deg, #007bff, #0056b3)',
        success: 'linear-gradient(135deg, #28a745, #20c997)',
        error: 'linear-gradient(135deg, #dc3545, #c82333)',
    };
    if (toaster) {
        toaster.style.background = gradients[state] || gradients.running;
    }

    if (toasterProgressBar) {
        toasterProgressBar.style.width = progressPercent + '%';
    }

    if (toasterProgressText) {
        toasterProgressText.textContent = message;
    }
}

// Analiz tamamlanınca cihaz listesini güvenilir şekilde tazele. loadDevices()
// tek başına yeterli olmalı ama zamanlama/yarış durumlarına karşı: (1) tam
// listeyi yeniden çek, (2) yetmezse ilgili cihazı /device/<ip> ile tek tek
// çekip global `devices` dizisine enjekte ederek kartı yeniden çizdir, (3) bir
// kez daha dene. Böylece "Details" butonu app'i yeniden başlatmadan gelir.
async function refreshDevicesAfterAnalysis(ip) {
    const hasEnhanced = (d) => d && (d.enhanced_comprehensive_info || d.advanced_scan_summary || d.enhanced_info);

    async function fullRefresh() {
        if (typeof loadDevices === 'function') {
            try { await loadDevices(true); } catch (e) { console.warn('loadDevices hatası:', e); }
        }
    }

    async function mergeSingle() {
        // Fallback: authoritative tekil cihaz verisini çekip global diziye işle.
        try {
            const resp = await fetch(`/device/${ip}`);
            if (!resp.ok) return false;
            const dev = await resp.json();
            if (!hasEnhanced(dev)) return false;
            if (typeof devices !== 'undefined' && Array.isArray(devices)) {
                const i = devices.findIndex(d => d.ip === ip);
                if (i >= 0) Object.assign(devices[i], dev); else devices.push(dev);
                if (typeof filterDevices === 'function') filterDevices();
                else if (typeof displayDevices === 'function') displayDevices(devices);
            }
            return true;
        } catch (e) {
            console.warn('mergeSingle hatası:', e);
            return false;
        }
    }

    await fullRefresh();
    // Kart hâlâ enhanced göstermiyorsa tekil merge + bir tekrar dene.
    const shown = (typeof devices !== 'undefined' && Array.isArray(devices))
        ? hasEnhanced(devices.find(d => d.ip === ip)) : true;
    if (!shown) {
        if (!(await mergeSingle())) {
            setTimeout(() => { fullRefresh().then(() => mergeSingle()); }, 1500);
        }
    }
}

// Analiz bittikten sonra "Başlat" butonunu kilitle - yanlışlıkla yeniden analizi engeller
function markAnalysisDone(sessionKey) {
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    const modal = document.getElementById(session.modalId);
    if (!modal) return;
    const startBtn = modal.querySelector(`#startBtn_${sessionKey.replace(/\./g, '_')}`);
    if (startBtn) {
        startBtn.disabled = true;
        startBtn.style.opacity = '0.6';
        startBtn.style.cursor = 'not-allowed';
        startBtn.textContent = '✅ Analiz tamamlandı';
        startBtn.title = 'Yeniden analiz için pencereyi kapatıp tekrar açın';
    }
}

// Toaster kapama işlemini yönet - aktif analiz varsa sadece temp dosyasını temizle
function handleToasterClose(sessionKey) {
    // Aktif analiz durumunu kontrol et
    fetch('/get_active_analyses')
        .then(response => response.json())
        .then(activeAnalyses => {
            const isActive = activeAnalyses[sessionKey] && activeAnalyses[sessionKey].status === 'analyzing';
            
            if (isActive) {
                // Aktif analiz varsa, sadece temp dosyasını temizle, toaster'ı kapatma
                console.log('Aktif analiz devam ediyor, toaster açık kalacak');
                showToast('ℹ️ ' + t('analysis_in_progress_toast'), 'info');
                return;
            } else {
                // Analiz bitmişse toaster'ı kapat
                const toaster = document.getElementById(`analysisToaster_${sessionKey.replace(/\./g, '_')}`);
                if (toaster) {
                    toaster.remove();
                }
                
                // Session'ı temizle
                if (activeAnalysisSessions.has(sessionKey)) {
                    activeAnalysisSessions.delete(sessionKey);
                }

                // Kart listesini tazele ki tamamlanan analizin "Details" butonu gelsin
                if (typeof loadDevices === 'function') loadDevices(true);

                // Temp dosyasını temizle
                fetch(`/clear_analysis_temp/${sessionKey}`, { method: 'POST' })
                    .catch(error => console.warn('Temp dosya temizleme hatası:', error));
            }
        })
        .catch(error => {
            console.error('Aktif analiz kontrolü hatası:', error);
        });
}

// Analiz verilerini temp dosyaya kaydet
async function saveAnalysisToTemp(sessionKey, analysisData) {
    try {
        const response = await fetch('/save_analysis_temp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                session_key: sessionKey,
                analysis_data: analysisData
            })
        });
        
        if (!response.ok) {
            console.warn('Temp dosya kaydetme hatası:', response.statusText);
        }
    } catch (error) {
        console.warn('Temp dosya kaydetme hatası:', error);
    }
}

// Analiz tamamlandı notification'ı göster
function showAnalysisCompletedNotification(ip, sessionKey) {
    const notificationHtml = `
        <div id="completedNotification" style="
            position: fixed;
            top: 20px;
            right: 20px;
            width: 350px;
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            z-index: 10001;
            animation: slideInRight 0.5s ease;
        ">
            <div style="display: flex; align-items: center; margin-bottom: 10px;">
                <div style="font-size: 24px; margin-right: 10px;">✅</div>
                <div style="font-weight: bold; flex: 1;">
                    Analiz Tamamlandı!
                </div>
                <div onclick="document.getElementById('completedNotification').remove();" style="
                    background: rgba(255,255,255,0.2);
                    border-radius: 50%;
                    width: 24px;
                    height: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    cursor: pointer;
                ">&times;</div>
            </div>
            <div style="font-size: 14px; opacity: 0.9;">
                ${ip} için detaylı analiz başarıyla tamamlandı.
            </div>
            <div style="margin-top: 15px;">
                <button onclick="maximizeAnalysisModal('${sessionKey}'); document.getElementById('completedNotification').remove();"
                        style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 8px 16px; border-radius: 5px; cursor: pointer;">
                    📊 Sonuçları Gör
                </button>
            </div>
        </div>
        
        <style>
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        </style>
    `;
    
    document.body.insertAdjacentHTML('beforeend', notificationHtml);
    
    // 10 saniye sonra otomatik kapat
    setTimeout(() => {
        const notification = document.getElementById('completedNotification');
        if (notification) {
            notification.remove();
        }
    }, 10000);
}

// Toplu analiz başlat
async function startBulkAnalysis() {
    const sessionKey = 'bulk';
    
    // Modal'ın var olduğunu kontrol et, yoksa oluştur
    if (!activeAnalysisSessions.has(sessionKey)) {
        console.error('Bulk analysis modal not found. Creating modal first...');
        showUnifiedAnalysisModal(null, 'bulk');
        // Modal oluşturulduktan sonra kısa bir bekleme
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    const modal = document.getElementById(session.modalId);
    
    const progressDiv = modal.querySelector('#analysisProgress');
    const progressBar = modal.querySelector('#progressBar');
    const progressText = modal.querySelector('#progressText');
    const resultsDiv = modal.querySelector('#analysisResults');
    const verboseLogsSection = modal.querySelector('#verboseLogsSection');
    const verboseLogs = modal.querySelector('#verboseLogs');
    const minimizeBtn = modal.querySelector(`#minimizeBtn_${sessionKey.replace(/\./g, '_')}`);
    
    // Element'lerin var olduğunu kontrol et
    if (!progressDiv || !progressBar || !progressText || !resultsDiv || !verboseLogsSection || !verboseLogs || !minimizeBtn) {
        console.error('Required modal elements not found:', {
            progressDiv: !!progressDiv,
            progressBar: !!progressBar,
            progressText: !!progressText,
            resultsDiv: !!resultsDiv,
            verboseLogsSection: !!verboseLogsSection,
            verboseLogs: !!verboseLogs,
            minimizeBtn: !!minimizeBtn
        });
        alert(t('modal_elements_missing'));
        return;
    }
    
    // Progress göster
    progressDiv.style.display = 'block';
    resultsDiv.style.display = 'none';
    verboseLogsSection.style.display = 'block';
    minimizeBtn.style.display = 'inline-block';
    
    // Verbose logları temizle
    verboseLogs.innerHTML = '';
    
    try {
        addVerboseLog('🚀 Toplu gelişmiş analiz başlatılıyor...');
        
        // Toplu analiz başlat
        const response = await fetch('/detailed_analysis');
        const result = await response.json();
        
        if (response.ok) {
            progressText.textContent = 'Toplu analiz başlatıldı, ilerlenme takip ediliyor...';
            progressBar.style.width = '5%';
            progressBar.textContent = '5%';
            addVerboseLog('✅ Toplu analiz başarıyla başlatıldı');
            addVerboseLog('🔄 Real-time izleme başlatılıyor...');
            
            // Progress takip et
            monitorBulkAnalysisProgress();
            
        } else {
            progressText.textContent = `Analysis error: ${result.error}`;
            addVerboseLog(`❌ Analiz başlatma hatası: ${result.error}`);
            progressDiv.style.display = 'none';
        }
    } catch (error) {
        progressText.textContent = `Connection error: ${error.message}`;
        addVerboseLog(`❌ Bağlantı hatası: ${error.message}`);
        progressDiv.style.display = 'none';
    }
}

// Toplu analiz durumunu takip et
function monitorBulkAnalysisProgress() {
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const resultsDiv = document.getElementById('analysisResults');
    const resultsContent = document.getElementById('analysisResultsContent');
    
    let progressPercent = 5;
    let lastMessage = '';
    
    const checkInterval = setInterval(async () => {
        try {
            const response = await fetch('/detailed_analysis_status');
            const status = await response.json();
            
            if (status.status === 'completed') {
                clearInterval(checkInterval);
                progressPercent = 100;
                progressBar.style.width = '100%';
                progressBar.textContent = '100%';
                progressText.textContent = 'Toplu analiz tamamlandı!';
                
                addVerboseLog('✅ Toplu analiz başarıyla tamamlandı!');
                addVerboseLog('📊 Sonuçlar hazırlanıyor...');
                
                // Toaster progress güncelle
                if (isAnalysisMinimized) {
                    updateToasterProgress('bulk', 100, 'Toplu analiz tamamlandı!');
                }
                
                // Tamamlandı notification göster
                showAnalysisCompletedNotification();
                
                // Sonuçları göster
                setTimeout(() => {
                    document.getElementById('analysisProgress').style.display = 'none';
                    resultsDiv.style.display = 'block';
                    resultsContent.innerHTML = `
                        <div class="analysis-summary">
                            <h4>🎉 Toplu Gelişmiş Analiz Tamamlandı</h4>
                            <p>Tüm cihazların gelişmiş analizi başarıyla tamamlandı. Güncellenmiş bilgileri görmek için cihaz listesini yenileyin.</p>
                            <button onclick="if(typeof loadDevices === 'function') loadDevices(true); else window.location.reload();" class="btn btn-success">
                                🔄 Cihaz Listesini Yenile
                            </button>
                        </div>
                    `;
                }, 1000);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                progressText.textContent = `Analysis error: ${status.message}`;
                progressBar.style.backgroundColor = '#dc3545';
                progressBar.textContent = 'HATA';
                
                addVerboseLog(`❌ Analiz hatası: ${status.message}`);
                
                // Toaster'ı güncelle
                if (isAnalysisMinimized) {
                    updateToasterProgress('bulk', 0, 'Analiz hatası!');
                }
                
            } else if (status.status === 'analyzing') {
                const currentMessage = status.message || 'Analysis in progress...';
                progressText.textContent = currentMessage;
                
                // Verbose log'a sadece yeni mesajları ekle
                if (currentMessage !== lastMessage) {
                    addVerboseLog(`🔄 ${currentMessage}`);
                    lastMessage = currentMessage;
                }
                
                // Progress artır (max %90'a kadar)
                if (progressPercent < 90) {
                    progressPercent += 3;
                    progressBar.style.width = progressPercent + '%';
                    progressBar.textContent = progressPercent + '%';
                }
                
                // Toaster progress güncelle
                if (isAnalysisMinimized) {
                    updateToasterProgress('bulk', progressPercent, currentMessage);
                }
                
                // Temp dosyaya kaydet
                saveAnalysisToTemp('bulk', {
                    progress: progressPercent,
                    message: currentMessage,
                    status: status.status,
                    analysis_results: resultsContent ? resultsContent.innerHTML : '',
                    timestamp: new Date().toISOString()
                });
            }
        } catch (error) {
            console.error('Toplu analiz durumu kontrol hatası:', error);
            addVerboseLog(`⚠️ Status kontrol hatası: ${error.message}`);
        }
    }, 2000); // Her 2 saniyede kontrol et
}

// Tek cihaz analizi başlat
async function startSingleDeviceAnalysis(ip) {
    const sessionKey = ip;
    
    // Session kontrolü
    if (!activeAnalysisSessions.has(sessionKey)) {
        console.error('Single device analysis session not found for:', ip);
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    const modal = document.getElementById(session.modalId);
    
    const progressDiv = modal.querySelector('#analysisProgress');
    const progressBar = modal.querySelector('#progressBar');
    const progressText = modal.querySelector('#progressText');
    const resultsDiv = modal.querySelector('#analysisResults');
    const verboseLogsSection = modal.querySelector('#verboseLogsSection');
    const verboseLogs = modal.querySelector('#verboseLogs');
    const minimizeBtn = modal.querySelector(`#minimizeBtn_${sessionKey.replace(/\./g, '_')}`);
    
    // Progress göster
    progressDiv.style.display = 'block';
    resultsDiv.style.display = 'none';
    verboseLogsSection.style.display = 'block';
    minimizeBtn.style.display = 'inline-block';
    
    // Verbose logları temizle
    verboseLogs.innerHTML = '';
    
    // Butonları güncelle
    updateAnalysisButtons(sessionKey, true);
    
    const scope = getAnalysisScope(sessionKey);

    try {
        addVerboseLog(`🚀 ${t('an_starting')}`, sessionKey);
        addVerboseLog(`📡 ${ip} (${scope})`, sessionKey);

        // Enhanced analiz başlat - kapsam (port scan scope) ile birlikte
        const response = await fetch(`/enhanced_analysis/${ip}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope })
        });

        const result = await response.json();

        if (response.ok) {
            progressText.textContent = t('an_starting');
            progressBar.textContent = '5%';
            addVerboseLog('✅ Analysis started successfully', sessionKey);
            addVerboseLog('🔄 Starting real-time monitoring...', sessionKey);
            
            // Progress takip et
            monitorSingleDeviceAnalysis(ip);
            
        } else {
            progressText.textContent = `Analysis error: ${result.error}`;
            addVerboseLog(`❌ Failed to start analysis: ${result.error}`, sessionKey);
            progressDiv.style.display = 'none';
        }
    } catch (error) {
        progressText.textContent = `Connection error: ${error.message}`;
        addVerboseLog(`❌ Connection error: ${error.message}`, sessionKey);
        progressDiv.style.display = 'none';
    }
}

// Analiz butonlarını güncelle (başlat/durdur)
function updateAnalysisButtons(sessionKey, isRunning) {
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    const modal = document.getElementById(session.modalId);
    if (!modal) return;
    
    const startBtn = modal.querySelector(`#startBtn_${sessionKey.replace(/\./g, '_')}`);
    const stopBtn = modal.querySelector(`#stopBtn_${sessionKey.replace(/\./g, '_')}`);
    
    if (startBtn && stopBtn) {
        if (isRunning) {
            startBtn.disabled = true;
            startBtn.style.opacity = '0.6';
            stopBtn.style.display = 'inline-block';
        } else {
            startBtn.disabled = false;
            startBtn.style.opacity = '1';
            stopBtn.style.display = 'none';
        }
    }
}

// Analizi durdur
async function stopAnalysis(sessionKey) {
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    try {
        if (session.type === 'bulk') {
            // Toplu analizi durdur
            const response = await fetch('/stop_bulk_analysis', {
                method: 'POST'
            });
            addVerboseLog('🛑 Bulk analysis stop request sent...', sessionKey);
        } else {
            // Tek cihaz analizini durdur
            const response = await fetch(`/stop_enhanced_analysis/${session.targetIP}`, {
                method: 'POST'
            });
            addVerboseLog(`🛑 Stop request sent for ${session.targetIP} analysis...`, sessionKey);
        }
        
        // Butonları güncelle
        updateAnalysisButtons(sessionKey, false);
        
        // Progress'i durdur
        const modal = document.getElementById(session.modalId);
        const progressText = modal.querySelector('#progressText');
        if (progressText) {
            progressText.textContent = 'Analysis stopped.';
        }
        
        addVerboseLog('✅ Analysis stopped successfully', sessionKey);
        
    } catch (error) {
        addVerboseLog(`❌ Failed to stop analysis: ${error.message}`, sessionKey);
    }
}

// Verbose log ekle - Session-aware version
function addVerboseLog(message, sessionKey = null) {
    // Session key yoksa, aktif session'ları kontrol et
    if (!sessionKey && activeAnalysisSessions.size > 0) {
        // İlk aktif session'ı kullan
        sessionKey = activeAnalysisSessions.keys().next().value;
    }
    
    if (sessionKey && activeAnalysisSessions.has(sessionKey)) {
        const session = activeAnalysisSessions.get(sessionKey);
        const modal = document.getElementById(session.modalId);
        if (modal) {
            const verboseLogs = modal.querySelector('#verboseLogs');
            if (verboseLogs) {
                const timestamp = new Date().toLocaleTimeString();
                const logEntry = document.createElement('div');
                logEntry.style.marginBottom = '4px';
                logEntry.innerHTML = `<span style="color: #666;">[${timestamp}]</span> ${message}`;
                verboseLogs.appendChild(logEntry);
                verboseLogs.scrollTop = verboseLogs.scrollHeight;
            }
        }
    }
}

// Tek cihaz analiz durumunu takip et
function monitorSingleDeviceAnalysis(ip) {
    const sessionKey = ip;
    const session = activeAnalysisSessions.get(sessionKey);
    const modal = document.getElementById(session.modalId);

    const progressBar = modal.querySelector('#progressBar');
    const progressText = modal.querySelector('#progressText');

    // Reveal the live progress + log sections whenever monitoring is active.
    // On a page refresh the modal is rebuilt fresh (start() never ran), so
    // without this the reopened popup shows only buttons and looks idle even
    // though the analysis is still running.
    const progressDiv = modal.querySelector('#analysisProgress');
    const verboseLogsSection = modal.querySelector('#verboseLogsSection');
    if (progressDiv) progressDiv.style.display = 'block';
    if (verboseLogsSection) verboseLogsSection.style.display = 'block';
    updateAnalysisButtons(sessionKey, true);
    const resultsDiv = modal.querySelector('#analysisResults');
    const resultsContent = modal.querySelector('#analysisResultsContent');
    
    let progressPercent = 5;
    let lastMessage = '';
    
    const checkInterval = setInterval(async () => {
        try {
            const response = await fetch(`/enhanced_analysis_status/${ip}`);
            const status = await response.json();
            
            if (status.status === 'completed') {
                clearInterval(checkInterval);
                progressPercent = 100;
                progressBar.style.width = '100%';
                progressBar.textContent = '100%';
                progressBar.style.background = 'linear-gradient(90deg, #28a745, #20c997)';
                progressText.textContent = '✅ Analysis complete!';

                addVerboseLog('✅ Analysis completed successfully!', sessionKey);
                addVerboseLog('📊 Loading results...', sessionKey);

                // Butonları sıfırla ve tekrar başlatmayı engelle (yanlışlıkla yeniden analiz)
                updateAnalysisButtons(sessionKey, false);
                markAnalysisDone(sessionKey);

                // Toaster'ı yeşile çevir (bittiğini göster) - her durumda güncelle
                updateToasterProgress(sessionKey, 100, '✅ Analiz tamamlandı!', 'success');

                // Tamamlandı notification göster
                showAnalysisCompletedNotification(ip, sessionKey);
                showToast(`🎉 ${t('enhanced_analysis_completed', {ip: ip})}`, 'success');

                // Kart listesini HEMEN ve koşulsuz tazele - "Details" butonunun
                // gelmesi buna bağlı. Modal minimize/kapalı olsa bile çalışsın diye
                // modal'a dokunan koddan ÖNCE ve ayrı olarak çağırıyoruz.
                refreshDevicesAfterAnalysis(ip);

                // Analiz bitince ham JSON dökmek yerine analiz penceresini kapat
                // ve doğrudan cihazın "Details" sayfasını aç.
                setTimeout(async () => {
                    try {
                        const device = await fetch(`/device/${ip}`).then(r => r.json());
                        closeUnifiedAnalysisModal(sessionKey);
                        if (device && typeof openEnhancedDetailsModal === 'function') {
                            openEnhancedDetailsModal(device);
                        }
                    } catch (e) {
                        console.warn('Details açılışı atlandı:', e);
                    }
                }, 800);

            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                progressText.textContent = `Analysis error: ${status.message}`;
                progressBar.style.backgroundColor = '#dc3545';
                progressBar.textContent = 'HATA';
                
                addVerboseLog(`❌ Analysis error: ${status.message}`, sessionKey);
                showToast(`❌ ${t('enhanced_analysis_error', {ip: ip, error: status.message || ''})}`, 'error');

                // Butonları sıfırla
                updateAnalysisButtons(sessionKey, false);

                // Toaster'ı kırmızıya çevir (hata) - her durumda güncelle
                updateToasterProgress(sessionKey, progressPercent || 100, `❌ ${status.message || 'Analiz hatası'}`, 'error');

            } else if (status.status === 'stopped') {
                clearInterval(checkInterval);
                progressText.textContent = 'Analysis stopped';
                progressBar.style.backgroundColor = '#6c757d';
                progressBar.textContent = 'DURDURULDU';
                
                addVerboseLog('🛑 Analysis stopped by user', sessionKey);
                
                // Butonları sıfırla
                updateAnalysisButtons(sessionKey, false);
                
                // Toaster'ı güncelle
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, 0, 'Analiz durduruldu');
                }
                
            } else if (status.status === 'analyzing') {
                const currentMessage = status.message || 'Analysis in progress...';
                progressText.textContent = currentMessage;
                
                // Verbose log'a sadece yeni mesajları ekle
                if (currentMessage !== lastMessage) {
                    addVerboseLog(`🔄 ${currentMessage}`, sessionKey);
                    lastMessage = currentMessage;
                }
                
                // Backend'ten gelen progress kullan, yoksa artır
                if (status.progress) {
                    progressPercent = Math.round(status.progress);
                    progressBar.style.width = progressPercent + '%';
                    progressBar.textContent = progressPercent + '%';
                } else {
                    // Fallback: manuel artırım (max %90'a kadar)
                    if (progressPercent < 90) {
                        progressPercent += 5;
                        progressBar.style.width = progressPercent + '%';
                        progressBar.textContent = progressPercent + '%';
                    }
                }
                
                // Toaster progress güncelle
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, progressPercent, currentMessage);
                }

                // Temp dosyaya kaydet
                saveAnalysisToTemp(sessionKey, {
                    progress: progressPercent,
                    message: currentMessage,
                    status: status.status,
                    analysis_results: resultsContent ? resultsContent.innerHTML : '',
                    timestamp: new Date().toISOString()
                });
                // Not: backend'ten gelen `currentMessage` zaten hangi port aralığının
                // tarandığını içeriyor ve yukarıda sadece değiştiğinde loglanıyor.
                // Eskiden burada çağrılan analyzeStatusMessage() her poll'da generic
                // "Port tarama devam ediyor" satırı basıp log'u dolduruyordu - kaldırıldı.
            }
        } catch (error) {
            console.error('Analiz durumu kontrol hatası:', error);
            addVerboseLog(`⚠️ Status check error: ${error.message}`, sessionKey);
        }
    }, 2000); // Her 2 saniyede kontrol et
}


// Cihaz analiz sonuçlarını yükle ve göster
async function loadDeviceAnalysisResults(ip, sessionKey) {
    const session = activeAnalysisSessions.get(sessionKey);
    const modal = document.getElementById(session.modalId);
    const resultsContent = modal.querySelector('#analysisResultsContent');
    
    try {
        const response = await fetch(`/device/${ip}`);
        const device = await response.json();
        
        if (response.ok && device) {
            const enhancedInfo = device.enhanced_comprehensive_info || device.enhanced_info || {};
            
            let resultsHtml = `
                <div class="device-analysis-summary">
                    <h4>${device.alias || device.hostname || ip}</h4>
                    <p><strong>IP:</strong> ${device.ip}</p>
                    <p><strong>MAC:</strong> ${device.mac || 'N/A'}</p>
                    <p><strong>Vendor:</strong> ${device.vendor || 'N/A'}</p>
                    <p><strong>Device Type:</strong> ${device.device_type || 'Unknown'}</p>
                    <p><strong>Status:</strong> ${device.status || 'N/A'}</p>
                </div>
            `;
            
            // Open ports
            if (device.open_ports && device.open_ports.length > 0) {
                resultsHtml += `
                    <div class="analysis-section">
                        <h4>🔌 Açık Portlar</h4>
                        <div class="ports-grid">
                `;
                
                device.open_ports.forEach(port => {
                    if (typeof port === 'object') {
                        resultsHtml += `
                            <div class="port-item">
                                <span class="port-number">${port.port}</span>
                                <span class="port-description">${port.description || port.service || 'Unknown'}</span>
                            </div>
                        `;
                    } else {
                        resultsHtml += `
                            <div class="port-item">
                                <span class="port-number">${port}</span>
                                <span class="port-description">Unknown Service</span>
                            </div>
                        `;
                    }
                });
                
                resultsHtml += `
                        </div>
                    </div>
                `;
            }
            
            // Enhanced info
            if (enhancedInfo && Object.keys(enhancedInfo).length > 0) {
                resultsHtml += `
                    <div class="analysis-section">
                        <h4>🔍 Gelişmiş Analiz Bilgileri</h4>
                        <div class="enhanced-info">
                            <pre>${JSON.stringify(enhancedInfo, null, 2)}</pre>
                        </div>
                    </div>
                `;
            }
            
            resultsContent.innerHTML = resultsHtml;
        } else {
            resultsContent.innerHTML = '<p>Cihaz bilgileri yüklenemedi.</p>';
        }
    } catch (error) {
        resultsContent.innerHTML = `<p>Hata: ${error.message}</p>`;
    }
}

// Gelişmiş analiz durumunu takip et
function monitorEnhancedAnalysis(ip) {
    const checkInterval = setInterval(async () => {
        try {
            const response = await fetch(`/enhanced_analysis_status/${ip}`);
            const status = await response.json();
            
            if (status.status === 'completed') {
                clearInterval(checkInterval);
                showToast(`🎉 ${t('enhanced_analysis_completed', {ip: ip})}`, 'success');
                
                // Cihaz listesini yenile
                await loadDevices(true);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                showToast(`❌ ${t('enhanced_analysis_error', {ip: ip, error: status.message})}`, 'error');
            } else if (status.status === 'analyzing') {
                // Progress göster (isteğe bağlı)
                console.log(`${ip} analiz ediliyor: ${status.message}`);
            }
        } catch (error) {
            console.error('Enhanced analiz durumu kontrol hatası:', error);
        }
    }, 3000); // Her 3 saniyede kontrol et
}

// Cihaz tablosuna erişim butonu ekle
function addAccessButtonToDevice(deviceRow, ip) {
    const actionsCell = deviceRow.querySelector('.device-actions');
    if (actionsCell) {
        const accessBtn = document.createElement('button');
        accessBtn.className = 'btn btn-sm btn-info';
        accessBtn.innerHTML = '🔐';
        accessBtn.title = t('access_credentials');
        accessBtn.onclick = () => openDeviceAccessModal(ip);
        
        actionsCell.appendChild(accessBtn);
    }
}

// Bulk analiz durumunu kontrol et ve UI'yi restore et
async function checkBulkAnalysisStatusAndRestoreUI(sessionKey) {
    try {
        const response = await fetch('/get_active_analyses');
        const activeAnalyses = await response.json();
        
        if (activeAnalyses.bulk && activeAnalyses.bulk.status === 'analyzing') {
            // Server'da bulk analiz devam ediyor, UI'yi restore et
            updateUnifiedAnalysisButtons(sessionKey, true);
            
            // Verbose logs bölümünü göster
            const verboseSection = document.getElementById('verboseLogsSection');
            if (verboseSection) {
                verboseSection.style.display = 'block';
            }
            
            // Global değişkeni güncelle
            if (typeof bulkAnalysisRunning !== 'undefined') {
                window.bulkAnalysisRunning = true;
            }
            
            console.log('✅ Bulk analiz UI durumu server state\'inden restore edildi');
        } else {
            // Analiz devam etmiyor, normal UI
            updateUnifiedAnalysisButtons(sessionKey, false);
            console.log('ℹ️ Bulk analiz tamamlanmış veya durmuş');
        }
    } catch (error) {
        console.error('Bulk analiz durumu kontrol hatası:', error);
    }
}

// Modal dışına tıklandığında kapat
window.addEventListener('click', function(event) {
    const modal = document.getElementById('deviceAccessModal');
    if (event.target === modal) {
        closeDeviceAccessModal();
    }
});

// Klavye kısayolları
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape' && document.getElementById('deviceAccessModal').style.display === 'block') {
        closeDeviceAccessModal();
    }
});