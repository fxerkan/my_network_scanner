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
                    passwordField.placeholder = 'Şifre girin';
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
        showToast('Geçersiz cihaz!', 'error');
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
            showToast('Erişim bilgileri kaydedildi!', 'success');
            console.log('Credentials saved successfully');
        } else {
            console.error('Save error:', result.error);
            showToast(`Kayıt hatası: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Save connection error:', error);
        showToast(`Bağlantı hatası: ${error.message}`, 'error');
    }
}

// Erişim testi
async function testDeviceAccess() {
    if (!currentAccessDevice) {
        showToast('Geçersiz cihaz!', 'error');
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
    testBtn.innerHTML = '🔄 Test ediliyor...';
    
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
                showToast(`✅ Erişim başarılı! ${result.details || ''}`, 'success');
            } else {
                console.error('Test failed:', result.error);
                showToast(`❌ Erişim başarısız: ${result.error}`, 'error');
            }
        } else {
            console.error('Test error response:', result.error);
            showToast(`Test hatası: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Test connection error:', error);
        showToast(`Bağlantı hatası: ${error.message}`, 'error');
    } finally {
        // Test butonunu tekrar aktif et
        testBtn.disabled = false;
        testBtn.innerHTML = originalText;
    }
}

// Gelişmiş analiz çalıştır - artık Detaylı Cihaz Analizi sayfasını açar
async function runEnhancedAnalysis() {
    if (!currentAccessDevice) {
        showToast('Geçersiz cihaz!', 'error');
        return;
    }
    
    // IP'yi kaydet (modal kapanmadan önce)
    const deviceIP = currentAccessDevice;
    
    // Önce erişim bilgilerini kaydet
    await saveDeviceAccess();
    
    showToast('Erişim bilgileri kaydedildi! Detaylı Cihaz Analizi sayfası açılıyor...', 'success');
    
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
    const title = isSingleDevice ? `🔬 Gelişmiş Analiz - ${targetIP}` : '🔬 Toplu Gelişmiş Analiz';
    const buttonText = isSingleDevice ? '🚀 Gelişmiş Analizi Başlat' : '🚀 Toplu Gelişmiş Analizi Başlat';
    const startFunction = isSingleDevice ? `startSingleDeviceAnalysis('${targetIP}')` : `startUnifiedBulkAnalysis('${sessionKey}')`;
    
    // Açıklama metni
    const descriptionText = isSingleDevice ? 
        `Bu analiz ${targetIP} cihazında kapsamlı bir inceleme yapar. Erişim bilgileri varsa SSH, FTP, HTTP ve SNMP protokolleri üzerinden detaylı sistem bilgileri toplar.` :
        'Bu analiz tüm ağdaki cihazlarda gelişmiş tarama ve analiz işlemleri gerçekleştirir. Her cihaz için mevcut erişim bilgileri kullanılarak kapsamlı bilgi toplama yapar.';
    
    // Benzersiz modal ID'si oluştur
    const modalId = `unifiedAnalysisModal_${sessionKey.replace(/\./g, '_')}`;
    
    // Session'ı kaydet
    activeAnalysisSessions.set(sessionKey, {
        isMinimized: false,
        type: analysisType,
        modalId: modalId,
        targetIP: targetIP
    });
    
    // Modal oluştur
    const modalHtml = `
        <div id="${modalId}" class="modal" style="display: block;">
            <div class="modal-content" style="width: 95%; max-width: 1400px; max-height: 90vh; overflow-y: auto;">
                <div class="modal-header">
                    <h2>${title}</h2>
                    <div class="modal-controls">
                        <span class="close" onclick="handleModalClose('${sessionKey}')">&times;</span>
                    </div>
                </div>
                <div class="modal-body">
                    <!-- Açıklama Bölümü -->
                    <div class="analysis-description" style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #007bff;">
                        <h4 style="margin: 0 0 10px 0; color: #007bff;">📋 Gelişmiş Analiz Hakkında</h4>
                        <p style="margin: 0; color: #6c757d; line-height: 1.5;">${descriptionText}</p>
                        <div style="margin-top: 10px; font-size: 0.9em;">
                            <strong>Yapılacak İşlemler:</strong>
                            <ul style="margin: 5px 0 0 20px; color: #6c757d;">
                                <li>🔍 Port tarama ve servis tespiti</li>
                                <li>🔐 Erişim bilgileri ile sistem analizi</li>
                                <li>💻 Donanım ve yazılım bilgisi toplama</li>
                                <li>🛡️ Güvenlik durumu değerlendirmesi</li>
                                <li>📊 Kapsamlı rapor oluşturma</li>
                            </ul>
                        </div>
                    </div>

                    <div id="unifiedAnalysisContent">
                        <div class="analysis-section">
                            <button id="startBtn_${sessionKey.replace(/\./g, '_')}" onclick="${startFunction}" class="btn btn-primary">
                                ${buttonText}
                            </button>
                            <button id="stopBtn_${sessionKey.replace(/\./g, '_')}" onclick="stopAnalysis('${sessionKey}')" 
                                class="btn btn-danger" style="display: none; margin-left: 10px;">
                                🛑 Analizi Durdur
                            </button>
                            <button id="minimizeBtn_${sessionKey.replace(/\./g, '_')}" onclick="minimizeAnalysisModal('${sessionKey}')" 
                                class="btn btn-secondary" style="display: none; margin-left: 10px;">
                                📦 Minimize
                            </button>
                            <div id="analysisProgress" style="display: none; margin-top: 15px;">
                                <div class="progress-bar" style="background: #e9ecef; height: 25px; border-radius: 5px; overflow: hidden;">
                                    <div id="progressBar" style="width: 0%; background: linear-gradient(90deg, #007bff, #0056b3); height: 100%; transition: width 0.5s; color: white; text-align: center; line-height: 25px; font-weight: bold;"></div>
                                </div>
                                <div id="progressText" style="margin-top: 10px; font-weight: bold;">Analiz başlatılıyor...</div>
                            </div>
                        </div>
                        
                        <!-- Verbose Log Section -->
                        <div class="verbose-logs-section" id="verboseLogsSection" style="display: none; margin-top: 20px;">
                            <div style="border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa;">
                                <div style="background: #e9ecef; padding: 10px; border-bottom: 1px solid #ddd; font-weight: bold;">
                                    📝 Detaylı Analiz Logları (Real-time)
                                </div>
                                <div id="verboseLogs" style="height: 300px; overflow-y: auto; padding: 10px; font-family: 'Courier New', monospace; font-size: 12px; line-height: 1.4; background: #fff;">
                                    <!-- Verbose loglar buraya gelecek -->
                                </div>
                            </div>
                        </div>
                        
                        <div class="analysis-results" id="analysisResults" style="display: none; margin-top: 20px;">
                            <h3>Analiz Sonuçları</h3>
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
        showToast('❌ Analiz session restore edilemedi', 'error');
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
function updateToasterProgress(sessionKey, progressPercent, message) {
    if (!sessionKey) {
        console.warn('updateToasterProgress called without sessionKey');
        return;
    }
    
    const toasterProgressBar = document.getElementById(`toasterProgressBar_${sessionKey.replace(/\./g, '_')}`);
    const toasterProgressText = document.getElementById(`toasterProgressText_${sessionKey.replace(/\./g, '_')}`);
    
    if (toasterProgressBar) {
        toasterProgressBar.style.width = progressPercent + '%';
    }
    
    if (toasterProgressText) {
        toasterProgressText.textContent = message;
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
                showToast('ℹ️ Analiz devam ediyor, toaster açık kalacak', 'info');
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
function showAnalysisCompletedNotification() {
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
                ${currentAnalysisIP} için detaylı analiz başarıyla tamamlandı.
            </div>
            <div style="margin-top: 15px;">
                <button onclick="maximizeAnalysisModal(); document.getElementById('completedNotification').remove();" 
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
        alert('Modal elementleri bulunamadı. Lütfen sayfayı yenileyin.');
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
            progressText.textContent = `Analiz hatası: ${result.error}`;
            addVerboseLog(`❌ Analiz başlatma hatası: ${result.error}`);
            progressDiv.style.display = 'none';
        }
    } catch (error) {
        progressText.textContent = `Bağlantı hatası: ${error.message}`;
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
                progressText.textContent = `Analiz hatası: ${status.message}`;
                progressBar.style.backgroundColor = '#dc3545';
                progressBar.textContent = 'HATA';
                
                addVerboseLog(`❌ Analiz hatası: ${status.message}`);
                
                // Toaster'ı güncelle
                if (isAnalysisMinimized) {
                    updateToasterProgress('bulk', 0, 'Analiz hatası!');
                }
                
            } else if (status.status === 'analyzing') {
                const currentMessage = status.message || 'Analiz devam ediyor...';
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
    
    try {
        addVerboseLog('🚀 Detaylı analiz başlatılıyor...', sessionKey);
        addVerboseLog(`📡 Hedef cihaz: ${ip}`, sessionKey);
        
        // Enhanced analiz başlat
        const response = await fetch(`/enhanced_analysis/${ip}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            progressText.textContent = 'Analiz başlatıldı, ilerlenme takip ediliyor...';
            progressBar.textContent = '5%';
            addVerboseLog('✅ Analiz başarıyla başlatıldı', sessionKey);
            addVerboseLog('🔄 Real-time izleme başlatılıyor...', sessionKey);
            
            // Progress takip et
            monitorSingleDeviceAnalysis(ip);
            
        } else {
            progressText.textContent = `Analiz hatası: ${result.error}`;
            addVerboseLog(`❌ Analiz başlatma hatası: ${result.error}`, sessionKey);
            progressDiv.style.display = 'none';
        }
    } catch (error) {
        progressText.textContent = `Bağlantı hatası: ${error.message}`;
        addVerboseLog(`❌ Bağlantı hatası: ${error.message}`, sessionKey);
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
            addVerboseLog('🛑 Toplu analiz durdurma talebi gönderildi...', sessionKey);
        } else {
            // Tek cihaz analizini durdur
            const response = await fetch(`/stop_enhanced_analysis/${session.targetIP}`, {
                method: 'POST'
            });
            addVerboseLog(`🛑 ${session.targetIP} analizi durdurma talebi gönderildi...`, sessionKey);
        }
        
        // Butonları güncelle
        updateAnalysisButtons(sessionKey, false);
        
        // Progress'i durdur
        const modal = document.getElementById(session.modalId);
        const progressText = modal.querySelector('#progressText');
        if (progressText) {
            progressText.textContent = 'Analiz durduruldu.';
        }
        
        addVerboseLog('✅ Analiz başarıyla durduruldu', sessionKey);
        
    } catch (error) {
        addVerboseLog(`❌ Analiz durdurma hatası: ${error.message}`, sessionKey);
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
                progressText.textContent = 'Analiz tamamlandı!';
                
                addVerboseLog('✅ Analiz başarıyla tamamlandı!', sessionKey);
                addVerboseLog('📊 Sonuçlar yükleniyor...', sessionKey);
                
                // Butonları sıfırla
                updateAnalysisButtons(sessionKey, false);
                
                // Toaster progress güncelle
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, 100, 'Analiz tamamlandı!');
                }
                
                // Tamamlandı notification göster
                showAnalysisCompletedNotification();
                
                // Sonuçları göster
                setTimeout(() => {
                    modal.querySelector('#analysisProgress').style.display = 'none';
                    resultsDiv.style.display = 'block';
                    
                    // Cihaz detaylarını yeniden yükle ve göster
                    loadDeviceAnalysisResults(ip, sessionKey);
                }, 1000);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                progressText.textContent = `Analiz hatası: ${status.message}`;
                progressBar.style.backgroundColor = '#dc3545';
                progressBar.textContent = 'HATA';
                
                addVerboseLog(`❌ Analiz hatası: ${status.message}`, sessionKey);
                
                // Butonları sıfırla
                updateAnalysisButtons(sessionKey, false);
                
                // Toaster'ı güncelle
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, 0, 'Analiz hatası!');
                }
                
            } else if (status.status === 'stopped') {
                clearInterval(checkInterval);
                progressText.textContent = 'Analiz durduruldu';
                progressBar.style.backgroundColor = '#6c757d';
                progressBar.textContent = 'DURDURULDU';
                
                addVerboseLog('🛑 Analiz kullanıcı tarafından durduruldu', sessionKey);
                
                // Butonları sıfırla
                updateAnalysisButtons(sessionKey, false);
                
                // Toaster'ı güncelle
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, 0, 'Analiz durduruldu');
                }
                
            } else if (status.status === 'analyzing') {
                const currentMessage = status.message || 'Analiz devam ediyor...';
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
                
                // Mesajdan analiz türünü çıkar ve verbose log'a ekle
                analyzeStatusMessage(currentMessage, sessionKey);
            }
        } catch (error) {
            console.error('Analiz durumu kontrol hatası:', error);
            addVerboseLog(`⚠️ Status kontrol hatası: ${error.message}`, sessionKey);
        }
    }, 2000); // Her 2 saniyede kontrol et
}

// Status mesajını analiz et ve detaylı bilgi ekle
function analyzeStatusMessage(message, sessionKey) {
    const verboseMessages = {
        'erişim bilgileri': '🔐 Cihaz erişim bilgileri kontrol ediliyor',
        'credential': '🔑 Kimlik bilgileri işleniyor',
        'port tarama': '🔌 Port tarama işlemi devam ediyor',
        'ssh': '🖥️ SSH servis analizi yapılıyor',
        'web': '🌐 Web servisleri taranıyor', 
        'snmp': '📊 SNMP bilgileri alınıyor',
        'raspberry': '🥧 Raspberry Pi donanım analizi',
        'analiz sonuçları': '💾 Sonuçlar kaydediliyor',
        'kapsamlı': '🔍 Kapsamlı sistem taraması'
    };
    
    const lowerMessage = message.toLowerCase();
    for (const [keyword, verboseMsg] of Object.entries(verboseMessages)) {
        if (lowerMessage.includes(keyword)) {
            addVerboseLog(verboseMsg, sessionKey);
            break;
        }
    }
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
                showToast(`🎉 ${ip} gelişmiş analizi tamamlandı!`, 'success');
                
                // Cihaz listesini yenile
                await loadDevices(true);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                showToast(`❌ ${ip} analiz hatası: ${status.message}`, 'error');
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
        accessBtn.title = 'Erişim Bilgileri';
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