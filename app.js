// API 基礎 URL
const API_BASE_URL = 'https://aivideobackend.zeabur.app/api';

// 全域變數
let charts = {};

// ===== CSRF Token 管理 =====
let csrfTokenCache = null;

async function getCsrfToken() {
    // 如果已有緩存的 Token，直接返回
    if (csrfTokenCache) return csrfTokenCache;
    
    try {
        const token = getAdminToken();
        if (!token) return null; // 未登入，不需要 CSRF Token
        
        const res = await fetch(`${API_BASE_URL}/csrf-token`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.ok) {
            const data = await res.json();
            csrfTokenCache = data.csrf_token;
            return csrfTokenCache;
        }
    } catch (e) {
        console.warn('獲取 CSRF Token 失敗:', e);
    }
    return null;
}

function clearCsrfToken() {
    csrfTokenCache = null;
}

// ===== 管理員認證機制 =====
// 從 localStorage 讀取管理員 token
function getAdminToken() {
    return localStorage.getItem('adminToken') || '';
}

function setAdminToken(token) {
    if (token) {
        localStorage.setItem('adminToken', token);
        // Token 改變時，清除 CSRF Token 緩存（需要重新獲取）
        clearCsrfToken();
    } else {
        localStorage.removeItem('adminToken');
        // 清除 Token 時，也清除 CSRF Token 緩存
        clearCsrfToken();
    }
}

// 檢查 token 是否過期
function isTokenExpired(token) {
    if (!token) return true;
    
    try {
        // JWT token 格式：header.payload.signature
        const parts = token.split('.');
        if (parts.length !== 3) return true;
        
        // 解碼 payload（base64url）
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        
        // 檢查過期時間
        if (payload.exp) {
            const now = Math.floor(Date.now() / 1000);
            return payload.exp < now;
        }
        
        return false;
    } catch (e) {
        console.error('檢查 token 過期時出錯:', e);
        return true; // 如果無法解析，視為過期
    }
}

// 檢查 token 是否即將過期（5分鐘內）
function isTokenExpiringSoon(token) {
    if (!token) return true;
    
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return true;
        
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        
        if (payload.exp) {
            const now = Math.floor(Date.now() / 1000);
            const fiveMinutes = 5 * 60; // 5分鐘
            return payload.exp < (now + fiveMinutes);
        }
        
        return false;
    } catch (e) {
        return true;
    }
}

// 登出功能
function logout() {
    if (confirm('確定要登出嗎？')) {
        // 清除 token（setAdminToken 會自動清除 CSRF Token 緩存）
        setAdminToken('');
        
        // 清除任何其他相關的 localStorage 數據
        localStorage.removeItem('admin_token');
        localStorage.removeItem('admin_login_time');
        
        // 顯示登入提示
        showLoginRequired('已登出');
        
        showToast('已成功登出', 'success');
    }
}

// 強制登出並清除所有狀態
function forceLogout(reason = '登入已過期，請重新登入') {
    // 清除 token（setAdminToken 會自動清除 CSRF Token 緩存）
    setAdminToken('');
    
    // 清除任何其他相關的 localStorage 數據（如果需要）
    localStorage.removeItem('admin_token');
    localStorage.removeItem('admin_login_time');
    
    // 顯示登入提示，並顯示過期訊息
    showLoginRequired(reason);
    
    // 停止所有正在進行的請求（可選）
    // 可以實作一個請求取消機制
}

// 統一的 fetch 函數，自動帶上 Authorization header 和 CSRF Token
async function adminFetch(url, options = {}) {
    // 使用統一的 token 狀態檢查
    if (!checkTokenStatus()) {
        // checkTokenStatus 已經處理了顯示登入視窗的邏輯
        throw new Error('需要登入');
    }
    
    const token = getAdminToken();
    
    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };
    
    // 為 POST/PUT/DELETE/PATCH 請求添加 CSRF Token
    const method = (options.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        // 檢查是否已提供 CSRF Token（允許手動覆寫）
        if (!headers['X-CSRF-Token'] && !headers['x-csrf-token']) {
            const csrfToken = await getCsrfToken();
            if (csrfToken) {
                headers['X-CSRF-Token'] = csrfToken;
            }
        }
    }
    
    try {
        const response = await fetch(url, { ...options, headers });
        
        // 處理 403 錯誤（可能是 CSRF Token 驗證失敗）
        if (response.status === 403) {
            try {
                const errorData = await response.clone().json();
                if (errorData.error && (errorData.error.includes('CSRF') || errorData.error.includes('csrf'))) {
                    // CSRF Token 驗證失敗，清除緩存並重新獲取
                    clearCsrfToken();
                    const csrfToken = await getCsrfToken();
                    if (csrfToken) {
                        // 重試請求
                        const retryHeaders = {
                            ...options.headers,
                            'Authorization': `Bearer ${token}`,
                            'X-CSRF-Token': csrfToken
                        };
                        const retryResponse = await fetch(url, { ...options, headers: retryHeaders });
                        if (retryResponse.ok) {
                            return retryResponse;
                        }
                    }
                }
            } catch (e) {
                // 如果無法解析 JSON，繼續處理
            }
        }
        
        // 如果收到 401 或 403，清除 token 並顯示登入提示
        if (response.status === 401 || response.status === 403) {
            let errorMessage = '認證失敗，請重新登入';
            
            // 嘗試從回應中獲取錯誤訊息
            try {
                const errorData = await response.clone().json();
                if (errorData.detail || errorData.error) {
                    errorMessage = errorData.detail || errorData.error;
                }
            } catch (e) {
                // 如果無法解析 JSON，使用預設訊息
            }
            
            forceLogout(errorMessage);
            throw new Error(errorMessage);
        }
        
        return response;
    } catch (error) {
        // 如果是網路錯誤，不要清除 token（可能是暫時的網路問題）
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            throw error;
        }
        
        // 其他錯誤（包括我們自己拋出的）繼續傳播
        throw error;
    }
}

// 顯示登入提示
function showLoginRequired(message = '請選擇登入方式') {
    // 檢查是否已經顯示登入提示
    if (document.getElementById('login-required-modal')) {
        // 如果已經顯示，更新訊息
        const existingMessage = document.querySelector('#login-required-modal .login-message');
        if (existingMessage && message !== '請選擇登入方式') {
            existingMessage.textContent = message;
            existingMessage.style.color = '#ef4444';
        }
        return;
    }
    
    const modal = document.createElement('div');
    modal.id = 'login-required-modal';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 10000;
    `;
    
    modal.innerHTML = `
        <div style="background: white; border-radius: 12px; padding: 2rem; max-width: 500px; width: 90%;">
            <h2 style="margin: 0 0 1rem 0; color: #1f2937;">🔐 管理員登入</h2>
            <p class="login-message" style="margin: 0 0 1.5rem 0; color: ${message.includes('過期') || message.includes('失敗') ? '#ef4444' : '#6b7280'};">
                ${message}
            </p>
            <div style="display: flex; gap: 1rem; flex-direction: column;">
                <button id="admin-login-btn" style="
                    padding: 0.75rem 1.5rem;
                    background: #3b82f6;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 1rem;
                    font-weight: 600;
                    cursor: pointer;
                ">使用 Google 登入</button>
                <button id="admin-password-login-btn" style="
                    padding: 0.75rem 1.5rem;
                    background: #10b981;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 1rem;
                    font-weight: 600;
                    cursor: pointer;
                ">帳號密碼登入</button>
            </div>
            <div id="password-login-form" style="display: none; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid #e5e7eb;">
                <div style="margin-bottom: 1rem;">
                    <label style="display: block; margin-bottom: 0.5rem; color: #374151; font-weight: 500;">帳號（Email）</label>
                    <input type="email" id="admin-email-input" style="
                        width: 100%;
                        padding: 0.5rem;
                        border: 1px solid #d1d5db;
                        border-radius: 6px;
                        font-size: 1rem;
                        box-sizing: border-box;
                    " placeholder="請輸入 Email">
                </div>
                <div style="margin-bottom: 1rem;">
                    <label style="display: block; margin-bottom: 0.5rem; color: #374151; font-weight: 500;">密碼</label>
                    <input type="password" id="admin-password-input" style="
                        width: 100%;
                        padding: 0.5rem;
                        border: 1px solid #d1d5db;
                        border-radius: 6px;
                        font-size: 1rem;
                        box-sizing: border-box;
                    " placeholder="請輸入密碼">
                </div>
                <div style="display: flex; gap: 0.5rem;">
                    <button id="admin-login-submit-btn" style="
                        flex: 1;
                        padding: 0.75rem 1.5rem;
                        background: #3b82f6;
                        color: white;
                        border: none;
                        border-radius: 8px;
                        font-size: 1rem;
                        font-weight: 600;
                        cursor: pointer;
                    ">登入</button>
                    <button id="admin-login-cancel-btn" style="
                        padding: 0.75rem 1.5rem;
                        background: #f3f4f6;
                        color: #374151;
                        border: 1px solid #d1d5db;
                        border-radius: 8px;
                        font-size: 1rem;
                        cursor: pointer;
                    ">取消</button>
                </div>
                <div id="login-error" style="margin-top: 0.5rem; color: #ef4444; font-size: 0.875rem; display: none;"></div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Google 登入按鈕
    document.getElementById('admin-login-btn').onclick = function() {
        // 使用與主前端相同的 Google OAuth 流程
        const backendUrl = 'https://aivideobackend.zeabur.app';
        // 使用當前頁面作為 redirect_uri，並在 URL 參數中標記為 admin
        const redirectUri = encodeURIComponent(window.location.origin + window.location.pathname + '?admin_login=true');
        const authUrl = `${backendUrl}/api/auth/google?redirect_uri=${redirectUri}`;
        
        // 直接跳轉到 Google OAuth 頁面
        window.location.href = authUrl;
    };
    
    // 帳號密碼登入按鈕
    document.getElementById('admin-password-login-btn').onclick = function() {
        const form = document.getElementById('password-login-form');
        form.style.display = form.style.display === 'none' ? 'block' : 'none';
    };
    
    // 取消按鈕
    document.getElementById('admin-login-cancel-btn').onclick = function() {
        document.getElementById('password-login-form').style.display = 'none';
        document.getElementById('admin-email-input').value = '';
        document.getElementById('admin-password-input').value = '';
        document.getElementById('login-error').style.display = 'none';
    };
    
    // 登入提交按鈕
    document.getElementById('admin-login-submit-btn').onclick = async function() {
        const email = document.getElementById('admin-email-input').value.trim();
        const password = document.getElementById('admin-password-input').value.trim();
        const errorDiv = document.getElementById('login-error');
        
        if (!email || !password) {
            errorDiv.textContent = '請輸入帳號和密碼';
            errorDiv.style.display = 'block';
            return;
        }
        
        try {
            const response = await fetch('https://aivideobackend.zeabur.app/api/admin/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (response.ok && data.access_token) {
                setAdminToken(data.access_token);
                // 保存登入時間
                localStorage.setItem('admin_login_time', new Date().toISOString());
                // 登入成功後，預先獲取 CSRF Token（在頁面重新載入前）
                try {
                    await getCsrfToken();
                } catch (e) {
                    console.warn('預先獲取 CSRF Token 失敗:', e);
                }
                modal.remove();
                location.reload();
            } else {
                errorDiv.textContent = data.error || '登入失敗，請檢查帳號密碼';
                errorDiv.style.display = 'block';
            }
        } catch (error) {
            errorDiv.textContent = '網路錯誤，請稍後再試';
            errorDiv.style.display = 'block';
            console.error('登入錯誤:', error);
        }
    };
    
    // Enter 鍵觸發登入
    document.getElementById('admin-password-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            document.getElementById('admin-login-submit-btn').click();
        }
    });
}

// 檢查是否需要登入
async function checkAdminAuth() {
    // 檢查 URL 參數中是否有 token（來自 OAuth callback）
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('token') || urlParams.get('access_token');
    const adminLogin = urlParams.get('admin_login');
    
    if (tokenFromUrl) {
        setAdminToken(tokenFromUrl);
        // 保存登入時間
        localStorage.setItem('admin_login_time', new Date().toISOString());
        // OAuth 登入成功後，預先獲取 CSRF Token（在頁面重新載入前）
        try {
            await getCsrfToken();
        } catch (e) {
            console.warn('預先獲取 CSRF Token 失敗:', e);
        }
        // 清除 URL 參數並重新載入
        window.history.replaceState({}, document.title, window.location.pathname);
        location.reload();
        return;
    }
    
    // 如果 URL 中有 admin_login 參數但沒有 token，可能是正在進行 OAuth 流程
    if (adminLogin) {
        // 等待 OAuth callback，不要顯示登入提示
        return;
    }
    
    // 使用統一的 token 狀態檢查函數
    if (!checkTokenStatus()) {
        // checkTokenStatus 已經處理了顯示登入視窗的邏輯
        return;
    }
}

// 定期檢查 token 狀態（每 30 秒檢查一次，更快檢測過期）
function startTokenMonitor() {
    // 立即檢查一次（不等待第一個間隔）
    checkTokenStatus();
    
    // 然後每 30 秒檢查一次
    setInterval(() => {
        checkTokenStatus();
    }, 30000); // 每 30 秒檢查一次
}

// 檢查 token 狀態的統一函數
function checkTokenStatus() {
    const token = getAdminToken();
    if (token) {
        // 檢查是否過期
        if (isTokenExpired(token)) {
            forceLogout('登入已過期，請重新登入');
            return false;
        } else if (isTokenExpiringSoon(token)) {
            // Token 即將過期，可以顯示一個非阻塞的提醒
            // 這裡選擇不顯示，避免干擾用戶操作
            // 如果需要，可以在這裡顯示一個頂部橫幅提醒
        }
        return true;
    } else {
        // 沒有 token，顯示登入視窗
        if (!document.getElementById('login-required-modal')) {
            showLoginRequired('請先登入');
        }
        return false;
    }
}

// 定期更新最近活動（每30秒更新一次）
function startActivityMonitor() {
    setInterval(() => {
        // 只在當前頁面是概覽頁面時更新
        const activeSection = document.querySelector('.section.active');
        if (activeSection && activeSection.id === 'overview') {
            loadRecentActivities();
        }
    }, 30000); // 每30秒更新一次
}

// ===== DOM 安全渲染工具（依據 Admin_Dashboard_DOM_Render_Fix.md） =====
function setHTML(sel, html) {
    const el = typeof sel === 'string' ? document.querySelector(sel) : sel;
    if (!el) {
        console.warn('[render] missing container:', sel);
        return;
    }
    el.innerHTML = html;
}

function assertEl(sel) {
    const el = document.querySelector(sel);
    console.assert(el, 'missing element for', sel);
    return el;
}

async function waitFor(selector, timeout = 5000, interval = 50) {
    const start = Date.now();
    return new Promise((resolve, reject) => {
        const t = setInterval(() => {
            const el = document.querySelector(selector);
            if (el) { clearInterval(t); resolve(el); }
            else if (Date.now() - start > timeout) { clearInterval(t); reject(new Error('waitFor timeout: ' + selector)); }
        }, interval);
    });
}

// 初始化
document.addEventListener('DOMContentLoaded', async function() {
    // 檢查管理員認證
    await checkAdminAuth();
    
    // 啟動 token 監控（每 30 秒檢查一次，更快檢測過期）
    startTokenMonitor();
    
    // 啟動活動監控（每30秒更新一次）
    startActivityMonitor();
    
    // 檢查 token 狀態，如果未登入則不執行後續操作
    if (!checkTokenStatus()) {
        // 未登入，登入視窗已顯示，不執行數據載入
        console.log('⚠️ 未登入，等待用戶登入...');
        // 只初始化基本 UI 功能（時間顯示、導航等），不載入數據
        initializeNavigation();
        updateTime();
        setInterval(updateTime, 1000);
        return;
    }
    
    // 已登入，正常初始化
    initializeNavigation();
    updateTime();
    setInterval(updateTime, 1000);
    loadOverview();
    
    // 監聽視窗大小改變，重新載入當前頁面數據以切換佈局
    let resizeTimer;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function() {
            // 檢查 token 狀態，避免未登入時載入數據
            if (!checkTokenStatus()) {
                return;
            }
            const activeSection = document.querySelector('.section.active');
            if (activeSection) {
                loadSectionData(activeSection.id);
            }
        }, 300);
    });
});

// 導航控制
function initializeNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const section = this.getAttribute('data-section');
            switchSection(section);
        });
    });
}

function switchSection(section) {
    // 在切換頁面前檢查 token 狀態
    if (!checkTokenStatus()) {
        // Token 已過期或無效，登入視窗已顯示，不執行後續操作
        return;
    }
    
    // 更新導航狀態
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    document.querySelector(`[data-section="${section}"]`).classList.add('active');
    
    // 更新頁面標題
    const titles = {
        'overview': '數據概覽',
        'users': '用戶管理',
        'modes': '模式分析',
        'conversations': '對話記錄',
        'long-term-memory': '長期記憶',
        'scripts': '腳本管理',
        'ip-planning': 'IP人設規劃',
        'orders': '購買記錄',
        'order-cleanup-logs': '訂單清理日誌',
        // 'generations': '生成記錄', // 已隱藏
        'analytics': '數據分析',
        'admin-settings': '管理員設定'
    };
    document.getElementById('page-title').textContent = titles[section];
    
    // 顯示對應區塊
    document.querySelectorAll('.section').forEach(sec => {
        sec.classList.remove('active');
    });
    document.getElementById(section).classList.add('active');
    
    // 載入對應數據
    loadSectionData(section);
}

function loadSectionData(section) {
    switch(section) {
        case 'overview':
            loadOverview();
            break;
        case 'users':
            loadUsers();
            break;
        case 'modes':
            loadModes();
            break;
        case 'conversations':
            loadConversations();
            break;
        case 'long-term-memory':
            loadLongTermMemory();
            break;
        case 'scripts':
            loadScripts();
            break;
        case 'ip-planning':
            loadIpPlanningResults();
            break;
        case 'orders':
            loadOrders();
            break;
        case 'order-cleanup-logs':
            loadOrderCleanupLogs();
            break;
        case 'license-activations':
            loadLicenseActivations();
            break;
        // case 'generations': // 已隱藏
        //     loadGenerations();
        //     break;
        case 'analytics':
            loadAnalytics();
            break;
        case 'admin-settings':
            loadAdminSettings();
            break;
    }
}

// 更新時間（台灣時區 GMT+8）
function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleString('zh-TW', {
        timeZone: 'Asia/Taipei',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
    const timeElement = document.getElementById('current-time');
    if (timeElement) {
        timeElement.textContent = timeString;
    }
}

// 重新整理數據
function refreshData() {
    // 在重新整理前檢查 token 狀態
    if (!checkTokenStatus()) {
        // Token 已過期或無效，登入視窗已顯示，不執行後續操作
        return;
    }
    
    const activeSection = document.querySelector('.section.active').id;
    loadSectionData(activeSection);
    showToast('數據已重新整理', 'success');
}

// Toast 提示
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
        color: white;
        border-radius: 0.5rem;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ===== 數據概覽 =====
async function loadOverview() {
    try {
        // 載入統計數據
        const statsResponse = await adminFetch(`${API_BASE_URL}/admin/statistics`);
        const stats = await statsResponse.json();
        
        document.getElementById('total-users').textContent = stats.total_users || 0;
        document.getElementById('total-conversations').textContent = stats.total_conversations || 0;
        document.getElementById('total-scripts').textContent = stats.total_scripts || 0;
        document.getElementById('total-positioning').textContent = stats.total_positioning || 0;
        
        // 載入圖表數據
        loadCharts(stats);
        loadRecentActivities();
    } catch (error) {
        console.error('載入概覽數據失敗:', error);
        showToast('載入數據失敗', 'error');
    }
}

async function loadCharts(stats) {
    try {
        // 調用 API 獲取模式統計
        const response = await adminFetch(`${API_BASE_URL}/admin/mode-statistics`);
        const modeData = await response.json();
        
        // 用戶增長趨勢圖 - 暫時使用統計數據替代（需要 API 支援）
        if (charts.userGrowth) charts.userGrowth.destroy();
        const userGrowthCtx = document.getElementById('user-growth-chart');
        charts.userGrowth = new Chart(userGrowthCtx, {
            type: 'line',
            data: {
                labels: ['週一', '週二', '週三', '週四', '週五', '週六', '週日'],
                datasets: [{
                    label: '新增用戶',
                    data: [0, 0, 0, 0, 0, 0, stats?.today_users || 0],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: window.innerWidth <= 768 ? 1.5 : 2,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
        
        // 模式使用分布圖 - 使用真實數據
        if (charts.modeDistribution) charts.modeDistribution.destroy();
        const modeDistributionCtx = document.getElementById('mode-distribution-chart');
        const modeStats = modeData.mode_stats || {};
        charts.modeDistribution = new Chart(modeDistributionCtx, {
            type: 'doughnut',
            data: {
                labels: ['一鍵生成', 'AI顧問', 'IP人設規劃'],
                datasets: [{
                    data: [
                        modeStats.mode1_quick_generate?.count || 0,
                        modeStats.mode2_ai_consultant?.count || 0,
                        modeStats.mode3_ip_planning?.count || 0
                    ],
                    backgroundColor: [
                        '#3b82f6',
                        '#8b5cf6',
                        '#f59e0b'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: window.innerWidth <= 768 ? 1.5 : 2
            }
        });
    } catch (error) {
        console.error('載入圖表失敗:', error);
    }
}

async function loadRecentActivities() {
    try {
        // 調用真實 API
        const response = await adminFetch(`${API_BASE_URL}/admin/user-activities`);
        const data = await response.json();
        const activities = data.activities || [];
        
        // 載入最近活動
        let activitiesHtml = '';
        
        if (activities.length > 0) {
            activitiesHtml = activities.map(activity => {
                // 計算時間差
                const timeAgo = calculateTimeAgo(activity.time);
                
                return `
                    <div class="activity-item">
                        <div class="activity-icon">${activity.icon}</div>
                        <div>
                            <strong>${activity.type}</strong>
                            <p style="margin: 0; font-size: 0.875rem; color: #64748b;">
                                ${activity.title || activity.name || ''} - ${timeAgo}
                            </p>
                        </div>
                    </div>
                `;
            }).join('');
        } else {
            activitiesHtml = '<div class="empty-state" style="text-align: center; color: #64748b;">暫無活動記錄</div>';
        }
        const actEl = await waitFor('#recent-activities', 5000).catch(() => null);
        if (actEl) setHTML(actEl, activitiesHtml);
    } catch (error) {
        console.error('載入活動失敗:', error);
        const actEl = document.querySelector('#recent-activities');
        if (actEl) setHTML(actEl, '<div class="empty-state" style="text-align: center; color: #64748b;">載入活動失敗</div>');
    }
}

function calculateTimeAgo(timeString) {
    if (!timeString) return '未知時間';
    
    try {
        // 確保使用台灣時區進行時間計算
        const time = new Date(timeString);
        const now = new Date();
        
        // 轉換為台灣時區的 Unix 時間戳
        const taiwanTime = new Date(time.toLocaleString('en-US', { timeZone: 'Asia/Taipei' }));
        const taiwanNow = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Taipei' }));
        
        const diff = taiwanNow - taiwanTime;
        
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        
        if (days > 0) return `${days} 天前`;
        if (hours > 0) return `${hours} 小時前`;
        if (minutes > 0) return `${minutes} 分鐘前`;
        return '剛剛';
    } catch (e) {
        console.error('計算時間差錯誤:', e);
        return '時間格式錯誤';
    }
}

// 格式化台灣時區時間
function formatTaiwanTime(dateString) {
    if (!dateString) return '-';
    try {
        const date = new Date(dateString);
        return date.toLocaleString('zh-TW', {
            timeZone: 'Asia/Taipei',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    } catch (e) {
        console.error('格式化時間錯誤:', e);
        return dateString;
    }
}

// 格式化日期時間（用於表格顯示）
function formatDateTime(dateString) {
    return formatTaiwanTime(dateString);
}

// ===== 用戶管理 =====
async function loadUsers() {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/users`);
        const data = await response.json();
        
        // 檢測是否為手機版
        const isMobile = window.innerWidth <= 768;
        const tableContainer = document.querySelector('.table-container');
        
        if (isMobile) {
            // 手機版：卡片式佈局
            // 清空表格內容
            tableContainer.innerHTML = '';
            
            // 創建卡片容器
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            // 添加卡片
            cardsContainer.innerHTML = data.users.map(user => {
                const isSubscribed = user.is_subscribed !== false;
                const subscribeStatus = isSubscribed ? '已訂閱' : '未訂閱';
                
                return `
                <div class="mobile-card">
                    <div class="mobile-card-header">
                        <span class="mobile-card-title">${user.name || '未命名用戶'}</span>
                        <span class="mobile-card-badge ${isSubscribed ? 'badge-success' : 'badge-danger'}">${subscribeStatus}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">用戶ID</span>
                        <span class="mobile-card-value">${user.user_id.substring(0, 16)}...</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">Email</span>
                        <span class="mobile-card-value">${user.email}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">訂閱狀態</span>
                        <span class="mobile-card-value" id="mobile-subscribe-status-${user.user_id}">${subscribeStatus}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">註冊時間</span>
                        <span class="mobile-card-value">${formatDate(user.created_at)}</span>
                    </div>
                    <div class="mobile-card-actions">
                        <button class="btn-action ${isSubscribed ? 'btn-danger' : 'btn-success'}" 
                                onclick="toggleSubscribe('${user.user_id}', ${!isSubscribed})" 
                                type="button">
                            ${isSubscribed ? '❌ 取消訂閱' : '✅ 啟用訂閱'}
                        </button>
                        <button class="btn-action btn-view" onclick="viewUser('${user.user_id}')" type="button">查看詳情</button>
                    </div>
                </div>
            `;
            }).join('');
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            const tbody = document.getElementById('users-table-body');
            if (!tbody) {
                console.error('找不到 users-table-body 元素');
                showToast('找不到表格元素', 'error');
                return;
            }
            tbody.innerHTML = data.users.map(user => {
                const isSubscribed = user.is_subscribed !== false; // 預設為已訂閱
                const subscribeStatus = isSubscribed ? 
                    '<span class="badge badge-success">已訂閱</span>' : 
                    '<span class="badge badge-danger">未訂閱</span>';
                
                // LLM Key 綁定狀態（後端監控但不顯示給管理者）
                // 注意：has_llm_key 和 llm_keys 數據仍會從後端獲取用於監控，但不顯示在界面上
                
                return `
                <tr>
                    <td>${user.user_id.substring(0, 12)}...</td>
                    <td>${user.email}</td>
                    <td>${user.name || '-'}</td>
                    <td id="subscribe-status-${user.user_id}">${subscribeStatus}</td>
                    <td>${formatDate(user.created_at)}</td>
                    <td>${user.conversation_count || 0}</td>
                    <td>${user.script_count || 0}</td>
                    <td>
                        <button class="btn-action btn-subscribe ${isSubscribed ? 'btn-danger' : 'btn-success'}" 
                                onclick="toggleSubscribe('${user.user_id}', ${!isSubscribed})" 
                                type="button">
                            ${isSubscribed ? '❌ 取消訂閱' : '✅ 啟用訂閱'}
                        </button>
                        <button class="btn-action btn-view" onclick="viewUser('${user.user_id}')" type="button">查看</button>
                    </td>
                </tr>
            `;
            }).join('');
        }
        
        // 添加匯出按鈕
        const actionsDiv = document.querySelector('#users .section-actions');
        if (actionsDiv) {
            let exportBtn = actionsDiv.querySelector('.btn-export');
            if (!exportBtn) {
                exportBtn = document.createElement('button');
                exportBtn.className = 'btn btn-secondary btn-export';
                exportBtn.innerHTML = '<i class="icon">📥</i> 匯出 CSV';
                exportBtn.onclick = () => exportCSV('users');
                actionsDiv.insertBefore(exportBtn, actionsDiv.firstChild);
            }
        }
    } catch (error) {
        console.error('載入用戶失敗:', error);
        showToast('載入用戶數據失敗', 'error');
    }
}

function filterUsers() {
    const search = document.getElementById('user-search').value.toLowerCase();
    const platform = document.getElementById('user-filter-platform').value;
    
    const rows = document.querySelectorAll('#users-table tbody tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const shouldShow = text.includes(search) && (!platform || row.textContent.includes(platform));
        row.style.display = shouldShow ? '' : 'none';
    });
}

async function viewUser(userId) {
    // 檢查按鈕是否被禁用
    if (event && event.target.disabled) return;
    
    showToast('正在載入用戶詳細資訊...', 'info');
    
    try {
        // 使用管理員端點獲取完整用戶資料（包含訂單和授權資訊）
        const response = await adminFetch(`${API_BASE_URL}/admin/user/${userId}/data`);
        const userData = await response.json();
        
        // 從回應中提取資料
        const orders = userData.orders || [];
        const licenseData = userData.license;
        const userInfo = userData.user_info || {};
        
        // 構建詳情內容
        let content = `<div style="padding: 20px;">`;
        content += `<h3 style="margin-bottom: 16px;">用戶詳情</h3>`;
        content += `<p><strong>用戶ID：</strong>${userId}</p>`;
        if (userInfo.email) {
            content += `<p><strong>Email：</strong>${userInfo.email}</p>`;
        }
        if (userInfo.name) {
            content += `<p><strong>姓名：</strong>${userInfo.name}</p>`;
        }
        
        // 授權資訊
        if (licenseData && licenseData.tier !== 'none') {
            const expiresAt = licenseData.expires_at ? new Date(licenseData.expires_at).toLocaleString('zh-TW', {
                timeZone: 'Asia/Taipei',
                year: 'numeric',
                month: '2-digit',
                day: '2-digit'
            }) : '未知';
            
            // 訂閱來源顯示
            let sourceDisplay = '未知';
            if (licenseData.source) {
                const sourceMap = {
                    'portaly': 'Portaly',
                    'ppa': 'PPA',
                    'ecpay': '官網購買',
                    'admin': '管理員手動啟用'
                };
                sourceDisplay = sourceMap[licenseData.source] || licenseData.source;
            }
            
            content += `<div style="margin-top: 16px; padding: 12px; background: #f0f9ff; border-radius: 8px;">`;
            content += `<h4 style="margin-bottom: 8px;">🔑 授權資訊</h4>`;
            content += `<p><strong>等級：</strong>${licenseData.tier === 'yearly' ? '年費' : licenseData.tier === 'monthly' ? '月費' : licenseData.tier}</p>`;
            content += `<p><strong>席次：</strong>${licenseData.seats || 1}</p>`;
            content += `<p><strong>訂閱來源：</strong><span style="color: #0f3dde; font-weight: 600;">${sourceDisplay}</span></p>`;
            content += `<p><strong>到期時間：</strong>${expiresAt}</p>`;
            content += `<p><strong>狀態：</strong>${licenseData.status === 'active' ? '✅ 有效' : '❌ 已過期'}</p>`;
            content += `</div>`;
        }
        
        // 購買記錄
        if (orders.length > 0) {
            content += `<div style="margin-top: 16px;">`;
            content += `<h4 style="margin-bottom: 8px;">💳 購買記錄</h4>`;
            content += `<table style="width: 100%; border-collapse: collapse;">`;
            content += `<thead><tr style="background: #f3f4f6;">`;
            content += `<th style="padding: 8px; text-align: left;">訂單編號</th>`;
            content += `<th style="padding: 8px; text-align: left;">方案</th>`;
            content += `<th style="padding: 8px; text-align: left;">金額</th>`;
            content += `<th style="padding: 8px; text-align: left;">付款方式/通路</th>`;
            content += `<th style="padding: 8px; text-align: left;">狀態</th>`;
            content += `<th style="padding: 8px; text-align: left;">付款時間</th>`;
            content += `</tr></thead><tbody>`;
            
            orders.forEach(order => {
                const paidDate = order.paid_at ? new Date(order.paid_at).toLocaleString('zh-TW', {
                    timeZone: 'Asia/Taipei',
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit'
                }) : '-';
                
                // 付款方式/通路顯示
                let paymentMethodDisplay = '-';
                if (order.payment_method) {
                    const methodMap = {
                        'portaly': '🔗 Portaly',
                        'ppa': '🔗 PPA',
                        'ecpay': '💳 官網購買',
                        'Credit': '💳 官網購買（信用卡）',
                        'ATM': '💳 官網購買（ATM）',
                        'CVS': '💳 官網購買（超商）',
                        'BARCODE': '💳 官網購買（條碼）'
                    };
                    paymentMethodDisplay = methodMap[order.payment_method] || order.payment_method;
                }
                
                content += `<tr>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${order.order_id || order.id}</td>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${order.plan_type === 'monthly' ? '月費' : '年費'}</td>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">NT$${order.amount?.toLocaleString() || 0}</td>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${paymentMethodDisplay}</td>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${order.payment_status === 'paid' ? '✅ 已付款' : '⏳ 待付款'}</td>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${paidDate}</td>`;
                content += `</tr>`;
            });
            
            content += `</tbody></table>`;
            content += `</div>`;
        } else {
            content += `<p style="margin-top: 16px; color: #64748b;">尚無購買記錄</p>`;
        }
        
        content += `</div>`;
        
        // 顯示自定義彈窗
        showUserDetailModal(content);
    } catch (error) {
        console.error('載入用戶詳情失敗:', error);
        showToast('載入用戶詳情失敗', 'error');
        alert(`查看用戶詳情\n用戶ID: ${userId}\n\n載入詳細資訊失敗，請稍後再試。`);
    }
}

function showUserDetailModal(content) {
    // 創建模態框
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 9999;
    `;
    
    const modalContent = document.createElement('div');
    modalContent.style.cssText = `
        background: white;
        border-radius: 12px;
        width: 90%;
        max-width: 800px;
        max-height: 80vh;
        overflow-y: auto;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    `;
    
    modalContent.innerHTML = content;
    
    // 添加關閉按鈕
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '關閉';
    closeBtn.style.cssText = `
        padding: 10px 20px;
        background: #3b82f6;
        color: white;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        margin: 20px;
        margin-top: 10px;
        font-weight: 600;
    `;
    closeBtn.onclick = () => document.body.removeChild(modal);
    
    modalContent.appendChild(closeBtn);
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
    
    // 點擊背景關閉
    modal.onclick = (e) => {
        if (e.target === modal) {
            document.body.removeChild(modal);
        }
    };
}

// ===== 模式分析 =====
async function loadModes() {
    try {
        // 調用真實 API
        const response = await adminFetch(`${API_BASE_URL}/admin/mode-statistics`);
        const data = await response.json();
        
        // 檢查數據結構是否存在
        if (!data || !data.mode_stats) {
            console.error('模式統計數據格式錯誤:', data);
            showToast('載入模式分析失敗：數據格式錯誤', 'error');
            return;
        }
        
        // 更新模式統計數據（根據後端實際返回的鍵名）
        // 後端返回：mode1_ip_planning, mode2_ai_consultant, mode3_quick_generate
        const mode1 = data.mode_stats.mode1_ip_planning || { count: 0, profiles_generated: 0 };
        const mode2 = data.mode_stats.mode2_ai_consultant || { count: 0, avg_turns: 0 };
        const mode3 = data.mode_stats.mode3_quick_generate || { count: 0, completion_rate: 0 };
        
        // Mode1: IP人設規劃（顯示使用次數和生成的Profile數）
        const mode1CountEl = document.getElementById('mode1-count');
        const mode1CompletionEl = document.getElementById('mode1-completion');
        if (mode1CountEl) mode1CountEl.textContent = mode1.count || 0;
        if (mode1CompletionEl) mode1CompletionEl.textContent = mode1.profiles_generated || 0;
        
        // Mode2: AI顧問（顯示使用次數和平均對話輪數）
        const mode2CountEl = document.getElementById('mode2-count');
        const mode2AvgEl = document.getElementById('mode2-avg');
        if (mode2CountEl) mode2CountEl.textContent = mode2.count || 0;
        if (mode2AvgEl) mode2AvgEl.textContent = mode2.avg_turns ? `${mode2.avg_turns}` : '0';
        
        // Mode3: 一鍵生成（顯示使用次數和完成率）
        const mode3CountEl = document.getElementById('mode3-count');
        const mode3ProfileEl = document.getElementById('mode3-profile');
        if (mode3CountEl) mode3CountEl.textContent = mode3.count || 0;
        if (mode3ProfileEl) mode3ProfileEl.textContent = mode3.completion_rate ? `${mode3.completion_rate}%` : '0%';
        
        // 使用真實時間分布數據（分別顯示三個模式）
        const timeDist = data.time_distribution || {};
        const mode1Time = timeDist.mode1 || {};
        const mode2Time = timeDist.mode2 || {};
        const mode3Time = timeDist.mode3 || {};
        
        // 載入模式使用時間分布圖
        if (charts.modeTime) charts.modeTime.destroy();
        const modeTimeCtx = document.getElementById('mode-time-chart');
        charts.modeTime = new Chart(modeTimeCtx, {
            type: 'bar',
            data: {
                labels: ['00:00-06:00', '06:00-12:00', '12:00-18:00', '18:00-24:00'],
                datasets: [
                    {
                        label: '一鍵生成',
                        data: [
                            mode1Time['00:00-06:00'] || 0,
                            mode1Time['06:00-12:00'] || 0,
                            mode1Time['12:00-18:00'] || 0,
                            mode1Time['18:00-24:00'] || 0
                        ],
                        backgroundColor: '#3b82f6'
                    },
                    {
                        label: 'AI顧問',
                        data: [
                            mode2Time['00:00-06:00'] || 0,
                            mode2Time['06:00-12:00'] || 0,
                            mode2Time['12:00-18:00'] || 0,
                            mode2Time['18:00-24:00'] || 0
                        ],
                        backgroundColor: '#8b5cf6'
                    },
                    {
                        label: 'IP人設規劃',
                        data: [
                            mode3Time['00:00-06:00'] || 0,
                            mode3Time['06:00-12:00'] || 0,
                            mode3Time['12:00-18:00'] || 0,
                            mode3Time['18:00-24:00'] || 0
                        ],
                        backgroundColor: '#f59e0b'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: window.innerWidth <= 768 ? 1.5 : 2,
                scales: {
                    x: {
                        stacked: false
                    },
                    y: {
                        stacked: false,
                        beginAtZero: true
                    }
                }
            }
        });
        
        // 添加匯出按鈕
        const exportBtn = document.querySelector('#modes .section-actions')?.querySelector('.btn');
        if (!exportBtn) {
            const actionsDiv = document.querySelector('#modes .section-actions');
            if (actionsDiv) {
                const btn = document.createElement('button');
                btn.className = 'btn btn-secondary';
                btn.innerHTML = '<i class="icon">📥</i> 匯出 CSV';
                btn.onclick = () => exportCSV('modes');
                actionsDiv.insertBefore(btn, actionsDiv.firstChild);
            }
        }
    } catch (error) {
        console.error('載入模式分析失敗:', error);
        showToast('載入模式分析失敗', 'error');
    }
}

// ===== 對話記錄 =====
async function loadConversations() {
    try {
        const filter = document.getElementById('conversation-filter').value;
        
        // 檢測是否為手機版
        const isMobile = window.innerWidth <= 768;
        const tableContainer = await waitFor('#conversations .table-container', 8000).catch(() => null);
        if (!tableContainer) {
            console.warn('[conversations] container missing');
            return;
        }
        
        // 顯示載入中
        if (isMobile) {
            tableContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">載入中...</div>';
        } else {
            const tbody = document.getElementById('conversations-table-body');
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;">載入中...</td></tr>';
            }
        }
        
        // 獲取對話記錄（帶分頁參數）
        const response = await adminFetch(`${API_BASE_URL}/admin/conversations?page=${currentConversationPage}&limit=100`);
        const data = await response.json();
        let allConversations = data.conversations || [];
        
        // 根據篩選條件過濾對話記錄
        if (filter === 'mode2') {
            // AI顧問模式：選題討論、腳本生成、一般諮詢
            allConversations = allConversations.filter(conv => 
                ['topic_selection', 'script_generation', 'general_consultation'].includes(conv.conversation_type)
            );
        } else if (filter === 'mode3') {
            // IP人設規劃模式
            allConversations = allConversations.filter(conv => 
                conv.conversation_type === 'ip_planning'
            );
        }
        // filter === 'all' 時不進行篩選，顯示所有對話
        
        // 顯示對話記錄
        if (allConversations.length === 0) {
            if (isMobile) {
                tableContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">暫無對話記錄</div>';
            } else {
                document.getElementById('conversations-table-body').innerHTML = 
                    '<tr><td colspan="6" style="text-align: center; padding: 2rem;">暫無對話記錄</td></tr>';
            }
            return;
        }
        
        if (isMobile) {
            // 手機版：卡片式佈局
            setHTML(tableContainer, '');
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            cardsContainer.innerHTML = allConversations.map(conv => `
                <div class="mobile-card">
                    <div class="mobile-card-header">
                        <span class="mobile-card-title">${conv.mode}</span>
                        <span class="mobile-card-badge">${conv.message_count} 條消息</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">用戶ID</span>
                        <span class="mobile-card-value">${conv.user_id.substring(0, 16)}...</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">對話摘要</span>
                        <span class="mobile-card-value">${conv.summary.substring(0, 40)}...</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">時間</span>
                        <span class="mobile-card-value">${formatDate(conv.created_at)}</span>
                    </div>
                    <div class="mobile-card-actions">
                        <button class="btn-action btn-view" onclick="viewConversation('${escapeHtml(conv.user_id)}', '${escapeHtml(conv.conversation_type || conv.mode)}', '${escapeHtml(conv.mode)}')" type="button">查看詳情</button>
                    </div>
                </div>
            `).join('');
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            const tbody = await waitFor('#conversations-table-body', 8000).catch(() => null);
            if (!tbody) return;
            setHTML(tbody, allConversations.map(conv => {
                // 使用 conversation_type 如果存在，否則使用 mode
                const convType = conv.conversation_type || conv.mode;
                return `
                <tr>
                    <td>${escapeHtml(conv.user_id.substring(0, 12))}...</td>
                    <td>${escapeHtml(conv.mode)}</td>
                    <td>${escapeHtml(conv.summary.substring(0, 30))}...</td>
                    <td>${conv.message_count}</td>
                    <td>${formatDate(conv.created_at)}</td>
                    <td>
                        <button class="btn-action btn-view" onclick="viewConversation('${escapeHtml(conv.user_id)}', '${escapeHtml(convType)}', '${escapeHtml(conv.mode)}')" type="button">查看</button>
                    </td>
                </tr>
            `;
            }).join(''));
        }
        
        // 添加分頁控制和匯出按鈕
        const actionsDiv = document.querySelector('#conversations .section-actions');
        if (actionsDiv) {
            // 清除現有分頁按鈕
            const existingPagination = actionsDiv.querySelector('.pagination-controls');
            if (existingPagination) {
                existingPagination.remove();
            }
            
            // 添加分頁控制（如果有分頁資訊）
            if (data.pagination && data.pagination.total_pages > 1) {
                const paginationDiv = document.createElement('div');
                paginationDiv.className = 'pagination-controls';
                paginationDiv.style.cssText = 'display: flex; align-items: center; gap: 8px; margin-right: 12px;';
                
                const pageInfo = document.createElement('span');
                pageInfo.style.cssText = 'color: #64748b; font-size: 0.9em; margin-right: 8px;';
                pageInfo.textContent = `第 ${data.pagination.page} / ${data.pagination.total_pages} 頁（共 ${data.pagination.total} 筆）`;
                
                const prevBtn = document.createElement('button');
                prevBtn.className = 'btn btn-secondary';
                prevBtn.innerHTML = '← 上一頁';
                prevBtn.disabled = !data.pagination.has_prev;
                prevBtn.onclick = () => {
                    if (data.pagination.has_prev) {
                        loadConversationsWithPage(data.pagination.page - 1);
                    }
                };
                
                const nextBtn = document.createElement('button');
                nextBtn.className = 'btn btn-secondary';
                nextBtn.innerHTML = '下一頁 →';
                nextBtn.disabled = !data.pagination.has_next;
                nextBtn.onclick = () => {
                    if (data.pagination.has_next) {
                        loadConversationsWithPage(data.pagination.page + 1);
                    }
                };
                
                paginationDiv.appendChild(pageInfo);
                paginationDiv.appendChild(prevBtn);
                paginationDiv.appendChild(nextBtn);
                actionsDiv.insertBefore(paginationDiv, actionsDiv.firstChild);
            }
            
            // 添加匯出按鈕
            let exportBtn = actionsDiv.querySelector('.btn-export');
            if (!exportBtn) {
                exportBtn = document.createElement('button');
                exportBtn.className = 'btn btn-secondary btn-export';
                exportBtn.innerHTML = '<i class="icon">📥</i> 匯出 CSV';
                exportBtn.onclick = () => exportCSV('conversations');
                actionsDiv.appendChild(exportBtn);
            }
        }
    } catch (error) {
        console.error('載入對話記錄失敗:', error);
        showToast('載入對話記錄失敗', 'error');
        const isMobile = window.innerWidth <= 768;
        const tableContainer = document.querySelector('#conversations .table-container');
        if (isMobile) {
            if (tableContainer) tableContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">載入失敗</div>';
        } else {
            const tbody = document.querySelector('#conversations-table-body');
            if (tbody) tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;">載入失敗</td></tr>';
        }
    }
}

// 載入指定頁的對話記錄
let currentConversationPage = 1;
async function loadConversationsWithPage(page) {
    currentConversationPage = page;
    await loadConversations();
}

// 查看對話詳情
async function viewConversation(userId, conversationType, modeDisplay) {
    // conversationType: 原始的 conversation_type（如 'account_positioning'）
    // modeDisplay: 顯示用的 mode（如 '帳號定位'）
    
    // 打開彈窗
    const modal = document.getElementById('conversation-modal');
    modal.classList.add('active');
    
    // 顯示載入中
    const content = document.getElementById('conversation-detail-content');
    content.innerHTML = '<p style="text-align: center; padding: 2rem;">載入對話內容中...</p>';
    
    try {
        // 將 mode 轉換為 conversation_type（如果沒有直接傳入 conversationType）
        const modeToType = {
            '帳號定位': 'account_positioning',
            '選題討論': 'topic_selection',
            '腳本生成': 'script_generation',
            'AI顧問': 'general_consultation',
            'IP人設規劃': 'ip_planning',
            'account_positioning': 'account_positioning',
            'topic_selection': 'topic_selection',
            'script_generation': 'script_generation',
            'general_consultation': 'general_consultation',
            'ip_planning': 'ip_planning',
            'ai_advisor': 'ai_advisor'
        };
        
        // 如果 conversationType 是中文，需要轉換
        const actualType = conversationType && !modeToType[conversationType] ? 
            modeToType[conversationType] || conversationType : 
            conversationType || modeToType[modeDisplay] || modeDisplay;
        
        const displayMode = modeDisplay || conversationType;
        
        // 從 API 獲取該用戶的長期記憶
        const response = await adminFetch(`${API_BASE_URL}/admin/long-term-memory/user/${userId}`);
        
        if (!response.ok) {
            content.innerHTML = `<p style="text-align: center; padding: 2rem; color: #ef4444;">載入失敗: ${response.status}</p>`;
            showToast('載入對話詳情失敗', 'error');
            return;
        }
        
        const data = await response.json();
        const memories = data.memories || [];
        
        // 篩選出符合對話類型的記憶
        const filteredMemories = memories.filter(mem => {
            // 直接匹配 conversation_type
            if (mem.conversation_type === actualType) {
                return true;
            }
            // 兼容性匹配：處理不同命名方式
            if (actualType === 'general_consultation' && mem.conversation_type === 'ai_advisor') {
                return true;
            }
            if (actualType === 'ai_advisor' && mem.conversation_type === 'general_consultation') {
                return true;
            }
            if (actualType === 'account_positioning' && mem.conversation_type === 'ip_planning') {
                return true;
            }
            if (actualType === 'ip_planning' && mem.conversation_type === 'account_positioning') {
                return true;
            }
            return false;
        });
        
        if (filteredMemories.length === 0) {
            // 如果長期記憶沒有記錄，嘗試從 conversation_summaries 獲取摘要
            try {
                const summaryResponse = await adminFetch(`${API_BASE_URL}/admin/conversations?limit=1000`);
                const summaryData = await summaryResponse.json();
                const summaryConversations = summaryData.conversations || [];
                const summaryConv = summaryConversations.find(conv => 
                    conv.user_id === userId && 
                    (conv.conversation_type === actualType || conv.mode === displayMode)
                );
                
                if (summaryConv) {
                    content.innerHTML = `
                        <div style="padding: 2rem;">
                            <div style="padding: 12px; background: #f8fafc; border-radius: 8px; margin-bottom: 16px;">
                                <p style="margin: 4px 0;"><strong>用戶：</strong>${escapeHtml(summaryConv.user_name || '未知')} <span style="color: #64748b;">${escapeHtml(summaryConv.user_email || '')}</span></p>
                                <p style="margin: 4px 0;"><strong>對話類型：</strong>${escapeHtml(displayMode)}</p>
                                <p style="margin: 4px 0;"><strong>消息數：</strong>${summaryConv.message_count || 0} 條</p>
                                <p style="margin: 4px 0;"><strong>時間：</strong>${formatDate(summaryConv.created_at)}</p>
                            </div>
                            <div style="padding: 16px; background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;">
                                <h4 style="margin: 0 0 12px 0; color: #1e293b;">對話摘要</h4>
                                <p style="color: #64748b; line-height: 1.6; white-space: pre-wrap;">${escapeHtml(summaryConv.summary || '無摘要')}</p>
                            </div>
                            <div style="margin-top: 16px; padding: 12px; background: #fef3c7; border: 1px solid #fcd34d; border-radius: 8px;">
                                <p style="margin: 0; color: #92400e; font-size: 0.9em;">
                                    ⚠️ 注意：此對話僅有摘要記錄，完整對話內容可能尚未保存到長期記憶中。
                                </p>
                            </div>
                        </div>
                    `;
                    return;
                }
            } catch (e) {
                console.error('獲取對話摘要失敗:', e);
            }
            
            // 如果連摘要都沒有，顯示提示
            content.innerHTML = `
                <div style="padding: 2rem; text-align: center;">
                    <p style="color: #64748b; margin-bottom: 1rem;">此對話類型沒有找到詳細記錄</p>
                    <p style="color: #94a3b8; font-size: 0.9em;">用戶ID: ${escapeHtml(userId)}</p>
                    <p style="color: #94a3b8; font-size: 0.9em;">對話類型: ${escapeHtml(displayMode)}</p>
                </div>
            `;
            return;
        }
        
        // 按 session_id 分組，然後按時間排序
        const sessions = {};
        filteredMemories.forEach(mem => {
            const sessionId = mem.session_id || 'default';
            if (!sessions[sessionId]) {
                sessions[sessionId] = [];
            }
            sessions[sessionId].push(mem);
        });
        
        // 獲取最新的會話（按第一個消息的時間排序）
        const sortedSessions = Object.entries(sessions).sort((a, b) => {
            const aTime = a[1][0]?.created_at || '';
            const bTime = b[1][0]?.created_at || '';
            return new Date(bTime) - new Date(aTime);
        });
        
        // 顯示最新的會話（或所有會話）
        let messagesHtml = '<div class="conversation-detail">';
        
        // 顯示用戶資訊
        if (memories.length > 0) {
            const userInfo = memories[0];
            messagesHtml += `
                <div style="padding: 12px; background: #f8fafc; border-radius: 8px; margin-bottom: 16px;">
                    <p style="margin: 4px 0;"><strong>用戶：</strong>${escapeHtml(userInfo.user_name || '未知')} <span style="color: #64748b;">${escapeHtml(userInfo.user_email || '')}</span></p>
                    <p style="margin: 4px 0;"><strong>對話類型：</strong>${escapeHtml(displayMode)}</p>
                    <p style="margin: 4px 0;"><strong>消息數：</strong>${filteredMemories.length} 條</p>
                </div>
            `;
        }
        
        // 顯示每個會話的對話內容
        sortedSessions.forEach(([sessionId, sessionMessages], sessionIndex) => {
            // 按時間排序會話內的消息
            sessionMessages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
            
            if (sortedSessions.length > 1) {
                messagesHtml += `<div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e2e8f0;"><strong style="color: #64748b;">會話 ${sessionIndex + 1}</strong></div>`;
            }
            
            sessionMessages.forEach(msg => {
                const isUser = msg.message_role === 'user';
                const timeStr = formatDateTime(msg.created_at);
                
                messagesHtml += `
                    <div class="message-item ${msg.message_role}" style="margin-bottom: 16px; padding: 12px; background: ${isUser ? '#f1f5f9' : '#f8fafc'}; border-radius: 8px; border-left: 3px solid ${isUser ? '#3b82f6' : '#10b981'};">
                        <div class="message-header" style="margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                            <span class="message-role" style="font-weight: 600; color: ${isUser ? '#3b82f6' : '#10b981'};">${isUser ? '👤 用戶' : '🤖 AI助理'}</span>
                            <span class="message-time" style="color: #64748b; font-size: 0.85em;">${timeStr}</span>
                        </div>
                        <div class="message-content" style="white-space: pre-wrap; word-wrap: break-word; color: #1e293b;">${escapeHtml(msg.message_content || '')}</div>
                    </div>
                `;
            });
        });
        
        messagesHtml += '</div>';
        content.innerHTML = messagesHtml;
        
    } catch (error) {
        console.error('載入對話詳情失敗:', error);
        content.innerHTML = `<p style="text-align: center; padding: 2rem; color: #ef4444;">載入失敗: ${escapeHtml(error.message)}</p>`;
        showToast('載入對話詳情失敗', 'error');
    }
}

// 關閉彈窗
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.classList.remove('active');
}

// 查看腳本（通過索引）
function viewScriptByIdx(index) {
    const script = window.allScripts?.[index];
    if (!script) {
        showToast('找不到腳本', 'error');
        return;
    }
    
    // 打開彈窗
    const modal = document.getElementById('script-modal');
    if (!modal) {
        console.error('找不到腳本詳情彈窗元素');
        showToast('無法顯示腳本詳情：缺少必要的UI元素', 'error');
        return;
    }
    
    modal.classList.add('active');
    
    // 顯示載入中
    const content = document.getElementById('script-detail-content');
    if (!content) {
        console.error('找不到腳本詳情內容元素');
        modal.classList.remove('active');
        return;
    }
    
    content.innerHTML = '<p style="text-align: center; padding: 2rem;">載入腳本詳情中...</p>';
    
    // 渲染腳本內容
    setTimeout(() => {
        const scriptTitle = script.title || script.name || '未命名腳本';
        const scriptPlatform = script.platform || '未設定';
        const scriptCategory = script.category || script.topic || '未分類';
        const scriptContent = script.content || script.script_content || '無內容';
        const userId = script.user_id || '未知';
        const userName = script.user_name || '未知用戶';
        const userEmail = script.user_email || '';
        
        content.innerHTML = `
            <div style="padding: 1rem;">
                <div style="padding: 12px; background: #f8fafc; border-radius: 8px; margin-bottom: 16px;">
                    <p style="margin: 4px 0;"><strong>用戶：</strong>${escapeHtml(userName)} <span style="color: #64748b;">${escapeHtml(userEmail)}</span></p>
                    <p style="margin: 4px 0;"><strong>用戶ID：</strong><span style="font-family: monospace; color: #64748b;">${escapeHtml(userId)}</span></p>
                    <p style="margin: 4px 0;"><strong>腳本ID：</strong>${script.id}</p>
                </div>
                
                <div style="padding: 12px; background: #f8fafc; border-radius: 8px; margin-bottom: 16px;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                        <div>
                            <span style="color: #64748b; font-size: 0.9em;">腳本標題</span>
                            <p style="margin: 4px 0 0 0; font-weight: 600; color: #1e293b;">${escapeHtml(scriptTitle)}</p>
                        </div>
                        <div>
                            <span style="color: #64748b; font-size: 0.9em;">平台</span>
                            <p style="margin: 4px 0 0 0; color: #1e293b;">${escapeHtml(scriptPlatform)}</p>
                        </div>
                        <div>
                            <span style="color: #64748b; font-size: 0.9em;">分類</span>
                            <p style="margin: 4px 0 0 0; color: #1e293b;">${escapeHtml(scriptCategory)}</p>
                        </div>
                        <div>
                            <span style="color: #64748b; font-size: 0.9em;">創建時間</span>
                            <p style="margin: 4px 0 0 0; color: #1e293b;">${formatDate(script.created_at)}</p>
                        </div>
                    </div>
                </div>
                
                <div style="padding: 16px; background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;">
                    <h4 style="margin: 0 0 12px 0; color: #1e293b;">📝 腳本內容</h4>
                    <div style="color: #64748b; line-height: 1.6; white-space: pre-wrap; max-height: 500px; overflow-y: auto; padding: 12px; background: #f8fafc; border-radius: 4px;">${escapeHtml(scriptContent)}</div>
                </div>
            </div>
        `;
    }, 100);
}

// 查看腳本（舊版兼容）
function viewScript(scriptId, scriptContent, scriptTitle) {
    viewScriptByIdx(0); // 簡單處理，實際應該根據ID查找
}

// 刪除腳本
async function deleteScript(scriptId) {
    if (!confirm('確定要刪除這個腳本嗎？此操作無法復原。')) {
        return;
    }
    
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/scripts/${scriptId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showToast('腳本已刪除', 'success');
            loadScripts(); // 重新載入列表
        } else {
            const error = await response.json();
            showToast(error.error || '刪除失敗', 'error');
        }
    } catch (error) {
        console.error('刪除腳本失敗:', error);
        showToast('刪除腳本失敗', 'error');
    }
}

// ===== 長期記憶管理 =====
async function loadLongTermMemory() {
    try {
        // 載入統計數據
        await loadMemoryStats();
        
        // 載入按用戶分組的記憶列表
        const response = await adminFetch(`${API_BASE_URL}/admin/long-term-memory/by-user`);
        
        // 檢查回應狀態
        if (!response.ok) {
            const errorText = await response.text();
            console.error('API 回應錯誤:', response.status, errorText);
            showToast(`載入失敗: ${response.status}`, 'error');
            
            const tbody = await waitFor('#memory-table-body', 8000).catch(() => null);
            if (tbody) {
                setHTML(tbody, `<tr><td colspan="7" style="text-align: center; padding: 2rem; color: #ef4444;">載入失敗 (${response.status})，請檢查控制台</td></tr>`);
            }
            return;
        }
        
        const data = await response.json();
        console.log('長期記憶 API 回應:', data); // 調試用
        
        // 檢查返回的數據結構
        if (!data) {
            console.error('API 返回空數據');
            const tbody = await waitFor('#memory-table-body', 8000).catch(() => null);
            if (tbody) {
                setHTML(tbody, '<tr><td colspan="7" style="text-align: center; padding: 2rem;">API 返回空數據</td></tr>');
            }
            return;
        }
        
        const users = data.users || [];
        console.log('用戶列表:', users); // 調試用
        
        // 檢測是否為手機版
        const isMobile = window.innerWidth <= 768;
        const tableContainer = document.querySelector('#long-term-memory .table-container');
        
        if (users.length === 0) {
            if (isMobile && tableContainer) {
                tableContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">暫無長期記憶記錄</div>';
            } else {
                const tbody = await waitFor('#memory-table-body', 8000).catch(() => null);
                if (tbody) {
                    setHTML(tbody, '<tr><td colspan="7" style="text-align: center; padding: 2rem;">暫無長期記憶記錄</td></tr>');
                }
            }
            return;
        }
        
        if (isMobile && tableContainer) {
            // 手機版：卡片式佈局
            setHTML(tableContainer, '');
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            cardsContainer.innerHTML = users.map(user => {
                const typesList = user.types_list || '';
                const types = typesList ? typesList.split(',').map(type => type.trim()).filter(type => type) : [];
                
                return `
                <div class="mobile-card">
                    <div class="mobile-card-header">
                        <span class="mobile-card-title">${escapeHtml(user.user_name || '未知')}</span>
                        <span class="mobile-card-badge">${user.total_memories || 0} 筆</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">Email</span>
                        <span class="mobile-card-value">${escapeHtml(user.user_email || '-')}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">用戶ID</span>
                        <span class="mobile-card-value">${escapeHtml(user.user_id ? (user.user_id.substring(0, 16) + '...') : '未知')}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">記憶數</span>
                        <span class="mobile-card-value">${user.total_memories || 0}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">會話數</span>
                        <span class="mobile-card-value">${user.session_count || 0}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">對話類型</span>
                        <span class="mobile-card-value">${types.length > 0 ? types.map(type => getConversationTypeLabel(type)).join(', ') : '未知'}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">首次記錄</span>
                        <span class="mobile-card-value">${formatDateTime(user.first_memory || '')}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">最後記錄</span>
                        <span class="mobile-card-value">${formatDateTime(user.last_memory || '')}</span>
                    </div>
                    <div class="mobile-card-actions">
                        <button class="btn-action btn-view" onclick="viewUserMemoryDetail('${escapeHtml(user.user_id || '')}')" type="button">查看詳情</button>
                    </div>
                </div>
            `;
            }).join('');
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            const tbody = await waitFor('#memory-table-body', 8000).catch(() => null);
            if (!tbody) {
                console.error('找不到表格 tbody 元素');
                return;
            }
            
            setHTML(tbody, users.map(user => {
                // 安全處理 types_list（可能為空或 null）
                const typesList = user.types_list || '';
                const types = typesList ? typesList.split(',').map(type => type.trim()).filter(type => type) : [];
                
                return `
                <tr>
                    <td>
                        <div class="user-info">
                            <span class="user-name">${escapeHtml(user.user_name || '未知')}</span>
                            <span class="user-email">${escapeHtml(user.user_email || '')}</span>
                        </div>
                    </td>
                    <td>
                        <span class="user-id">${escapeHtml(user.user_id ? (user.user_id.substring(0, 20) + (user.user_id.length > 20 ? '...' : '')) : '未知')}</span>
                    </td>
                    <td>
                        <span class="badge">${user.total_memories || 0}</span>
                    </td>
                    <td>
                        <span class="badge">${user.session_count || 0}</span>
                    </td>
                    <td>
                        <span class="conversation-types">
                            ${types.length > 0 ? types.map(type => `<span class="conversation-type ${type}">${getConversationTypeLabel(type)}</span>`).join(' ') : '<span class="conversation-type">未知</span>'}
                        </span>
                    </td>
                    <td>
                        <span class="timestamp">${formatDateTime(user.first_memory || '')}</span>
                        <br>
                        <span class="timestamp" style="color: #64748b; font-size: 0.85em;">最後: ${formatDateTime(user.last_memory || '')}</span>
                    </td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="viewUserMemoryDetail('${escapeHtml(user.user_id || '')}')">查看詳情</button>
                    </td>
                </tr>
            `;
            }).join(''));
        }
        
    } catch (error) {
        console.error('載入長期記憶失敗:', error);
        console.error('錯誤詳情:', error.stack);
        showToast(`載入長期記憶失敗: ${error.message}`, 'error');
        
        // 顯示錯誤信息在表格中
        const tbody = await waitFor('#memory-table-body', 8000).catch(() => null);
        if (tbody) {
            setHTML(tbody, `<tr><td colspan="7" style="text-align: center; padding: 2rem; color: #ef4444;">載入失敗: ${escapeHtml(error.message)}</td></tr>`);
        }
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function viewUserMemoryDetail(userId) {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/long-term-memory/user/${userId}`);
        if (!response.ok) {
            showToast('載入用戶記憶詳情失敗', 'error');
            return;
        }
        const data = await response.json();
        const memories = data.memories || [];
        const user = memories.length > 0 ? {
            name: memories[0].user_name || '未知',
            email: memories[0].user_email || '',
            id: data.user_id
        } : { name: '未知', email: '', id: userId };
        
        // 按會話分組
        const sessions = {};
        memories.forEach(mem => {
            const sessionId = mem.session_id || 'unknown';
            if (!sessions[sessionId]) {
                sessions[sessionId] = {
                    conversation_type: mem.conversation_type,
                    messages: []
                };
            }
            sessions[sessionId].messages.push(mem);
        });
        
        // 按時間排序會話
        const sortedSessions = Object.entries(sessions).sort((a, b) => {
            const aTime = a[1].messages[0]?.created_at || '';
            const bTime = b[1].messages[0]?.created_at || '';
            return bTime.localeCompare(aTime);
        });
        
        let content = `
            <div style="padding:20px; max-height: 80vh; overflow-y: auto;">
                <h3 style="margin:0 0 12px 0;">用戶長期記憶詳情</h3>
                <div style="margin-bottom:16px; padding:12px; background:#f8fafc; border-radius:8px;">
                    <div style="margin-bottom:4px;"><strong>用戶：</strong>${escapeHtml(user.name)} <span style="color:#64748b;">${escapeHtml(user.email)}</span></div>
                    <div style="margin-bottom:4px;"><strong>用戶ID：</strong>${escapeHtml(user.id)}</div>
                    <div><strong>總記憶數：</strong>${memories.length} 筆</div>
                </div>
        `;
        
        sortedSessions.forEach(([sessionId, session], index) => {
            const messages = session.messages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
            const firstMessage = messages[0];
            const lastMessage = messages[messages.length - 1];
            
            content += `
                <div style="margin-bottom:24px; padding:16px; background:#ffffff; border:1px solid #e2e8f0; border-radius:8px;">
                    <div style="margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid #e2e8f0;">
                        <strong>會話 ${index + 1}</strong>
                        <span style="color:#64748b; margin-left:12px;">${getConversationTypeLabel(session.conversation_type)}</span>
                        <span style="color:#64748b; margin-left:12px;">(${messages.length} 條訊息)</span>
                        <span style="color:#64748b; margin-left:12px; font-size:0.9em;">${formatDateTime(firstMessage.created_at)}</span>
                    </div>
                    <div style="max-height: 400px; overflow-y: auto;">
            `;
            
            messages.forEach((msg, msgIndex) => {
                const isUser = msg.message_role === 'user';
                content += `
                    <div style="margin-bottom:12px; padding:12px; background:${isUser ? '#f1f5f9' : '#f8fafc'}; border-radius:6px; border-left:3px solid ${isUser ? '#3b82f6' : '#10b981'};">
                        <div style="margin-bottom:4px; font-weight:600; color:${isUser ? '#3b82f6' : '#10b981'};">
                            ${isUser ? '👤 用戶' : '🤖 AI'}
                            <span style="color:#64748b; font-weight:400; font-size:0.85em; margin-left:8px;">${formatDateTime(msg.created_at)}</span>
                        </div>
                        <div style="white-space:pre-wrap; word-wrap:break-word;">${escapeHtml(msg.message_content || '-')}</div>
                    </div>
                `;
            });
            
            content += `
                    </div>
                </div>
            `;
        });
        
        content += `</div>`;
        showUserDetailModal(content);
    } catch (error) {
        console.error('載入用戶記憶詳情失敗:', error);
        showToast('載入用戶記憶詳情失敗', 'error');
    }
}

async function loadMemoryStats() {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/memory-stats`);
        const data = await response.json();
        
        document.getElementById('total-memories').textContent = data.total_memories || 0;
        document.getElementById('active-users-memory').textContent = data.active_users || 0;
        document.getElementById('today-memories').textContent = data.today_memories || 0;
        document.getElementById('avg-memories-per-user').textContent = data.avg_memories_per_user || 0;
        
    } catch (error) {
        console.error('載入記憶統計失敗:', error);
    }
}

function getConversationTypeLabel(type) {
    const labels = {
        'ai_advisor': 'AI顧問',
        'ip_planning': 'IP人設規劃',
        'llm_chat': 'LLM對話',
        'script_generation': '腳本生成',
        'general': '一般對話'
    };
    return labels[type] || type;
}

function viewMemoryDetail(memoryId) {
    (async () => {
        try {
            const res = await adminFetch(`${API_BASE_URL}/admin/long-term-memory/${memoryId}`);
            if (!res.ok) {
                showToast('載入記憶詳情失敗', 'error');
                return;
            }
            const m = await res.json();
            const content = `
                <div style="padding:20px;">
                  <h3 style="margin:0 0 12px 0;">長期記憶詳情</h3>
                  <div style="margin-bottom:8px;"><strong>用戶：</strong>${m.user_name || m.user_id} <span style="color:#64748b;">${m.user_email || ''}</span></div>
                  <div style="margin-bottom:8px;"><strong>對話類型：</strong>${getConversationTypeLabel(m.conversation_type)}</div>
                  <div style="margin-bottom:8px;"><strong>會話ID：</strong>${m.session_id || '-'}</div>
                  <div style="margin-bottom:8px;"><strong>角色：</strong>${m.message_role === 'user' ? '👤 用戶' : '🤖 AI'}</div>
                  <div style="margin-bottom:8px;"><strong>建立時間：</strong>${formatDateTime(m.created_at)}</div>
                  <div style="margin-top:12px; padding:12px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; white-space:pre-wrap;">${m.message_content || '-'}</div>
                </div>`;
            showUserDetailModal(content);
        } catch (e) {
            console.error('載入記憶詳情失敗:', e);
            showToast('載入記憶詳情失敗', 'error');
        }
    })();
}

function deleteMemory(memoryId) {
    if (!confirm('確定要刪除這筆記憶記錄嗎？')) return;
    (async () => {
        try {
            const res = await adminFetch(`${API_BASE_URL}/admin/long-term-memory/${memoryId}`, { method: 'DELETE' });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                showToast(err.error || '刪除失敗', 'error');
                return;
            }
            showToast('已刪除', 'success');
            // 重新載入列表
            loadLongTermMemory();
        } catch (e) {
            console.error('刪除記憶失敗:', e);
            showToast('刪除失敗', 'error');
        }
    })();
}

// ===== 腳本管理 =====
async function loadScripts() {
    try {
        // 檢測是否為手機版
        const isMobile = window.innerWidth <= 768;
        const tableContainer = await waitFor('#scripts .table-container', 8000).catch(() => null);
        if (!tableContainer) {
            console.warn('[scripts] container missing');
            return;
        }
        
        // 直接獲取所有腳本
        const response = await adminFetch(`${API_BASE_URL}/admin/scripts`);
        const data = await response.json();
        const allScripts = data.scripts || [];
        
        // 顯示腳本
        if (allScripts.length === 0) {
            if (isMobile) {
                tableContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">暫無腳本記錄</div>';
            } else {
                document.getElementById('scripts-table-body').innerHTML = 
                    '<tr><td colspan="7" style="text-align: center; padding: 2rem;">暫無腳本記錄</td></tr>';
            }
            return;
        }
        
        if (isMobile) {
            // 手機版：卡片式佈局
            setHTML(tableContainer, '');
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            cardsContainer.innerHTML = allScripts.map((script, index) => `
                <div class="mobile-card">
                    <div class="mobile-card-header">
                        <span class="mobile-card-title">${script.title || script.name || '未命名腳本'}</span>
                        <span class="mobile-card-badge">${script.platform || '未設定'}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">用戶ID</span>
                        <span class="mobile-card-value">${script.user_id.substring(0, 16)}...</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">分類</span>
                        <span class="mobile-card-value">${script.category || script.topic || '未分類'}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">時間</span>
                        <span class="mobile-card-value">${formatDate(script.created_at)}</span>
                    </div>
                    <div class="mobile-card-actions">
                        <button class="btn-action btn-view" onclick="viewScriptByIdx(${index})" type="button">查看</button>
                        <button class="btn-action btn-delete" onclick="deleteScript(${script.id})" type="button">刪除</button>
                    </div>
                </div>
            `).join('');
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            const tbody = await waitFor('#scripts-table-body', 8000).catch(() => null);
            if (!tbody) return;
            setHTML(tbody, allScripts.map((script, index) => `
                <tr>
                    <td>${script.id}</td>
                    <td>${script.user_id.substring(0, 12)}...</td>
                    <td>${script.title || script.name || '未命名腳本'}</td>
                    <td>${script.platform || '未設定'}</td>
                    <td>${script.category || script.topic || '未分類'}</td>
                    <td>${formatDate(script.created_at)}</td>
                    <td>
                        <button class="btn-action btn-view" onclick="viewScriptByIdx(${index})" type="button">查看</button>
                        <button class="btn-action btn-delete" onclick="deleteScript(${script.id})" type="button">刪除</button>
                    </td>
                </tr>
            `).join(''));
        }
        
        // 保存腳本數據供查看功能使用
        window.allScripts = allScripts;
        
        // 添加匯出按鈕
        const actionsDiv = document.querySelector('#scripts .section-actions');
        if (actionsDiv) {
            let exportBtn = actionsDiv.querySelector('.btn-export');
            if (!exportBtn) {
                exportBtn = document.createElement('button');
                exportBtn.className = 'btn btn-secondary btn-export';
                exportBtn.innerHTML = '<i class="icon">📥</i> 匯出 CSV';
                exportBtn.onclick = () => exportCSV('scripts');
                actionsDiv.insertBefore(exportBtn, actionsDiv.firstChild);
            }
        }
        
    } catch (error) {
        console.error('載入腳本失敗:', error);
        showToast('載入腳本失敗', 'error');
    }
}

// ===== IP人設規劃管理 =====
async function loadIpPlanningResults() {
    try {
        const isMobile = window.innerWidth <= 768;
        const tableContainer = await waitFor('#ip-planning .table-container', 8000).catch(() => null);
        if (!tableContainer) {
            console.warn('[ip-planning] container missing');
            return;
        }
        
        // 獲取篩選條件
        const typeFilter = document.getElementById('ip-planning-filter-type')?.value || '';
        const url = typeFilter 
            ? `${API_BASE_URL}/admin/ip-planning?result_type=${typeFilter}`
            : `${API_BASE_URL}/admin/ip-planning`;
        
        const response = await adminFetch(url);
        const data = await response.json();
        const results = data.results || [];
        
        // 顯示結果
        if (results.length === 0) {
            if (isMobile) {
                tableContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">暫無 IP 人設規劃記錄</div>';
            } else {
                document.getElementById('ip-planning-table-body').innerHTML = 
                    '<tr><td colspan="7" style="text-align: center; padding: 2rem;">暫無 IP 人設規劃記錄</td></tr>';
            }
            return;
        }
        
        // 按用戶分組
        const groupedByUser = {};
        results.forEach((result, index) => {
            const userId = result.user_id;
            if (!groupedByUser[userId]) {
                groupedByUser[userId] = {
                    user_id: userId,
                    user_name: result.user_name || '未知用戶',
                    user_email: result.user_email || '',
                    results: []
                };
            }
            groupedByUser[userId].results.push({ ...result, originalIndex: index });
        });
        
        const userList = Object.values(groupedByUser);
        
        if (isMobile) {
            // 手機版：按用戶分組的卡片式佈局
            setHTML(tableContainer, '');
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            cardsContainer.innerHTML = userList.map((userGroup, groupIndex) => {
                const userResults = userGroup.results;
                const totalCount = userResults.length;
                
                return `
                <div class="mobile-card" style="margin-bottom: 16px;">
                    <div class="mobile-card-header" onclick="toggleUserIpPlanningResults(${groupIndex})" style="cursor: pointer;">
                        <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                            <div>
                                <span class="mobile-card-title">${userGroup.user_name}</span>
                                <span style="font-size: 0.85rem; color: #6B7280; margin-left: 8px;">(${totalCount} 筆記錄)</span>
                            </div>
                            <span id="user-toggle-${groupIndex}" style="font-size: 1.2rem;">▼</span>
                        </div>
                        ${userGroup.user_email ? `<div style="font-size: 0.85rem; color: #9CA3AF; margin-top: 4px;">${userGroup.user_email}</div>` : ''}
                    </div>
                    <div id="user-results-${groupIndex}" style="display: none; margin-top: 12px; padding-top: 12px; border-top: 1px solid #E5E7EB;">
                        ${userResults.map((result, idx) => {
                            const typeName = result.result_type === 'profile' ? 'IP Profile' : 
                                            result.result_type === 'plan' ? '14天規劃' : '今日腳本';
                            const contentPreview = (result.content || '').replace(/<[^>]*>/g, '').substring(0, 80);
                            
                            return `
                            <div style="background: #F9FAFB; padding: 12px; border-radius: 6px; margin-bottom: 8px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <span style="font-weight: 600; color: #1F2937;">${result.title || typeName}</span>
                                    <span style="font-size: 0.8rem; color: #6B7280;">${formatDate(result.created_at)}</span>
                                </div>
                                <div style="font-size: 0.85rem; color: #6B7280; margin-bottom: 8px;">
                                    <span class="badge" style="background: #3B82F6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;">${typeName}</span>
                                </div>
                                <div style="font-size: 0.85rem; color: #4B5563; margin-bottom: 8px;">${contentPreview}...</div>
                                <button class="btn-action btn-view" onclick="viewIpPlanningResultByIdx(${result.originalIndex})" type="button" style="padding: 4px 12px; font-size: 0.85rem;">查看詳情</button>
                            </div>
                        `;
                        }).join('')}
                    </div>
                </div>
            `;
            }).join('');
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：按用戶分組的可展開視窗
            const tbody = await waitFor('#ip-planning-table-body', 8000).catch(() => null);
            if (!tbody) return;
            
            setHTML(tbody, userList.map((userGroup, groupIndex) => {
                const userResults = userGroup.results;
                const totalCount = userResults.length;
                
                return `
                <tr class="user-group-header" onclick="toggleUserIpPlanningResults(${groupIndex})" style="cursor: pointer; background: #F9FAFB; font-weight: 600;">
                    <td colspan="7" style="padding: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <span>${userGroup.user_name}</span>
                                ${userGroup.user_email ? `<span style="color: #6B7280; font-weight: normal; margin-left: 12px;">${userGroup.user_email}</span>` : ''}
                                <span style="color: #3B82F6; font-weight: normal; margin-left: 12px;">(${totalCount} 筆記錄)</span>
                            </div>
                            <span id="user-toggle-${groupIndex}">▼</span>
                        </div>
                    </td>
                </tr>
                <tr class="user-group-results" id="user-results-${groupIndex}" style="display: none;">
                    <td colspan="7" style="padding: 0;">
                        <div style="padding: 16px; background: #FEFEFE;">
                            ${userResults.map((result, idx) => {
                                const typeName = result.result_type === 'profile' ? 'IP Profile' : 
                                                result.result_type === 'plan' ? '14天規劃' : '今日腳本';
                                const contentPreview = (result.content || '').replace(/<[^>]*>/g, '').substring(0, 150);
                                
                                return `
                                <div style="display: grid; grid-template-columns: 60px 120px 150px 200px 1fr 150px 120px; gap: 12px; padding: 12px; border-bottom: 1px solid #E5E7EB; align-items: center;">
                                    <div style="color: #6B7280; font-size: 0.9rem;">${result.id}</div>
                                    <div><span class="badge">${typeName}</span></div>
                                    <div style="font-weight: 500; color: #1F2937;">${result.title || '-'}</div>
                                    <div style="color: #4B5563; font-size: 0.9rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${contentPreview}">${contentPreview}...</div>
                                    <div style="color: #6B7280; font-size: 0.85rem;">${formatDate(result.created_at)}</div>
                                    <div>
                                        <button class="btn-action btn-view" onclick="viewIpPlanningResultByIdx(${result.originalIndex})" type="button" style="padding: 4px 12px; font-size: 0.85rem;">查看詳情</button>
                                    </div>
                                </div>
                            `;
                            }).join('')}
                        </div>
                    </td>
                </tr>
            `;
            }).join(''));
        }
        
        // 保存結果數據供查看功能使用
        window.allIpPlanningResults = results;
        window.userIpPlanningGroups = userList;
        
    } catch (error) {
        console.error('載入 IP 人設規劃結果失敗:', error);
        showToast('載入 IP 人設規劃結果失敗', 'error');
    }
}

// 切換用戶結果展開/收起
function toggleUserIpPlanningResults(groupIndex) {
    const resultsDiv = document.getElementById(`user-results-${groupIndex}`);
    const toggleSpan = document.getElementById(`user-toggle-${groupIndex}`);
    
    if (resultsDiv && toggleSpan) {
        if (resultsDiv.style.display === 'none') {
            resultsDiv.style.display = '';
            toggleSpan.textContent = '▲';
        } else {
            resultsDiv.style.display = 'none';
            toggleSpan.textContent = '▼';
        }
    }
}

// 查看 IP 人設規劃結果詳情
function viewIpPlanningResultByIdx(index) {
    const result = window.allIpPlanningResults?.[index];
    if (!result) {
        showToast('找不到結果', 'error');
        return;
    }
    
    const typeName = result.result_type === 'profile' ? 'IP Profile' : 
                    result.result_type === 'plan' ? '14天規劃' : '今日腳本';
    
    // 創建詳情彈窗
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';
    
    const modalContent = document.createElement('div');
    modalContent.className = 'modal-content';
    modalContent.style.cssText = 'background: white; border-radius: 8px; padding: 24px; max-width: 800px; max-height: 80vh; overflow-y: auto; position: relative;';
    
    modalContent.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <h2 style="margin: 0;">${typeName} - 詳細內容</h2>
            <button onclick="this.closest('.modal').remove()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #666;">&times;</button>
        </div>
        <div style="margin-bottom: 16px;">
            <strong>用戶：</strong>${result.user_name || result.user_id}<br>
            <strong>類型：</strong>${typeName}<br>
            <strong>標題：</strong>${result.title || '-'}<br>
            <strong>創建時間：</strong>${formatDate(result.created_at)}
        </div>
        <div style="border-top: 1px solid #e2e8f0; padding-top: 20px;">
            <h3 style="margin-top: 0;">內容：</h3>
            <div style="background: #f8f9fa; padding: 16px; border-radius: 4px; line-height: 1.6; color: #374151;">
                ${result.content || '無內容'}
            </div>
        </div>
    `;
    
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
    
    // 點擊背景關閉
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

// ===== 生成記錄 =====
async function loadGenerations() {
    try {
        // 調用真實 API
        const response = await adminFetch(`${API_BASE_URL}/admin/generations`);
        const data = await response.json();
        const generations = data.generations || [];
        
        // 檢測是否為手機版
        const isMobile = window.innerWidth <= 768;
        const tableContainer = await waitFor('#generations .table-container', 8000).catch(() => null);
        if (!tableContainer) {
            console.warn('[generations] container missing');
            return;
        }
        
        if (isMobile) {
            // 手機版：卡片式佈局
            setHTML(tableContainer, '');
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            if (generations.length > 0) {
                cardsContainer.innerHTML = generations.map(gen => `
                    <div class="mobile-card">
                        <div class="mobile-card-header">
                            <span class="mobile-card-title">${gen.type || '生成記錄'}</span>
                            <span class="mobile-card-badge">${gen.platform}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">生成ID</span>
                            <span class="mobile-card-value">${gen.id}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">用戶</span>
                            <span class="mobile-card-value">${gen.user_name}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">主題</span>
                            <span class="mobile-card-value">${gen.topic}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">時間</span>
                            <span class="mobile-card-value">${formatDate(gen.created_at)}</span>
                        </div>
                    </div>
                `).join('');
            } else {
                cardsContainer.innerHTML = '<div class="empty-state">暫無生成記錄</div>';
            }
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            const tbody = await waitFor('#generations-table-body', 8000).catch(() => null);
            if (!tbody) return;
            if (generations.length > 0) {
                setHTML(tbody, generations.map(gen => `
                    <tr>
                        <td>${gen.id}</td>
                        <td>${gen.user_name}</td>
                        <td>${gen.platform}</td>
                        <td>${gen.topic}</td>
                        <td>${gen.type}</td>
                        <td>${formatDate(gen.created_at)}</td>
                    </tr>
                `).join(''));
            } else {
                setHTML(tbody, '<tr><td colspan="6" style="text-align: center; padding: 2rem;">暫無生成記錄</td></tr>');
            }
        }
        
        // 添加匯出按鈕
        const actionsDiv = document.querySelector('#generations .section-actions');
        if (actionsDiv) {
            let exportBtn = actionsDiv.querySelector('.btn-export');
            if (!exportBtn) {
                exportBtn = document.createElement('button');
                exportBtn.className = 'btn btn-secondary btn-export';
                exportBtn.innerHTML = '<i class="icon">📥</i> 匯出 CSV';
                exportBtn.onclick = () => exportCSV('generations');
                actionsDiv.insertBefore(exportBtn, actionsDiv.firstChild);
            }
        }
    } catch (error) {
        console.error('載入生成記錄失敗:', error);
        showToast('載入生成記錄失敗', 'error');
    }
}

// ===== 數據分析 =====
async function loadAnalytics() {
    try {
        // 調用真實 API
        const response = await adminFetch(`${API_BASE_URL}/admin/analytics-data`);
        const data = await response.json();
        
        // 平台使用分布
        if (charts.platform) charts.platform.destroy();
        const platformCtx = document.getElementById('platform-chart');
        charts.platform = new Chart(platformCtx, {
            type: 'pie',
            data: {
                labels: data.platform?.labels || ['暫無數據'],
                datasets: [{
                    data: data.platform?.data || [1],
                    backgroundColor: ['#3b82f6', '#ec4899', '#8b5cf6', '#ef4444', '#10b981']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: window.innerWidth <= 768 ? 1.5 : 2
            }
        });
        
        // 時間段使用分析
        if (charts.timeUsage) charts.timeUsage.destroy();
        const timeUsageCtx = document.getElementById('time-usage-chart');
        charts.timeUsage = new Chart(timeUsageCtx, {
            type: 'bar',
            data: {
                labels: data.time_usage?.labels || ['週一', '週二', '週三', '週四', '週五', '週六', '週日'],
                datasets: [{
                    label: '使用次數',
                    data: data.time_usage?.data || [0, 0, 0, 0, 0, 0, 0],
                    backgroundColor: '#10b981'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: window.innerWidth <= 768 ? 1.5 : 2
            }
        });
        
        // 用戶活躍度
        if (charts.activity) charts.activity.destroy();
        const activityCtx = document.getElementById('activity-chart');
        charts.activity = new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: data.activity?.labels || ['第1週', '第2週', '第3週', '第4週'],
                datasets: [{
                    label: '活躍用戶數',
                    data: data.activity?.data || [0, 0, 0, 0],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: window.innerWidth <= 768 ? 1.5 : 2
            }
        });
        
        // 內容類型分布
        if (charts.contentType) charts.contentType.destroy();
        const contentTypeCtx = document.getElementById('content-type-chart');
        charts.contentType = new Chart(contentTypeCtx, {
            type: 'doughnut',
            data: {
                labels: data.content_type?.labels || ['暫無數據'],
                datasets: [{
                    data: data.content_type?.data || [1],
                    backgroundColor: [
                        '#3b82f6',
                        '#8b5cf6',
                        '#ec4899',
                        '#f59e0b',
                        '#10b981'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: window.innerWidth <= 768 ? 1.5 : 2
            }
        });
    } catch (error) {
        console.error('載入分析數據失敗:', error);
        showToast('載入分析數據失敗', 'error');
    }
}

// ===== 工具函數 =====
// 格式化日期（台灣時區）
function formatDate(dateString) {
    if (!dateString) return '-';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('zh-TW', {
            timeZone: 'Asia/Taipei',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit'
        });
    } catch (e) {
        console.error('格式化日期錯誤:', e);
        return dateString;
    }
}

// 與前端一致的日期時間格式化（含時區處理與容錯）- 已更新為使用 formatTaiwanTime
function formatDateTime(dateString) {
    return formatTaiwanTime(dateString);
}

// 手機版側邊欄控制
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        sidebar.classList.toggle('active');
    }
}

// 點擊側邊欄外部時關閉
document.addEventListener('click', function(event) {
    const sidebar = document.querySelector('.sidebar');
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    
    if (sidebar && mobileMenuBtn) {
        // 如果在手機版且側邊欄打開
        if (window.innerWidth <= 768 && sidebar.classList.contains('active')) {
            // 如果點擊的不是側邊欄內部和按鈕
            if (!sidebar.contains(event.target) && !mobileMenuBtn.contains(event.target)) {
                sidebar.classList.remove('active');
            }
        }
    }
});

// ===== 訂閱管理功能 =====
// 儲存當前操作的用戶 ID
let currentSubscriptionUserId = null;

async function toggleSubscribe(userId, subscribe) {
    currentSubscriptionUserId = userId;
    
    if (subscribe) {
        // 啟用訂閱：顯示訂閱設置彈窗
        showSubscriptionModal(userId);
    } else {
        // 取消訂閱：直接執行
        if (confirm('確定要取消此用戶的訂閱嗎？')) {
            await executeSubscriptionToggle(userId, false, null, null);
        }
    }
}

function showSubscriptionModal(userId) {
    // 重置表單
    document.querySelector('input[name="subscription-period"][value="monthly"]').checked = true;
    document.getElementById('subscription-note').value = '';
    
    // 初始化樣式
    setTimeout(() => {
        initSubscriptionPeriodStyles();
    }, 10);
    
    // 顯示彈窗
    const modal = document.getElementById('subscription-modal');
    modal.classList.add('active');
}

function updateSubscriptionPeriod(period) {
    // 更新選中的樣式
    const monthlyLabel = document.getElementById('subscription-monthly-label');
    const yearlyLabel = document.getElementById('subscription-yearly-label');
    
    if (monthlyLabel && yearlyLabel) {
        if (period === 'monthly') {
            monthlyLabel.style.borderColor = '#3b82f6';
            monthlyLabel.style.backgroundColor = '#eff6ff';
            yearlyLabel.style.borderColor = '#e5e7eb';
            yearlyLabel.style.backgroundColor = 'transparent';
        } else {
            yearlyLabel.style.borderColor = '#3b82f6';
            yearlyLabel.style.backgroundColor = '#eff6ff';
            monthlyLabel.style.borderColor = '#e5e7eb';
            monthlyLabel.style.backgroundColor = 'transparent';
        }
    }
}

// 處理彈窗背景點擊關閉
function handleModalClick(event, modalId) {
    if (event.target.id === modalId) {
        closeModal(modalId);
    }
}

// 初始化訂閱期限選擇樣式
function initSubscriptionPeriodStyles() {
    updateSubscriptionPeriod();
}

async function confirmSubscription() {
    if (!currentSubscriptionUserId) {
        showToast('錯誤：找不到用戶ID', 'error');
        return;
    }
    
    // 獲取選中的訂閱期限
    const selectedPeriod = document.querySelector('input[name="subscription-period"]:checked').value;
    const subscriptionDays = selectedPeriod === 'yearly' ? 365 : 30;
    
    // 獲取備註
    const note = document.getElementById('subscription-note').value.trim();
    
    // 關閉彈窗
    closeModal('subscription-modal');
    
    // 執行訂閱啟用
    await executeSubscriptionToggle(currentSubscriptionUserId, true, subscriptionDays, note);
    
    // 清除臨時變數
    currentSubscriptionUserId = null;
}

async function executeSubscriptionToggle(userId, subscribe, subscriptionDays, note) {
    try {
        const requestBody = {
            is_subscribed: subscribe
        };
        
        // 如果啟用訂閱，添加期限和備註
        if (subscribe && subscriptionDays) {
            requestBody.subscription_days = subscriptionDays;
            if (note) {
                requestBody.admin_note = note;
            }
        }
        
        const response = await adminFetch(`${API_BASE_URL}/admin/users/${userId}/subscription`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        
        if (response.ok) {
            const result = await response.json();
            const periodText = subscribe && subscriptionDays === 365 ? '年費' : subscribe && subscriptionDays === 30 ? '月費' : '';
            const message = subscribe ? `已啟用訂閱${periodText ? `（${periodText}）` : ''}` : '已取消訂閱';
            showToast(message, 'success');
            
            // 更新 UI
            updateSubscribeUI(userId, subscribe);
        } else {
            const error = await response.json();
            showToast(error.error || '操作失敗', 'error');
        }
    } catch (error) {
        console.error('修改訂閱狀態失敗:', error);
        showToast('修改訂閱狀態失敗', 'error');
    }
}

function updateSubscribeUI(userId, isSubscribed) {
    // 更新桌面版
    const statusCell = document.getElementById(`subscribe-status-${userId}`);
    if (statusCell) {
        statusCell.innerHTML = isSubscribed ? 
            '<span class="badge badge-success">已訂閱</span>' : 
            '<span class="badge badge-danger">未訂閱</span>';
    }
    
    // 更新手機版
    const mobileStatusCell = document.getElementById(`mobile-subscribe-status-${userId}`);
    if (mobileStatusCell) {
        mobileStatusCell.textContent = isSubscribed ? '已訂閱' : '未訂閱';
    }
    
    // 更新按鈕
    const rows = document.querySelectorAll(`[id^='${userId}']`);
    rows.forEach(row => {
        const parentRow = row.closest('tr') || row.closest('.mobile-card');
        if (parentRow) {
            const buttons = parentRow.querySelectorAll('.btn-subscribe');
            buttons.forEach(btn => {
                btn.textContent = isSubscribed ? '❌ 取消訂閱' : '✅ 啟用訂閱';
                btn.className = `btn-action btn-subscribe ${isSubscribed ? 'btn-danger' : 'btn-success'}`;
                btn.setAttribute('onclick', `toggleSubscribe('${userId}', ${!isSubscribed})`);
            });
        }
    });
    
    // 重新載入列表以更新所有數據
    loadUsers();
}

// ===== CSV 匯出功能 =====
async function exportCSV(type) {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/export/${type}`);
        const blob = await response.blob();
        
        // 創建下載連結
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${type}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        showToast(`已匯出 ${type}.csv`, 'success');
    } catch (error) {
        console.error('匯出 CSV 失敗:', error);
        showToast('匯出 CSV 失敗', 'error');
    }
}

// ===== 完整資料匯出功能 =====
async function exportAllData(type) {
    try {
        showToast(`正在匯出 ${type}...`, 'info');
        
        if (type === 'full-backup') {
            // 匯出完整備份：下載所有類型的 CSV 並打包
            const types = ['users', 'conversations', 'scripts', 'orders', 'long-term-memory', 'generations'];
            const files = [];
            
            for (const exportType of types) {
                try {
                    const response = await adminFetch(`${API_BASE_URL}/admin/export/${exportType}`);
                    const blob = await response.blob();
                    const text = await blob.text();
                    files.push({ name: `${exportType}.csv`, content: text });
                } catch (e) {
                    console.warn(`匯出 ${exportType} 失敗:`, e);
                }
            }
            
            // 創建 ZIP 檔案（如果瀏覽器支援）
            if (typeof JSZip !== 'undefined') {
                const zip = new JSZip();
                files.forEach(file => {
                    zip.file(file.name, file.content);
                });
                const zipBlob = await zip.generateAsync({ type: 'blob' });
                const url = window.URL.createObjectURL(zipBlob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `reelmind-backup-${new Date().toISOString().split('T')[0]}.zip`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                showToast('完整備份已匯出', 'success');
            } else {
                // 如果不支援 ZIP，逐一下載
                files.forEach((file, index) => {
                    setTimeout(() => {
                        const blob = new Blob([file.content], { type: 'text/csv' });
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = file.name;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        window.URL.revokeObjectURL(url);
                    }, index * 500);
                });
                showToast('已開始下載所有檔案', 'success');
            }
        } else {
            // 單一類型匯出
            await exportCSV(type);
        }
    } catch (error) {
        console.error('匯出失敗:', error);
        showToast('匯出失敗', 'error');
    }
}

// ===== 登出功能 =====
function logout() {
    if (confirm('確定要登出嗎？')) {
        // 清除 token
        setAdminToken('');
        
        // 清除其他相關數據
        localStorage.removeItem('admin_token');
        localStorage.removeItem('admin_login_time');
        
        // 顯示登入提示
        showLoginRequired('已登出');
        
        showToast('已登出', 'success');
    }
}

// ===== 管理員設定頁面 =====
async function loadAdminSettings() {
    try {
        // 載入當前管理員資訊
        const token = getAdminToken();
        if (token) {
            try {
                // 嘗試從 token 中解析管理員資訊（如果 token 包含）
                const payload = JSON.parse(atob(token.split('.')[1] || '{}'));
                const adminName = payload.email || payload.admin_id || '管理員';
                document.getElementById('current-admin-name').textContent = adminName;
            } catch (e) {
                document.getElementById('current-admin-name').textContent = '管理員';
            }
            
            // 顯示登入時間（從 localStorage 或當前時間）
            const loginTime = localStorage.getItem('admin_login_time');
            if (loginTime) {
                document.getElementById('login-time').textContent = new Date(loginTime).toLocaleString('zh-TW');
            } else {
                localStorage.setItem('admin_login_time', new Date().toISOString());
                document.getElementById('login-time').textContent = new Date().toLocaleString('zh-TW');
            }
        } else {
            document.getElementById('current-admin-name').textContent = '未登入';
            document.getElementById('login-time').textContent = '-';
        }
    } catch (error) {
        console.error('載入管理員設定失敗:', error);
    }
}

// ===== 檔案選擇處理 =====
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        if (!file.name.endsWith('.csv')) {
            showToast('請選擇 CSV 檔案', 'error');
            event.target.value = '';
            return;
        }
        
        document.getElementById('import-file-name').textContent = file.name;
        document.getElementById('import-btn').disabled = false;
    }
}

// ===== 資料匯入功能 =====
async function importData() {
    const fileInput = document.getElementById('import-file');
    const importType = document.getElementById('import-type').value;
    const importMode = document.getElementById('import-mode').value;
    
    if (!fileInput.files || !fileInput.files[0]) {
        showToast('請先選擇要匯入的檔案', 'error');
        return;
    }
    
    const file = fileInput.files[0];
    
    if (!confirm(`確定要匯入 ${file.name} 嗎？匯入模式：${importMode === 'add' ? '新增模式' : '覆蓋模式'}`)) {
        return;
    }
    
    try {
        // 顯示進度條
        const progressDiv = document.getElementById('import-progress');
        const progressBar = document.getElementById('import-progress-bar');
        const statusText = document.getElementById('import-status');
        progressDiv.style.display = 'block';
        progressBar.style.width = '10%';
        statusText.textContent = '正在讀取檔案...';
        
        // 讀取檔案內容
        const fileContent = await file.text();
        progressBar.style.width = '30%';
        statusText.textContent = '正在上傳資料...';
        
        // 創建 FormData
        const formData = new FormData();
        formData.append('file', file);
        formData.append('mode', importMode);
        
        // 發送請求
        const token = getAdminToken();
        const response = await fetch(`${API_BASE_URL}/admin/import/${importType}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });
        
        progressBar.style.width = '80%';
        statusText.textContent = '正在處理資料...';
        
        const result = await response.json();
        
        if (response.ok) {
            progressBar.style.width = '100%';
            statusText.textContent = `匯入成功！成功：${result.success_count || 0}，失敗：${result.error_count || 0}`;
            showToast(`匯入完成：成功 ${result.success_count || 0} 筆，失敗 ${result.error_count || 0} 筆`, 'success');
            
            // 重置表單
            setTimeout(() => {
                fileInput.value = '';
                document.getElementById('import-file-name').textContent = '';
                document.getElementById('import-btn').disabled = true;
                progressDiv.style.display = 'none';
                progressBar.style.width = '0%';
                
                // 重新載入相關頁面
                if (importType === 'users') {
                    loadUsers();
                } else if (importType === 'scripts') {
                    loadScripts();
                } else if (importType === 'conversations') {
                    loadConversations();
                } else if (importType === 'orders') {
                    loadOrders();
                }
            }, 2000);
        } else {
            progressBar.style.width = '0%';
            statusText.textContent = `匯入失敗：${result.error || '未知錯誤'}`;
            showToast(result.error || '匯入失敗', 'error');
        }
    } catch (error) {
        console.error('匯入失敗:', error);
        showToast('匯入失敗：' + error.message, 'error');
        document.getElementById('import-progress').style.display = 'none';
        document.getElementById('import-progress-bar').style.width = '0%';
    }
}

// ===== 購買記錄 =====
async function loadOrders() {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/orders`);
        const data = await response.json();
        const allOrders = data.orders || [];
        
        console.log('訂單數據:', allOrders);
        
        // 檢測是否為手機版
        const isMobile = window.innerWidth <= 768;
        const tableContainer = await waitFor('#orders .table-container', 8000).catch(() => null);
        if (!tableContainer) {
            console.error('找不到訂單表格容器');
            return;
        }
        
        if (isMobile) {
            // 手機版：卡片式佈局
            setHTML(tableContainer, '');
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            if (allOrders.length === 0) {
                cardsContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">暫無訂單記錄</div>';
            } else {
                cardsContainer.innerHTML = allOrders.map(order => {
                    const orderId = order.order_id || order.id;
                    const safeOrderId = String(orderId || '').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
                    const paidDate = order.paid_at ? new Date(order.paid_at).toLocaleString('zh-TW', {
                        timeZone: 'Asia/Taipei',
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit'
                    }) : '-';
                    const expiresDate = order.expires_at ? new Date(order.expires_at).toLocaleString('zh-TW', {
                        timeZone: 'Asia/Taipei',
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit'
                    }) : '-';
                    const paymentMethodDisplay = order.payment_method || '-';
                    
                    return `
                    <div class="mobile-card">
                        <div class="mobile-card-header">
                            <span class="mobile-card-title">${escapeHtml(orderId || '未知訂單')}</span>
                            <span class="mobile-card-badge ${order.payment_status === 'paid' ? 'badge-success' : 'badge-danger'}">
                                ${order.payment_status === 'paid' ? '已付款' : '待付款'}
                            </span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">用戶</span>
                            <span class="mobile-card-value">${escapeHtml(order.user_name || '未知用戶')}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">Email</span>
                            <span class="mobile-card-value">${escapeHtml(order.user_email || '-')}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">方案</span>
                            <span class="mobile-card-value">${order.plan_type === 'monthly' ? '月費' : '年費'}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">金額</span>
                            <span class="mobile-card-value">NT$${order.amount?.toLocaleString() || 0}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">付款方式</span>
                            <span class="mobile-card-value">${escapeHtml(paymentMethodDisplay)}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">付款時間</span>
                            <span class="mobile-card-value">${paidDate}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">到期日期</span>
                            <span class="mobile-card-value">${expiresDate}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">發票號碼</span>
                            <span class="mobile-card-value">${escapeHtml(order.invoice_number || '-')}</span>
                        </div>
                        <div class="mobile-card-actions">
                            <button class="btn-action btn-delete" data-order-id="${safeOrderId}" onclick="adminDeleteOrder(this.dataset.orderId)" type="button">刪除</button>
                        </div>
                    </div>
                `;
                }).join('');
            }
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            setHTML(tableContainer, '');
            // 生成表格HTML
            let tableHTML = `
            <div class="table-wrapper">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>訂單編號</th>
                            <th>用戶</th>
                            <th>方案</th>
                            <th>金額</th>
                            <th>付款方式</th>
                            <th>付款狀態</th>
                            <th>付款時間</th>
                            <th>到期日期</th>
                            <th>發票號碼</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            allOrders.forEach(order => {
            const orderDate = order.created_at ? new Date(order.created_at).toLocaleString('zh-TW', {
                timeZone: 'Asia/Taipei',
                year: 'numeric',
                month: '2-digit',
                day: '2-digit'
            }) : '未知';
            
            const paidDate = order.paid_at ? new Date(order.paid_at).toLocaleString('zh-TW', {
                timeZone: 'Asia/Taipei',
                year: 'numeric',
                month: '2-digit',
                day: '2-digit'
            }) : '-';
            
            const expiresDate = order.expires_at ? new Date(order.expires_at).toLocaleString('zh-TW', {
                timeZone: 'Asia/Taipei',
                year: 'numeric',
                month: '2-digit',
                day: '2-digit'
            }) : '-';
            
            const orderId = order.order_id || order.id;
            // 確保 orderId 是有效的字符串
            if (!orderId) {
                console.warn('訂單缺少 ID:', order);
                return; // 跳過無效訂單
            }
            
            // 轉義訂單 ID，避免特殊字符導致問題
            const escapedOrderId = escapeHtml(String(orderId));
            // 使用 data 屬性安全地傳遞 orderId，避免 JSON.stringify 導致的語法錯誤
            const safeOrderId = String(orderId).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
            
            tableHTML += `
                <tr>
                    <td>${escapedOrderId}</td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span>${escapeHtml(order.user_name || '未知用戶')}</span>
                            <span style="font-size: 0.85rem; color: #64748b;">${escapeHtml(order.user_email || '')}</span>
                        </div>
                    </td>
                    <td>${order.plan_type === 'monthly' ? '月費' : '年費'}</td>
                    <td>NT$${order.amount?.toLocaleString() || 0}</td>
                    <td>${escapeHtml(order.payment_method || '-')}</td>
                    <td>
                        <span class="badge ${order.payment_status === 'paid' ? 'badge-success' : 'badge-danger'}">
                            ${order.payment_status === 'paid' ? '已付款' : '待付款'}
                        </span>
                    </td>
                    <td>${paidDate}</td>
                    <td>${expiresDate}</td>
                    <td>${escapeHtml(order.invoice_number || '-')}</td>
                    <td>
                        <button class="btn-action btn-delete" data-order-id="${safeOrderId}" onclick="adminDeleteOrder(this.dataset.orderId)" type="button" title="刪除訂單">
                            🗑️ 刪除
                        </button>
                    </td>
                </tr>
            `;
        });
        
            tableHTML += `
                    </tbody>
                </table>
            </div>
            `;
            
            setHTML(tableContainer, tableHTML);
        }
        
        // 更新統計
        const totalRevenue = allOrders.filter(o => o.payment_status === 'paid').reduce((sum, o) => sum + (o.amount || 0), 0);
        const paidCount = allOrders.filter(o => o.payment_status === 'paid').length;
        const pendingCount = allOrders.filter(o => o.payment_status !== 'paid').length;
    } catch (error) {
        console.error('載入訂單失敗:', error);
        showToast('載入訂單失敗', 'error');
    }
}

// ===== 訂單清理日誌 =====
async function loadOrderCleanupLogs() {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/order-cleanup-logs`);
        const data = await response.json();
        const logs = data.logs || [];
        
        // 檢測是否為手機版
        const isMobile = window.innerWidth <= 768;
        const tableContainer = document.querySelector('#order-cleanup-logs .table-container');
        
        if (logs.length === 0) {
            if (isMobile && tableContainer) {
                tableContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">暫無清理日誌</div>';
            } else {
                const tbody = document.getElementById('cleanup-logs-table-body');
                if (tbody) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem;">暫無清理日誌</td></tr>';
                }
            }
            return;
        }
        
        if (isMobile && tableContainer) {
            // 手機版：卡片式佈局
            setHTML(tableContainer, '');
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            cardsContainer.innerHTML = logs.map(log => {
                const cleanupDate = formatDateTime(log.cleanup_date);
                const deletedCount = log.deleted_count || 0;
                const totalAmount = log.details?.total_amount || 0;
                const deletedOrders = log.deleted_orders || '';
                const orderIds = deletedOrders.split(',').filter(id => id.trim()).slice(0, 3);
                const moreCount = deletedOrders.split(',').filter(id => id.trim()).length - orderIds.length;
                
                return `
                <div class="mobile-card">
                    <div class="mobile-card-header">
                        <span class="mobile-card-title">清理記錄</span>
                        <span class="mobile-card-badge">${deletedCount} 筆</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">清理時間</span>
                        <span class="mobile-card-value">${escapeHtml(cleanupDate)}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">刪除數量</span>
                        <span class="mobile-card-value">${deletedCount} 筆</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">總金額</span>
                        <span class="mobile-card-value">NT$${totalAmount.toLocaleString()}</span>
                    </div>
                    <div class="mobile-card-row">
                        <span class="mobile-card-label">訂單ID</span>
                        <span class="mobile-card-value" style="font-size: 0.85rem;">
                            ${orderIds.map(id => `<code style="background: #f3f4f6; padding: 2px 4px; border-radius: 3px; margin-right: 4px;">${escapeHtml(id.trim())}</code>`).join('')}
                            ${moreCount > 0 ? `<span style="color: #64748b;">...還有 ${moreCount} 筆</span>` : ''}
                        </span>
                    </div>
                    <div class="mobile-card-actions">
                        <button class="btn-action btn-view" onclick="viewCleanupLogDetail(${log.id})" type="button">查看詳情</button>
                    </div>
                </div>
            `;
            }).join('');
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            const tbody = document.getElementById('cleanup-logs-table-body');
            if (!tbody) {
                console.error('找不到清理日誌表格 tbody 元素');
                return;
            }
            
            setHTML(tbody, logs.map(log => {
                const cleanupDate = formatDateTime(log.cleanup_date);
                const deletedCount = log.deleted_count || 0;
                const totalAmount = log.details?.total_amount || 0;
                const deletedOrders = log.deleted_orders || '';
                const orderIds = deletedOrders.split(',').filter(id => id.trim()).slice(0, 5); // 最多顯示5個
                const moreCount = deletedOrders.split(',').filter(id => id.trim()).length - orderIds.length;
                
                return `
                    <tr>
                        <td>${escapeHtml(cleanupDate)}</td>
                        <td><span class="badge">${deletedCount} 筆</span></td>
                        <td>NT$${totalAmount.toLocaleString()}</td>
                        <td>
                            <div style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">
                                ${orderIds.map(id => `<code style="font-size: 0.75rem; background: #f3f4f6; padding: 2px 6px; border-radius: 4px; margin-right: 4px;">${escapeHtml(id.trim())}</code>`).join('')}
                                ${moreCount > 0 ? `<span style="color: #64748b; font-size: 0.85rem;">...還有 ${moreCount} 筆</span>` : ''}
                            </div>
                        </td>
                        <td>
                            <button class="btn-action btn-view" onclick="viewCleanupLogDetail(${log.id})" type="button">查看詳情</button>
                        </td>
                    </tr>
                `;
            }).join(''));
        }
    } catch (error) {
        console.error('載入清理日誌失敗:', error);
        showToast('載入清理日誌失敗', 'error');
        const tbody = document.getElementById('cleanup-logs-table-body');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem; color: #ef4444;">載入失敗</td></tr>';
        }
    }
}

async function viewCleanupLogDetail(logId) {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/order-cleanup-logs`);
        const data = await response.json();
        const logs = data.logs || [];
        const log = logs.find(l => l.id === logId);
        
        if (!log) {
            showToast('找不到清理日誌', 'error');
            return;
        }
        
        const details = log.details || {};
        const deletedOrders = details.deleted_orders || [];
        
        let content = `
            <div style="padding: 20px;">
                <h3 style="margin-bottom: 16px;">清理日誌詳情</h3>
                <div style="padding: 12px; background: #f8fafc; border-radius: 8px; margin-bottom: 16px;">
                    <p style="margin: 4px 0;"><strong>清理時間：</strong>${escapeHtml(formatDateTime(log.cleanup_date))}</p>
                    <p style="margin: 4px 0;"><strong>刪除數量：</strong>${log.deleted_count || 0} 筆</p>
                    <p style="margin: 4px 0;"><strong>總金額：</strong>NT$${(details.total_amount || 0).toLocaleString()}</p>
                    <p style="margin: 4px 0;"><strong>清理閾值：</strong>${details.hours_threshold || 24} 小時</p>
                </div>
        `;
        
        if (deletedOrders.length > 0) {
            content += `
                <div style="margin-top: 16px;">
                    <h4 style="margin-bottom: 8px;">已刪除的訂單列表</h4>
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="background: #f3f4f6;">
                                <th style="padding: 8px; text-align: left;">訂單編號</th>
                                <th style="padding: 8px; text-align: left;">用戶ID</th>
                                <th style="padding: 8px; text-align: left;">方案</th>
                                <th style="padding: 8px; text-align: right;">金額</th>
                                <th style="padding: 8px; text-align: left;">創建時間</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            deletedOrders.forEach(order => {
                content += `
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${escapeHtml(order.order_id || '-')}</td>
                        <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${escapeHtml((order.user_id || '').substring(0, 16))}...</td>
                        <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${escapeHtml(order.plan_type === 'monthly' ? '月費' : order.plan_type === 'yearly' ? '年費' : order.plan_type || '-')}</td>
                        <td style="padding: 8px; border-bottom: 1px solid #e5e7eb; text-align: right;">NT$${(order.amount || 0).toLocaleString()}</td>
                        <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${escapeHtml(formatDateTime(order.created_at))}</td>
                    </tr>
                `;
            });
            
            content += `
                        </tbody>
                    </table>
                </div>
            `;
        }
        
        content += `</div>`;
        showUserDetailModal(content);
    } catch (error) {
        console.error('載入清理日誌詳情失敗:', error);
        showToast('載入清理日誌詳情失敗', 'error');
    }
}

// 管理員刪除訂單
async function adminDeleteOrder(orderId) {
    // 確保 orderId 是有效的字符串
    if (!orderId) {
        showToast('訂單 ID 無效', 'error');
        console.error('adminDeleteOrder: orderId 為空或無效', orderId);
        return;
    }
    
    // 轉換為字符串（處理可能的數字或其他類型）
    orderId = String(orderId);
    
    // 清理訂單 ID（移除可能的額外字符，如 :1）
    const cleanOrderId = orderId.trim().split(':')[0]; // 移除冒號後的所有內容
    
    if (!confirm(`確定要刪除訂單 ${cleanOrderId} 嗎？此操作無法復原。\n\n注意：管理員可以刪除任何狀態的訂單（包括已付款的訂單）。`)) {
        return;
    }
    
    try {
        // 使用 encodeURIComponent 確保 URL 安全
        const encodedOrderId = encodeURIComponent(cleanOrderId);
        const response = await adminFetch(`${API_BASE_URL}/admin/orders/${encodedOrderId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            const result = await response.json();
            showToast('訂單已刪除', 'success');
            loadOrders(); // 重新載入訂單列表
        } else {
            const errorData = await response.json().catch(() => ({ error: '刪除失敗' }));
            showToast(errorData.error || '刪除失敗', 'error');
            console.error('刪除訂單失敗:', response.status, errorData);
        }
    } catch (error) {
        console.error('刪除訂單失敗:', error);
        showToast('刪除訂單失敗: ' + error.message, 'error');
    }
}

// ===== 授權記錄管理 =====
async function loadLicenseActivations() {
    try {
        const statusFilter = document.getElementById('activation-filter-status')?.value || '';
        const channelFilter = document.getElementById('activation-filter-channel')?.value || '';
        
        let url = `${API_BASE_URL}/admin/license-activations?limit=100`;
        if (statusFilter) url += `&status=${statusFilter}`;
        if (channelFilter) url += `&channel=${channelFilter}`;
        
        const response = await adminFetch(url);
        const data = await response.json();
        const activations = data.activations || [];
        
        console.log('授權記錄數據:', activations);
        
        // 檢測是否為手機版
        const isMobile = window.innerWidth <= 768;
        const tableContainer = await waitFor('#license-activations .table-container', 8000).catch(() => null);
        if (!tableContainer) {
            console.error('找不到授權記錄表格容器');
            return;
        }
        
        if (isMobile) {
            // 手機版：卡片式佈局
            setHTML(tableContainer, '');
            const cardsContainer = document.createElement('div');
            cardsContainer.className = 'mobile-cards-container';
            
            if (activations.length === 0) {
                cardsContainer.innerHTML = '<div style="text-align: center; padding: 2rem;">暫無授權記錄</div>';
            } else {
                const formatDate = (dateStr) => {
                    if (!dateStr) return '-';
                    try {
                        return new Date(dateStr).toLocaleString('zh-TW', {
                            timeZone: 'Asia/Taipei',
                            year: 'numeric',
                            month: '2-digit',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit'
                        });
                    } catch (e) {
                        return dateStr;
                    }
                };
                
                cardsContainer.innerHTML = activations.map(activation => {
                    const statusBadge = {
                        'pending': '<span class="badge badge-warning">待啟用</span>',
                        'activated': '<span class="badge badge-success">已啟用</span>',
                        'expired': '<span class="badge badge-danger">已過期</span>'
                    }[activation.status] || '<span class="badge">未知</span>';
                    
                    return `
                    <div class="mobile-card">
                        <div class="mobile-card-header">
                            <span class="mobile-card-title">授權 #${activation.id}</span>
                            ${statusBadge}
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">Token</span>
                            <span class="mobile-card-value" style="font-size: 0.75rem; word-break: break-all;">${escapeHtml((activation.activation_token || '-').substring(0, 20) + '...')}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">通路</span>
                            <span class="mobile-card-value">${escapeHtml(activation.channel || '-')}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">訂單編號</span>
                            <span class="mobile-card-value">${escapeHtml(activation.order_id || '-')}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">Email</span>
                            <span class="mobile-card-value">${escapeHtml(activation.email || '-')}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">方案</span>
                            <span class="mobile-card-value">${activation.plan_type === 'monthly' ? '月費' : '年費'}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">金額</span>
                            <span class="mobile-card-value">NT$${activation.amount?.toLocaleString() || 0}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">連結到期</span>
                            <span class="mobile-card-value">${formatDate(activation.link_expires_at)}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">授權到期</span>
                            <span class="mobile-card-value">${formatDate(activation.license_expires_at)}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">啟用時間</span>
                            <span class="mobile-card-value">${formatDate(activation.activated_at)}</span>
                        </div>
                        <div class="mobile-card-row">
                            <span class="mobile-card-label">創建時間</span>
                            <span class="mobile-card-value">${formatDate(activation.created_at)}</span>
                        </div>
                        <div class="mobile-card-actions">
                            <button class="btn-action btn-danger" onclick="deleteLicenseActivation(${activation.id})" type="button">刪除</button>
                        </div>
                    </div>
                `;
                }).join('');
            }
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            setHTML(tableContainer, '');
            // 生成表格HTML
            let tableHTML = `
            <div class="table-wrapper">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>授權 Token</th>
                            <th>通路</th>
                            <th>訂單編號</th>
                            <th>Email</th>
                            <th>方案</th>
                            <th>金額</th>
                            <th>狀態</th>
                            <th>連結到期日</th>
                            <th>授權到期日</th>
                            <th>啟用時間</th>
                            <th>創建時間</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            activations.forEach(activation => {
            const statusBadge = {
                'pending': '<span class="badge badge-warning">待啟用</span>',
                'activated': '<span class="badge badge-success">已啟用</span>',
                'expired': '<span class="badge badge-danger">已過期</span>'
            }[activation.status] || '<span class="badge">未知</span>';
            
            const formatDate = (dateStr) => {
                if (!dateStr) return '-';
                try {
                    return new Date(dateStr).toLocaleString('zh-TW', {
                        timeZone: 'Asia/Taipei',
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit'
                    });
                } catch (e) {
                    return dateStr;
                }
            };
            
            tableHTML += `
                <tr>
                    <td>${activation.id}</td>
                    <td><code style="font-size: 0.85rem;">${activation.activation_token || '-'}</code></td>
                    <td>${activation.channel || '-'}</td>
                    <td>${activation.order_id || '-'}</td>
                    <td>${activation.email || '-'}</td>
                    <td>${activation.plan_type === 'monthly' ? '月費' : '年費'}</td>
                    <td>NT$${activation.amount?.toLocaleString() || 0}</td>
                    <td>${statusBadge}</td>
                    <td>${formatDate(activation.link_expires_at)}</td>
                    <td>${formatDate(activation.license_expires_at)}</td>
                    <td>${formatDate(activation.activated_at)}</td>
                    <td>${formatDate(activation.created_at)}</td>
                    <td>
                        <button class="btn-action btn-danger" onclick="deleteLicenseActivation(${activation.id})" type="button">
                            🗑️ 刪除
                        </button>
                    </td>
                </tr>
            `;
        });
        
            tableHTML += `
                    </tbody>
                </table>
            </div>
            `;
            
            setHTML(tableContainer, tableHTML);
        }
    } catch (error) {
        console.error('載入授權記錄失敗:', error);
        showToast('載入授權記錄失敗', 'error');
    }
}

async function deleteLicenseActivation(activationId) {
    if (!confirm('確定要刪除這筆授權記錄嗎？此操作無法復原。')) {
        return;
    }
    
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/license-activations/${activationId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showToast('授權記錄已刪除', 'success');
            loadLicenseActivations(); // 重新載入列表
        } else {
            const error = await response.json();
            showToast(error.error || '刪除失敗', 'error');
        }
    } catch (error) {
        console.error('刪除授權記錄失敗:', error);
        showToast('刪除授權記錄失敗', 'error');
    }
}