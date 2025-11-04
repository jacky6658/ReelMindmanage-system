// API 基礎 URL
const API_BASE_URL = 'https://aivideobackend.zeabur.app/api';

// 全域變數
let charts = {};

// ===== 管理員認證機制 =====
// 從 localStorage 讀取管理員 token
function getAdminToken() {
    return localStorage.getItem('adminToken') || '';
}

function setAdminToken(token) {
    if (token) {
        localStorage.setItem('adminToken', token);
    } else {
        localStorage.removeItem('adminToken');
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

// 強制登出並清除所有狀態
function forceLogout(reason = '登入已過期，請重新登入') {
    // 清除 token
    setAdminToken('');
    
    // 清除任何其他相關的 localStorage 數據（如果需要）
    // localStorage.removeItem('其他相關數據');
    
    // 顯示登入提示，並顯示過期訊息
    showLoginRequired(reason);
    
    // 停止所有正在進行的請求（可選）
    // 可以實作一個請求取消機制
}

// 統一的 fetch 函數，自動帶上 Authorization header
async function adminFetch(url, options = {}) {
    const token = getAdminToken();
    
    // 檢查 token 是否存在
    if (!token) {
        forceLogout('請先登入');
        throw new Error('需要登入');
    }
    
    // 檢查 token 是否過期
    if (isTokenExpired(token)) {
        forceLogout('登入已過期，請重新登入');
        throw new Error('Token 已過期');
    }
    
    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };
    
    try {
        const response = await fetch(url, { ...options, headers });
        
        // 如果收到 401 或 403，清除 token 並顯示登入提示
        if (response.status === 401 || response.status === 403) {
            let errorMessage = '認證失敗，請重新登入';
            
            // 嘗試從回應中獲取錯誤訊息
            try {
                const errorData = await response.clone().json();
                if (errorData.detail) {
                    errorMessage = errorData.detail;
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
function checkAdminAuth() {
    // 檢查 URL 參數中是否有 token（來自 OAuth callback）
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('token') || urlParams.get('access_token');
    const adminLogin = urlParams.get('admin_login');
    
    if (tokenFromUrl) {
        setAdminToken(tokenFromUrl);
        // 清除 URL 參數並重新載入
        window.history.replaceState({}, document.title, window.location.pathname);
        location.reload();
        return;
    }
    
    // 檢查是否有儲存的 token
    const token = getAdminToken();
    if (!token) {
        // 如果 URL 中有 admin_login 參數但沒有 token，可能是正在進行 OAuth 流程
        if (adminLogin) {
            // 等待 OAuth callback，不要顯示登入提示
            return;
        }
        showLoginRequired();
        return;
    }
    
    // 檢查 token 是否過期
    if (isTokenExpired(token)) {
        forceLogout('登入已過期，請重新登入');
        return;
    }
    
    // 檢查 token 是否即將過期（提前提醒）
    if (isTokenExpiringSoon(token)) {
        // 可以選擇顯示一個非阻塞的提醒，但不在這裡實作
        // 因為這可能會在每次檢查時都顯示，造成干擾
    }
}

// 定期檢查 token 狀態（每分鐘檢查一次）
function startTokenMonitor() {
    setInterval(() => {
        const token = getAdminToken();
        if (token) {
            // 檢查是否過期
            if (isTokenExpired(token)) {
                forceLogout('登入已過期，請重新登入');
            } else if (isTokenExpiringSoon(token)) {
                // Token 即將過期，可以顯示一個非阻塞的提醒
                // 這裡選擇不顯示，避免干擾用戶操作
                // 如果需要，可以在這裡顯示一個頂部橫幅提醒
            }
        }
    }, 60000); // 每分鐘檢查一次
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
document.addEventListener('DOMContentLoaded', function() {
    // 檢查管理員認證
    checkAdminAuth();
    
    // 啟動 token 監控（每分鐘檢查一次）
    startTokenMonitor();
    
    // 啟動活動監控（每30秒更新一次）
    startActivityMonitor();
    
    initializeNavigation();
    updateTime();
    setInterval(updateTime, 1000);
    loadOverview();
    
    // 監聽視窗大小改變，重新載入當前頁面數據以切換佈局
    let resizeTimer;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function() {
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
        'orders': '購買記錄',
        'generations': '生成記錄',
        'analytics': '數據分析'
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
        case 'orders':
            loadOrders();
            break;
        case 'generations':
            loadGenerations();
            break;
        case 'analytics':
            loadAnalytics();
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
                aspectRatio: 2,
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
                aspectRatio: 2
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
            tbody.innerHTML = data.users.map(user => {
                const isSubscribed = user.is_subscribed !== false; // 預設為已訂閱
                const subscribeStatus = isSubscribed ? 
                    '<span class="badge badge-success">已訂閱</span>' : 
                    '<span class="badge badge-danger">未訂閱</span>';
                
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
            
            content += `<div style="margin-top: 16px; padding: 12px; background: #f0f9ff; border-radius: 8px;">`;
            content += `<h4 style="margin-bottom: 8px;">🔑 授權資訊</h4>`;
            content += `<p><strong>等級：</strong>${licenseData.tier}</p>`;
            content += `<p><strong>席次：</strong>${licenseData.seats || 1}</p>`;
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
                
                content += `<tr>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${order.order_id || order.id}</td>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">${order.plan_type === 'monthly' ? '月費' : '年費'}</td>`;
                content += `<td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">NT$${order.amount?.toLocaleString() || 0}</td>`;
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
        
        // 更新模式統計數據
        const mode1 = data.mode_stats.mode1_quick_generate;
        const mode2 = data.mode_stats.mode2_ai_consultant;
        const mode3 = data.mode_stats.mode3_ip_planning;
        
        document.getElementById('mode1-count').textContent = mode1.count || 0;
        document.getElementById('mode1-success').textContent = mode1.success_rate ? `${mode1.success_rate}%` : '0%';
        document.getElementById('mode2-count').textContent = mode2.count || 0;
        document.getElementById('mode2-avg').textContent = mode2.avg_turns ? `${mode2.avg_turns}` : '0';
        document.getElementById('mode3-count').textContent = mode3.count || 0;
        document.getElementById('mode3-profile').textContent = mode3.profiles_generated || 0;
        
        // 使用真實時間分布數據
        const timeDist = data.time_distribution;
        
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
                            timeDist['00:00-06:00'] || 0,
                            timeDist['06:00-12:00'] || 0,
                            timeDist['12:00-18:00'] || 0,
                            timeDist['18:00-24:00'] || 0
                        ],
                        backgroundColor: '#3b82f6'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: 2
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
        
        // 直接獲取所有對話記錄
        const response = await adminFetch(`${API_BASE_URL}/admin/conversations`);
        const data = await response.json();
        const allConversations = data.conversations || [];
        
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
                        <button class="btn-action btn-view" onclick="viewConversation('${conv.user_id}', '${conv.mode}')" type="button">查看詳情</button>
                    </div>
                </div>
            `).join('');
            
            tableContainer.appendChild(cardsContainer);
        } else {
            // 桌面版：表格佈局
            const tbody = await waitFor('#conversations-table-body', 8000).catch(() => null);
            if (!tbody) return;
            setHTML(tbody, allConversations.map(conv => `
                <tr>
                    <td>${conv.user_id.substring(0, 12)}...</td>
                    <td>${conv.mode}</td>
                    <td>${conv.summary.substring(0, 30)}...</td>
                    <td>${conv.message_count}</td>
                    <td>${formatDate(conv.created_at)}</td>
                    <td>
                        <button class="btn-action btn-view" onclick="viewConversation('${conv.user_id}', '${conv.mode}')" type="button">查看</button>
                    </td>
                </tr>
            `).join(''));
        }
        
        // 添加匯出按鈕
        const actionsDiv = document.querySelector('#conversations .section-actions');
        if (actionsDiv) {
            let exportBtn = actionsDiv.querySelector('.btn-export');
            if (!exportBtn) {
                exportBtn = document.createElement('button');
                exportBtn.className = 'btn btn-secondary btn-export';
                exportBtn.innerHTML = '<i class="icon">📥</i> 匯出 CSV';
                exportBtn.onclick = () => exportCSV('conversations');
                actionsDiv.insertBefore(exportBtn, actionsDiv.firstChild);
            }
        }
        
    } catch (error) {
        console.error('載入對話記錄失敗:', error);
        showToast('載入對話記錄失敗', 'error');
        const isMobile = window.innerWidth <= 768;
        const tableContainer = document.querySelector('#conversations .table-container');
        if (isMobile) {
            if (tableContainer) setHTML(tableContainer, '<div style="text-align: center; padding: 2rem;">載入失敗</div>');
        } else {
            const tbody = document.querySelector('#conversations-table-body');
            if (tbody) setHTML(tbody, '<tr><td colspan="6" style="text-align: center; padding: 2rem;">載入失敗</td></tr>');
        }
    }
}

// 查看對話詳情
function viewConversation(userId, mode) {
    // 打開彈窗
    const modal = document.getElementById('conversation-modal');
    modal.classList.add('active');
    
    // 顯示載入中
    const content = document.getElementById('conversation-detail-content');
    content.innerHTML = '<p>載入對話內容中...</p>';
    
    // 模擬對話數據（實際應該從API獲取）
    const mockMessages = [
        {
            role: 'user',
            content: '我想要開始做短影音，應該怎麼開始？',
            time: '2025-01-10 10:30:00'
        },
        {
            role: 'ai',
            content: '很高興為您服務！開始做短影音之前，我需要了解幾個問題：\n1. 您想在哪個平台發布？（抖音、小紅書、Instagram等）\n2. 您的目標受眾是誰？\n3. 您想創作什麼類型的內容？（美食、旅遊、教育等）',
            time: '2025-01-10 10:30:15'
        },
        {
            role: 'user',
            content: '我想在抖音上做美食類的短影音，目標受眾是年輕女性。',
            time: '2025-01-10 10:31:00'
        },
        {
            role: 'ai',
            content: '很棒的方向！針對抖音美食內容，我建議：\n\n🎯 帳號定位：年輕女性的美食探索日記\n📝 內容方向：\n- 快速美食製作（3-5分鐘內）\n- 網紅美食探店\n- 在家就能做的餐廳級料理\n\n🔥 熱門標籤：#美食日常 #在家做飯 #美食探店',
            time: '2025-01-10 10:31:30'
        }
    ];
    
    // 渲染對話內容
    setTimeout(() => {
        let messagesHtml = '<div class="conversation-detail">';
        mockMessages.forEach(msg => {
            messagesHtml += `
                <div class="message-item ${msg.role}">
                    <div class="message-header">
                        <span class="message-role">${msg.role === 'user' ? '👤 用戶' : '🤖 AI助理'}</span>
                        <span class="message-time">${msg.time}</span>
                    </div>
                    <div class="message-content">${msg.content}</div>
                </div>
            `;
        });
        messagesHtml += '</div>';
        content.innerHTML = messagesHtml;
    }, 500);
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
    modal.classList.add('active');
    
    // 顯示載入中
    const content = document.getElementById('script-detail-content');
    content.innerHTML = '<p>載入腳本詳情中...</p>';
    
    // 渲染腳本內容
    setTimeout(() => {
        content.innerHTML = `
            <div class="script-detail">
                <div class="script-info">
                    <div class="script-info-item">
                        <span class="script-info-label">腳本標題</span>
                        <span class="script-info-value">${script.title}</span>
                    </div>
                    <div class="script-info-item">
                        <span class="script-info-label">平台</span>
                        <span class="script-info-value">${script.platform}</span>
                    </div>
                    <div class="script-info-item">
                        <span class="script-info-label">分類</span>
                        <span class="script-info-value">${script.category}</span>
                    </div>
                    <div class="script-info-item">
                        <span class="script-info-label">創建時間</span>
                        <span class="script-info-value">${formatDate(script.created_at)}</span>
                    </div>
                </div>
                
                <div class="script-content">
                    <h4>📝 腳本內容</h4>
                    <div class="script-text">${script.content || '無內容'}</div>
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
function deleteScript(scriptId) {
    if (confirm('確定要刪除這個腳本嗎？')) {
        alert(`刪除腳本\n腳本ID: ${scriptId}`);
        showToast('腳本已刪除', 'success');
        // TODO: 實現真實的刪除API調用
        // loadScripts(); // 重新載入列表
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
        
        // 顯示用戶列表
        const tbody = await waitFor('#memory-table-body', 8000).catch(() => null);
        if (!tbody) {
            console.error('找不到表格 tbody 元素');
            return;
        }
        
        if (users.length === 0) {
            setHTML(tbody, '<tr><td colspan="7" style="text-align: center; padding: 2rem;">暫無長期記憶記錄</td></tr>');
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
                aspectRatio: 2
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
                aspectRatio: 2
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
                aspectRatio: 2
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
                aspectRatio: 2
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
async function toggleSubscribe(userId, subscribe) {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/users/${userId}/subscription`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ is_subscribed: subscribe })
        });
        
        if (response.ok) {
            const result = await response.json();
            showToast(subscribe ? '已啟用訂閱' : '已取消訂閱', 'success');
            
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

// ===== 購買記錄 =====
async function loadOrders() {
    try {
        const response = await adminFetch(`${API_BASE_URL}/admin/orders`);
        const data = await response.json();
        const allOrders = data.orders || [];
        
        console.log('訂單數據:', allOrders);
        
        const tableContainer = await waitFor('#orders .table-container', 8000).catch(() => null);
        if (!tableContainer) {
            console.error('找不到訂單表格容器');
            return;
        }
        
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
            
            tableHTML += `
                <tr>
                    <td>${order.order_id || order.id}</td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span>${order.user_name || '未知用戶'}</span>
                            <span style="font-size: 0.85rem; color: #64748b;">${order.user_email || ''}</span>
                        </div>
                    </td>
                    <td>${order.plan_type === 'monthly' ? '月費' : '年費'}</td>
                    <td>NT$${order.amount?.toLocaleString() || 0}</td>
                    <td>${order.payment_method || '-'}</td>
                    <td>
                        <span class="badge ${order.payment_status === 'paid' ? 'badge-success' : 'badge-danger'}">
                            ${order.payment_status === 'paid' ? '已付款' : '待付款'}
                        </span>
                    </td>
                    <td>${paidDate}</td>
                    <td>${expiresDate}</td>
                    <td>${order.invoice_number || '-'}</td>
                </tr>
            `;
        });
        
        tableHTML += `
                    </tbody>
                </table>
            </div>
        `;
        
        setHTML(tableContainer, tableHTML);
        
        // 更新統計
        const totalRevenue = allOrders.filter(o => o.payment_status === 'paid').reduce((sum, o) => sum + (o.amount || 0), 0);
        const paidCount = allOrders.filter(o => o.payment_status === 'paid').length;
        const pendingCount = allOrders.filter(o => o.payment_status !== 'paid').length;
        
        // 更新統計卡片（如果存在）
        const statsContainer = document.querySelector('#orders .stats-grid');
        if (statsContainer) {
            statsContainer.innerHTML = `
                <div class="stat-card">
                    <div class="stat-icon">💳</div>
                    <div class="stat-value">${allOrders.length}</div>
                    <div class="stat-label">總訂單數</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">✅</div>
                    <div class="stat-value">${paidCount}</div>
                    <div class="stat-label">已付款</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⏳</div>
                    <div class="stat-value">${pendingCount}</div>
                    <div class="stat-label">待付款</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">💰</div>
                    <div class="stat-value">NT$${totalRevenue.toLocaleString()}</div>
                    <div class="stat-label">總營收</div>
                </div>
            `;
        }
        
        showToast(`已載入 ${allOrders.length} 筆訂單記錄`, 'success');
    } catch (error) {
        console.error('載入訂單失敗:', error);
        showToast('載入訂單失敗', 'error');
    }
}