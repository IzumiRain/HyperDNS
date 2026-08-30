// =======================================================
// HyperDNS Front-End Application Logic (ES6)
// Bulletproof, Offline-Safe, Self-Healing
// =======================================================

let authToken = localStorage.getItem('hyperdns_token') || '';
let sseSource = null;
let qpsChart = null;
let currentConfig = null;
let isStreamPaused = false;

function safeFeatherReplace() {
  try {
    if (typeof feather !== 'undefined' && feather.replace) {
      feather.replace();
    }
  } catch (e) {
    console.warn('Feather icons render notice:', e);
  }
}

// Init when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  safeFeatherReplace();
  try { initChart(); } catch (e) {}
  checkAuthAndBoot();

  // Login form submit
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const u = document.getElementById('login-username').value.trim();
      const p = document.getElementById('login-password').value.trim();
      const errDiv = document.getElementById('login-error');
      if (errDiv) errDiv.classList.add('hidden');

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: u, password: p })
        });

        if (!res.ok) {
          if (errDiv) {
            errDiv.innerText = 'Invalid credentials';
            errDiv.classList.remove('hidden');
          }
          return;
        }

        const data = await res.json();
        authToken = data.token;
        localStorage.setItem('hyperdns_token', authToken);
        hideLoginModal();
        bootDashboard();

        if (data.is_default_password) {
          showChangePwdModal();
        }
      } catch (err) {
        if (errDiv) {
          errDiv.innerText = 'Server connection failed';
          errDiv.classList.remove('hidden');
        }
      }
    });
  }

  // Password change form submit
  const pwdForm = document.getElementById('change-pwd-form');
  if (pwdForm) {
    pwdForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const newUsername = document.getElementById('new-admin-user').value.trim();
      const newPassword = document.getElementById('new-admin-pass').value.trim();
      if (!newUsername || !newPassword) return;

      try {
        const res = await fetch('/api/config/server', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({
            admin_username: newUsername,
            admin_password: newPassword
          })
        });

        if (res.ok) {
          hideChangePwdModal();
          showToast('Credentials updated successfully!', 'success');
        } else {
          showToast('Failed to update credentials', 'error');
        }
      } catch (err) {
        showToast('Error updating credentials', 'error');
      }
    });
  }

  document.getElementById('logout-btn')?.addEventListener('click', () => {
    localStorage.removeItem('hyperdns_token');
    authToken = '';
    showLoginModal();
  });
});

// =======================================================
// AUTH & BOOTSTRAP
// =======================================================
function checkAuthAndBoot() {
  if (!authToken) {
    showLoginModal();
  } else {
    bootDashboard();
  }
}

function showLoginModal() {
  document.getElementById('login-modal')?.classList.remove('hidden');
}

function hideLoginModal() {
  document.getElementById('login-modal')?.classList.add('hidden');
}

function showChangePwdModal() {
  document.getElementById('change-pwd-modal')?.classList.remove('hidden');
}

function hideChangePwdModal() {
  document.getElementById('change-pwd-modal')?.classList.add('hidden');
}

let areEventListenersAttached = false;

async function bootDashboard() {
  if (!areEventListenersAttached) {
    initEventListeners();
    initClientEventListeners();
    areEventListenersAttached = true;
  }
  await loadConfig();
  await loadClients();
  startStatsPolling();
  startLiveStream();
}

// =======================================================
// CONFIG & POLICIES SYNC
// =======================================================
async function loadConfig() {
  try {
    const res = await fetch('/api/auth/me', {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });

    if (res.status === 401) {
      showLoginModal();
      return;
    }

    const meData = await res.json();
    if (meData.is_default_password) {
      showChangePwdModal();
    }

    const cfgRes = await fetch('/api/config', {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    currentConfig = await cfgRes.json();
    renderConfig(currentConfig);
  } catch (e) {
    console.error('Failed to load config:', e);
  }
}

function renderConfig(cfg) {
  if (!cfg) return;

  // Header & guide public IP
  const pubIP = cfg.server.public_ip || '127.0.0.1';
  const headerIPEl = document.getElementById('header-public-ip');
  if (headerIPEl) headerIPEl.innerText = pubIP;
  const guideWinEl = document.getElementById('guide-win-ip');
  if (guideWinEl) guideWinEl.innerText = pubIP;
  const guideConsoleEl = document.getElementById('guide-console-ip');
  if (guideConsoleEl) guideConsoleEl.innerText = pubIP;
  const guideDohEl = document.getElementById('guide-doh-url');
  if (guideDohEl) guideDohEl.innerText = `http://${pubIP}:${cfg.server.web_port}/dns-query`;

  if (cfg.tls && cfg.tls.domain) {
    const guideDotEl = document.getElementById('guide-dot-hostname');
    if (guideDotEl) guideDotEl.innerText = cfg.tls.domain;
    const sslDomInput = document.getElementById('ssl-domain-input');
  // Render API Key
  const apiKeyDisp = document.getElementById('api-key-display');
  if (apiKeyDisp && cfg.server && cfg.server.api_key) {
    apiKeyDisp.innerText = cfg.server.api_key;
  }

  // Preset Switches
  setSwitch('preset-riot', cfg.rules.enable_riot);
  setSwitch('preset-epic', cfg.rules.enable_epic);
  setSwitch('preset-steam', cfg.rules.enable_steam);
  setSwitch('preset-pubg', cfg.rules.enable_pubg);
  setSwitch('preset-cod', cfg.rules.enable_call_of_duty);
  setSwitch('preset-supercell', cfg.rules.enable_supercell);
  setSwitch('preset-discord', cfg.rules.enable_discord);
  setSwitch('preset-ea', cfg.rules.enable_ea);
  setSwitch('preset-blizzard', cfg.rules.enable_blizzard);
  setSwitch('preset-ubisoft', cfg.rules.enable_ubisoft);
  setSwitch('preset-rockstar', cfg.rules.enable_rockstar);
  setSwitch('preset-xbox', cfg.rules.enable_xbox);
  setSwitch('preset-playstation', cfg.rules.enable_playstation);
  setSwitch('preset-roblox', cfg.rules.enable_roblox);
  setSwitch('preset-spotify', cfg.rules.enable_spotify);
  setSwitch('preset-twitch', cfg.rules.enable_twitch);
  setSwitch('preset-kick', cfg.rules.enable_kick);
  setSwitch('preset-dev403', cfg.rules.enable_dev403);
  setSwitch('preset-adblock', cfg.rules.enable_adblock);
  setSwitch('preset-familysafe', cfg.rules.enable_familysafe);

  // Render Custom Rules Lists
  renderList('custom-proxied-list', cfg.rules.custom_proxied, 'remove-proxied');
  renderList('custom-blocked-list', cfg.rules.custom_blocked, 'remove-blocked');
  renderList('tokens-list', cfg.access.doh_tokens, 'remove-token');
  renderCustomRecords(cfg.rules.custom_records);
}

function setSwitch(id, val) {
  const el = document.getElementById(id);
  if (el) el.checked = !!val;
}

function getSwitch(id) {
  const el = document.getElementById(id);
  return el ? el.checked : false;
}

function renderList(containerId, items, removeClass) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="text-slate-500 text-xs py-1">No custom entries yet</div>';
    return;
  }
  items.forEach(item => {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between py-1.5 px-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs';
    row.innerHTML = `
      <span class="font-mono text-cyan-300">${item}</span>
      <button class="${removeClass} text-slate-500 hover:text-red-400 p-1" data-val="${item}">
        <i data-feather="x" class="w-3.5 h-3.5"></i>
      </button>
    `;
    container.appendChild(row);
  });
  safeFeatherReplace();
}

function renderCustomRecords(records) {
  const container = document.getElementById('custom-records-list');
  if (!container) return;
  container.innerHTML = '';
  if (!records || Object.keys(records).length === 0) {
    container.innerHTML = '<div class="text-slate-500 text-xs py-1">No static records yet</div>';
    return;
  }
  for (const [dom, ip] of Object.entries(records)) {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between py-1.5 px-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs';
    row.innerHTML = `
      <span class="font-mono text-emerald-300">${dom} &rarr; ${ip}</span>
      <button class="remove-record text-slate-500 hover:text-red-400 p-1" data-dom="${dom}">
        <i data-feather="x" class="w-3.5 h-3.5"></i>
      </button>
    `;
    container.appendChild(row);
  }
  safeFeatherReplace();
}

// =======================================================
// SAVE RULES API
// =======================================================
async function saveRules() {
  if (!currentConfig) return;

  const payload = {
    enable_riot: getSwitch('preset-riot'),
    enable_epic: getSwitch('preset-epic'),
    enable_steam: getSwitch('preset-steam'),
    enable_pubg: getSwitch('preset-pubg'),
    enable_call_of_duty: getSwitch('preset-cod'),
    enable_supercell: getSwitch('preset-supercell'),
    enable_discord: getSwitch('preset-discord'),
    enable_ea: getSwitch('preset-ea'),
    enable_blizzard: getSwitch('preset-blizzard'),
    enable_ubisoft: getSwitch('preset-ubisoft'),
    enable_rockstar: getSwitch('preset-rockstar'),
    enable_xbox: getSwitch('preset-xbox'),
    enable_playstation: getSwitch('preset-playstation'),
    enable_roblox: getSwitch('preset-roblox'),
    enable_spotify: getSwitch('preset-spotify'),
    enable_twitch: getSwitch('preset-twitch'),
    enable_kick: getSwitch('preset-kick'),
    enable_dev403: getSwitch('preset-dev403'),
    enable_adblock: getSwitch('preset-adblock'),
    enable_familysafe: getSwitch('preset-familysafe'),
    custom_proxied: currentConfig.rules.custom_proxied,
    custom_blocked: currentConfig.rules.custom_blocked,
    custom_direct: currentConfig.rules.custom_direct,
    custom_records: currentConfig.rules.custom_records
  };

  try {
    const res = await fetch('/api/config/rules', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      currentConfig.rules = payload;
      showToast('Policies updated & active!', 'success');
    }
  } catch (e) {
    showToast('Failed to save policies', 'error');
  }
}

// =======================================================
// STATS POLLING
// =======================================================
function startStatsPolling() {
  updateStats();
  setInterval(updateStats, 2000);
}

async function updateStats() {
  if (!authToken) return;
  try {
    const res = await fetch('/api/stats', {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (!res.ok) return;

    const data = await res.json();
    
    const setTxt = (id, txt) => {
      const el = document.getElementById(id);
      if (el) el.innerText = txt;
    };

    setTxt('stat-qps', data.qps.toFixed(1));
    setTxt('stat-total-queries', data.total_queries.toLocaleString());
    setTxt('stat-cache-ratio', data.cache_hit_ratio.toFixed(1) + '%');
    setTxt('stat-cache-entries', data.cache_entries.toLocaleString());
    setTxt('stat-proxy-active', data.active_proxy_conns);
    setTxt('stat-proxy-total', data.total_proxy_conns.toLocaleString());
    setTxt('stat-memory', data.alloc_memory_mb.toFixed(1));
    setTxt('stat-memory-sys', data.sys_memory_mb.toFixed(1));
    setTxt('stat-cpu-percent', data.cpu_usage_percent.toFixed(1) + '%');
    setTxt('stat-cpu-cores', data.num_cpu);
    setTxt('stat-goroutines', data.num_goroutines);
    setTxt('stat-speed-in', data.speed_in_kbps.toFixed(1));
    setTxt('stat-speed-out', data.speed_out_kbps.toFixed(1));
    setTxt('stat-traffic-total', formatBytes(data.total_bytes_transferred));

    // Render upstreams list
    renderUpstreams(data.upstreams);

    // Push QPS point to chart
    pushChartData(data.qps);
  } catch (e) {
    // Silent fail
  }
}

function formatBytes(bytes) {
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function renderUpstreams(upstreams) {
  const container = document.getElementById('upstreams-list');
  if (!container) return;
  container.innerHTML = '';

  if (!upstreams || upstreams.length === 0) {
    container.innerHTML = '<div class="text-slate-500 text-xs py-2">No upstreams configured</div>';
    return;
  }

  upstreams.forEach(u => {
    const latMs = (u.latency / 1000000).toFixed(1);
    let badgeClass = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    if (latMs > 40) badgeClass = 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    if (latMs > 80) badgeClass = 'text-red-400 bg-red-500/10 border-red-500/30';

    const row = document.createElement('div');
    row.className = 'flex items-center justify-between py-1.5 px-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs';
    row.innerHTML = `
      <div class="flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
        <span class="font-mono text-slate-200">${u.address}</span>
      </div>
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded border ${badgeClass} text-[10px] font-bold font-mono">${latMs} ms</span>
        <button class="remove-upstream text-slate-500 hover:text-red-400 p-0.5" data-addr="${u.address}" title="Remove upstream">
          <i data-feather="trash" class="w-3 h-3"></i>
        </button>
      </div>
    `;
    container.appendChild(row);
  });
  safeFeatherReplace();
}

// =======================================================
// LIVE QUERY STREAM (SSE)
// =======================================================
function startLiveStream() {
  if (sseSource) {
    try { sseSource.close(); } catch(e) {}
  }

  const tbody = document.getElementById('stream-tbody');
  const tokenParam = authToken ? `?token=${encodeURIComponent(authToken)}` : '';
  sseSource = new EventSource(`/api/stream/queries${tokenParam}`);

  // Handle single query event
  sseSource.addEventListener('query', (event) => {
    if (isStreamPaused) return;
    try {
      const q = JSON.parse(event.data);
      if (tbody) appendQueryRow(tbody, q);
    } catch (e) {
      console.error('Error parsing live query:', e);
    }
  });

  // Handle initial history batch
  sseSource.addEventListener('history', (event) => {
    try {
      const list = JSON.parse(event.data);
      if (Array.isArray(list) && list.length > 0 && tbody) {
        tbody.innerHTML = '';
        for (let i = list.length - 1; i >= 0; i--) {
          appendQueryRow(tbody, list[i]);
        }
      }
    } catch (e) {
      console.error('Error parsing query history:', e);
    }
  });

  // Fallback for default messages
  sseSource.onmessage = (event) => {
    if (isStreamPaused) return;
    try {
      const q = JSON.parse(event.data);
      if (Array.isArray(q)) {
        if (tbody) {
          tbody.innerHTML = '';
          for (let i = q.length - 1; i >= 0; i--) {
            appendQueryRow(tbody, q[i]);
          }
        }
      } else {
        if (tbody) appendQueryRow(tbody, q);
      }
    } catch (e) {}
  };

  sseSource.onerror = (err) => {
    console.warn('SSE stream status update (reconnecting if interrupted)...');
  };
}

function appendQueryRow(tbody, q) {
  if (!q || !tbody) return;

  if (tbody.children.length === 1 && tbody.children[0].innerText.includes('Listening')) {
    tbody.innerHTML = '';
  }

  // Filter check
  const filterEl = document.getElementById('stream-filter');
  const filter = filterEl ? filterEl.value : 'ALL';
  if (filter !== 'ALL') {
    if (filter === 'CACHED' && !q.cached) return;
    if (filter !== 'CACHED' && q.action !== filter) return;
  }

  // Search check
  const searchEl = document.getElementById('stream-search');
  const searchVal = searchEl ? searchEl.value.toLowerCase().trim() : '';
  const domain = q.domain || '';
  const clientIP = q.client_ip || '';
  if (searchVal && !domain.toLowerCase().includes(searchVal) && !clientIP.includes(searchVal)) {
    return;
  }

  const row = document.createElement('tr');
  row.className = 'hover:bg-slate-800/40 transition border-b border-slate-800/40';

  let actBadge = '<span class="badge badge-direct">DIRECT</span>';
  if (q.action === 'PROXY') {
    actBadge = '<span class="badge badge-proxy">PROXY</span>';
  } else if (q.action === 'BLOCK') {
    actBadge = '<span class="badge badge-block">BLOCK</span>';
  } else if (q.action === 'CUSTOM') {
    actBadge = '<span class="badge badge-custom">CUSTOM</span>';
  }

  let cacheBadge = q.cached ? '<span class="badge badge-cached ml-1">RAM</span>' : '';
  const timeStr = q.timestamp ? new Date(q.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
  const latVal = (typeof q.latency_ms === 'number') ? q.latency_ms : ((typeof q.latency === 'number') ? q.latency / 1000000 : 0.0);
  const latStr = latVal.toFixed(1) + ' ms';
  const ruleStr = q.rule_name || q.rule || 'Default Direct';
  const protoStr = q.protocol || 'UDP';

  row.innerHTML = `
    <td class="py-2.5 px-3 text-slate-400">${timeStr}</td>
    <td class="py-2.5 px-3 text-slate-300 font-mono">${clientIP}</td>
    <td class="py-2.5 px-3 text-purple-400 font-bold">${protoStr}</td>
    <td class="py-2.5 px-3 text-cyan-300 font-semibold max-w-xs truncate" title="${domain}">${domain}</td>
    <td class="py-2.5 px-3 text-slate-400">${ruleStr}</td>
    <td class="py-2.5 px-3">${actBadge}${cacheBadge}</td>
    <td class="py-2.5 px-3 text-right text-emerald-400 font-mono">${latStr}</td>
  `;

  tbody.insertBefore(row, tbody.firstChild);

  if (tbody.children.length > 80) {
    tbody.removeChild(tbody.lastChild);
  }
}

// =======================================================
// CHART.JS TELEMETRY GRAPH
// =======================================================
function initChart() {
  try {
    const canvas = document.getElementById('qpsChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (typeof Chart === 'undefined') {
      console.warn('Chart.js not yet available');
      return;
    }
    
    const gradient = ctx.createLinearGradient(0, 0, 0, 220);
    gradient.addColorStop(0, 'rgba(0, 240, 255, 0.45)');
    gradient.addColorStop(1, 'rgba(0, 240, 255, 0.0)');

    const labels = Array.from({ length: 25 }, () => '');
    const data = Array.from({ length: 25 }, () => 0);

    qpsChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'QPS',
          data: data,
          borderColor: '#00f0ff',
          borderWidth: 2,
          backgroundColor: gradient,
          fill: true,
          tension: 0.4,
          pointRadius: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255,255,255,0.05)' },
            ticks: { color: '#64748b', font: { size: 10, family: 'JetBrains Mono' } }
          }
        }
      }
    });
  } catch (e) {
    console.warn('Chart init error:', e);
  }
}

function pushChartData(val) {
  if (!qpsChart) {
    initChart();
    if (!qpsChart) return;
  }
  try {
    const d = qpsChart.data.datasets[0].data;
    d.shift();
    d.push(val);
    qpsChart.update('none');
  } catch (e) {}
}

// =======================================================
// EVENT LISTENERS & UI CONTROLS
// =======================================================
function switchTab(target) {
  document.querySelectorAll('.sidebar-nav-item, .nav-tab').forEach(t => {
    if (t.dataset.tab === target) {
      t.classList.add('active');
    } else {
      t.classList.remove('active');
    }
  });

  document.querySelectorAll('.mobile-nav-item').forEach(t => {
    if (t.dataset.tab === target) {
      t.classList.add('active', 'text-cyan-400');
      t.classList.remove('text-slate-400');
    } else {
      t.classList.remove('active', 'text-cyan-400');
      t.classList.add('text-slate-400');
    }
  });

  document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
  const targetEl = document.getElementById(`tab-${target}`);
  if (targetEl) {
    targetEl.classList.remove('hidden');
    if (target === 'clients') {
      loadClients();
    }
  }
  safeFeatherReplace();
}

function initEventListeners() {
  // Tabs Navigation (Sidebar & Mobile Bottom Bar)
  document.querySelectorAll('.sidebar-nav-item, .nav-tab, .mobile-nav-item').forEach(tab => {
    tab.onclick = (e) => {
      e.preventDefault();
      const target = tab.dataset.tab;
      if (target) switchTab(target);
    };
  });

  // Copy Server IP Sidebar Button
  const copyBtn = document.getElementById('copy-ip-btn');
  if (copyBtn) {
    copyBtn.onclick = () => {
      const ip = document.getElementById('header-public-ip')?.innerText || '127.0.0.1';
      copyText(ip, copyBtn);
    };
  }

  // Restart Core Engine Action
  const triggerRestart = async () => {
    if (!confirm('Are you sure you want to restart the HyperDNS Core Engine and reload all policies?')) return;
    try {
      const res = await fetch('/api/server/restart', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (res.ok) {
        showToast('✓ Core Engine restarted & rules reloaded!', 'success');
        updateStats();
      }
    } catch (e) {
      showToast('Failed to restart engine', 'error');
    }
  };

  const restartBtn = document.getElementById('restart-engine-btn');
  if (restartBtn) restartBtn.onclick = triggerRestart;
  const mobileRestartBtn = document.getElementById('mobile-restart-btn');
  if (mobileRestartBtn) mobileRestartBtn.onclick = triggerRestart;

  // Diagnostics Suite Handlers
  const diagModal = document.getElementById('diagnostics-modal');
  const openDiag = () => {
    if (diagModal) {
      diagModal.classList.remove('hidden');
      runFullDiagnostics();
    }
  };

  const openDiagBtn = document.getElementById('open-diagnostics-btn');
  if (openDiagBtn) openDiagBtn.onclick = openDiag;
  const mobileOpenDiagBtn = document.getElementById('mobile-open-diag');
  if (mobileOpenDiagBtn) mobileOpenDiagBtn.onclick = openDiag;

  const closeDiagBtn = document.getElementById('close-diagnostics-btn');
  if (closeDiagBtn) closeDiagBtn.onclick = () => diagModal?.classList.add('hidden');

  const rerunDiagBtn = document.getElementById('rerun-diagnostics-btn');
  if (rerunDiagBtn) rerunDiagBtn.onclick = () => runFullDiagnostics();

  // Mobile Logout Button
  const mobileLogout = document.getElementById('mobile-logout-btn');
  if (mobileLogout) {
    mobileLogout.onclick = () => {
      localStorage.removeItem('hyperdns_token');
      authToken = '';
      showLoginModal();
    };
  }

  // Add Custom Upstream
  const addUpstreamBtn = document.getElementById('add-upstream-btn');
  if (addUpstreamBtn) {
    addUpstreamBtn.onclick = async () => {
      const input = document.getElementById('new-upstream-input');
      const addr = input ? input.value.trim() : '';
      if (!addr) return;

      try {
        const res = await fetch('/api/upstreams/add', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ address: addr })
        });
        if (res.ok) {
          if (input) input.value = '';
          showToast('✓ Upstream resolver added & tested!', 'success');
          updateStats();
        }
      } catch (e) {
        showToast('Failed to add upstream', 'error');
      }
    };
  }

  // Regenerate Master API Key
  const regenKeyBtn = document.getElementById('regen-api-key-btn');
  if (regenKeyBtn) {
    regenKeyBtn.onclick = async () => {
      if (!confirm('Are you sure you want to regenerate your API Key? All connected Telegram bots and billing integrations will need to be updated with the new key.')) return;
      try {
        const res = await fetch('/api/v1/api-key', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (data.success && data.data && data.data.api_key) {
          const disp = document.getElementById('api-key-display');
          if (disp) disp.innerText = data.data.api_key;
          showToast('✓ Master API Key regenerated successfully!', 'success');
        }
      } catch (e) {
        showToast('Failed to regenerate API Key', 'error');
      }
    };
  }

  // Issue SSL Certificate
  const issueSslBtn = document.getElementById('issue-ssl-btn');
  if (issueSslBtn) {
    issueSslBtn.onclick = async () => {
      const dom = document.getElementById('ssl-domain-input')?.value.trim();
      const email = document.getElementById('ssl-email-input')?.value.trim();
      if (!dom) {
        showToast('Please enter a domain name', 'error');
        return;
      }

      showToast('Requesting Let\'s Encrypt SSL certificate...', 'info');
      try {
        const res = await fetch('/api/tls/issue', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ domain: dom, email: email })
        });
        if (res.ok) {
          showToast('✓ SSL issuance triggered in background!', 'success');
        }
      } catch (e) {
        showToast('Failed to trigger SSL issuance', 'error');
      }
    };
  }

  // Quick Action Profiles
  document.getElementById('profile-gaming-btn')?.addEventListener('click', () => {
    ['preset-riot', 'preset-epic', 'preset-steam', 'preset-pubg', 'preset-cod', 'preset-supercell',
     'preset-ea', 'preset-blizzard', 'preset-ubisoft', 'preset-rockstar', 'preset-xbox', 'preset-playstation', 'preset-roblox'].forEach(id => {
      setSwitch(id, true);
    });
    saveRules();
    showToast('🎯 Pro Gamer Profile Activated!', 'success');
  });

  document.getElementById('profile-streamer-btn')?.addEventListener('click', () => {
    ['preset-discord', 'preset-twitch', 'preset-kick', 'preset-spotify'].forEach(id => {
      setSwitch(id, true);
    });
    saveRules();
    showToast('🎬 Streamer & Media Profile Activated!', 'success');
  });

  document.getElementById('profile-dev-btn')?.addEventListener('click', () => {
    setSwitch('preset-dev403', true);
    saveRules();
    showToast('💻 Developer 403 Profile Activated!', 'success');
  });

  document.getElementById('profile-privacy-btn')?.addEventListener('click', () => {
    setSwitch('preset-adblock', true);
    setSwitch('preset-familysafe', true);
    saveRules();
    showToast('🛡️ AdBlock & Safe Profile Activated!', 'success');
  });

  // Preset switches
  const switches = [
    'preset-riot', 'preset-epic', 'preset-steam', 'preset-pubg', 'preset-cod', 'preset-supercell',
    'preset-discord', 'preset-ea', 'preset-blizzard', 'preset-ubisoft', 'preset-rockstar', 
    'preset-xbox', 'preset-playstation', 'preset-roblox', 'preset-spotify',
    'preset-twitch', 'preset-kick', 
    'preset-dev403', 'preset-adblock', 'preset-familysafe'
  ];
  switches.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.onchange = () => saveRules();
    }
  });

  // Flush Cache
  const flushBtn = document.getElementById('flush-cache-btn');
  if (flushBtn) {
    flushBtn.onclick = async () => {
      try {
        await fetch('/api/cache/flush', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        showToast('DNS cache flushed successfully!', 'success');
        updateStats();
      } catch (e) {
        showToast('Failed to flush cache', 'error');
      }
    };
  }

  // Run Benchmark
  const benchBtn = document.getElementById('run-benchmark-btn');
  if (benchBtn) {
    benchBtn.onclick = async () => {
      showToast('Running benchmark across upstreams...', 'info');
      try {
        await fetch('/api/benchmark', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        setTimeout(updateStats, 1000);
        showToast('Benchmark completed!', 'success');
      } catch (e) {}
    };
  }

  // Add Custom Proxied
  document.getElementById('add-proxied-btn')?.addEventListener('click', () => {
    const input = document.getElementById('new-proxied-input');
    const val = input ? input.value.trim().toLowerCase() : '';
    if (!val || !currentConfig) return;
    if (!currentConfig.rules.custom_proxied.includes(val)) {
      currentConfig.rules.custom_proxied.push(val);
      if (input) input.value = '';
      saveRules();
      renderConfig(currentConfig);
    }
  });

  // Add Custom Blocked
  document.getElementById('add-blocked-btn')?.addEventListener('click', () => {
    const input = document.getElementById('new-blocked-input');
    const val = input ? input.value.trim().toLowerCase() : '';
    if (!val || !currentConfig) return;
    if (!currentConfig.rules.custom_blocked.includes(val)) {
      currentConfig.rules.custom_blocked.push(val);
      if (input) input.value = '';
      saveRules();
      renderConfig(currentConfig);
    }
  });

  // Add DoH Token
  document.getElementById('add-token-btn')?.addEventListener('click', async () => {
    const input = document.getElementById('new-token-input');
    const val = input ? input.value.trim() : '';
    if (!val || !currentConfig) return;
    if (!currentConfig.access.doh_tokens.includes(val)) {
      currentConfig.access.doh_tokens.push(val);
      if (input) input.value = '';
      await fetch('/api/config/access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify(currentConfig.access)
      });
      showToast('DoH Token added!', 'success');
      renderConfig(currentConfig);
    }
  });

  // Add Custom Record
  document.getElementById('add-custom-record-btn')?.addEventListener('click', () => {
    const dInput = document.getElementById('custom-record-domain');
    const ipInput = document.getElementById('custom-record-ip');
    const dom = dInput ? dInput.value.trim().toLowerCase() : '';
    const ip = ipInput ? ipInput.value.trim() : '';
    if (!dom || !ip || !currentConfig) return;
    if (!currentConfig.rules.custom_records) currentConfig.rules.custom_records = {};
    currentConfig.rules.custom_records[dom] = ip;
    if (dInput) dInput.value = '';
    if (ipInput) ipInput.value = '';
    saveRules();
    renderConfig(currentConfig);
  });

  // Event Delegation for List Removals
  document.onclick = async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;

    if (btn.classList.contains('remove-upstream')) {
      const addr = btn.dataset.addr;
      try {
        await fetch('/api/upstreams/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ address: addr })
        });
        showToast('Upstream removed', 'info');
        updateStats();
      } catch (err) {}
    } else if (btn.classList.contains('remove-proxied')) {
      const val = btn.dataset.val;
      if (currentConfig) {
        currentConfig.rules.custom_proxied = currentConfig.rules.custom_proxied.filter(x => x !== val);
        saveRules();
        renderConfig(currentConfig);
      }
    } else if (btn.classList.contains('remove-blocked')) {
      const val = btn.dataset.val;
      if (currentConfig) {
        currentConfig.rules.custom_blocked = currentConfig.rules.custom_blocked.filter(x => x !== val);
        saveRules();
        renderConfig(currentConfig);
      }
    } else if (btn.classList.contains('remove-token')) {
      const val = btn.dataset.val;
      if (currentConfig) {
        currentConfig.access.doh_tokens = currentConfig.access.doh_tokens.filter(x => x !== val);
        await fetch('/api/config/access', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify(currentConfig.access)
        });
        showToast('DoH Token removed', 'info');
        renderConfig(currentConfig);
      }
    } else if (btn.classList.contains('remove-record')) {
      const dom = btn.dataset.dom;
      if (currentConfig && currentConfig.rules.custom_records) {
        delete currentConfig.rules.custom_records[dom];
        saveRules();
        renderConfig(currentConfig);
      }
    }
  };

  // Live Stream Controls
  const pauseBtn = document.getElementById('stream-pause-btn');
  if (pauseBtn) {
    pauseBtn.onclick = (e) => {
      isStreamPaused = !isStreamPaused;
      const btn = e.currentTarget;
      btn.innerHTML = isStreamPaused 
        ? '<i data-feather="play" class="w-3.5 h-3.5"></i> <span>Resume</span>' 
        : '<i data-feather="pause" class="w-3.5 h-3.5"></i> <span>Pause</span>';
      safeFeatherReplace();
    };
  }

  const clearBtn = document.getElementById('stream-clear-btn');
  if (clearBtn) {
    clearBtn.onclick = () => {
      const tbody = document.getElementById('stream-tbody');
      if (tbody) tbody.innerHTML = '';
    };
  }
}

// =======================================================
// RUN FULL DIAGNOSTICS
// =======================================================
async function runFullDiagnostics() {
  const container = document.getElementById('diag-items-list');
  if (container) {
    container.innerHTML = '<div class="text-center py-8 text-cyan-400 font-mono text-xs"><span class="pulse-dot inline-block mr-2"></span> Testing VPS connectivity to Riot, Epic, Steam, Discord, PUBG, CoD, EA...</div>';
  }

  try {
    const res = await fetch('/api/diagnostics/run', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (!res.ok) return;

    const report = await res.json();
    const scoreEl = document.getElementById('diag-score');
    if (scoreEl) scoreEl.innerText = `${report.overall_score}%`;
    const qualEl = document.getElementById('diag-quality');
    if (qualEl) qualEl.innerText = report.overall_quality;

    if (container) {
      container.innerHTML = '';
      report.results.forEach(r => {
        const row = document.createElement('div');
        row.className = 'flex items-center justify-between py-2 px-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs';
        
        const badge = r.success 
          ? `<span class="text-emerald-400 font-bold font-mono">${r.latency_ms.toFixed(1)} ms</span>` 
          : `<span class="text-red-400 font-bold font-mono">BLOCKED</span>`;

        row.innerHTML = `
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full ${r.success ? 'bg-emerald-400' : 'bg-red-400'}"></span>
            <div>
              <span class="font-bold text-white">${r.name}</span>
              <span class="text-[10px] text-slate-500 font-mono ml-1.5">(${r.target})</span>
            </div>
          </div>
          <div>${badge}</div>
        `;
        container.appendChild(row);
      });
    }
  } catch (e) {
    if (container) {
      container.innerHTML = '<div class="text-center py-6 text-red-400 text-xs">Failed to run diagnostic test suite.</div>';
    }
  }
}

// =======================================================
// CLIENTS & IP WHITELIST MANAGEMENT (Shelter/Shecan Style)
// =======================================================
let clientsDataCache = null;

async function loadClients() {
  if (!authToken) return;
  try {
    const res = await fetch('/api/clients', {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (!res.ok) return;

    clientsDataCache = await res.json();
    renderClientsView(clientsDataCache);
  } catch (e) {
    console.error('Failed to load clients:', e);
  }
}

function renderClientsView(data) {
  if (!data) return;

  // Access Control Mode Switch & Badges
  const modeSwitch = document.getElementById('access-mode-switch');
  const modeBadge = document.getElementById('access-mode-badge');
  const modeText = document.getElementById('access-mode-status-text');

  const isWhitelistEnforced = !data.allow_all;
  if (modeSwitch) modeSwitch.checked = isWhitelistEnforced;

  if (isWhitelistEnforced) {
    if (modeBadge) {
      modeBadge.className = 'badge badge-proxy';
      modeBadge.innerText = '🔒 WHITELIST ENFORCED';
    }
    if (modeText) {
      modeText.innerText = 'Whitelist Mode (Only Registered Clients)';
      modeText.className = 'text-xs font-mono text-cyan-400 font-bold';
    }
  } else {
    if (modeBadge) {
      modeBadge.className = 'badge badge-direct';
      modeBadge.innerText = '🔓 PUBLIC ACCESS';
    }
    if (modeText) {
      modeText.innerText = 'Public Mode (Anyone can connect)';
      modeText.className = 'text-xs font-mono text-slate-400 font-semibold';
    }
  }

  // Filter clients by search
  const searchInput = document.getElementById('client-search-input');
  const searchVal = searchInput ? searchInput.value.toLowerCase().trim() : '';

  let clients = data.clients || [];
  if (searchVal) {
    clients = clients.filter(c => 
      c.name.toLowerCase().includes(searchVal) || 
      c.id.includes(searchVal) || 
      c.allowed_ips.some(ip => ip.includes(searchVal))
    );
  }

  const listContainer = document.getElementById('clients-list');
  if (!listContainer) return;
  listContainer.innerHTML = '';

  if (clients.length === 0) {
    listContainer.innerHTML = `
      <div class="col-span-1 md:col-span-2 glass-panel p-8 text-center text-slate-400 border border-slate-800">
        <i data-feather="users" class="w-8 h-8 mx-auto text-slate-600 mb-2"></i>
        <div class="font-bold text-slate-300 font-heading">No Clients Found</div>
        <p class="text-xs text-slate-500 mt-1">Click "Add New Client" above to create client accounts & registration links.</p>
      </div>
    `;
    safeFeatherReplace();
    return;
  }

  // Dynamic origin detection based on what admin used to open the dashboard (domain or IP)!
  const currentOrigin = window.location.origin;
  const dnsPrimaryIP = data.public_ip || window.location.hostname;

  clients.forEach(c => {
    const isExpired = c.expires_at && c.expires_at !== '0001-01-01T00:00:00Z' && new Date(c.expires_at) < new Date();
    
    let statusBadge = '<span class="badge badge-direct">ACTIVE</span>';
    if (!c.enabled) {
      statusBadge = '<span class="badge badge-block">DISABLED</span>';
    } else if (isExpired) {
      statusBadge = '<span class="badge badge-block">EXPIRED</span>';
    }

    let expText = 'Lifetime (No Expiry)';
    let remainingText = '';
    if (c.expires_at && c.expires_at !== '0001-01-01T00:00:00Z') {
      const expDate = new Date(c.expires_at);
      expText = expDate.toLocaleDateString() + ' ' + expDate.toLocaleTimeString();
      const diffMs = expDate - new Date();
      if (diffMs > 0) {
        const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        remainingText = `(${days}d ${hours}h remaining)`;
      } else {
        remainingText = '(Expired)';
      }
    }

    const regUrl = `${currentOrigin}/ip/${c.token}`;

    // Whitelisted IPs HTML tags
    let ipsHtml = '';
    if (c.allowed_ips && c.allowed_ips.length > 0) {
      ipsHtml = c.allowed_ips.map(ip => `
        <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-950 border border-cyan-500/30 text-[11px] font-mono text-cyan-300">
          <span>${ip}</span>
          <button class="remove-client-ip-btn hover:text-red-400 ml-1" data-id="${c.id}" data-ip="${ip}" title="Remove IP">×</button>
        </span>
      `).join('');
    } else {
      ipsHtml = '<span class="text-slate-500 text-[11px] italic">No IPs registered yet (Share link below)</span>';
    }

    const card = document.createElement('div');
    card.className = 'glass-panel p-4 sm:p-5 flex flex-col justify-between space-y-4 border border-slate-800 hover:border-cyan-500/40 transition';
    card.innerHTML = `
      <div>
        <!-- Card Header -->
        <div class="flex items-start justify-between gap-2 mb-2 pb-2 border-b border-slate-800/80">
          <div>
            <div class="flex items-center gap-2">
              <h4 class="text-sm font-bold text-white font-heading">${c.name}</h4>
              ${statusBadge}
            </div>
            <div class="text-[10px] text-slate-400 font-mono mt-0.5">
              Code: <span class="text-amber-300 font-bold">${c.id}</span> · Slug: <span class="text-slate-500">${c.token}</span>
            </div>
          </div>

          <div class="flex items-center gap-1">
            <button class="toggle-client-btn p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-cyan-400 border border-slate-800 transition" data-id="${c.id}" data-enabled="${!c.enabled}" title="${c.enabled ? 'Disable Client' : 'Enable Client'}">
              <i data-feather="${c.enabled ? 'pause' : 'play'}" class="w-3.5 h-3.5"></i>
            </button>
            <button class="delete-client-btn p-1.5 rounded-lg bg-slate-900 hover:bg-red-500/20 text-slate-400 hover:text-red-400 border border-slate-800 transition" data-id="${c.id}" data-name="${c.name}" title="Delete Client">
              <i data-feather="trash-2" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </div>

        <!-- Whitelisted IPs Row -->
        <div class="space-y-1.5 mb-3">
          <div class="flex items-center justify-between text-[11px]">
            <span class="text-slate-400 font-semibold">Registered IP (Max 1):</span>
            <button class="add-ip-prompt-btn text-cyan-400 hover:text-cyan-300 text-[10px] font-mono flex items-center gap-0.5" data-id="${c.id}">
              + Set IP Manually
            </button>
          </div>
          <div class="flex flex-wrap gap-1.5">
            ${ipsHtml}
          </div>
        </div>

        <!-- Expiration & Metrics -->
        <div class="grid grid-cols-2 gap-2 text-[10px] font-mono bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
          <div>
            <span class="text-slate-500 uppercase">Plan Expiry</span>
            <div class="text-slate-200 font-bold truncate" title="${expText}">${expText}</div>
            <div class="text-emerald-400 text-[9px]">${remainingText}</div>
          </div>
          <div>
            <span class="text-slate-500 uppercase">Queries Served</span>
            <div class="text-cyan-300 font-bold">${c.total_queries.toLocaleString()}</div>
            <div class="text-slate-500 text-[9px]">Last seen: ${c.last_seen ? new Date(c.last_seen).toLocaleTimeString() : 'Never'}</div>
          </div>
        </div>
      </div>

      <!-- Quick Action Buttons -->
      <div class="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-xs">
        <button class="copy-reg-link-btn py-1.5 px-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[11px] font-bold font-heading flex items-center justify-center gap-1 transition truncate" data-url="${regUrl}">
          <i data-feather="link" class="w-3 h-3 flex-shrink-0"></i>
          <span>Reg Link</span>
        </button>

        <button class="copy-telegram-card-btn py-1.5 px-2 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[11px] font-bold font-heading flex items-center justify-center gap-1 transition truncate" 
          data-id="${c.id}" data-name="${c.name}" data-exp="${expText}" data-url="${regUrl}" data-ip="${dnsPrimaryIP}">
          <i data-feather="send" class="w-3 h-3 flex-shrink-0"></i>
          <span>Bot Card</span>
        </button>

        <button class="renew-client-btn py-1.5 px-2 rounded-lg bg-slate-900 hover:bg-emerald-500/20 text-slate-300 hover:text-emerald-400 border border-slate-800 text-[11px] font-bold font-heading flex items-center justify-center gap-1 transition truncate" data-id="${c.id}">
          <i data-feather="clock" class="w-3 h-3 flex-shrink-0"></i>
          <span>+30 Days</span>
        </button>
      </div>
    `;

    listContainer.appendChild(card);
  });

  safeFeatherReplace();
}

// Generate Shelter/Shecan formatted Telegram card text (matching user's screenshot!)
function generateClientTelegramMessage(clientId, clientName, expStr, regUrl, dnsIP) {
  return `🔹 تاریخ انقضاء پلن : ${expStr}
دی ان اس اختصاصی شما : 

🔹 Primary : ${dnsIP}
🔹 Secondary : 1.1.1.1

مراحل ثبت آیپی : 
1️⃣ : در ابتدا گوشی موبایل و کنسول بازی رو به یک اینترنت مشترک وصل کنید .
2️⃣ : بدون فیلتر شکن روی دکمه ثبت آیپی زیر کلیک کنید.
❌ در صورت عدم ثبت آیپی DNS ها برای شما متصل نخواهد شد ❌

کد کاربری شما : ${clientId}
🔗 لینک ثبت آیپی اتوماتیک:
${regUrl}`;
}

// Attach Client View Event Listeners
function initClientEventListeners() {
  // Add Client Modal handlers
  const addModal = document.getElementById('add-client-modal');
  const openBtn = document.getElementById('open-add-client-btn');
  if (openBtn) {
    openBtn.onclick = () => addModal?.classList.remove('hidden');
  }
  const closeBtn = document.getElementById('close-add-client-btn');
  if (closeBtn) {
    closeBtn.onclick = () => addModal?.classList.add('hidden');
  }

  // Add Client Form Submit (Direct onsubmit handler with button debounce)
  const addForm = document.getElementById('add-client-form');
  if (addForm) {
    addForm.onsubmit = async (e) => {
      e.preventDefault();
      const submitBtn = addForm.querySelector('button[type="submit"]');
      if (submitBtn && submitBtn.disabled) return;
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.classList.add('opacity-50');
      }

      const name = document.getElementById('client-name-input')?.value.trim();
      const expDays = parseInt(document.getElementById('client-expires-select')?.value || '30', 10);
      const initIP = document.getElementById('client-initial-ip')?.value.trim();

      try {
        const res = await fetch('/api/clients/add', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ name: name, expires_days: expDays, initial_ip: initIP })
        });

        if (res.ok) {
          addModal?.classList.add('hidden');
          const nameInput = document.getElementById('client-name-input');
          if (nameInput) nameInput.value = '';
          const ipInput = document.getElementById('client-initial-ip');
          if (ipInput) ipInput.value = '';
          showToast('✓ Client account created!', 'success');
          await loadClients();
        } else {
          showToast('Failed to create client', 'error');
        }
      } catch (e) {
        showToast('Network error creating client', 'error');
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.classList.remove('opacity-50');
        }
      }
    };
  }

  // Access Mode Switch (Public vs Whitelist)
  document.getElementById('access-mode-switch')?.addEventListener('change', async (e) => {
    const isEnforced = e.target.checked;
    const allowAll = !isEnforced;

    try {
      const res = await fetch('/api/access/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify({ allow_all: allowAll })
      });

      if (res.ok) {
        showToast(isEnforced ? '🔒 Whitelist mode enforced (Only registered clients)' : '🔓 Open public mode activated', 'info');
        loadClients();
      }
    } catch (e) {
      showToast('Failed to update access mode', 'error');
    }
  });

  // Search input live filter
  document.getElementById('client-search-input')?.addEventListener('input', () => {
    if (clientsDataCache) renderClientsView(clientsDataCache);
  });

  // Event Delegation for Client Action Buttons
  document.addEventListener('click', async (e) => {
    // 1. Copy Registration Link
    const regBtn = e.target.closest('.copy-reg-link-btn');
    if (regBtn) {
      const url = regBtn.dataset.url;
      copyText(url, regBtn);
      return;
    }

    // 2. Copy Telegram Bot Card
    const cardBtn = e.target.closest('.copy-telegram-card-btn');
    if (cardBtn) {
      const id = cardBtn.dataset.id;
      const name = cardBtn.dataset.name;
      const exp = cardBtn.dataset.exp;
      const url = cardBtn.dataset.url;
      const ip = cardBtn.dataset.ip;
      const msg = generateClientTelegramMessage(id, name, exp, url, ip);
      copyText(msg, cardBtn);
      showToast('📋 Persian client card copied for Telegram!', 'success');
      return;
    }

    // 3. Renew Client (+30 Days)
    const renewBtn = e.target.closest('.renew-client-btn');
    if (renewBtn) {
      const id = renewBtn.dataset.id;
      try {
        const res = await fetch('/api/clients/renew', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ id: id, extend_days: 30 })
        });
        if (res.ok) {
          showToast('✓ Client plan extended by 30 days!', 'success');
          loadClients();
        }
      } catch (err) {}
      return;
    }

    // 4. Toggle Client
    const toggleBtn = e.target.closest('.toggle-client-btn');
    if (toggleBtn) {
      const id = toggleBtn.dataset.id;
      const enabled = toggleBtn.dataset.enabled === 'true';
      try {
        await fetch('/api/clients/toggle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ id: id, enabled: enabled })
        });
        showToast(`Client ${enabled ? 'enabled' : 'disabled'}`, 'info');
        loadClients();
      } catch (err) {}
      return;
    }

    // 5. Delete Client
    const delBtn = e.target.closest('.delete-client-btn');
    if (delBtn) {
      const id = delBtn.dataset.id;
      const name = delBtn.dataset.name;
      if (!confirm(`Are you sure you want to delete client "${name}" (${id})?`)) return;
      try {
        await fetch('/api/clients/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ id: id })
        });
        showToast('Client deleted', 'info');
        loadClients();
      } catch (err) {}
      return;
    }

    // 6. Add IP Manually (Prompt)
    const addIpBtn = e.target.closest('.add-ip-prompt-btn');
    if (addIpBtn) {
      const id = addIpBtn.dataset.id;
      const ip = prompt('Enter IPv4 address to whitelist for this client (e.g. 2.189.86.32):');
      if (ip && ip.trim()) {
        try {
          await fetch('/api/clients/add_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
            body: JSON.stringify({ id: id, ip: ip.trim() })
          });
          showToast('✓ IP added to client whitelist!', 'success');
          loadClients();
        } catch (err) {}
      }
      return;
    }

    // 7. Remove Whitelisted IP
    const remIpBtn = e.target.closest('.remove-client-ip-btn');
    if (remIpBtn) {
      const id = remIpBtn.dataset.id;
      const ip = remIpBtn.dataset.ip;
      try {
        await fetch('/api/clients/remove_ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ id: id, ip: ip })
        });
        showToast('IP removed from client', 'info');
        loadClients();
      } catch (err) {}
      return;
    }
  });
}

// =======================================================
// BULLETPROOF COPY & TOAST NOTIFICATIONS
// =======================================================
function fallbackCopy(text) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.top = '0';
  textArea.style.left = '0';
  textArea.style.width = '2em';
  textArea.style.height = '2em';
  textArea.style.padding = '0';
  textArea.style.border = 'none';
  textArea.style.outline = 'none';
  textArea.style.boxShadow = 'none';
  textArea.style.background = 'transparent';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
  } catch (err) {}
  document.body.removeChild(textArea);
}

function copyText(text, btnElement) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text)
      .then(() => {
        showToast(`Copied!`, 'success');
      })
      .catch(() => {
        fallbackCopy(text);
        showToast(`Copied!`, 'success');
      });
  } else {
    fallbackCopy(text);
    showToast(`Copied!`, 'success');
  }

  if (btnElement) {
    btnElement.classList.add('ring-2', 'ring-cyan-400');
    setTimeout(() => {
      btnElement.classList.remove('ring-2', 'ring-cyan-400');
    }, 800);
  }
}

function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'glass-panel px-4 py-2.5 rounded-xl border flex items-center gap-2.5 shadow-2xl text-xs font-semibold text-white pointer-events-auto transition-all duration-300 transform translate-y-2 opacity-0';
  
  if (type === 'success') {
    toast.classList.add('border-emerald-500/50', 'bg-slate-950/90');
    toast.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span><span>${msg}</span>`;
  } else if (type === 'error') {
    toast.classList.add('border-red-500/50', 'bg-slate-950/90');
    toast.innerHTML = `<span class="w-2 h-2 rounded-full bg-red-400"></span><span>${msg}</span>`;
  } else {
    toast.classList.add('border-cyan-500/50', 'bg-slate-950/90');
    toast.innerHTML = `<span class="w-2 h-2 rounded-full bg-cyan-400"></span><span>${msg}</span>`;
  }

  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => {
      if (toast.parentElement) toast.parentElement.removeChild(toast);
    }, 300);
  }, 2500);
}
