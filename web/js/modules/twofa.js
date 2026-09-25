// Two-factor authentication panel (v2.1) — extracted from app.js as the first
// ES module of the dashboard (rework Phase 4). Loaded with
// <script type="module"> after app.js, which stays classic so its pre-paint
// dependencies keep working. The module reads the shared state it needs off
// window (authToken/currentConfig/api/DASH_BASE) rather than importing it,
// because app.js's classic globals are the one seam a no-build setup has;
// strict mode comes free, and the browser defers execution until the
// document is parsed.

(() => {
  // Shared state, read live from the app.js globals at call time (a captured
  // copy would go stale across a re-login).
  // Shared state lives in app.js (classic globals); this bridge reads it live
  // so a re-login or a config refresh is never observed stale.
  const S = () => window.__hdns;
  const authToken = () => S().getToken();
  const setAuthToken = (v) => S().setToken(v);
  const currentConfig = () => S().getConfig();
  const DASH_BASE = () => S().DASH_BASE || '';
  const api = (p) => S().api(p);
  const showToast = (m, t) => S().showToast(m, t);
  const errorMessage = (r, f) => S().errorMessage(r, f);

// =======================================================
// v2.1 TWO-FACTOR AUTHENTICATION (settings tab)
// =======================================================

function initTwoFactorControls() {
  const statusEl = document.getElementById('twofa-status');
  const offBox = document.getElementById('twofa-off-box');
  const onBox = document.getElementById('twofa-on-box');
  const enrollBox = document.getElementById('twofa-enroll-box');
  const secretEl = document.getElementById('twofa-secret-display');
  const uriEl = document.getElementById('twofa-uri-display');
  const beginBtn = document.getElementById('twofa-begin-btn');
  const confirmBtn = document.getElementById('twofa-confirm-btn');
  const disableBtn = document.getElementById('twofa-disable-btn');
  const enablePassword = document.getElementById('twofa-enable-password');
  const enableCode = document.getElementById('twofa-enable-code');
  const disablePassword = document.getElementById('twofa-disable-password');
  const disableCode = document.getElementById('twofa-disable-code');

  // Renders the snapshot /api/auth/2fa/status returns. The enrollment box
  // only appears while an enrollment is open — the server shows the secret
  // for exactly that window and never again.
  window.renderTwoFactor = function () {
    fetch(api('/api/auth/2fa/status'), {
      headers: { 'Authorization': `Bearer ${authToken()}` }
    }).then(async res => {
      if (!res.ok) return;
      const s = await res.json();
      const enabled = !!s.totp_enabled;
      const enrolling = !!s.totp_enrolling;
      if (statusEl) {
        statusEl.textContent = enabled ? 'ENABLED' : (enrolling ? 'ENROLLMENT OPEN' : 'OFF');
        statusEl.className = 'font-mono ' + (enabled ? 'text-emerald-400' : (enrolling ? 'text-amber-400' : 'text-slate-300'));
      }
      if (offBox) offBox.classList.toggle('hidden', enabled);
      if (onBox) onBox.classList.toggle('hidden', !enabled);
      if (enrollBox) {
        enrollBox.classList.toggle('hidden', !(enrolling && !enabled));
        // The enrollment URI is rendered only from the setup response, which
        // is password-gated. The status endpoint deliberately answers with a
        // bare "present" marker instead of the URI — the URI embeds the
        // shared secret, and status is readable with any live session.
      }
    }).catch(() => {});
  };

  if (beginBtn) {
    beginBtn.addEventListener('click', async () => {
      if (!enablePassword || !enablePassword.value) {
        showToast('Enter your current password to start enrollment.', 'error');
        return;
      }
      beginBtn.disabled = true;
      try {
        const res = await fetch(api('/api/auth/2fa/setup'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken()}` },
          body: JSON.stringify({ username: currentConfig()?.server?.admin_username || 'admin', current_password: enablePassword.value })
        });
        if (!res.ok) {
          showToast(await errorMessage(res, 'Could not start the enrollment'), 'error');
          return;
        }
        const data = await res.json();
        if (secretEl) secretEl.textContent = data.secret || '';
        if (uriEl) uriEl.textContent = data.otpauth_uri || '';
        if (enrollBox) enrollBox.classList.remove('hidden');
        enablePassword.value = '';
        window.renderTwoFactor();
      } catch (err) {
        showToast('Could not reach the server.', 'error');
      } finally {
        beginBtn.disabled = false;
      }
    });
  }

  if (confirmBtn) {
    confirmBtn.addEventListener('click', async () => {
      if (!enableCode) return;
      // The enrollment POST re-asks the password: the setup step did not
      // create a trust window, the code alone proves nothing. The field lives
      // in this box because the begin step's password field is cleared the
      // moment the secret is shown — an operator pointed only at the code was
      // left sending an empty password, and "Invalid credentials" reads as a
      // wrong code.
      const confirmPwd = document.getElementById('twofa-confirm-password');
      if (!confirmPwd || !confirmPwd.value) {
        showToast('Enter your current password again to confirm enrollment.', 'error');
        if (confirmPwd) confirmPwd.focus();
        return;
      }
      confirmBtn.disabled = true;
      try {
        const res = await fetch(api('/api/auth/2fa/enable'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken()}` },
          body: JSON.stringify({ username: currentConfig()?.server?.admin_username || 'admin', current_password: confirmPwd.value, code: (enableCode.value || '').trim() })
        });
        if (!res.ok) {
          showToast(await errorMessage(res, 'Confirmation refused — check the password and code'), 'error');
          return;
        }
        showToast('Two-factor enabled. Please sign in again.', 'success');
        localStorage.removeItem('hyperdns_token');
        setAuthToken('');
        window.location.reload();
      } catch (err) {
        showToast('Could not reach the server.', 'error');
      } finally {
        confirmBtn.disabled = false;
        if (confirmPwd) confirmPwd.value = '';
      }
    });
  }

  if (disableBtn) {
    disableBtn.addEventListener('click', async () => {
      if (!disablePassword || !disableCode) return;
      if (!disablePassword.value || !(disableCode.value || '').trim()) {
        showToast('Both the current password and a current code are required to disable 2FA.', 'error');
        return;
      }
      disableBtn.disabled = true;
      try {
        const res = await fetch(api('/api/auth/2fa/disable'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken()}` },
          body: JSON.stringify({ username: currentConfig()?.server?.admin_username || 'admin', current_password: disablePassword.value, code: (disableCode.value || '').trim() })
        });
        if (!res.ok) {
          showToast(await errorMessage(res, 'Disable refused — check both fields'), 'error');
          return;
        }
        showToast('Two-factor disabled. Please sign in again.', 'success');
        localStorage.removeItem('hyperdns_token');
        setAuthToken('');
        window.location.reload();
      } catch (err) {
        showToast('Could not reach the server.', 'error');
      } finally {
        disableBtn.disabled = false;
      }
    });
  }
}

// =======================================================
// v2.1 LDAP DIRECTORY LOGIN (settings tab)
// =======================================================

function initLdapControls() {
  const enabled = document.getElementById('ldap-enabled-input');
  const mode = document.getElementById('ldap-mode-input');
  const urlInput = document.getElementById('ldap-url-input');
  const userAttr = document.getElementById('ldap-userattr-input');
  const bindDN = document.getElementById('ldap-binddn-input');
  const bindPW = document.getElementById('ldap-bindpw-input');
  const baseDN = document.getElementById('ldap-basedn-input');
  const saveBtn = document.getElementById('ldap-save-btn');
  const statusEl = document.getElementById('ldap-save-status');

  window.renderLdap = function () {
    fetch(api('/api/auth/ldap'), {
      headers: { 'Authorization': `Bearer ${authToken()}` }
    }).then(async res => {
      if (!res.ok) return;
      const s = await res.json();
      if (enabled) enabled.checked = !!s.ldap_enabled;
      if (mode) mode.value = s.ldap_login_mode || 'local';
      if (urlInput) urlInput.value = s.ldap_server_url || '';
      if (userAttr) userAttr.value = s.ldap_user_attr || '';
      if (bindDN) bindDN.value = s.ldap_bind_dn || '';
      if (baseDN) baseDN.value = s.ldap_base_dn || '';
      if (bindPW) bindPW.value = '';
    }).catch(() => {});
  };

  if (!saveBtn) return;
  saveBtn.addEventListener('click', async () => {
    if (!enabled || !mode) return;
    if (enabled.checked && (urlInput ? urlInput.value.trim() : '') && !/^ldaps?:\/\//.test(urlInput.value.trim())) {
      showToast('The server URL must start with ldap:// or ldaps://', 'error');
      return;
    }
    const ldapPassword = document.getElementById('ldap-admin-password');
    const ldapCode = document.getElementById('ldap-totp-code');
    if (!ldapPassword || !ldapPassword.value) {
      showToast('Enter your current password to save the directory settings.', 'error');
      return;
    }
    saveBtn.disabled = true;
    if (statusEl) statusEl.textContent = 'Saving…';
    try {
      const res = await fetch(api('/api/auth/ldap'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken()}` },
        body: JSON.stringify({
          enabled: enabled.checked ? 'true' : 'false',
          current_password: ldapPassword.value,
          code: (ldapCode ? ldapCode.value : '').trim(),
          ldap_server_url: urlInput ? urlInput.value.trim() : '',
          ldap_bind_dn: bindDN ? bindDN.value.trim() : '',
          // Empty means "keep the stored one" — the bind password never
          // round-trips through the browser.
          ldap_bind_password: bindPW ? bindPW.value : '',
          ldap_base_dn: baseDN ? baseDN.value.trim() : '',
          ldap_user_attr: userAttr ? userAttr.value.trim() : '',
          ldap_login_mode: mode.value
        })
      });
      if (!res.ok) {
        if (statusEl) statusEl.textContent = '';
        showToast(await errorMessage(res, 'The server refused the LDAP settings'), 'error');
        return;
      }
      if (statusEl) statusEl.textContent = 'Saved.';
      showToast('LDAP settings saved — sign in again.', 'success');
      localStorage.removeItem('hyperdns_token');
      setAuthToken('');
      window.location.reload();
    } catch (err) {
      if (statusEl) statusEl.textContent = '';
      showToast('Could not reach the server.', 'error');
    } finally {
      saveBtn.disabled = false;
    }
  });
}

// =======================================================
// v2.1 SUBSCRIPTION SETTINGS (settings tab, third group)
// =======================================================

function initSubscriptionSettings() {
  const enabled = document.getElementById('sub-enabled-input');
  const domain = document.getElementById('sub-domain-input');
  const port = document.getElementById('sub-port-input');
  const title = document.getElementById('sub-title-input');
  const cssSource = document.getElementById('sub-css-source');
  const cssInline = document.getElementById('sub-css-inline');
  const cssPath = document.getElementById('sub-css-path');
  const cssUrl = document.getElementById('sub-css-url');
  const saveBtn = document.getElementById('save-subscription-btn');
  const statusEl = document.getElementById('sub-save-status');
  const originPreview = document.getElementById('sub-origin-preview');
  const leBtn = document.getElementById('sub-issue-ssl-btn');

  // Show only the input that matches the selected CSS source.
  function syncCSSSourceFields() {
    if (!cssSource) return;
    const v = cssSource.value;
    if (cssInline) cssInline.classList.toggle('hidden', v !== 'inline');
    if (cssPath) cssPath.classList.toggle('hidden', v !== 'local');
    if (cssUrl) cssUrl.classList.toggle('hidden', v !== 'url');
  }
  if (cssSource) cssSource.addEventListener('change', syncCSSSourceFields);

  // Render the record into the form. Called from renderConfig as well, so a
  // save elsewhere cannot leave the form describing a stale state.
  window.renderSubscriptionSettings = function () {
    const sub = currentConfig()?.subscription;
    if (!sub || !enabled || !domain || !port || !title) return;
    enabled.checked = !!sub.enabled;
    domain.value = sub.domain || '';
    port.value = sub.port || '';
    title.value = sub.title || '';
    if (cssSource) cssSource.value = sub.theme_css_source || 'inline';
    if (cssInline) cssInline.value = sub.theme_css || '';
    if (cssPath) cssPath.value = sub.theme_css_path || '';
    if (cssUrl) cssUrl.value = sub.theme_css_url || '';
    syncCSSSourceFields();
    renderSubOriginPreview();
  };

  function renderSubOriginPreview() {
    if (!originPreview) return;
    const tls = currentConfig()?.tls || {};
    // A distinct subscription domain is HTTPS by construction (its ACME pair
    // exists before the domain can apply); everything else follows the panel.
    const distinct = domain && domain.value.trim() && domain.value.trim() !== (tls.domain || '');
    const scheme = (distinct || tls.panel_https) ? 'https' : 'http';
    const host = (domain && domain.value.trim()) || tls.domain || currentConfig()?.server?.public_ip || '<server>';
    const rawPort = parseInt(port && port.value, 10) || currentConfig()?.server?.web_port;
    const isDefault = (scheme === 'https' && rawPort === 443) || (scheme === 'http' && rawPort === 80);
    originPreview.textContent = scheme + '://' + host + (isDefault || !rawPort ? '' : ':' + rawPort) + '/sub/';
  }
  if (domain) domain.addEventListener('input', renderSubOriginPreview);
  if (port) port.addEventListener('input', renderSubOriginPreview);

  // The Let's Encrypt button for the subscription domain. The daemon issues
  // the certificate and applies the domain itself on success (record, links,
  // listener); the progress bar polls the shared ACME status. The section
  // reads back through the config so every field stays truthful.
  if (leBtn && typeof window.bindLEButton === 'function') {
    window.bindLEButton(leBtn, domain, 'subscription', 'sub-le-progress');
  }

  if (!saveBtn) return;
  saveBtn.addEventListener('click', async () => {
    const payload = {
      enabled: enabled ? enabled.checked : true,
      domain: (domain ? domain.value.trim() : ''),
      port: parseInt(port ? port.value : '0', 10) || 0,
      uri_path: '/sub',
      title: (title ? title.value.trim() : ''),
      theme_css_source: (cssSource ? cssSource.value : 'inline'),
      theme_css: (cssInline ? cssInline.value : ''),
      theme_css_path: (cssPath ? cssPath.value.trim() : ''),
      theme_css_url: (cssUrl ? cssUrl.value.trim() : '')
    };
    saveBtn.disabled = true;
    if (statusEl) statusEl.textContent = 'Saving…';
    try {
      const res = await fetch(api('/api/settings/subscription'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken()}` },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const msg = await errorMessage(res, 'The server refused the subscription settings');
        if (statusEl) statusEl.textContent = '';
        showToast(msg, 'error');
        return;
      }
      const data = await res.json().catch(() => ({}));
      if (data && data.subscription && currentConfig()) {
        currentConfig().subscription = data.subscription;
        window.renderSubscriptionSettings();
      }
      // The client cards' Reg Link and Bot Card URLs are built from the origin,
      // not from the record: absorb the recomputed origin the save hands back
      // and re-render the cards, or the buttons keep copying the port that was
      // just replaced — a link nothing answers on. loadClients re-fetches and
      // re-renders without flashing the grid away (it skips the loader when
      // cards are already showing). It is a top-level function of the classic
      // app.js, so it is global and reachable from this module.
      if (data && typeof data.subscription_origin === 'string' && currentConfig()) {
        currentConfig().subscription_origin = data.subscription_origin;
      }
      if (typeof loadClients === 'function') {
        loadClients();
      }
      if (data && data.listener_error) {
        // The record saved but the port could not be bound — most often a port
        // another process already holds. Saying "Saved." here would be the same
        // lie the card used to tell when the port field changed nothing at all,
        // so the conflict is surfaced with the address that failed.
        if (statusEl) statusEl.textContent = 'Saved, but the portal listener could not start.';
        showToast('Subscription saved, but the portal port could not be opened: ' + data.listener_error, 'error');
        return;
      }
      if (statusEl) statusEl.textContent = data && data.restart_required ? 'Saved — restart required.' : 'Saved.';
      showToast('Subscription settings saved.', 'success');
    } catch (err) {
      if (statusEl) statusEl.textContent = '';
      showToast('Could not reach the server.', 'error');
    } finally {
      saveBtn.disabled = false;
    }
  });
}


  // Rebind the init hooks onto window so app.js (classic) can call them.
  // initSubscriptionSettings is app.js's own call site (settings tab, third
  // group); exporting it is what keeps the ReferenceError from taking down the
  // whole route switch (UI bug found by the Playwright E2E: /dash/settings
  // stayed on Dashboard because handleRouteFromURL never ran).
  window.initTwoFactorControls = initTwoFactorControls;
  window.initLdapControls = initLdapControls;
  window.initSubscriptionSettings = initSubscriptionSettings;
})();
