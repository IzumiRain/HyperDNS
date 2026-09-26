// =======================================================
// HyperDNS Front-End Application Logic (ES6)
// Bulletproof, Offline-Safe, Self-Healing
// =======================================================


// authToken is empty until a real login. Earlier builds seeded the literal
// 'hdns_session_admin' here and wrote it to localStorage, which the server has
// never accepted — it only produced a guaranteed 401 on first load and made a
// logged-out browser look logged in.
let authToken = localStorage.getItem('hyperdns_token') || '';

// The admin namespace. Since v2.1 the panel is not at the root of the host: the
// SPA lives at /<admin-path>/dash/... and every dashboard API at
// /<admin-path>/api/..., where <admin-path> is a 16-hex-character value drawn
// once per install. The bundle is built without knowing it — the same bytes ship
// to every install, and baking one in would publish the hidden path — so it is
// read from the address bar instead. The shape is exactly what the server
// generates (16 lowercase hex characters, security.go's IsValidAdminPath), so a
// match is reliable, and anything else means the page was reached some other way,
// in which case the empty prefix degrades to the pre-v2.1 root paths.
const ADMIN_BASE = (function () {
  const m = window.location.pathname.match(/^\/([0-9a-f]{16})(?=\/|$)/);
  return m ? '/' + m[1] : '';
})();
const DASH_BASE = ADMIN_BASE + '/dash';

// api() prefixes a server path with the admin namespace. Every dashboard call —
// fetches, the SSE stream, the docs link — goes through this, because the day
// one call site forgets the prefix is the day that call starts answering 404
// while every other tab keeps working.
const api = (path) => ADMIN_BASE + path;
// The bridge the ES modules read shared state through. Modules cannot import
// from this classic script, and a captured copy of any of these would go stale
// across a re-login or a config refresh — so each accessor resolves the live
// value at call time.
window.__hdns = {
  getToken: () => authToken,
  setToken: (v) => { authToken = v; },
  getConfig: () => currentConfig,
  api: (p) => api(p),
  DASH_BASE: DASH_BASE,
  showToast: (m, t) => showToast(m, t),
  errorMessage: (r, f) => errorMessage(r, f),
};

let sseSource = null;
let qpsChart = null;
let currentConfig = null;
let isStreamPaused = false;

// The live query table is a rendering of this buffer rather than the record itself.
//
// The filter dropdown and the search box used to be read inside the append path — at the
// moment a query arrived and nowhere else — so they only ever applied to arriving rows.
// Selecting BLOCK left every DIRECT row sitting on screen; typing a domain into the search
// box did nothing at all until the next query happened to show up, which on a resolver
// serving one household can be minutes. Neither control has an event listener in this file,
// so there was nothing to re-render with: the operator's only evidence that the filter works
// is that later rows obey it. That reads as a broken control, not a quiet network.
//
// Holding the queries as data makes the filter, the search box, and Clear all cheap and
// exact, and it makes "the last STREAM_BUFFER_MAX queries received" true regardless of what
// the view is currently showing — the old 80-row cap applied to whatever survived the
// filter, so a narrow filter silently discarded history it had already been handed.
const STREAM_BUFFER_MAX = 200;
let streamBuffer = [];

function safeFeatherReplace() {
  try {
    if (typeof feather !== 'undefined' && feather.replace) {
      feather.replace();
    }
  } catch (e) {
    console.warn('Feather icons render notice:', e);
  }
}

// errorMessage pulls the server's explanation out of a failed response. Handlers
// answer with {"error":"..."} and the text is the actionable part — which policy
// rule a password failed, or that the IP is locked out rather than mistyped.
async function errorMessage(res, fallback) {
  try {
    const text = await res.text();
    if (text) {
      try {
        const parsed = JSON.parse(text);
        if (parsed && parsed.error) return String(parsed.error);
      } catch (e) {
        const trimmed = text.trim();
        if (trimmed && trimmed.length < 200) return trimmed;
      }
    }
  } catch (e) { /* fall through to the generic message */ }
  return res.status === 429 ? 'Too many attempts. Try again later.' : fallback;
}

// clientAction posts one subscriber mutation and reports what actually happened.
//
// Each of the five callers used to be its own try/catch that either ignored res.ok
// or swallowed the throw in `catch (err) {}`. So a refused delete showed "Client
// deleted" and the follow-up loadClients() quietly put the row back — which reads
// as the dashboard being out of sync rather than as the server having said no. A
// dropped connection showed nothing at all, and the operator was left looking at a
// row they believed they had just changed.
//
// It returns true only when the server confirmed the change, so a caller can chain
// on the result rather than assume.
async function clientAction(path, payload, successMsg, tone) {
  try {
    const res = await fetch(api(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      showToast(await errorMessage(res, 'The server refused the request'), 'error');
      return false;
    }
    showToast(successMsg, tone || 'info');
    // Only on success: nothing changed on a refusal, so the rows on screen are
    // already correct and a reload would just hide the error toast behind a redraw.
    loadClients();
    return true;
  } catch (err) {
    // fetch rejects only on a transport failure, so this is the daemon being gone or
    // the tab being offline. Worth saying: the row on screen is now unverified.
    showToast('Could not reach the server — the list may be out of date.', 'error');
    return false;
  }
}

// isProbablyIP is a typo catcher, not the authority. The server re-parses with
// net.ParseIP and stores the canonical form, because whitelisting is an exact string
// compare against the address the listener reports — this check only exists so an
// obvious slip is caught while the operator can still see and fix what they typed.
//
// Leading zeros are rejected on purpose: Go's parser refuses them too, since
// "010.1.1.1" is octal to some tools and decimal to others.
function isProbablyIP(value) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) <= 255 && (part === '0' || !part.startsWith('0')));
  }
  // A colon is what separates a v6 attempt from a mistyped v4. Hand-rolling the full
  // v6 grammar here would only find new ways to disagree with Go's parser, so the
  // shape is checked and the verdict is left to the server.
  return value.includes(':') && /^[0-9a-fA-F:.]+$/.test(value) && !value.includes(':::');
}

// Init when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  safeFeatherReplace();
  try { initChart(); } catch (e) {}
  // Before checkAuthAndBoot, which unhides the login overlay synchronously: the observers
  // inside have to be watching already or they miss the modal that is up first.
  initModalA11y();
  checkAuthAndBoot();

  // The API docs live under the admin namespace too, and the anchor's href in
  // index.html is a static "/api/v1/docs" that cannot know the install's path.
  // Rewritten here from the same value every fetch uses, so the page the button
  // opens is the one the server actually serves.
  document.querySelectorAll('a[href="/api/v1/docs"]').forEach((a) => {
    a.href = api('/api/v1/docs');
  });

  // Login form submit
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const u = document.getElementById('login-username').value.trim();
      // Not trimmed: the password is compared byte for byte, and a pre-v1.5.0
      // record can hold any plaintext the operator originally chose.
      const p = document.getElementById('login-password').value;
      // The 2FA row stays hidden until the server says a code is needed; once
      // it has said so once in this tab, the row stays visible so a mistyped
      // code can be corrected without the field vanishing.
      const codeInput = document.getElementById('login-code');
      const code = codeInput ? (codeInput.value || '').trim() : '';
      const errDiv = document.getElementById('login-error');
      if (errDiv) errDiv.classList.add('hidden');

      try {
        const res = await fetch(api('/api/auth/login'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: u, password: p, code })
        });

        if (!res.ok) {
          // The body is parsed exactly once, here, and both the message and the
          // second-factor flag below read that one parse. errorMessage() calls
          // res.text() — it consumes the stream — so any later res.clone() on
          // this response throws "body already used" and the flag check would
          // silently never fire. That ordering bug is why a correct password
          // with 2FA on showed "Invalid credentials" and no code field.
          let errJSON = null;
          try { errJSON = await res.clone().json(); } catch (e) { /* body was not JSON */ }
          if (errDiv) {
            // The server distinguishes bad credentials from a lockout; showing
            // "Invalid credentials" for a 429 sends the operator hunting for a
            // typo when the real answer is "wait fifteen minutes".
            errDiv.innerText = await errorMessage(res, 'Invalid credentials');
            errDiv.classList.remove('hidden');
          }
          // The server flags the one case that needs the code field: the
          // password verified but the second factor did not (twofactor_required
          // in the 401 body). Revealing the row on every bad password — the old
          // behaviour, keyed on the status alone — is how a first-time operator
          // on an install with no 2FA enrolled was greeted by a TWO-FACTOR CODE
          // box. Once genuinely shown the row stays up for this tab, so a
          // mistyped code can be corrected without the field vanishing.
          if (res.status === 401 && p && codeInput) {
            const needs2fa = !!(errJSON && errJSON.twofactor_required);
            if (needs2fa) codeInput.closest('div').classList.remove('hidden');
          }
          return;
        }

        const data = await res.json();
        authToken = data.token;
        localStorage.setItem('hyperdns_token', authToken);
        hideLoginModal();
        bootDashboard();

        if (data.password_weak || data.is_default_password) {
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
      const userField = document.getElementById('new-admin-user');
      const currentField = document.getElementById('current-admin-pass');
      const submitted = userField ? userField.value.trim() : '';
      const newPassword = document.getElementById('new-admin-pass').value;
      const currentPassword = currentField ? currentField.value : '';

      // The username field is prefilled with the live value, so "unchanged" has to
      // be measured against it — otherwise reopening the modal and saving would
      // read as a rename and demand a re-authentication for nothing.
      const liveUser = currentConfig?.server?.admin_username || 'admin';
      const newUsername = submitted && submitted !== liveUser ? submitted : '';
      if (!newPassword && !newUsername) {
        hideChangePwdModal();
        return;
      }
      // The server re-authenticates before touching either credential, so a
      // change without this field can only ever come back 403.
      if (!currentPassword) {
        showToast('Enter your current password to confirm the change', 'error');
        if (currentField) currentField.focus();
        return;
      }

      const payload = { current_password: currentPassword };
      if (newUsername) payload.admin_username = newUsername;
      if (newPassword) payload.admin_password = newPassword;
      // v2.1.0 (B-04 remediation): the second factor rides the same body. The
      // row is revealed when the config shows 2FA enabled; sending it while 2FA
      // is off is harmless (the server ignores it).
      const codeRow = document.getElementById('change-pwd-2fa-row');
      const codeInput = document.getElementById('change-pwd-code');
      if (codeRow) codeRow.classList.toggle('hidden', !currentConfig?.auth?.totp_enabled);
      if (codeInput && codeInput.value.trim()) payload.code = codeInput.value.trim();

      try {
        const res = await fetch(api('/api/config/server'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify(payload)
        });

        if (!res.ok) {
          // The server explains exactly which policy rule the password failed;
          // a generic "Failed" left the operator guessing.
          showToast(await errorMessage(res, 'Failed to update credentials'), 'error');
          return;
        }

        const data = await res.json().catch(() => ({}));
        // A password change revokes every session, including this one, and hands
        // back a replacement. A username-only change does not, and sends no
        // token — overwriting the stored one with undefined would log us out.
        if (data.token) {
          authToken = data.token;
          localStorage.setItem('hyperdns_token', authToken);
        }
        // Keep the local copy in step so the Settings card and the next open of
        // this modal show the name that is now in force.
        if (currentConfig?.server && data.username) {
          currentConfig.server.admin_username = data.username;
          const adminNameEl = document.getElementById('current-admin-name');
          if (adminNameEl) adminNameEl.innerText = data.username;
        }
        // The nag is satisfied, so a later voluntary open must not be forced.
        if (currentConfig?.server && newPassword) {
          currentConfig.server.admin_password_weak = false;
        }
        hideChangePwdModal();
        showToast(newPassword
          ? 'Credentials updated — other sessions have been signed out'
          : 'Username updated', 'success');
      } catch (err) {
        showToast('Error updating credentials', 'error');
      }
    });
  }

  // Voluntary credential rotation from the Settings tab.
  document.getElementById('open-change-pwd-btn')?.addEventListener('click', () => {
    showChangePwdModal(false);
  });
  document.getElementById('change-pwd-cancel')?.addEventListener('click', () => {
    hideChangePwdModal();
  });

  document.getElementById('logout-btn')?.addEventListener('click', () => {
    signOut();
  });
});

// signOut revokes the session on the daemon, then clears local state.
//
// Removing the token from localStorage is not a logout: the session stayed live
// server-side for the rest of its lifetime, so any copy of it — a shared browser,
// a proxy log, a captured Authorization header — kept working after the operator
// believed they had signed out. The network call revokes exactly this session;
// sibling sessions on other devices are deliberately left alone.
//
// The local state is cleared in `finally` so a daemon that is unreachable, or a
// token already expired, still returns the operator to the login screen instead
// of trapping them in a dashboard they can no longer use.
async function signOut() {
  try {
    await fetch(api('/api/auth/logout'), {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + authToken, 'Content-Type': 'application/json' },
      body: '{}',
    });
  } catch (e) {
    // Nothing to surface: the operator asked to leave, and the only thing left
    // to do either way is drop the local session.
  } finally {
    localStorage.removeItem('hyperdns_token');
    authToken = '';
    showLoginModal();
  }
}

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

// The credential modal has two modes. Forced is the security nag: the stored
// password fails the policy, so a new one is mandatory and there is nothing safe
// to cancel back to. Voluntary is the operator rotating a compliant password from
// Settings — the escape hatch has to be there, and a username-only change is
// legitimate, so the password field stops being mandatory.
function showChangePwdModal(forced = true) {
  const modal = document.getElementById('change-pwd-modal');
  if (!modal) return;

  const title = document.getElementById('change-pwd-title');
  const badge = document.getElementById('change-pwd-badge');
  const intro = document.getElementById('change-pwd-intro');
  const cancel = document.getElementById('change-pwd-cancel');
  const icon = document.getElementById('change-pwd-icon');
  const newPass = document.getElementById('new-admin-pass');
  const userField = document.getElementById('new-admin-user');

  if (forced) {
    if (title) title.innerText = 'Security Setup';
    if (badge) badge.innerText = 'WEAK ADMIN PASSWORD DETECTED';
    if (intro) {
      intro.innerText = 'This account is still on a password that fails the current policy. '
        + 'Anyone who can reach this dashboard may be able to log in with it. '
        + 'Set a new administrator password now:';
    }
    cancel?.classList.add('hidden');
    newPass?.setAttribute('required', 'required');
    if (newPass) newPass.placeholder = 'At least 10 characters';
  } else {
    if (title) title.innerText = 'Administrator Credentials';
    if (badge) badge.innerText = 'ROTATE YOUR DASHBOARD LOGIN';
    if (intro) {
      intro.innerText = 'Confirm with your current password. Saving a new password signs out '
        + 'every session, including this browser, and issues you a fresh one. '
        + 'Leave the password blank to change only the username.';
    }
    cancel?.classList.remove('hidden');
    // Not required here: the server accepts a username-only change.
    newPass?.removeAttribute('required');
    if (newPass) newPass.placeholder = 'Leave blank to keep the current password';
  }
  if (icon) {
    icon.setAttribute('data-feather', forced ? 'alert-triangle' : 'user-check');
  }
  // The field is prefilled with the live username so that submitting it unchanged
  // is a no-op rather than an accidental rename.
  if (userField) {
    userField.value = currentConfig?.server?.admin_username || userField.value || 'admin';
  }

  modal.classList.remove('hidden');
  // Through the helper rather than a bare window.feather test: the icon above was just swapped
  // by setAttribute, so this call is what draws it, and the helper is the version that also
  // checks the replace function exists and swallows a failure. An exception thrown here would
  // abort showChangePwdModal after the modal is already visible — losing the focus() below, on
  // the one modal that cannot be dismissed when it is forced.
  safeFeatherReplace();
  document.getElementById('current-admin-pass')?.focus();
}

function hideChangePwdModal() {
  document.getElementById('change-pwd-modal')?.classList.add('hidden');
  const cur = document.getElementById('current-admin-pass');
  const np = document.getElementById('new-admin-pass');
  if (cur) cur.value = '';
  if (np) np.value = '';
}

// ── Static modal behaviour ───────────────────────────────────────────────────────────────
//
// index.html carries five modals as static markup and showDialog builds a sixth kind at
// runtime. The runtime one has always been correct — role="dialog", aria-modal, a labelled
// heading, a focus trap, Escape, focus return — and the five static ones had none of it.
// A screen reader announced the login overlay as an ordinary div; Tab walked straight out of
// it into the dashboard's own controls behind the backdrop, before anyone had authenticated;
// and the only way out of the diagnostics panel was to find the small × in its corner.
//
// The dismissible ones declare their own close control with data-modal-close and the handlers
// below click it rather than hiding the modal themselves. Some of those buttons do more than
// remove a class — change-pwd-cancel runs hideChangePwdModal, which also clears both password
// fields so a typed-then-abandoned password is not left sitting in the DOM — and a second,
// parallel way to close would skip that half. The ones that only hide today cost nothing by
// going through the same path, and stop costing nothing the moment one of them grows a reset.
//
// Two modals are not dismissible, on purpose. login-modal is the authentication gate, and
// change-pwd-modal in forced mode is the weak-password gate: there is nothing safe behind
// either. change-pwd-modal does name change-pwd-cancel, but showChangePwdModal hides that
// button whenever the modal is forced, and modalCloseControl below returns null for a hidden
// control — so Escape is a no-op in exactly the mode where cancelling is not offered, and the
// two can never drift apart.
const MODAL_IDS = ['login-modal', 'change-pwd-modal', 'diagnostics-modal', 'edit-client-modal', 'add-client-modal', 'client-created-modal'];

// Every one of these modals is shown and hidden by toggling .hidden, so reading the class is
// both the truth and cheap enough for a keydown handler.
function isShown(el) {
  return !!el && !el.classList.contains('hidden');
}

// The topmost open modal, in document order. Nothing stacks two static modals today, but
// Escape has to pick one, and document order is the right tiebreak: they all carry z-50, and
// with equal z-index the later element paints on top.
function topmostOpenModal() {
  let found = null;
  for (const id of MODAL_IDS) {
    const el = document.getElementById(id);
    if (isShown(el)) found = el;
  }
  return found;
}

// The panel is the single child of the backdrop container in all five.
function modalPanel(modal) {
  return modal.firstElementChild || modal;
}

// The close control the modal declares, or null when it declares none or the one it declares
// is currently hidden.
function modalCloseControl(modal) {
  const id = modal.getAttribute('data-modal-close');
  if (!id) return null;
  const btn = document.getElementById(id);
  return isShown(btn) ? btn : null;
}

// MODAL_FOCUSABLE is showDialog's trap selector with :not([disabled]) extended to select and
// textarea and hidden inputs excluded. The disabled part is not hypothetical: runFullDiagnostics
// disables #rerun-diagnostics-btn for the length of a run, and that button lives inside
// diagnostics-modal — a trap that stopped on it would park the keyboard on a dead control.
const MODAL_FOCUSABLE = 'button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [href]';

function modalFocusables(panel) {
  // offsetParent is null for anything display:none — a collapsed section, a .hidden button —
  // and none of these panels is itself position:fixed, so the check is safe here.
  return [...panel.querySelectorAll(MODAL_FOCUSABLE)].filter((el) => el.offsetParent !== null);
}

// A modal can hold its own popover — the expiry datepicker inside edit-client-modal is the only
// one today — and Escape there means "close the popover", not "throw away the form behind it".
// The popovers are marked in the markup rather than listed here, and each is closed the way its
// own handlers already close it: by putting .hidden back. Before this existed Escape did nothing
// at all in the datepicker, so nothing is being taken away.
function closeNestedPopover(modal) {
  for (const pop of modal.querySelectorAll('[data-modal-popover]')) {
    if (isShown(pop)) {
      pop.classList.add('hidden');
      return true;
    }
  }
  return false;
}

// Escape closes, Tab stays inside. Both are delegated from document once, at parse time, so
// they are live before the login overlay is unhidden — bootDashboard is where the rest of the
// listeners are attached and it only runs once authentication has succeeded.
document.addEventListener('keydown', (e) => {
  // showDialog's own trap runs on the capture phase and calls preventDefault, so a press it
  // has already dealt with arrives here marked. Without this, Escape on a confirm dialog
  // opened over the edit-client modal would close both — the dialog and the modal that asked
  // the question.
  if (e.defaultPrevented) return;
  if (e.key !== 'Escape' && e.key !== 'Tab') return;
  // A showDialog overlay on top owns the keyboard outright. Its own capture-phase trap handles
  // Tab, but it only calls preventDefault on the two wrap cases — so in the middle of its tab
  // order the press arrives here unmarked, and the static modal underneath would pull focus back
  // out of the dialog that is actually in front. defaultPrevented alone is not enough for that.
  if (activeDialog) return;

  const modal = topmostOpenModal();
  if (!modal) return;

  if (e.key === 'Escape') {
    // A popover inside the modal takes the press first, so Escape in the datepicker closes the
    // datepicker rather than discarding the client edit behind it.
    if (closeNestedPopover(modal)) {
      e.preventDefault();
      return;
    }
    const closeBtn = modalCloseControl(modal);
    if (!closeBtn) return;
    e.preventDefault();
    closeBtn.click();
    return;
  }

  // aria-modal="true" tells assistive technology the rest of the page is inert; the trap is
  // what makes that true for the keyboard as well. A real trap, not a wrap: focus that has
  // already escaped — a click on the backdrop, a focus the browser restored across a reload —
  // is pulled back in rather than left outside.
  const panel = modalPanel(modal);
  const focusables = modalFocusables(panel);
  if (!focusables.length) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  const inside = panel.contains(document.activeElement);
  if (e.shiftKey && (!inside || document.activeElement === first)) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && (!inside || document.activeElement === last)) {
    e.preventDefault();
    first.focus();
  }
});

// A press that lands on the backdrop itself, never one that bubbled up from inside the panel.
// mousedown rather than click, matching showDialog: a drag that starts inside a text field and
// releases over the backdrop is a selection, not a dismissal.
document.addEventListener('mousedown', (e) => {
  const el = e.target;
  if (!(el instanceof Element) || !el.id || !MODAL_IDS.includes(el.id) || !isShown(el)) return;
  const closeBtn = modalCloseControl(el);
  if (closeBtn) closeBtn.click();
});

// modalReturnFocus holds, per modal, whatever had focus when it opened.
const modalReturnFocus = new WeakMap();

// Focus in on open, focus back on close, observed rather than wired into each of the thirteen
// places that add or remove .hidden — one behaviour in one place, and no risk of the next
// modal being added without it.
//
// The "only if focus is not already inside" guard is what preserves the deliberate choices the
// show functions make: showChangePwdModal focuses the current-password field and runs
// synchronously, while this callback is a microtask, so it sees that focus and leaves it alone.
function initModalA11y() {
  for (const id of MODAL_IDS) {
    const modal = document.getElementById(id);
    if (!modal) continue;

    let wasOpen = isShown(modal);
    const observer = new MutationObserver(() => {
      const open = isShown(modal);
      if (open === wasOpen) return;
      wasOpen = open;

      if (open) {
        modalReturnFocus.set(modal, document.activeElement);
        const panel = modalPanel(modal);
        if (!panel.contains(document.activeElement)) {
          modalFocusables(panel)[0]?.focus();
        }
        return;
      }

      // Closing drops focus to <body>, which puts the next Tab back at the top of the
      // document — a long walk back to the button the operator had just pressed.
      const back = modalReturnFocus.get(modal);
      modalReturnFocus.delete(modal);
      if (back instanceof HTMLElement && back.isConnected && back.offsetParent !== null) {
        try { back.focus(); } catch (err) { /* went away mid-close */ }
      }
    });
    observer.observe(modal, { attributes: true, attributeFilter: ['class'] });
  }
}

let areEventListenersAttached = false;

async function bootDashboard() {
  if (!areEventListenersAttached) {
    initEventListeners();
    initClientEventListeners();
    initAPIEvents();
    areEventListenersAttached = true;
  }
  const authed = await loadConfig();
  if (!authed) return; // 401 -> login modal is already shown
  await loadClients();
  startStatsPolling();
  startLiveStream();
  handleRouteFromURL();
}

// =======================================================
// CONFIG & POLICIES SYNC
// =======================================================
// loadConfig fetches the account probe and the configuration, and renders the Settings and
// Policies panels from them.
//
// Both fetches used to be checked for 401 and nothing else, and both bodies were parsed with
// res.json() regardless of the status. That failed in two directions on any other error status.
//
// The /api/config half was the damaging one. A 500 returns a JSON error body, so `currentConfig`
// became {error: "…"} — truthy, which is all `saveRules` guards on — and renderConfig then read
// cfg.rules?.enable_riot off it and got undefined for every preset, painting the whole policy
// grid as OFF. Press Save on that screen and getSwitch reads those unchecked boxes and writes
// them back: every game preset disabled on the server because one fetch returned 500. The
// operator sees a plausible screen and one click destroys the configuration.
//
// The /api/auth/me half failed quietly instead. meData.password_weak is undefined in an error
// body, so `weak` came out false and the forced credential-change modal was skipped — the weak
// password gate opening because its probe broke, which is the wrong direction for a gate.
//
// So: neither body is parsed unless the response is ok, and nothing is rendered from a config
// that did not arrive. Failing with the old screen still on display and a toast that says why is
// strictly better than replacing it with a confident, wrong one.
async function loadConfig() {
  if (!authToken) {
    showLoginModal();
    return false;
  }
  try {
    const res = await fetch(api('/api/auth/me'), {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });

    if (res.status === 401) {
      showLoginModal();
      return false;
    }
    if (!res.ok) {
      showToast(await errorMessage(res, 'Could not read the account state.'), 'error');
      return false;
    }

    const meData = await res.json();
    const weak = !!(meData.password_weak || meData.is_default_password);

    const cfgRes = await fetch(api('/api/config'), {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (cfgRes.status === 401) {
      showLoginModal();
      return false;
    }
    if (!cfgRes.ok) {
      showToast(await errorMessage(cfgRes, 'Could not load the configuration.'), 'error');
      return false;
    }
    currentConfig = await cfgRes.json();
    renderConfig(currentConfig);
    // Raised after the config lands so the modal can prefill the real username
    // rather than the markup's placeholder.
    if (weak) showChangePwdModal();
    return true;
  } catch (e) {
    console.error('Failed to load config:', e);
    showToast('Could not reach the server to load the configuration.', 'error');
    return false;
  }
}

let isAPIKeyMasked = true;

function renderConfig(cfg) {
  if (!cfg) return;
  currentConfig = cfg;

  // Normalize config structures to prevent runtime crashes on missing fields
  if (!cfg.rules || typeof cfg.rules !== 'object') cfg.rules = {};
  ['custom_proxied', 'custom_blocked', 'custom_direct'].forEach(k => {
    if (!Array.isArray(cfg.rules[k])) cfg.rules[k] = [];
  });
  if (!cfg.rules.custom_records || typeof cfg.rules.custom_records !== 'object' || Array.isArray(cfg.rules.custom_records)) {
    cfg.rules.custom_records = {};
  }
  if (!cfg.access || typeof cfg.access !== 'object') cfg.access = {};
  if (!Array.isArray(cfg.access.doh_tokens)) cfg.access.doh_tokens = [];

  // The subscription record may be absent on a pre-v2.1 config response; an
  // empty object keeps the renderers below total.
  if (!cfg.subscription || typeof cfg.subscription !== 'object') cfg.subscription = {};

  // The two v2.1 panels read straight from the config they were handed.
  if (typeof window.renderSubscriptionSettings === 'function') window.renderSubscriptionSettings();
  if (typeof window.renderAdminPath === 'function') window.renderAdminPath();
  if (typeof window.renderTwoFactor === 'function') window.renderTwoFactor();
  if (typeof window.renderLdap === 'function') window.renderLdap();

  // Version badge (single source of truth: version.json embedded in the binary).
  //
  // The mobile header deliberately gets the version *without* the commit hash. The two strings
  // differ by eleven characters — "v1.5.0-beta" against "v1.5.0-beta [3585f9bf]" — and at 9px
  // mono in a 56px sticky header that is the difference between a badge sitting beside the
  // wordmark and one that wraps, taking the brand line out through the top border. The hash
  // still reaches both places it is actually used from: the desktop sidebar badge, which has
  // Version badge displays: header and mobile show only version (e.g. "v2.0.0-beta"),
  // footer shows version + hash for bug reports (e.g. "v2.0.0-beta [3585f9bf]").
  if (cfg.version && cfg.version.display) {
    const versionOnly = cfg.version.display;
    const versionWithHash = `${cfg.version.display} [${cfg.version.hash}]`;

    const headerBadge = document.getElementById('app-version-badge');
    if (headerBadge) headerBadge.innerText = versionOnly;

    const footer = document.getElementById('app-version-footer');
    if (footer) footer.innerText = versionWithHash;

    const mobileBadge = document.getElementById('app-version-badge-mobile');
    if (mobileBadge) {
      mobileBadge.innerText = versionOnly;
      mobileBadge.title = versionWithHash;
    }
  }

  // v2.6: once the running version is known, ask the server whether a newer one
  // is published on the project's main branch. Runs once per page load and is
  // non-fatal when the box is offline.
  if (!window.__hdnsUpdateChecked) {
    window.__hdnsUpdateChecked = true;
    checkForUpdate();
  }

  // Header & guide public IP
  const pubIP = cfg.server.public_ip || '127.0.0.1';
  const headerIPEl = document.getElementById('header-public-ip');
  if (headerIPEl) headerIPEl.innerText = pubIP;

  // Administrator Credentials card. The password verifier is deliberately not in
  // this payload any more, so the username is all there is to show.
  const adminNameEl = document.getElementById('current-admin-name');
  if (adminNameEl) adminNameEl.innerText = cfg.server.admin_username || 'admin';
  const guideWinEl = document.getElementById('guide-win-ip');
  if (guideWinEl) guideWinEl.innerText = pubIP;
  const guideConsoleEl = document.getElementById('guide-console-ip');
  if (guideConsoleEl) guideConsoleEl.innerText = pubIP;
  const guideDohEl = document.getElementById('guide-doh-url');
  if (guideDohEl) {
    // The daemon's own URL builder: domain over IP, https scheme, the DoH
    // listener's own port. The old line guessed http://IP:web_port and got
    // the scheme, the port and the host wrong in one string.
    const doh = (typeof cfg.doh_url === 'string' && cfg.doh_url)
      ? cfg.doh_url
      : `http://${pubIP}:${(cfg.dns && cfg.dns.doh_port) || 8443}/dns-query`;
    guideDohEl.innerText = doh;
    guideDohEl.title = doh;
  }

  // The guide's DoT hostname prefers the dedicated DoH/DoT domain when one
  // is set — it is the only name the 853 certificate is guaranteed to cover.
  const dotHost = (cfg.tls && cfg.tls.dot_domain) || (cfg.tls && cfg.tls.domain) || '';
  if (dotHost) {
    const guideDotEl = document.getElementById('guide-dot-hostname');
    if (guideDotEl) guideDotEl.innerText = dotHost;
  }
  if (cfg.tls && cfg.tls.domain) {
    const sslDomInput = document.getElementById('ssl-domain-input');
    if (sslDomInput) sslDomInput.value = cfg.tls.domain;
  }
  if (cfg.tls) {
    const dotDomainInput = document.getElementById('dot-domain-input');
    if (dotDomainInput) dotDomainInput.value = cfg.tls.dot_domain || '';
  }

  // The registration contact is prefilled for the same reason the domain is, and not
  // only for convenience: /api/tls/issue stores both fields from one request, so an
  // operator who fixes a typo in the domain while this box sits empty sends an empty
  // email, and the stored contact — the address Let's Encrypt sends expiry warnings to
  // — is overwritten with nothing.
  if (cfg.tls && cfg.tls.email) {
    const sslEmailInput = document.getElementById('ssl-email-input');
    if (sslEmailInput) sslEmailInput.value = cfg.tls.email;
  }

  // Render API Key & Bind
  renderAPIKeyDisplay();

  const apiBind = (cfg.server && cfg.server.api_bind) ? cfg.server.api_bind : '127.0.0.1';
  // Phase D: reflect the live idle window (the accessor clamps; 0 here means
  // the default 15 the server applies).
  const idleEl = document.getElementById('session-idle-minutes');
  if (idleEl) {
    const live = Number(cfg.server?.session_idle_minutes);
    idleEl.value = Number.isFinite(live) && live > 0 ? live : 15;
  }
  const apiBindBadge = document.getElementById('api-bind-badge');
  const togglePublicAPI = document.getElementById('toggle-public-api');
  
  if (apiBindBadge) {
    if (apiBind === '0.0.0.0') {
      apiBindBadge.innerText = '0.0.0.0 (Public HTTPS)';
      apiBindBadge.className = 'px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30';
    } else {
      apiBindBadge.innerText = '127.0.0.1 (Localhost Only)';
      apiBindBadge.className = 'px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
    }
  }
  if (togglePublicAPI) {
    togglePublicAPI.checked = (apiBind === '0.0.0.0');
  }

  updateCodeSnippets(pubIP, cfg.server?.api_key || 'hdns_live_your_key_here');

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
  setSwitch('preset-shooters-extra', cfg.rules.enable_shooters_extra);
  setSwitch('preset-anime-gacha', cfg.rules.enable_anime_gacha);
  setSwitch('preset-sports-racing', cfg.rules.enable_sports_racing);
  setSwitch('preset-coop-survival', cfg.rules.enable_coop_survival);
  setSwitch('preset-platforms-extra', cfg.rules.enable_platforms_extra);
  // One switch drives both music presets: the card is labelled "Spotify &
  // SoundCloud" and its copy promises SoundCloud CDN streams, but only
  // enable_spotify was ever sent, so SoundCloud could not be toggled from the
  // dashboard at all. Shown as on when either category is on.
  setSwitch('preset-spotify', cfg.rules.enable_spotify || cfg.rules.enable_soundcloud);
  setSwitch('preset-twitch', cfg.rules.enable_twitch);
  setSwitch('preset-kick', cfg.rules.enable_kick);
  setSwitch('preset-google', cfg.rules.enable_google);
  setSwitch('preset-ai', cfg.rules.enable_ai);
  setSwitch('preset-social', cfg.rules.enable_social);
  setSwitch('preset-dev403', cfg.rules.enable_dev403);
  setSwitch('preset-adblock', cfg.rules.enable_adblock);
  setSwitch('preset-familysafe', cfg.rules.enable_familysafe);
  // Off by default, unlike every switch above it. The server sends the value, so a
  // missing key means an older config.json that predates the category — treat that
  // as off rather than letting `undefined` read as "leave it wherever the DOM was",
  // which on a re-render after a save is whatever the operator last clicked.
  setSwitch('preset-downloads', cfg.rules.enable_downloads === true);

  // Render Custom Rules Lists (with safe optional chaining)
  renderList('custom-proxied-list', cfg.rules?.custom_proxied || [], 'remove-proxied');
  renderList('custom-blocked-list', cfg.rules?.custom_blocked || [], 'remove-blocked');
  renderList('tokens-list', cfg.access?.doh_tokens || [], 'remove-token');
  renderCustomRecords(cfg.rules?.custom_records || {});
  loadCustomGroups();
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
    // The list entries are operator-supplied strings that arrive back from the
    // settings API, and the row is built with innerHTML — so they are escaped like
    // every other stored value the dashboard renders. data-val survives escaping
    // unchanged: the parser decodes the entities before dataset reads it.
    row.innerHTML = `
      <span class="font-mono text-cyan-300">${escapeHTML(item)}</span>
      <button class="${removeClass} inline-flex items-center justify-center w-6 h-6 shrink-0 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition" data-val="${escapeHTML(item)}" aria-label="Remove ${escapeHTML(item)}">
        <i data-feather="x" class="w-3.5 h-3.5"></i>
      </button>
    `;
    container.appendChild(row);
  });
  safeFeatherReplace();
}

// ---- Named custom policy groups (v2.3) --------------------------------------

let customGroupsCache = [];

async function loadCustomGroups() {
  const container = document.getElementById('custom-groups-list');
  if (!container) return;
  try {
    const res = await fetch(api('/api/custom-groups'), {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (!res.ok) throw new Error('load failed');
    const data = await res.json();
    customGroupsCache = data.groups || [];
    renderCustomGroups();
  } catch (e) {
    container.innerHTML = '<div class="text-red-400 text-xs py-1">Failed to load custom groups</div>';
  }
}

function renderCustomGroups() {
  const container = document.getElementById('custom-groups-list');
  if (!container) return;
  container.innerHTML = '';
  if (!customGroupsCache.length) {
    container.innerHTML = '<div class="text-slate-500 text-xs py-1">No custom groups yet</div>';
    return;
  }
  const actionColor = { proxy: 'text-cyan-300', direct: 'text-emerald-300', block: 'text-red-300' };
  customGroupsCache.forEach((g) => {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between py-2 px-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs';
    const state = g.enabled ? '' : ' <span class="text-slate-500">(disabled)</span>';
    const actionCls = actionColor[g.action] || 'text-slate-400';
    row.innerHTML = `
      <div class="min-w-0">
        <div class="font-bold text-white truncate">${escapeHTML(g.name)}${state}</div>
        <div class="font-mono ${actionCls}">${escapeHTML(g.action)} · ${g.domains.length} domain(s)</div>
      </div>
      <div class="flex items-center gap-1.5 shrink-0">
        <button class="edit-group-btn px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition" data-id="${escapeHTML(g.id)}">Edit</button>
        <button class="delete-group-btn inline-flex items-center justify-center w-6 h-6 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition" data-id="${escapeHTML(g.id)}" aria-label="Delete group ${escapeHTML(g.name)}">
          <i data-feather="trash-2" class="w-3.5 h-3.5"></i>
        </button>
      </div>
    `;
    container.appendChild(row);
  });
  safeFeatherReplace();
}

function openCustomGroupEditor(group) {
  const ed = document.getElementById('custom-group-editor');
  if (!ed) return;
  document.getElementById('custom-group-id').value = group ? group.id : '';
  document.getElementById('custom-group-name').value = group ? group.name : '';
  document.getElementById('custom-group-action').value = group ? group.action : 'proxy';
  document.getElementById('custom-group-domains').value = group ? group.domains.join('\n') : '';
  document.getElementById('custom-group-enabled').checked = group ? group.enabled : true;
  document.getElementById('custom-group-status').textContent = '';
  ed.classList.remove('hidden');
}

async function saveCustomGroup() {
  const id = document.getElementById('custom-group-id').value.trim();
  const status = document.getElementById('custom-group-status');
  const body = {
    name: document.getElementById('custom-group-name').value.trim(),
    action: document.getElementById('custom-group-action').value,
    domains: document.getElementById('custom-group-domains').value
      .split('\n').map((d) => d.trim().toLowerCase()).filter(Boolean),
    enabled: document.getElementById('custom-group-enabled').checked
  };
  const path = id ? `/api/custom-groups/${encodeURIComponent(id)}` : '/api/custom-groups';
  const method = id ? 'PUT' : 'POST';
  status.textContent = 'Saving…';
  try {
    const res = await fetch(api(path), {
      method,
      headers: { 'Authorization': `Bearer ${authToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      status.textContent = data.error || 'Save failed';
      return;
    }
    document.getElementById('custom-group-editor').classList.add('hidden');
    showToast('Custom group saved', 'success');
    loadCustomGroups();
  } catch (e) {
    status.textContent = 'Network error';
  }
}

async function deleteCustomGroup(id) {
  try {
    const res = await fetch(api(`/api/custom-groups/${encodeURIComponent(id)}`), {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (res.ok) {
      showToast('Custom group deleted', 'success');
      loadCustomGroups();
    }
  } catch (e) { /* ignore */ }
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
      <span class="font-mono text-emerald-300">${escapeHTML(dom)} &rarr; ${escapeHTML(ip)}</span>
      <button class="remove-record inline-flex items-center justify-center w-6 h-6 shrink-0 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition" data-dom="${escapeHTML(dom)}" aria-label="Remove record ${escapeHTML(dom)}">
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
    enable_shooters_extra: getSwitch('preset-shooters-extra'),
    enable_anime_gacha: getSwitch('preset-anime-gacha'),
    enable_sports_racing: getSwitch('preset-sports-racing'),
    enable_coop_survival: getSwitch('preset-coop-survival'),
    enable_platforms_extra: getSwitch('preset-platforms-extra'),
    enable_spotify: getSwitch('preset-spotify'),
    enable_soundcloud: getSwitch('preset-spotify'),
    enable_twitch: getSwitch('preset-twitch'),
    enable_kick: getSwitch('preset-kick'),
    enable_google: getSwitch('preset-google'),
    enable_ai: getSwitch('preset-ai'),
    enable_social: getSwitch('preset-social'),
    enable_dev403: getSwitch('preset-dev403'),
    enable_adblock: getSwitch('preset-adblock'),
    enable_familysafe: getSwitch('preset-familysafe'),
    enable_downloads: getSwitch('preset-downloads'),
    custom_proxied: currentConfig.rules.custom_proxied,
    custom_blocked: currentConfig.rules.custom_blocked,
    custom_direct: currentConfig.rules.custom_direct,
    custom_records: currentConfig.rules.custom_records
  };

  try {
    const res = await fetch(api('/api/config/rules'), {
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

// STATS_POLL_MS is the beat of the home tab. Every tile on it — Query Rate, RAM Cache,
// SNI Proxy, CPU Usage, RAM Usage, Live Traffic, Resolver Latency, Upstream Racers — is
// painted from one /api/stats response, so this interval *is* how live the page is. It
// was 2000 while the backend only resampled memory and CPU every fifth second; both
// halves now run at one second, and neither is the bottleneck for the other.
//
// setInterval is deliberately not used, for two reasons that bite at one second and did
// not at two:
//
//   A fetch can outlast the interval. setInterval does not care — it fires again
//   regardless. On a link where /api/stats takes 1.4 s, and an Iranian VPS answering a
//   home connection is exactly that link, polls overlap, queue behind each other, and
//   the tiles end up painted from whichever response happens to land last. Scheduling
//   the next poll only after the previous one settles makes overlap structurally
//   impossible and lets the real cadence degrade to whatever the link sustains, instead
//   of pretending to be 1 Hz while running four requests deep.
//
//   A hidden tab should not poll at all. A dashboard left open in a background tab over
//   an afternoon is fourteen thousand requests nobody looks at, on both ends of the one
//   scarce resource here. Polling stops on hide and resumes with an *immediate* refresh
//   rather than a wait, so coming back to the tab shows current numbers, not a second
//   of stale ones followed by a jump.
const STATS_POLL_MS = 1000;

// While the poll is failing, back off instead of hammering a daemon that is already
// unhappy once a second. The ceiling is low on purpose: a resolver that comes back up
// should light the badge again within a few seconds, not after a minute of silence.
const STATS_POLL_MAX_BACKOFF_MS = 8000;

let statsPollTimer = null;
// Tracked separately from the timer handle because a poll in flight has no timer: the
// handle is cleared on entry and only reassigned after the fetch settles. Without this
// flag, a visibilitychange landing inside that window would see "no timer scheduled",
// start a second chain, and quietly double the request rate for the rest of the session.
let statsPollInFlight = false;

async function pollStatsOnce() {
  if (statsPollInFlight) return;
  statsPollTimer = null;
  // Hidden tabs are resumed by the visibilitychange listener below, not by a timer.
  if (document.visibilityState === 'hidden') return;

  statsPollInFlight = true;
  try {
    await updateStats();
  } finally {
    statsPollInFlight = false;
  }

  // Checked again after the await: the tab may have been hidden while the request was
  // in flight, and arming a timer here would leave a background tab polling on.
  if (document.visibilityState === 'hidden') return;

  // The backoff reads statsFailures, which markStatsHealth already maintains for the
  // LIVE ENGINE badge. Deriving both from one counter keeps the page from claiming to
  // be live while polling every eight seconds, or the reverse.
  const delay = statsFailures > 0
    ? Math.min(STATS_POLL_MS * 2 ** statsFailures, STATS_POLL_MAX_BACKOFF_MS)
    : STATS_POLL_MS;

  statsPollTimer = setTimeout(pollStatsOnce, delay);
}

function startStatsPolling() {
  // Called once, from the post-login boot path. The listener is registered here rather
  // than at module scope so that a page which never logs in never installs it.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      clearTimeout(statsPollTimer);
      statsPollTimer = null;
      return;
    }
    if (statsPollTimer === null) pollStatsOnce();
    // Returning to a visible page while the stream tab is showing: the SSE
    // buffer kept growing hidden (per-query DOM work is skipped then — see
    // pushStreamQuery), so this is where the backlog becomes rows. Without
    // it the table stays stale until the next query happens to arrive.
    if (activeDashTab === 'stream' && !isStreamPaused) renderQueryStream();
  });

  pollStatsOnce();
}

async function updateStats() {
  if (!authToken) return;
  try {
    const res = await fetch(api('/api/stats'), {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (!res.ok) {
      markStatsHealth(false, `The server answered ${res.status}`);
      return;
    }

    const data = await res.json();

    const setTxt = (id, txt) => {
      const el = document.getElementById(id);
      if (el) el.innerText = txt;
    };

    // Every tile below used to read `data.field.toFixed(1)` straight. The endpoint
    // does send all of these today — handleStats builds a map literal with no
    // omitempty — but the failure mode if one ever goes missing is invisible: the
    // TypeError lands in the catch below, and every tile *after* the failing line
    // keeps whatever it showed two seconds ago, forever, while the page looks alive.
    // num() makes one missing field cost one dash instead of the whole update.
    const num = (v, digits) => (typeof v === 'number' && isFinite(v)) ? v.toFixed(digits) : '—';
    const count = (v) => (typeof v === 'number' && isFinite(v)) ? v.toLocaleString() : '—';

    setTxt('stat-qps', num(data.qps, 1));
    setTxt('stat-total-queries', count(data.total_queries));
    setTxt('stat-cache-ratio', typeof data.cache_hit_ratio === 'number' ? num(data.cache_hit_ratio, 1) + '%' : '—');
    setTxt('stat-cache-entries', count(data.cache_entries));
    setTxt('stat-proxy-active', count(data.active_proxy_conns));
    setTxt('stat-proxy-total', count(data.total_proxy_conns));
    setTxt('stat-cpu-percent', typeof data.cpu_usage_percent === 'number' ? num(data.cpu_usage_percent, 1) + '%' : '—');
    setTxt('stat-cpu-cores', count(data.num_cpu));
    setTxt('stat-memory', typeof data.ram_usage_mb === 'number' ? num(data.ram_usage_mb, 1) : '—');
    // Machine-wide load (internal/sysmetrics): the whole server, not just the
    // daemon process. Negative values mean the platform cannot answer — dash.
    const sysCPU = typeof data.system_cpu_percent === 'number' && data.system_cpu_percent >= 0
      ? num(data.system_cpu_percent, 1) + '%' : '—';
    setTxt('stat-cpu-sys', sysCPU);
    const sysMemOK = typeof data.system_mem_used_mb === 'number' && data.system_mem_used_mb >= 0;
    setTxt('stat-mem-sys-used', sysMemOK ? num(data.system_mem_used_mb, 0) : '—');
    setTxt('stat-mem-sys-total', sysMemOK ? num(data.system_mem_total_mb, 0) : '—');
    setTxt('stat-mem-sys-pct', sysMemOK ? num(data.system_mem_percent, 0) : '—');
    setTxt('stat-speed-in', num(data.speed_in_kbps, 1));
    setTxt('stat-speed-out', num(data.speed_out_kbps, 1));
    setTxt('stat-traffic-total', formatBytes(data.total_bytes_transferred));
    renderRateLimit(data.rate_limit_qps, data.rate_limited);
    renderLatency(data.latency_uncached, data.latency);
    renderCacheHealth(data);
    renderProxyDrops(data);

    // Render upstreams list
    renderUpstreams(data.upstreams);

    // Push QPS point to chart
    pushChartData(data.qps);

    markStatsHealth(true);
  } catch (e) {
    // A dropped poll is normal — a reload, a restart, a phone changing networks —
    // so the badge only changes after two in a row. What must not happen is the old
    // behaviour: swallow it and leave the page claiming to be live.
    markStatsHealth(false, 'The dashboard cannot reach the daemon');
  }
}

// statsFailures counts consecutive failed polls so one blip does not repaint the badge.
let statsFailures = 0;

// markStatsHealth is the only thing that makes the numbers on the overview page
// trustworthy: without it a daemon that died two minutes ago is indistinguishable
// from a healthy one, because every tile simply keeps its last value.
function markStatsHealth(ok, reason) {
  const badge = document.getElementById('live-engine-badge');
  const dot = document.getElementById('live-engine-dot');
  const label = document.getElementById('live-engine-label');

  if (ok) {
    statsFailures = 0;
    if (badge) {
      badge.className = 'text-[10px] font-mono text-cyan-400 px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center gap-1.5';
      badge.title = 'The dashboard is receiving live telemetry';
    }
    if (dot) dot.className = 'pulse-dot';
    if (label) label.textContent = 'LIVE ENGINE';
    return;
  }

  statsFailures++;
  if (statsFailures < 2) return;

  if (badge) {
    badge.className = 'text-[10px] font-mono text-amber-400 px-2.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 flex items-center gap-1.5';
    badge.title = `${reason || 'Telemetry stopped'} — every number on this page is from the last successful poll`;
  }
  if (dot) dot.className = 'pulse-dot is-stale';
  if (label) label.textContent = 'STALE — NO TELEMETRY';
}

function formatBytes(bytes) {
  // Called with data.total_bytes_transferred and with a client's traffic counter, and
  // an absent counter used to render "NaN KB" here. Bytes below a kilobyte get their
  // own branch so a subscriber who has used nothing reads "0 B" rather than "0.0 KB".
  if (typeof bytes !== 'number' || !isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return Math.round(bytes) + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

// The per-source rate limiter drops a UDP flood without answering it, so the only
// way an operator can tell it fired is if the panel says so. Both numbers are
// shown together: "42 dropped" means nothing without the limit it was measured
// against, and a limit with no drops is the reassuring case worth displaying.
function renderRateLimit(qps, dropped) {
  const el = document.getElementById('stat-ratelimit');
  if (!el) return;

  if (!qps || qps <= 0) {
    el.textContent = 'Limit: off';
    el.className = 'text-slate-500';
    el.title = 'Per-source rate limiting is disabled (access.rate_limit_qps = 0)';
    return;
  }

  const n = dropped || 0;
  el.textContent = `Limit: ${qps}/s · ${n.toLocaleString()} dropped`;
  el.className = n > 0 ? 'text-amber-400 font-bold' : 'text-slate-400';
  el.title = n > 0
    ? `${n.toLocaleString()} queries dropped or refused for exceeding ${qps} qps per source since start`
    : `Limiting at ${qps} qps per source; nothing dropped so far`;
}

// Latency needs percentiles, not an average: at a healthy hit rate the mean is
// dominated by cache hits and reads under a millisecond while every real
// resolution crawls. `miss` excludes the cache hits — it is the distribution that
// moves when an upstream degrades — and `all` is every answer the resolver served.
function renderLatency(miss, all) {
  const setTxt = (id, txt) => {
    const el = document.getElementById(id);
    if (el) el.innerText = txt;
  };
  // Sub-10 ms readings need two decimals to be worth showing at all; past that
  // the tenth of a millisecond is noise.
  const fmt = (v) => (typeof v === 'number' && isFinite(v))
    ? (v < 10 ? v.toFixed(2) : v.toFixed(1))
    : '—';

  const haveMiss = !!(miss && miss.count > 0);
  setTxt('stat-lat-p50', haveMiss ? fmt(miss.p50_ms) : '—');
  setTxt('stat-lat-p95', haveMiss ? fmt(miss.p95_ms) : '—');
  setTxt('stat-lat-p99', haveMiss ? fmt(miss.p99_ms) : '—');
  setTxt('stat-lat-max', haveMiss ? fmt(miss.max_ms) : '—');

  const badge = document.getElementById('stat-lat-count');
  if (badge) {
    if (haveMiss) {
      badge.textContent = `${miss.count.toLocaleString()} resolved`;
      badge.title = 'Queries answered by an upstream rather than from cache, since the daemon started';
    } else if (all && all.count > 0) {
      // A real and reassuring state, not an error: nothing has needed an upstream.
      badge.textContent = 'every answer from cache';
      badge.title = 'No query has needed an upstream resolver yet';
    } else {
      badge.textContent = 'no data yet';
      badge.title = 'The resolver has not answered a query yet';
    }
  }

  // p50 carries the colour because it is the everyday experience. The thresholds
  // are the resolver's own service time, not a game's ping: past ~60 ms the
  // upstream path is the bottleneck, not this daemon.
  const p50El = document.getElementById('stat-lat-p50');
  if (p50El) {
    let tone = 'text-emerald-400';
    if (haveMiss && miss.p50_ms >= 60) tone = 'text-red-400';
    else if (haveMiss && miss.p50_ms >= 25) tone = 'text-amber-400';
    p50El.className = `text-lg sm:text-xl font-extrabold font-mono ${tone}`;
  }

  const allEl = document.getElementById('stat-lat-all');
  if (allEl) {
    allEl.textContent = (all && all.count > 0)
      ? `p50 ${fmt(all.p50_ms)} · p95 ${fmt(all.p95_ms)} · p99 ${fmt(all.p99_ms)} ms over ${all.count.toLocaleString()}`
      : '—';
  }
}

// Serve-stale answers a dead upstream instantly from an expired entry, which is
// precisely why it hides the outage: clients keep getting fast replies from a
// cache nothing is refilling. stale_served climbing alone is the feature working;
// climbing beside refresh_failed is the warning that names are about to go dark.
// refresh_started is carried in the tooltip rather than the line, because it is
// the denominator: "18 failed" is alarming on its own and unremarkable against
// 40,000 attempts, and the badge has no room for both numbers.
function renderCacheHealth(data) {
  const el = document.getElementById('stat-cache-health');
  if (!el) return;

  const served = data.stale_served || 0;
  const started = data.refresh_started || 0;
  const failed = data.refresh_failed || 0;
  const dropped = data.refresh_dropped || 0;

  if (!served && !started && !failed && !dropped) {
    el.textContent = 'Cache refresh: healthy';
    el.className = 'text-slate-500';
    el.title = 'No background refresh has run yet, no stale answer has been served';
    return;
  }

  // Share of attempts that failed. Only meaningful once something was attempted;
  // a failure with no attempt recorded would be a counter bug, not a bad upstream.
  const failRate = started > 0 ? (failed / started) * 100 : 0;

  el.textContent = `Cache refresh: ${served.toLocaleString()} stale · ${failed.toLocaleString()} failed · ${dropped.toLocaleString()} skipped`;
  el.className = failed > 0 ? 'text-amber-400 font-bold' : 'text-slate-400';
  if (failed > 0) {
    el.title = `${failed.toLocaleString()} of ${started.toLocaleString()} background refreshes failed (${failRate.toFixed(1)}%) while ${served.toLocaleString()} stale answer(s) were served. Clients are getting instant replies from a cache nothing is refilling — check the upstream resolvers before the grace window closes.`;
  } else if (dropped > 0) {
    el.title = `${started.toLocaleString()} background refresh(es) succeeded, ${dropped.toLocaleString()} were skipped because the refresh worker pool was saturated. Skipped renewals are not errors; they simply expire normally.`;
  } else {
    el.title = `${started.toLocaleString()} background refresh(es) run, none failed. ${served.toLocaleString()} expired entry/entries were served instantly while being renewed.`;
  }
}

// A connection can reach the SNI proxy and never become a relay, in which case it
// appears in none of the relay figures on the card above. Two ways that happens:
//
//   refused    — the target was blocked, resolved back to this host, or the relay
//                table was full. Expected, and mostly means the guards work.
//   unreadable — the opening bytes named no destination, so there was nowhere to
//                dial. A port scanner looks exactly like this, so a handful is
//                background noise on any public IP. A number that climbs with
//                real traffic does not: it means a name is being answered with
//                this server's address while the client then speaks something
//                the relay cannot read a destination out of — UDP-only, or TCP on
//                a port this relay does not accept on, or TCP that is not TLS or
//                HTTP. The client sees a connection that opens and dies, and
//                cannot tell why, because the substitution happened in DNS.
//
// So unreadable is shown even at zero-refused, and it is the one that gets the
// warning colour.
function renderProxyDrops(data) {
  const el = document.getElementById('stat-proxy-drops');
  if (!el) return;

  const refused = data.relays_refused || 0;
  const unreadable = data.relays_unreadable || 0;

  if (!refused && !unreadable) {
    el.textContent = 'no drops';
    el.className = 'text-slate-500';
    el.title = 'Every connection that reached the proxy named a destination and was relayed';
    return;
  }

  const parts = [];
  if (refused) parts.push(`${refused.toLocaleString()} refused`);
  if (unreadable) parts.push(`${unreadable.toLocaleString()} unreadable`);
  el.textContent = parts.join(' · ');
  el.className = unreadable > 0 ? 'text-amber-400 font-bold' : 'text-slate-400';
  el.title = unreadable > 0
    ? `${unreadable.toLocaleString()} connection(s) arrived without naming a destination — no TLS SNI and no HTTP Host header. A few are port scans. A rising count means a proxied name is sending clients here for traffic this relay cannot carry; check the server log for the sampled "unreadable destination" lines, which name the port and the first bytes.`
    : `${refused.toLocaleString()} connection(s) dropped for a blocked target, a self-dial, or a full relay table`;
}

// The trash icon as inline SVG. renderUpstreams runs once per stats poll
// (1 Hz), and the old row markup used a data-feather <i> plus a
// document-wide icon sweep — on a 1-core VPS that sweep was the single
// largest recurring cost on the dashboard, walking every element of every
// tab once a second. The SVG is byte-identical to what the icon library
// would substitute, so nothing changes visually.
const FEATHER_TRASH_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-3 h-3"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>';

// Signature of the last rendered upstream set: the poll repaints the list
// unconditionally and most ticks change nothing (latency only moves when the
// racer re-measures). Skipping identical payloads removes the innerHTML
// rebuild + the SVG re-parse for every one of those ticks. Built by
// concatenation because the row template below interpolates the escaped
// address into innerHTML; a bare template here would trip the raw-
// interpolation scan for exactly the value it exists to protect.
let lastUpstreamsSig = '';

function renderUpstreams(upstreams) {
  const container = document.getElementById('upstreams-list');
  if (!container) return;

  if (!upstreams || upstreams.length === 0) {
    if (lastUpstreamsSig !== 'empty') {
      container.innerHTML = '<div class="text-slate-500 text-xs py-2">No upstreams configured</div>';
      lastUpstreamsSig = 'empty';
    }
    return;
  }
  const sig = upstreams.map(u => u.address + ':' + (u.latency || 0)).join('|');
  if (sig === lastUpstreamsSig) return;
  lastUpstreamsSig = sig;

  container.innerHTML = '';

  upstreams.forEach(u => {
    // u.latency is nanoseconds, and it is absent until the racer has actually measured
    // this upstream — a freshly added one, or one that has never answered. The old code
    // did `(u.latency / 1000000).toFixed(1)` unconditionally and then compared the
    // resulting *string* to 40 and 80: for a missing latency that yields "NaN", both
    // comparisons are false, and the row rendered "NaN ms" wearing the green badge that
    // means "fastest". Zero was worse, because "0.0 ms" with a green badge reads as a
    // perfect upstream when it means nobody has timed it yet.
    const latency = Number(u.latency) / 1e6;
    const measured = Number.isFinite(latency) && latency > 0;

    let badgeClass = 'text-slate-400 bg-slate-500/10 border-slate-600/40';
    let dotClass = 'w-2 h-2 rounded-full bg-slate-600';
    if (measured) {
      badgeClass = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      dotClass = 'w-2 h-2 rounded-full bg-emerald-400';
      if (latency > 40) {
        badgeClass = 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
        dotClass = 'w-2 h-2 rounded-full bg-yellow-400';
      }
      if (latency > 80) {
        badgeClass = 'text-red-400 bg-red-500/10 border-red-500/30';
        dotClass = 'w-2 h-2 rounded-full bg-red-400';
      }
    }
    // "not timed yet" and "timed at 0.4 ms" have to look different, and the title is
    // where the distinction is spelled out for whoever hovers it.
    const latText = measured ? `${latency.toFixed(1)} ms` : '—';
    const latTitle = measured ? 'Last measured round-trip' : 'Not measured yet — no answer has been timed from this upstream';

    const row = document.createElement('div');
    row.className = 'flex items-center justify-between py-1.5 px-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs';
    row.innerHTML = `
      <div class="flex items-center gap-2">
        <span class="${dotClass}" aria-hidden="true"></span>
        <span class="font-mono text-slate-200">${escapeHTML(u.address)}</span>
      </div>
      <div class="flex items-center gap-2">
        <span class="px-2 py-0.5 rounded border ${badgeClass} text-[10px] font-bold font-mono" title="${latTitle}">${latText}</span>
        <!-- 24x24, up from the 16x16 that a p-0.5 box around a 12px icon gave: this
             deletes a resolver from the live racer set and it sat under the WCAG 2.2
             SC 2.5.8 floor on the surface where it is only ever touched. Enlarging a
             one-tap destructive control on its own would trade a target you cannot hit
             for one you hit by mistake, so the handler now asks first — see the
             confirmAction call in the click delegate. -->
        <button class="remove-upstream inline-flex items-center justify-center w-6 h-6 shrink-0 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition" data-addr="${escapeHTML(u.address)}" title="Remove upstream" aria-label="Remove upstream ${escapeHTML(u.address)}">
          ${FEATHER_TRASH_SVG}
        </button>
      </div>
    `;
    container.appendChild(row);
  });
}

// =======================================================
// LIVE QUERY STREAM (SSE)
// =======================================================
async function startLiveStream() {
  if (sseSource) {
    try { sseSource.close(); } catch(e) {}
  }

  // v2.1.0: the long-lived token no longer rides the query string. The
  // dashboard exchanges it (POST, authenticated) for a one-time, 60-second
  // ticket that the EventSource URL carries; the ticket is consumed on first
  // use, so a leaked URL authorises nothing afterwards.
  let ticketParam = '';
  if (authToken) {
    try {
      const tr = await fetch(api('/api/auth/sse-ticket'), {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (tr.ok) {
        const tj = await tr.json();
        ticketParam = `?ticket=${encodeURIComponent(tj.ticket)}`;
      }
    } catch (e) { /* fall through: stream will answer 401 and the UI retries on next tick */ }
  }
  sseSource = new EventSource(`${api('/api/stream/queries')}${ticketParam}`);

  // Handle single query event
  sseSource.addEventListener('query', (event) => {
    if (isStreamPaused) return;
    try {
      pushStreamQuery(JSON.parse(event.data));
    } catch (e) {
      console.error('Error parsing live query:', e);
    }
  });

  // Handle initial history batch
  sseSource.addEventListener('history', (event) => {
    try {
      const list = JSON.parse(event.data);
      if (Array.isArray(list)) seedStreamQueries(list);
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
        seedStreamQueries(q);
      } else {
        pushStreamQuery(q);
      }
    } catch (e) {}
  };

  sseSource.onerror = (err) => {
    console.warn('SSE stream status update (reconnecting if interrupted)...');
  };
}

function escapeHTML(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// streamFilterState reads the two controls once per render rather than once per row.
function streamFilterState() {
  const filterEl = document.getElementById('stream-filter');
  const searchEl = document.getElementById('stream-search');
  return {
    action: filterEl ? filterEl.value : 'ALL',
    search: searchEl ? searchEl.value.toLowerCase().trim() : '',
  };
}

// queryMatchesStream decides whether one query belongs in the current view. CACHED is handled
// apart from the others because it is not an action — it is a flag that can accompany any of
// them, so comparing it against q.action would match nothing.
function queryMatchesStream(q, f) {
  if (f.action !== 'ALL') {
    if (f.action === 'CACHED') {
      if (!q.cached) return false;
    } else if (q.action !== f.action) {
      return false;
    }
  }
  if (!f.search) return true;
  const domain = (q.domain || '').toLowerCase();
  const clientIP = q.client_ip || '';
  const accountName = (q.account_name || 'Public').toLowerCase();
  return domain.includes(f.search) || clientIP.includes(f.search) || accountName.includes(f.search);
}

// Every action string the resolver can log, mapped to the badge that stands for it. This is
// a table and not a chain of ifs because the previous chain defaulted to a green DIRECT
// badge: a query that was rate limited, was refused for a blown traffic quota, or had its
// AAAA sunk to keep a proxied domain off IPv6 all read as "resolved normally, straight out to
// the internet" — the opposite of what the engine did. The values are whole literal spans
// rather than a class plus a label so that nothing is interpolated into an attribute here.
// An action the frontend has never heard of is shown verbatim in a neutral badge instead of
// being dressed up as DIRECT.
// Keep in sync with the logQuery call sites in internal/core/dns/handler.go.
const STREAM_ACTION_BADGES = {
  PROXY: '<span class="badge badge-proxy">PROXY</span>',
  PROXY_IPV6_SINK: '<span class="badge badge-proxy">PROXY · IPv6 SINK</span>',
  BLOCK: '<span class="badge badge-block">BLOCK</span>',
  RATELIMIT: '<span class="badge badge-block">RATE LIMITED</span>',
  QUOTA: '<span class="badge badge-block">QUOTA</span>',
  CUSTOM: '<span class="badge badge-custom">CUSTOM</span>',
  CACHED: '<span class="badge badge-direct">DIRECT</span>',
  STALE: '<span class="badge badge-cached">STALE</span>',
  DIRECT: '<span class="badge badge-direct">DIRECT</span>',
};

// queryRowHTML renders one query into the seven cells of the stream table. Everything that
// came off the wire is escaped — the row reaches the DOM through innerHTML, and a domain is
// whatever a client asked this resolver to look up.
//
// The third and fifth cells (PROTO, RULE MATCHED) carry `hidden sm:table-cell` to match the
// two <th> in index.html that do the same. The pair has to stay in sync: hide a header
// without its cell and every column after it shifts one place left on a phone.
function queryRowHTML(q) {
  const domain = q.domain || '';
  const clientIP = q.client_ip || '';
  const accountName = q.account_name || 'Public';

  const action = q.action || 'DIRECT';
  const actBadge = STREAM_ACTION_BADGES[action]
    || `<span class="badge badge-unknown">${escapeHTML(action)}</span>`;

  let cacheBadge = q.cached ? '<span class="badge badge-cached ms-1">RAM</span>' : '';
  const timeStr = q.timestamp ? new Date(q.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
  const latVal = (typeof q.latency_ms === 'number') ? q.latency_ms : ((typeof q.latency === 'number') ? q.latency / 1000000 : 0.0);
  const latStr = latVal.toFixed(1) + ' ms';
  const ruleStr = q.rule_name || q.rule_matched || q.rule || 'Default Direct';
  const protoStr = q.protocol || 'UDP';

  // clientIP is escaped like the domain beside it. It is normally a parsed address,
  // but on DoH it can originate from a forwarding header, and the row is written with
  // innerHTML — so the value is treated as data, not markup, rather than relying on
  // every producer upstream to have parsed it first.
  let clientDisplay = `<div class="flex flex-col"><span class="text-cyan-400 font-bold font-mono text-xs leading-tight">${escapeHTML(accountName)}</span><span class="text-[10px] text-slate-400 font-mono">${escapeHTML(clientIP)}</span></div>`;
  if (accountName === 'Public') {
    clientDisplay = `<div class="flex flex-col"><span class="text-slate-300 font-mono text-xs leading-tight">${escapeHTML(clientIP)}</span><span class="text-[10px] text-slate-500 font-mono">Public / Direct</span></div>`;
  }

  return `
    <td class="py-2.5 px-2 sm:px-3 text-slate-400 whitespace-nowrap">${timeStr}</td>
    <td class="py-2.5 px-2 sm:px-3">${clientDisplay}</td>
    <td class="py-2.5 px-2 sm:px-3 text-purple-400 font-bold hidden sm:table-cell">${escapeHTML(protoStr)}</td>
    <td class="py-2.5 px-2 sm:px-3 text-cyan-300 font-semibold max-w-[120px] sm:max-w-xs truncate" title="${escapeHTML(domain)}">${escapeHTML(domain)}</td>
    <td class="py-2.5 px-2 sm:px-3 text-slate-400 hidden sm:table-cell">${escapeHTML(ruleStr)}</td>
    <td class="py-2.5 px-2 sm:px-3">${actBadge}${cacheBadge}</td>
    <td class="py-2.5 px-2 sm:px-3 text-end text-emerald-400 font-mono">${latStr}</td>
  `;
}

// newQueryRow builds the <tr> for one query. The class list is shared by every data row, and
// the absence of stream-placeholder on it is what tells renderQueryStream and the append path
// apart from the two placeholder states.
function newQueryRow(q) {
  const row = document.createElement('tr');
  row.className = 'hover:bg-slate-800/40 transition border-b border-slate-800/40';
  row.innerHTML = queryRowHTML(q);
  return row;
}

// The two placeholder rows. Both carry stream-placeholder, which is how they are recognised —
// the old code matched tbody.children[0].innerText against the string 'Listening', so
// rewording the copy in index.html would have left the placeholder stuck above the first real
// query forever, with nothing anywhere to say why.
const STREAM_LISTENING_ROW = `
  <tr class="stream-placeholder">
    <td colspan="7" class="py-12 text-center text-slate-500">
      <div class="flex flex-col items-center gap-2">
        <div class="pulse-dot"></div>
        <span>Listening for live DNS queries...</span>
      </div>
    </td>
  </tr>`;

// The no-match state names the term and the number of queries held, because "no queries have
// arrived" and "none of the 200 I am holding match this" are opposite situations: the first is
// a resolver nobody is using, the second is a filter to clear. They used to look identical —
// an empty table — and a filtered-out arrival even consumed the Listening placeholder on its
// way to being dropped, so the panel went blank and stayed blank.
function streamNoMatchRow(f) {
  const bits = [];
  if (f.action !== 'ALL') bits.push(`action <span class="text-slate-300">${escapeHTML(f.action)}</span>`);
  if (f.search) bits.push(`&ldquo;<span class="text-slate-300">${escapeHTML(f.search)}</span>&rdquo;`);
  // Unreachable today — with neither control set, every query matches and this row is not
  // rendered — but it keeps the sentence grammatical if that ever stops being true.
  const what = bits.length ? bits.join(' and ') : 'the current filter';
  const held = streamBuffer.length;
  const lead = held === 1
    ? 'The one query received so far does not match'
    : `None of the last ${held} queries match`;
  return `
    <tr class="stream-placeholder">
      <td colspan="7" class="py-12 text-center text-slate-500">
        <div class="flex flex-col items-center gap-1.5">
          <div class="font-bold text-slate-400 font-heading">No Match</div>
          <p class="text-xs">${lead} ${what}.</p>
          <button class="clear-stream-filter-btn mt-1.5 text-[11px] font-bold text-cyan-400 border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 rounded-lg hover:bg-cyan-500/20 transition">
            Show all queries
          </button>
        </div>
      </td>
    </tr>`;
}

// renderQueryStream redraws the table from the buffer. This is what the filter and the search
// box call, so a change applies to the queries already received instead of only to the next
// one to arrive.
function renderQueryStream() {
  const tbody = document.getElementById('stream-tbody');
  if (!tbody) return;

  if (streamBuffer.length === 0) {
    tbody.innerHTML = STREAM_LISTENING_ROW;
    return;
  }

  const f = streamFilterState();
  const rows = streamBuffer.filter((q) => queryMatchesStream(q, f));
  if (rows.length === 0) {
    tbody.innerHTML = streamNoMatchRow(f);
    return;
  }

  // One reflow rather than one per row: on a busy resolver this runs on every keystroke.
  const frag = document.createDocumentFragment();
  for (const q of rows) {
    frag.appendChild(newQueryRow(q));
  }
  tbody.innerHTML = '';
  tbody.appendChild(frag);
}

// The active dashboard tab, set by switchTab. The perf pass (v2.2.0) gates
// per-second DOM work on it: the SSE stream keeps buffering on every tab,
// but its rows are only painted while the stream view (the sidebar's Logs tab, id "stream") is actually showing.
let activeDashTab = 'dashboard';

// pushStreamQuery records one arriving query and, if it belongs in the current view, puts it
// on top without redrawing the rest.
//
// Perf (v2.2.0): the buffer write is cheap and always runs; the DOM work is
// what made the dashboard crawl on a 1-core VPS — one <tr> build + insert per
// DNS query at wire rate, from every tab, in every foreground state. Two
// gates now stand before it: the Logs tab must be the active tab (buffering
// continues elsewhere, and the view repaints from the buffer on switch), and
// the document must be visible. A rAF coalescer collapses bursts that arrive
// inside one frame into a single renderQueryStream pass.
let streamPendingRender = false;
function pushStreamQuery(q) {
  if (!q) return;

  streamBuffer.unshift(q);
  if (streamBuffer.length > STREAM_BUFFER_MAX) streamBuffer.pop();

  if (document.visibilityState === 'hidden' || activeDashTab !== 'stream') return;
  if (isStreamPaused) return;

  if (streamPendingRender) return;
  streamPendingRender = true;
  requestAnimationFrame(() => {
    streamPendingRender = false;
    if (document.visibilityState === 'hidden' || activeDashTab !== 'stream' || isStreamPaused) return;
    const tbody = document.getElementById('stream-tbody');
    // The placeholder (listening / no-match row) is replaced wholesale by a
    // full render; a table still holding one must not have rows inserted
    // above it, which is why the class is looked up before the repaint.
    if (tbody && tbody.querySelector('.stream-placeholder')) tbody.innerHTML = '';
    renderQueryStream();
  });
}

// seedStreamQueries replaces the buffer with a history batch. The server sends newest first,
// which is the order the buffer keeps.
function seedStreamQueries(list) {
  streamBuffer = list.slice(0, STREAM_BUFFER_MAX);
  renderQueryStream();
}

// =======================================================
// CHART.JS TELEMETRY GRAPH
// =======================================================
// QPS_CHART_POINTS is both the number of samples the chart holds and, because
// pushChartData is called exactly once per poll, the width of its window in seconds.
// It is tied to STATS_POLL_MS: change one and the other stops meaning what it says.
const QPS_CHART_POINTS = 60;

// Chart.js paints onto a canvas, and a canvas is the one surface in this panel that CSS
// cannot re-colour: every stroke is a literal string baked in at construction time. So the
// four colours here used to be the four places light mode had no effect at all. Three were
// merely wrong — neon #00f0ff on a white card is a bright smear rather than a line — and one
// was a genuine defect: grid lines of rgba(255,255,255,0.05) are white on white, so the y
// axis in light mode had no gridlines whatsoever and the graph read as a shape with no scale.
//
// The values come from the same custom properties the rest of the panel is built on, read off
// <html> after [data-theme] has changed, so there is one definition of "cyan" per theme rather
// than a canvas-shaped copy of it. The channel tokens hold space-separated RGB — `0 240 255` —
// which is what lets one read serve both an opaque rgb() and the two translucent stops.
function cssVar(name, fallback) {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  } catch (e) {
    return fallback;
  }
}

// chartPalette resolves the four colours for the theme in force right now. The gradient needs
// the 2d context because a CanvasGradient belongs to the context that made it — it cannot be
// built once and reused after a theme flip, which is why this returns a factory rather than a
// value and why applyChartTheme has to call it again rather than mutating a stored stop.
function chartPalette(ctx) {
  const cyan = cssVar('--c-cyan-400', '0 240 255');
  const gradient = ctx.createLinearGradient(0, 0, 0, 220);
  gradient.addColorStop(0, 'rgba(' + cyan.replace(/\s+/g, ',') + ', 0.45)');
  gradient.addColorStop(1, 'rgba(' + cyan.replace(/\s+/g, ',') + ', 0)');
  return {
    line: 'rgb(' + cyan + ')',
    fill: gradient,
    // --border-color is already a full rgba() and already flips: a translucent sky in dark,
    // a translucent slate in light. Reusing it means the gridlines match the hairline on
    // every card around the chart instead of approximating it.
    grid: cssVar('--border-color', 'rgba(255,255,255,0.05)'),
    tick: 'rgb(' + cssVar('--c-slate-400', '100 116 139') + ')'
  };
}

// Re-colour in place on a theme change. update('none') skips the animation, which matters
// here: the whole chart's colours change at once, and animating that reads as a flash.
//
// The context is looked up from the DOM rather than off qpsChart.ctx — Chart.js does expose
// it, but the canvas is the thing that is actually needed and initChart already proves that
// lookup works, so there is no version-specific property standing between a theme flip and a
// legible graph.
function applyChartTheme() {
  if (!qpsChart) return;
  try {
    const canvas = document.getElementById('qpsChart');
    if (!canvas) return;
    const pal = chartPalette(canvas.getContext('2d'));
    const ds = qpsChart.data.datasets[0];
    ds.borderColor = pal.line;
    ds.backgroundColor = pal.fill;
    qpsChart.options.scales.y.grid.color = pal.grid;
    qpsChart.options.scales.y.ticks.color = pal.tick;
    qpsChart.update('none');
  } catch (e) { /* a chart that fails to re-colour is still a readable chart */ }
}

document.addEventListener('hyperdns:theme', applyChartTheme);

function initChart() {
  try {
    const canvas = document.getElementById('qpsChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (typeof Chart === 'undefined') {
      console.warn('Chart.js not yet available');
      return;
    }

    const pal = chartPalette(ctx);

    // One point per poll, and the poll is now 1 Hz — so the point count is the chart's
    // window in seconds. 25 points was a fifty-second window while polling every two
    // seconds; keeping 25 would have silently halved it to twenty-five. Sixty is a
    // minute, which is a span worth reading and is what the panel's subtitle claims.
    const labels = Array.from({ length: QPS_CHART_POINTS }, () => '');
    const data = Array.from({ length: QPS_CHART_POINTS }, () => 0);

    qpsChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'QPS',
          data: data,
          borderColor: pal.line,
          borderWidth: 2,
          backgroundColor: pal.fill,
          fill: true,
          tension: 0.4,
          pointRadius: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        // update('none') already skips the tween, but the option is what
        // keeps Chart.js from arming its animator at all — the cheaper of
        // the two on the 1-core VPS this dashboard runs on.
        animation: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: {
            beginAtZero: true,
            grid: { color: pal.grid },
            ticks: { color: pal.tick, font: { size: 10, family: 'JetBrains Mono' } }
          }
        }
      }
    });
  } catch (e) {
    console.warn('Chart init error:', e);
  }
}

function pushChartData(val) {
  // The chart lives on the Dash view; painting it while another tab is
  // showing spends a canvas render per second on a picture nobody sees.
  // The poll keeps running (the tiles read the same response), so the
  // chart simply resumes on return.
  if (activeDashTab !== 'dashboard') return;
  if (!qpsChart) {
    initChart();
    if (!qpsChart) return;
  }
  // Chart.js draws no point for null and keeps the line's scale honest; pushing an
  // undefined or a NaN instead makes the axis collapse and the last few seconds of
  // real load disappear with it.
  const point = (typeof val === 'number' && isFinite(val) && val >= 0) ? val : null;
  try {
    const d = qpsChart.data.datasets[0].data;
    d.shift();
    d.push(point);
    qpsChart.update('none');
  } catch (e) {}
}

// =======================================================
// EVENT LISTENERS & SPA ROUTING
// =======================================================
const tabRoutes = {
  'dashboard': '/home',
  'clients': '/clients',
  'policy': '/rules',
  'stream': '/logs',
  'api': '/api',
  'rules': '/settings',
  'connect': '/guide'
};

const routeTabs = {
  '/home': 'dashboard',
  '/dashboard': 'dashboard',
  '/panel': 'dashboard',
  '/login': 'dashboard',
  '/clients': 'clients',
  '/rules': 'policy',
  '/policy': 'policy',
  '/logs': 'stream',
  '/stream': 'stream',
  '/api': 'api',
  '/settings': 'rules',
  '/guide': 'connect',
  '/connect': 'connect'
};

function switchTab(target, updateUrl = true) {
  activeDashTab = target;
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
    // Returning to the Logs view repaints the stream from the buffer: the
    // per-query DOM work was skipped while another tab was showing (see
    // pushStreamQuery), so this is where the queued history becomes rows.
    if (target === 'stream') {
      renderQueryStream();
    }
  }

  if (updateUrl && tabRoutes[target]) {
    // The path pushed to history lives below the admin namespace, so the URL a
    // bookmark or a reload comes back with is one the server actually serves
    // (BuildHandler strips <admin-path>/dash before matching it here).
    const newPath = DASH_BASE + tabRoutes[target];
    if (window.location.pathname !== newPath) {
      window.history.pushState({ tab: target }, '', newPath);
    }
  }

  safeFeatherReplace();
}

function handleRouteFromURL() {
  // The admin prefix and the /dash mount point are stripped before the table is
  // consulted, so the same keys work whatever path the install was given. A path
  // that matches nothing falls back to the dashboard, which is the pre-v2.1
  // behaviour for an unknown route and still the least surprising one.
  const stripped = window.location.pathname.toLowerCase().replace(/\/$/, '');
  const withoutBase = ADMIN_BASE && stripped.toLowerCase().startsWith(ADMIN_BASE + '/dash')
    ? stripped.slice((ADMIN_BASE + '/dash').length) || '/'
    : stripped;
  const path = withoutBase || '/home';
  const targetTab = routeTabs[path] || 'dashboard';
  switchTab(targetTab, false);
}

window.addEventListener('popstate', () => {
  handleRouteFromURL();
});

function renderAPIKeyDisplay() {
  const apiKeyDisp = document.getElementById('api-key-display');
  if (!apiKeyDisp || !currentConfig?.server?.api_key) return;
  const rawKey = currentConfig.server.api_key;
  if (isAPIKeyMasked) {
    apiKeyDisp.innerText = '•'.repeat(36);
  } else {
    apiKeyDisp.innerText = rawKey;
  }
}

function updateCodeSnippets(pubIP, apiKey) {
  // v2.1.0 (B-02/B-18 remediation): the snippets are generated from the live
  // configuration — real web port and scheme, not hardcoded 8080/http — and
  // they speak the API's actual contract: the create field is `days`
  // (`expires_days` was never read, silently producing lifetime accounts) and
  // the response is the bare client view, whose `token` is what a subscriber's
  // register link is built from. No `success`/`data.register_url` wrapper —
  // the old snippets treated a successful provisioning as a failure.
  const tls = currentConfig?.tls || {};
  const scheme = tls.panel_https ? 'https' : 'http';
  const port = currentConfig?.server?.web_port || window.location.port || 8080;
  // Domain first: with a configured domain the API is addressed by the name the
  // certificate covers, never the bare IP — an integration copy-pasted from
  // here has to keep working the day the server moves. The IP remains the
  // no-domain fallback, matching dashLoginURL on the Go side.
  const host = (tls.domain && String(tls.domain).trim()) || pubIP;
  const isDefaultPort = (scheme === 'https' && Number(port) === 443) || (scheme === 'http' && Number(port) === 80);
  const origin = `${scheme}://${host}${isDefaultPort ? '' : ':' + port}`;
  // v2 is the contract new integrations are documented against; v1 keeps
  // working behind a Deprecation header but the copy-paste examples a
  // reseller starts from should not begin life deprecated.
  const apiBase = `${origin}${ADMIN_BASE}/api/v2`;

  const curlEl = document.getElementById('snippet-curl');
  if (curlEl) {
    curlEl.innerText = `# 1. Check Engine Health
curl -s "${apiBase}/status" \\
  -H "X-API-Key: ${apiKey}"

# 2. Create User Account (30 Days). v2 answers 201 with the client object;
#    unknown fields are refused (a typo errors instead of being dropped).
curl -s -X POST "${apiBase}/clients" \\
  -H "X-API-Key: ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"display_name":"Gamer-VIP","validity_days":30}'`;
  }

  const pyEl = document.getElementById('snippet-python');
  if (pyEl) {
    pyEl.innerText = `import requests

API_URL = "${apiBase}"
ORIGIN = "${origin}"
HEADERS = {"X-API-Key": "${apiKey}"}

# Create subscriber account on plan purchase
def create_smartdns_user(username, days=30):
    res = requests.post(f"{API_URL}/clients", headers=HEADERS, json={
        "display_name": username,
        "validity_days": days
    })
    res.raise_for_status()          # 201 with the client object
    client = res.json()
    return f"{ORIGIN}/ip/{client['token']}"`;
  }

  const nodeEl = document.getElementById('snippet-nodejs');
  if (nodeEl) {
    nodeEl.innerText = `const axios = require('axios');

const ORIGIN = '${origin}';
const client = axios.create({
  baseURL: '${apiBase}',
  headers: { 'X-API-Key': '${apiKey}' }
});

// Example Telegram Bot Handler
async function onBuySubscription(ctx, username) {
  // 201 Created answers the client object; its token builds the 1-click
  // register link. ORIGIN is the const above — this runs in Node, where
  // window.location does not exist.
  const { data, status } = await client.post('/clients', { display_name: username, validity_days: 30 });
  if (status === 201) {
    ctx.reply(\`SmartDNS Created! Register IP: \${ORIGIN}/ip/\${data.token}\`);
  }
}`;
  }
}
function initAPIEvents() {
  // Show / Hide Key Toggle
  const toggleKeyBtn = document.getElementById('toggle-api-key-visibility');
  if (toggleKeyBtn) {
    toggleKeyBtn.onclick = () => {
      isAPIKeyMasked = !isAPIKeyMasked;
      renderAPIKeyDisplay();
      toggleKeyBtn.innerHTML = isAPIKeyMasked ? '<i data-feather="eye" class="w-4 h-4"></i>' : '<i data-feather="eye-off" class="w-4 h-4 text-cyan-400"></i>';
      safeFeatherReplace();
    };
  }

  // Copy API Key Button
  const copyKeyBtn = document.getElementById('copy-api-key-btn');
  if (copyKeyBtn) {
    copyKeyBtn.onclick = () => {
      if (currentConfig?.server?.api_key) {
        copyText(currentConfig.server.api_key, copyKeyBtn);
      }
    };
  }

  // Regenerate Key Button
  const regenKeyBtn = document.getElementById('regenerate-api-key-btn');
  if (regenKeyBtn) {
    regenKeyBtn.onclick = async () => {
      const ok = await confirmAction({
        destructive: true,
        title: 'Regenerate Master API Key?',
        hint: 'EVERY INTEGRATION BREAKS IMMEDIATELY',
        message: 'The current key stops working the moment the new one is issued. Every external bot, billing hook and script still holding the old key will start getting 401s until you update it by hand.',
        confirmText: 'REGENERATE KEY',
      });
      if (!ok) return;
      // Rotation is a credential change, so the current password is asked for
      // unconditionally — a hijacked session must not be able to rotate the
      // master key, whether or not 2FA is on.
      const currentPassword = await promptForValue({
        title: 'Current Password',
        message: 'Confirm your current admin password to authorise the rotation.',
        label: 'CURRENT PASSWORD',
        placeholder: 'current password',
        mask: true,
      });
      if (!currentPassword) return;
      // When 2FA is on the rotation also requires a current code (B-03
      // remediation): the server reads both from this JSON body.
      let totpCode = '';
      if (currentConfig?.auth?.totp_enabled) {
        totpCode = await promptForValue({
          title: 'Two-Factor Code',
          message: 'Enter the 6-digit code from your authenticator app to authorise the rotation.',
          placeholder: '6-digit code',
        });
        if (!totpCode) return;
      }
      try {
        const res = await fetch(api('/api/settings/regenerate-api-key'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({ regenerate: true, current_password: currentPassword, code: (totpCode || '').trim() })
        });
        if (res.ok) {
          const data = await res.json();
          const newKey = data.api_key || data.data?.api_key;
          if (newKey) {
            if (!currentConfig) currentConfig = { server: {} };
            if (!currentConfig.server) currentConfig.server = {};
            currentConfig.server.api_key = newKey;
            isAPIKeyMasked = false; // unmask on fresh regeneration so user can see it
            renderAPIKeyDisplay();
            updateCodeSnippets(currentConfig.server.public_ip || '127.0.0.1', newKey);
            showToast('Master API Key regenerated successfully!', 'success');
          } else {
            showToast('Failed to regenerate API key', 'error');
          }
        } else {
          showToast(await errorMessage(res, 'Failed to regenerate API key'), 'error');
        }
      } catch (err) {
        showToast('Error regenerating API key', 'error');
      }
    };
  }

  // Public API Toggle (0.0.0.0 bind)
  const togglePublic = document.getElementById('toggle-public-api');
  if (togglePublic) {
    togglePublic.onchange = async () => {
      const willBePublic = togglePublic.checked;
      
      // If attempting to expose publicly without HTTPS domain
      if (willBePublic && (!currentConfig?.tls?.domain || !currentConfig.tls.domain.trim())) {
        togglePublic.checked = false;
        showToast('Cannot expose API to 0.0.0.0: Public API requires an active custom domain and HTTPS configured in Settings to protect credentials.', 'error');
        return;
      }

      const targetBind = willBePublic ? '0.0.0.0' : '127.0.0.1';
      try {
        // /api/settings owns api_bind. This used to post to /api/config/server,
        // which has never read the field — the toggle reported success while
        // nothing was persisted, and reverted on the next page load.
        const res = await fetch(api('/api/settings'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({ api_bind: targetBind })
        });

        if (!res.ok) {
          togglePublic.checked = !willBePublic;
          showToast(await errorMessage(res, 'Failed to update API bind configuration'), 'error');
          return;
        }

        const data = await res.json().catch(() => null);
        if (currentConfig?.server) {
          currentConfig.server.api_bind = (data && data.api_bind) || targetBind;
        }
        renderConfig(currentConfig);
        showToast(willBePublic
          ? 'Public REST API enabled — external callers with a valid key are now accepted (0.0.0.0)'
          : 'REST API restricted to localhost (127.0.0.1)', 'success');
      } catch (err) {
        togglePublic.checked = !willBePublic;
        showToast('Error communicating with server', 'error');
      }
    };
  }

  // Dashboard session idle window (Phase D): load + save through /api/settings.
  const idleInput = document.getElementById('session-idle-minutes');
  const idleSave = document.getElementById('session-idle-save');
  if (idleInput && idleSave) {
    idleSave.addEventListener('click', async () => {
      const raw = Number(idleInput.value);
      if (!Number.isFinite(raw) || raw < 5 || raw > 1440) {
        showToast('Enter a value between 5 and 1440 minutes', 'error');
        return;
      }
      idleSave.disabled = true;
      try {
        const res = await fetch(api('/api/settings'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({ session_idle_minutes: Math.round(raw) })
        });
        if (!res.ok) {
          showToast(await errorMessage(res, 'Failed to save the session timeout'), 'error');
          return;
        }
        const data = await res.json().catch(() => null);
        if (currentConfig?.server && data?.server) {
          currentConfig.server.session_idle_minutes = data.server.session_idle_minutes;
        }
        if (data?.server?.session_idle_minutes) {
          idleInput.value = data.server.session_idle_minutes;
        }
        showToast('Dashboard session timeout applied', 'success');
      } catch (err) {
        showToast('Error communicating with server', 'error');
      } finally {
        idleSave.disabled = false;
      }
    });
  }

  // Snippet Tabs Switching
  document.querySelectorAll('.api-snippet-tab').forEach(tab => {
    tab.onclick = () => {
      const snip = tab.dataset.snippet;
      document.querySelectorAll('.api-snippet-tab').forEach(t => {
        t.className = 'api-snippet-tab px-3 py-1.5 rounded-lg text-xs font-bold font-heading bg-slate-900 text-slate-400 hover:text-white';
      });
      tab.className = 'api-snippet-tab px-3 py-1.5 rounded-lg text-xs font-bold font-heading bg-cyan-500/20 text-cyan-300 border border-cyan-500/30';

      document.querySelectorAll('.api-snippet-content').forEach(c => c.classList.add('hidden'));
      document.getElementById(`snippet-${snip}`)?.classList.remove('hidden');
    };
  });

  window.initSubscriptionSettings?.();
  initAdminPathControls();
  // The 2FA/LDAP panel lives in its own ES module (js/modules/twofa.js);
  // it registers these two hooks on window when the module executes.
  window.initTwoFactorControls?.();
  window.initLdapControls?.();
}

// =======================================================
// v2.1 HIDDEN ADMIN PATH DISPLAY + REGENERATION
// =======================================================

function initAdminPathControls() {
  const display = document.getElementById('admin-path-display');
  const regenBtn = document.getElementById('regen-admin-path-btn');
  const warn = document.getElementById('admin-path-warn');

  window.renderAdminPath = function () {
    if (!display) return;
    const p = currentConfig?.server?.admin_path;
    display.textContent = p ? `/${p}/dash/` : '/…';
  };

  if (!regenBtn) return;
  regenBtn.addEventListener('click', () => {
    if (warn) warn.classList.remove('hidden');
    // The confirm dialog is the operator's explicit second step on top of the
    // server's {"confirm":true} gate: two independent confirmations for an
    // action that invalidates every session and bookmark at once.
    if (!window.confirm('Regenerate the hidden admin path? Every bookmark, integration and session under the old path stops working immediately, and you will be signed out.')) {
      return;
    }
    regenBtn.disabled = true;
    (async () => {
      try {
        const res = await fetch(api('/api/settings/regenerate-admin-path'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ confirm: true })
        });
        if (!res.ok) {
          showToast(await errorMessage(res, 'Failed to regenerate the admin path'), 'error');
          return;
        }
        const data = await res.json().catch(() => ({}));
        const newPath = (data && data.admin_path) || '';
        // The old token died with the session wipe; carry nothing into the new
        // namespace but the browser itself.
        localStorage.removeItem('hyperdns_token');
        authToken = '';
        if (newPath) {
          showToast('Admin path regenerated. Sign in at the new address.', 'success');
          window.location.href = ADMIN_BASE === `/${newPath}`
            ? `${DASH_BASE}/`
            : `${window.location.origin}/${newPath}/dash/login`;
        } else {
          window.location.reload();
        }
      } catch (err) {
        showToast('Could not reach the server.', 'error');
      } finally {
        regenBtn.disabled = false;
      }
    })();
  });
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
    const ok = await confirmAction({
      destructive: true,
      title: 'Restart the Core Engine?',
      hint: 'IN-FLIGHT QUERIES AND RELAYS ARE DROPPED',
      message: 'All policies are reloaded from the database. Listeners go down and come back up, so queries and relays in flight at that moment are lost and clients retry.',
      confirmText: 'RESTART ENGINE',
    });
    if (!ok) return;
    try {
      const res = await fetch(api('/api/server/restart'), {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (res.ok) {
        showToast('Core Engine restarted & rules reloaded!', 'success');
        updateStats();
      } else {
        // A restart that was refused used to look exactly like one that worked:
        // no toast either way.
        showToast(await errorMessage(res, 'Failed to restart engine'), 'error');
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
      signOut();
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
        const res = await fetch(api('/api/upstreams/add'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ address: addr })
        });
        if (res.ok) {
          if (input) input.value = '';
          showToast('Upstream resolver added & tested!', 'success');
          updateStats();
        }
      } catch (e) {
        showToast('Failed to add upstream', 'error');
      }
    };
  }

  // Issue SSL Certificate
  //
  // bindLEButton wires one "Let's Encrypt" button to the shared ACME flow.
  // All three surfaces (panel, subscription, DoH/DoT) drive the same
  // single-flighted issuance; the purpose field tells the daemon which
  // record and listener the certificate belongs to. While a run is in
  // flight the progress bar polls GET /api/tls/acme/status every 500 ms and
  // renders stage + percentage; on completion the config is re-fetched so
  // every section (and the client cards) reflects the new domain, and on
  // failure the error toast carries the daemon's reason.
  window.bindLEButton = function (btn, domainInput, purpose, progressId) {
    if (!btn) return;
    const barWrap = document.getElementById(progressId);
    const bar = document.getElementById(`${progressId}-bar`);
    const barText = document.getElementById(`${progressId}-text`);

    function showProgress(state) {
      if (barWrap) barWrap.classList.remove('hidden');
      if (bar) bar.style.width = `${Math.max(0, Math.min(100, state.progress || 0))}%`;
      if (barText) {
        const stageLine = state.detail || state.stage || 'working…';
        barText.textContent = `${state.progress || 0}% — ${stageLine}`;
      }
    }
    function hideProgress() {
      if (barWrap) barWrap.classList.add('hidden');
    }

    async function pollUntilDone() {
      for (;;) {
        await new Promise(r => setTimeout(r, 500));
        let state = null;
        try {
          const res = await fetch(api('/api/tls/acme/status'), {
            headers: { 'Authorization': `Bearer ${authToken}` }
          });
          if (res.ok) state = await res.json();
        } catch (e) { /* transient poll failure: keep polling */ }
        if (!state || !state.running) return state;
        showProgress(state);
      }
    }

    btn.onclick = async () => {
      const dom = domainInput ? domainInput.value.trim() : '';
      const email = (document.getElementById('ssl-email-input')?.value || '').trim();
      if (!dom && purpose === 'panel') {
        showToast('Please enter a domain name', 'error');
        return;
      }
      btn.disabled = true;
      try {
        const res = await fetch(api('/api/tls/issue'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({ domain: dom, email, purpose })
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          showToast((body && body.error) || 'The request was refused.', 'error');
          return;
        }
        if (body.issuing) {
          showToast(body.detail || 'Requesting the certificate…', 'info');
          const final = await pollUntilDone();
          if (final && final.error) {
            showToast('Issuance failed: ' + (final.error || final.last_detail || 'see the daemon log'), 'error');
          } else if (final && final.progress === 100) {
            showToast(body.detail && body.detail.includes('already on this server')
              ? body.detail : 'Certificate issued and applied.', 'success');
          } else {
            showToast(final && final.last_detail ? final.last_detail : 'Issuance finished — check the daemon log.', 'warning');
          }
        } else {
          // Sync apply (cert already on disk) or the clear gesture.
          showToast(body.detail || 'Applied.', 'success');
        }
        // Refresh everything the domain touches: the config (which carries
        // the records and origins), then the sections rendered from it.
        await loadConfig();
        if (typeof window.renderSubscriptionSettings === 'function') window.renderSubscriptionSettings();
        if (typeof loadClients === 'function') loadClients();
        const dotInput = document.getElementById('dot-domain-input');
        if (dotInput && currentConfig && currentConfig.tls) dotInput.value = currentConfig.tls.dot_domain || '';
      } catch (e) {
        showToast('Could not reach the server, so it is not known whether the request was accepted.', 'error');
      } finally {
        hideProgress();
        btn.disabled = false;
      }
    };
  };

  // The panel + DoH/DoT buttons live in app.js's own settings scope; the
  // subscription button binds itself from its module (twofa.js).
  window.bindLEButton(document.getElementById('issue-ssl-btn'), document.getElementById('ssl-domain-input'), 'panel', 'panel-le-progress');
  window.bindLEButton(document.getElementById('issue-dot-ssl-btn'), document.getElementById('dot-domain-input'), 'dot', 'dot-le-progress');
  const dotDomainInput = document.getElementById('dot-domain-input');
  if (dotDomainInput && currentConfig && currentConfig.tls) dotDomainInput.value = currentConfig.tls.dot_domain || '';

  // Quick Action Profiles
  document.getElementById('profile-gaming-btn')?.addEventListener('click', () => {
    ['preset-riot', 'preset-epic', 'preset-steam', 'preset-pubg', 'preset-cod', 'preset-supercell',
     'preset-ea', 'preset-blizzard', 'preset-ubisoft', 'preset-rockstar', 'preset-xbox', 'preset-playstation', 'preset-roblox',
     'preset-shooters-extra', 'preset-anime-gacha', 'preset-sports-racing', 'preset-coop-survival', 'preset-platforms-extra'].forEach(id => {
      setSwitch(id, true);
    });
    saveRules();
    showToast('Pro Gamer Profile (All 171 Games) Activated!', 'success');
  });

  document.getElementById('profile-streamer-btn')?.addEventListener('click', () => {
    ['preset-discord', 'preset-twitch', 'preset-kick', 'preset-spotify'].forEach(id => {
      setSwitch(id, true);
    });
    saveRules();
    showToast('Streamer & Media Profile Activated!', 'success');
  });

  document.getElementById('profile-dev-btn')?.addEventListener('click', () => {
    setSwitch('preset-dev403', true);
    saveRules();
    showToast('Developer 403 Profile Activated!', 'success');
  });

  document.getElementById('profile-privacy-btn')?.addEventListener('click', () => {
    setSwitch('preset-adblock', true);
    setSwitch('preset-familysafe', true);
    saveRules();
    showToast('AdBlock & Safe Profile Activated!', 'success');
  });

  // Preset switches
  const switches = [
    'preset-riot', 'preset-epic', 'preset-steam', 'preset-pubg', 'preset-cod', 'preset-supercell',
    'preset-discord', 'preset-ea', 'preset-blizzard', 'preset-ubisoft', 'preset-rockstar', 
    'preset-xbox', 'preset-playstation', 'preset-roblox',
    'preset-shooters-extra', 'preset-anime-gacha', 'preset-sports-racing', 'preset-coop-survival', 'preset-platforms-extra',
    'preset-spotify', 'preset-twitch', 'preset-kick', 
    'preset-dev403', 'preset-adblock', 'preset-familysafe',
    // Deliberately absent from every Quick Action profile above: "Pro Gamer" turning
    // this on with one click is the exact bill nobody expects. It is opt-in only.
    'preset-downloads'
  ];
  switches.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.onchange = () => saveRules();
    }
  });

  // Flush Cache
  // Preset update channel (v2.3.0): check / apply / rollback.
  const presetCheckBtn = document.getElementById('preset-check-btn');
  const presetApplyBtn = document.getElementById('preset-apply-btn');
  const presetRollbackBtn = document.getElementById('preset-rollback-btn');
  const presetStatus = document.getElementById('preset-update-status');
  const presetBadge = document.getElementById('preset-update-badge');

  async function presetPost(path) {
    const res = await fetch(api(path), {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    return { ok: res.ok, data: await res.json().catch(() => ({})) };
  }

  if (presetCheckBtn) {
    presetCheckBtn.onclick = async () => {
      presetCheckBtn.disabled = true;
      presetStatus.textContent = 'Checking the preset channel…';
      try {
        const { ok, data } = await presetPost('/api/presets/update/check');
        if (!ok) {
          presetStatus.textContent = `Channel check failed: ${data.error || 'unknown error'}`;
          return;
        }
        if (data.up_to_date) {
          presetStatus.textContent = 'Policy catalog is already up to date.';
          presetBadge.classList.add('hidden');
          presetApplyBtn.classList.add('hidden');
        } else {
          const parts = data.updates.map(u => `${u.name} v${u.from_version}→v${u.to_version}`);
          presetStatus.textContent = `Update available: ${parts.join(', ')}`;
          presetBadge.classList.remove('hidden');
          presetApplyBtn.classList.remove('hidden');
        }
      } catch (e) {
        presetStatus.textContent = 'Channel check failed: network error';
      } finally {
        presetCheckBtn.disabled = false;
      }
    };
  }

  if (presetApplyBtn) {
    presetApplyBtn.onclick = async () => {
      presetApplyBtn.disabled = true;
      presetStatus.textContent = 'Downloading, verifying and applying…';
      try {
        const { ok, data } = await presetPost('/api/presets/update/apply');
        if (!ok) {
          presetStatus.textContent = `Apply failed (rolled back): ${data.error || 'unknown error'}`;
          presetApplyBtn.classList.remove('hidden');
          return;
        }
        presetStatus.textContent = `Catalog updated${data.applied ? `: ${data.applied} policy file(s)` : ''}. Flushing cache…`;
        presetBadge.classList.add('hidden');
        presetApplyBtn.classList.add('hidden');
        presetRollbackBtn.classList.remove('hidden');
        await fetch(api('/api/cache/flush'), {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        presetStatus.textContent += ' done.';
        showToast('Policy catalog updated', 'success');
      } catch (e) {
        presetStatus.textContent = 'Apply failed: network error';
        presetApplyBtn.classList.remove('hidden');
      } finally {
        presetApplyBtn.disabled = false;
      }
    };
  }

  if (presetRollbackBtn) {
    presetRollbackBtn.onclick = async () => {
      presetRollbackBtn.disabled = true;
      try {
        const { ok } = await presetPost('/api/presets/update/rollback');
        if (ok) {
          presetStatus.textContent = 'Rolled back to the previous policy set.';
          presetRollbackBtn.classList.add('hidden');
          showToast('Policy catalog rolled back', 'success');
        } else {
          presetStatus.textContent = 'Rollback failed — see the daemon log.';
          presetRollbackBtn.classList.remove('hidden');
        }
      } finally {
        presetRollbackBtn.disabled = false;
      }
    };
  }

  const flushBtn = document.getElementById('flush-cache-btn');
  if (flushBtn) {
    flushBtn.onclick = async () => {
      try {
        await fetch(api('/api/cache/flush'), {
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

  // Run Benchmark. The server probes every upstream in the background and answers
  // 202 immediately, so this cannot claim "completed" — it reports that the run
  // started, then refreshes the stats twice as the probes land (they are bounded by
  // the upstream timeout, and they all run in parallel).
  const benchBtn = document.getElementById('run-benchmark-btn');
  if (benchBtn) {
    benchBtn.onclick = async () => {
      benchBtn.disabled = true;
      try {
        const res = await fetch(api('/api/benchmark'), {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (res.status === 409) {
          showToast('A benchmark is already running', 'info');
          return;
        }
        if (!res.ok) {
          showToast('Failed to start benchmark', 'error');
          return;
        }
        showToast('Benchmark started — upstream latencies refresh as probes land', 'info');
        setTimeout(updateStats, 1500);
        setTimeout(updateStats, 4000);
      } catch (e) {
        showToast('Failed to start benchmark', 'error');
      } finally {
        setTimeout(() => { benchBtn.disabled = false; }, 4000);
      }
    };
  }

  // Custom policy groups (v2.3)
  document.getElementById('add-custom-group-btn')?.addEventListener('click', () => openCustomGroupEditor(null));
  document.getElementById('cancel-custom-group-btn')?.addEventListener('click', () => {
    document.getElementById('custom-group-editor')?.classList.add('hidden');
  });
  document.getElementById('save-custom-group-btn')?.addEventListener('click', saveCustomGroup);
  document.getElementById('custom-groups-list')?.addEventListener('click', (e) => {
    const editBtn = e.target.closest('.edit-group-btn');
    if (editBtn) {
      const g = customGroupsCache.find((x) => x.id === editBtn.dataset.id);
      if (g) openCustomGroupEditor(g);
      return;
    }
    const delBtn = e.target.closest('.delete-group-btn');
    if (delBtn) deleteCustomGroup(delBtn.dataset.id);
  });

  // Add Custom Proxied
  document.getElementById('add-proxied-btn')?.addEventListener('click', () => {    const input = document.getElementById('new-proxied-input');
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
      await fetch(api('/api/config/access'), {
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
      // Every other destructive control on this panel asks first; this one deleted a
      // resolver on a single tap, and it is rendered inside a list that re-sorts itself
      // by measured latency on every stats tick — so the row under your thumb is not
      // guaranteed to be the row that was there when you started reaching for it. The
      // dialog also gives the operator the one fact that decides the answer: with the
      // last upstream gone there is nothing left to race, and resolution stops.
      const ok = await confirmAction({
        destructive: true,
        title: 'Remove this upstream?',
        hint: 'THE RACER SET SHRINKS IMMEDIATELY',
        message: `${addr}\n\nQueries stop being raced against this resolver at once. If it is the last one configured, nothing remains to answer from and resolution fails until another is added.`,
        confirmText: 'REMOVE UPSTREAM',
      });
      if (!ok) return;
      try {
        await fetch(api('/api/upstreams/delete'), {
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
        await fetch(api('/api/config/access'), {
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
  //
  // The filter and the search box had no listeners at all: both were read inside the append
  // path, so they applied to arriving queries and never to the rows already on screen. These
  // two lines are the whole of the fix on the control side — renderQueryStream redraws from
  // the buffer, so a change now takes effect on the last STREAM_BUFFER_MAX queries at once.
  document.getElementById('stream-filter')?.addEventListener('change', renderQueryStream);
  document.getElementById('stream-search')?.addEventListener('input', renderQueryStream);

  // Delegated on the table body, because the button lives inside markup that is replaced on
  // every keystroke — a listener bound to the button itself would be discarded by the next
  // render.
  document.getElementById('stream-tbody')?.addEventListener('click', (e) => {
    if (!e.target.closest('.clear-stream-filter-btn')) return;
    const filterEl = document.getElementById('stream-filter');
    const searchEl = document.getElementById('stream-search');
    if (filterEl) filterEl.value = 'ALL';
    if (searchEl) searchEl.value = '';
    renderQueryStream();
  });

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
      // Empty the buffer and re-render rather than wiping the tbody. Clearing the markup left
      // a blank table with no placeholder and no way back to one — the old placeholder check
      // required exactly one row containing 'Listening', so it never returned, and a cleared
      // stream was indistinguishable from a dead one until the next query arrived.
      streamBuffer = [];
      renderQueryStream();
    };
  }
}

// =======================================================
// RUN FULL DIAGNOSTICS
// =======================================================
// One run at a time. The endpoint dials eight TCP endpoints with a 2.5 s timeout each, so a
// run against a blocked network takes the full 2.5 s — a wide window in which the Run Test
// button sat live and enabled. Clicking it fired a second concurrent POST, and the results
// list was written by whichever response *finished* first rather than whichever started last:
// the older run could land second and overwrite the newer one's numbers, with nothing on
// screen to say which run the operator was looking at. Opening the modal starts a run too, so
// close-and-reopen did the same thing.
let diagRunning = false;

async function runFullDiagnostics() {
  if (diagRunning) return;
  diagRunning = true;

  const container = document.getElementById('diag-items-list');
  const scoreEl = document.getElementById('diag-score');
  const qualEl = document.getElementById('diag-quality');
  const rerunBtn = document.getElementById('rerun-diagnostics-btn');

  // The banner used to keep the previous run's score for the whole of the next run and, if
  // that run then failed, for good — so the panel showed "88% / EXCELLENT (A+)" directly above
  // "The diagnostic run was refused", and nothing distinguished a fresh grade from a stale
  // one. A run in progress has no score; clear it before asking.
  if (scoreEl) scoreEl.innerText = '--%';
  if (qualEl) qualEl.innerText = 'Testing routes...';
  if (rerunBtn) {
    rerunBtn.disabled = true;
    rerunBtn.classList.add('opacity-50', 'cursor-not-allowed');
  }
  if (container) {
    container.innerHTML = '<div class="text-center py-8 text-cyan-400 font-mono text-xs"><span class="pulse-dot inline-block me-2"></span> Testing VPS connectivity to Riot, Epic, Steam, Discord, EA, Battle.net, PUBG, Spotify...</div>';
  }

  const fail = (msg) => {
    showToast(msg, 'error');
    if (qualEl) qualEl.innerText = 'Test failed';
    if (container) {
      container.innerHTML = `<div class="text-center py-6 text-red-400 text-xs">${escapeHTML(msg)}</div>`;
    }
  };

  try {
    const res = await fetch(api('/api/diagnostics/run'), {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    // A refusal used to `return` straight out, leaving the "Testing VPS
    // connectivity…" spinner on screen for good. An expired session answers 401
    // here, so the most likely reading of a permanent spinner was "the diagnostic
    // hangs", not "log in again".
    if (!res.ok) {
      fail(await errorMessage(res, 'The diagnostic run was refused'));
      return;
    }

    let report = null;
    try {
      report = await res.json();
    } catch (e) {
      // A 200 carrying something that is not JSON means a proxy answered, not the panel's
      // own server. Reporting that as "could not reach the server" named the one thing that
      // had demonstrably just worked.
      fail('The server answered the diagnostic run with a response that is not JSON.');
      return;
    }
    renderDiagnosticsReport(report);
  } catch (e) {
    fail('Could not reach the server to run diagnostics.');
  } finally {
    diagRunning = false;
    if (rerunBtn) {
      rerunBtn.disabled = false;
      rerunBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
  }
}

// renderDiagnosticsReport draws one report and must not throw: it runs inside the try above,
// so an exception here would surface as the catch's "could not reach the server" — a message
// about the network, for a bug in the renderer.
//
// It also shows reachable/total and avg_latency_ms, which the server has always computed and
// sent and the panel has always discarded. The grade alone cannot tell "all eight endpoints
// answered, slowly" from "seven answered instantly and one is unreachable", and average
// handshake time is the number this panel exists to report.
function renderDiagnosticsReport(rep) {
  const report = rep || {};
  const results = Array.isArray(report.results) ? report.results : [];

  const scoreEl = document.getElementById('diag-score');
  if (scoreEl) {
    scoreEl.innerText = Number.isFinite(report.overall_score) ? `${report.overall_score}%` : '--%';
  }

  const qualEl = document.getElementById('diag-quality');
  if (qualEl) {
    const bits = [];
    if (report.overall_quality) bits.push(String(report.overall_quality));
    if (Number.isFinite(report.reachable) && Number.isFinite(report.total)) {
      bits.push(`${report.reachable}/${report.total} reachable`);
    }
    // Guarded on reachable, because the average is over successful dials only: with none, the
    // server sends 0 and "0 ms avg" would read as a perfect result on a fully blocked network.
    if (Number.isFinite(report.avg_latency_ms) && report.reachable > 0) {
      bits.push(`${report.avg_latency_ms} ms avg`);
    }
    // innerText, so the separator and the server's grade string are text either way.
    qualEl.innerText = bits.length ? bits.join(' · ') : 'No result';
  }

  const container = document.getElementById('diag-items-list');
  if (!container) return;

  if (results.length === 0) {
    container.innerHTML = '<div class="text-center py-6 text-slate-500 text-xs">The server reported no diagnostic targets.</div>';
    return;
  }

  const frag = document.createDocumentFragment();
  for (const r of results) {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between py-2 px-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs';

    // latency_ms is 0 on a failed dial and absent from nothing the server sends — but
    // toFixed on a missing field throws, and that throw used to be reported as a network
    // error.
    const ms = Number.isFinite(r.latency_ms) ? r.latency_ms.toFixed(1) : '?';
    const badge = r.success
      ? `<span class="text-emerald-400 font-bold font-mono">${ms} ms</span>`
      : '<span class="text-red-400 font-bold font-mono">BLOCKED</span>';

    row.innerHTML = `
      <div class="flex items-center gap-2">
        <span class="w-2 h-2 rounded-full ${r.success ? 'bg-emerald-400' : 'bg-red-400'}"></span>
        <div>
          <span class="font-bold text-white">${escapeHTML(r.name)}</span>
          <span class="text-[10px] text-slate-500 font-mono ms-1.5">(${escapeHTML(r.target)})</span>
        </div>
      </div>
      <div>${badge}</div>
    `;
    frag.appendChild(row);
  }
  container.innerHTML = '';
  container.appendChild(frag);
}

// =======================================================
// CLIENTS & IP WHITELIST MANAGEMENT (Shelter/Shecan Style)
// =======================================================
let clientsDataCache = null;

// clientsPanelMessage paints a full-width notice into the client grid, in the same shape as the
// two empty states renderClientsList already draws. `body` is markup the caller has escaped —
// there is one caller that interpolates a server string and it wraps it in escapeHTML.
//
// The wrapper carries .clients-placeholder, the same convention the query stream uses for its
// empty row: it is how loadClients tells "the grid is showing a notice" apart from "the grid is
// showing subscriber cards", without inspecting the copy.
function clientsPanelMessage(icon, title, body, titleClass = 'text-slate-300') {
  const listContainer = document.getElementById('clients-list');
  if (!listContainer) return;
  listContainer.innerHTML = `
    <div class="clients-placeholder col-span-1 md:col-span-2 glass-panel p-8 text-center text-slate-400 border border-slate-800">
      <i data-feather="${icon}" class="w-8 h-8 mx-auto text-slate-600 mb-2"></i>
      <div class="font-bold ${titleClass} font-heading">${title}</div>
      <p class="text-xs text-slate-500 mt-1">${body}</p>
    </div>
  `;
  safeFeatherReplace();
}

// loadClients fetches the subscriber list and the access-control mode.
//
// A failure used to be a bare `return` and a console line, and #clients-list used to ship as an
// empty grid holding nothing but an HTML comment — so a 500 or a dropped connection on the first
// load left the operator looking at blank space. Blank space in a list is read as "there is
// nothing here", which for this panel means "my subscribers are gone": the one reading an operator
// would act on, and the one that was never true. The markup now ships a loading notice and every
// failure path below replaces it with what actually happened.
//
// 401 is separated out because it is not a failure of this endpoint, it is an expired session,
// and the answer to it is the login gate rather than an error inside a panel behind it.
async function loadClients() {
  if (!authToken) return;

  // Only when the grid holds no subscriber cards — the first load, or a retry after one that
  // failed. loadClients also runs after every mutation, and flashing the whole grid away each
  // time a client is toggled would be worse than showing nothing.
  const listContainer = document.getElementById('clients-list');
  const showingCards = !!listContainer && listContainer.children.length > 0 &&
    !listContainer.querySelector('.clients-placeholder');
  if (!showingCards) {
    clientsPanelMessage('loader', 'Loading clients…', 'Reading the subscriber list from the server.');
  }

  try {
    const res = await fetch(api('/api/clients'), {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });

    if (res.status === 401) {
      showLoginModal();
      return;
    }
    if (!res.ok) {
      const msg = await errorMessage(res, 'The server refused the request.');
      clientsPanelMessage('alert-triangle', 'Could not load clients',
        `${escapeHTML(msg)} Nothing has been changed — this is a failed read, not an empty list.`,
        'text-amber-300');
      showToast(msg, 'error');
      return;
    }

    clientsDataCache = await res.json();
    renderClientsView(clientsDataCache);
  } catch (e) {
    console.error('Failed to load clients:', e);
    clientsPanelMessage('wifi-off', 'Could not reach the server',
      'The subscriber list could not be read. Nothing has been changed — this is a failed read, not an empty list.',
      'text-amber-300');
    showToast('Could not reach the server to load the client list.', 'error');
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

  // The two badges carry an icon rather than the 🔒/🔓 they used to, and innerHTML rather
  // than innerText because of it. Both names exist in the bundle, and both paths out of this
  // function redraw — the placeholder return below and the tail of the card render — so the
  // <i> never survives as an empty element.
  if (isWhitelistEnforced) {
    if (modeBadge) {
      modeBadge.className = 'badge badge-proxy inline-flex items-center gap-1';
      modeBadge.innerHTML = '<i data-feather="lock" class="w-3 h-3"></i> WHITELIST ENFORCED';
    }
    if (modeText) {
      modeText.innerText = 'Whitelist Mode (Only Registered Clients)';
      modeText.className = 'text-xs font-mono text-cyan-400 font-bold';
    }
  } else {
    if (modeBadge) {
      modeBadge.className = 'badge badge-direct inline-flex items-center gap-1';
      modeBadge.innerHTML = '<i data-feather="unlock" class="w-3 h-3"></i> PUBLIC ACCESS';
    }
    if (modeText) {
      modeText.innerText = 'Public Mode (Anyone can connect)';
      modeText.className = 'text-xs font-mono text-slate-400 font-semibold';
    }
  }

  // Filter clients by search
  const searchInput = document.getElementById('client-search-input');
  const searchVal = searchInput ? searchInput.value.toLowerCase().trim() : '';

  // Kept apart from the filtered list on purpose: "you have no subscribers" and "your
  // search matched none of them" are opposite situations that used to print the same
  // message, and the message was the first one. An operator with fifty paying subscribers
  // who mistyped into the search box was told "No Clients Found — click Add New Client to
  // create client accounts", which reads exactly like a list that has just been wiped.
  const allClients = data.clients || [];
  let clients = allClients;
  if (searchVal) {
    clients = clients.filter(c =>
      c.name.toLowerCase().includes(searchVal) ||
      c.id.includes(searchVal) ||
      // Guarded because allowed_ips is not guaranteed to be an array on the wire: the
      // read path normalises a missing list to [], but POST /api/clients/add answers
      // with the record it just built, and an IP-less create left that field null. An
      // unguarded .some() there would throw on the first keystroke in the search box
      // and take the whole list render with it, so the panel would go blank with only
      // a console error to explain it. Every other allowed_ips reader here already
      // guards; this one was the exception.
      (Array.isArray(c.allowed_ips) && c.allowed_ips.some(ip => ip.includes(searchVal)))
    );
  }

  const listContainer = document.getElementById('clients-list');
  if (!listContainer) return;
  listContainer.innerHTML = '';

  if (clients.length === 0) {
    // Both carry .clients-placeholder for the same reason clientsPanelMessage does: they are
    // notices rather than subscriber cards, and loadClients uses that class to decide whether a
    // reload should show its loading state or leave a populated grid alone.
    listContainer.innerHTML = allClients.length === 0 ? `
      <div class="clients-placeholder col-span-1 md:col-span-2 glass-panel p-8 text-center text-slate-400 border border-slate-800">
        <i data-feather="users" class="w-8 h-8 mx-auto text-slate-600 mb-2"></i>
        <div class="font-bold text-slate-300 font-heading">No Clients Yet</div>
        <p class="text-xs text-slate-500 mt-1">Click "Add New Client" above to create client accounts &amp; registration links.</p>
      </div>
    ` : `
      <div class="clients-placeholder col-span-1 md:col-span-2 glass-panel p-8 text-center text-slate-400 border border-slate-800">
        <i data-feather="search" class="w-8 h-8 mx-auto text-slate-600 mb-2"></i>
        <div class="font-bold text-slate-300 font-heading">No Match</div>
        <p class="text-xs text-slate-500 mt-1">None of your ${allClients.length} client(s) match &ldquo;${escapeHTML(searchVal)}&rdquo;. The search looks at the name, the ID and the registered IPs.</p>
        <button class="clear-client-search-btn mt-3 text-[11px] font-bold text-cyan-400 border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 rounded-lg hover:bg-cyan-500/20 transition">
          Clear search
        </button>
      </div>
    `;
    safeFeatherReplace();
    return;
  }

  // The subscription origin from /api/config wins (Phase 4): links must carry
  // the origin subscribers will actually open, which can differ from the
  // address the panel happens to be viewed at. The scheme arrives with it and
  // is never rebuilt here — a record carrying its own certificate pair is
  // HTTPS even when the panel is plain HTTP, a fact the panel's tls flag
  // cannot express. An empty origin means the daemon has nothing to advertise,
  // and the address the operator is viewing from is the least-bad fallback.
  const subOrigin = currentConfig?.subscription_origin || window.location.origin;
  const currentOrigin = subOrigin || window.location.origin;
  let dnsPrimaryIP = data.public_ip;
  if (!dnsPrimaryIP || dnsPrimaryIP === '127.0.0.1' || dnsPrimaryIP === '0.0.0.0' || dnsPrimaryIP === 'localhost') {
    if (window.location.hostname && window.location.hostname !== '127.0.0.1' && window.location.hostname !== 'localhost') {
      dnsPrimaryIP = window.location.hostname;
    } else {
      dnsPrimaryIP = data.public_ip || '127.0.0.1';
    }
  }

  clients.forEach(c => {
    const isExpired = c.expires_at && c.expires_at !== '0001-01-01T00:00:00Z' && new Date(c.expires_at) < new Date();
    
    let statusBadge = '<span class="badge badge-direct">ACTIVE</span>';
    if (!c.enabled) {
      statusBadge = '<span class="badge badge-block">DISABLED</span>';
    } else if (isExpired) {
      statusBadge = '<span class="badge badge-block">EXPIRED</span>';
    } else if (c.quota_exceeded === true) {
      // The third reason the resolver refuses an account, and the one the card used to
      // hide: a subscriber whose volume is spent was still badged ACTIVE, so the first
      // the reseller heard of it was the customer complaining that nothing resolves.
      // Red like EXPIRED because the effect is the same, worded differently because the
      // fix is not — this one needs volume, not days.
      statusBadge = '<span class="badge badge-block">NO QUOTA</span>';
    }

    let policyBadge = '';
    if (c.custom_policies && c.custom_policies.length > 0) {
      policyBadge = `<span class="badge bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[9px]" title="${escapeHTML(c.custom_policies.join(', '))}">${c.custom_policies.length} Policies</span>`;
    }

    // Two forms of the same instant, because the card shows it in a 103px column and the
    // Bot Card copies it into a message. expText stays precise — full date, hours, minutes,
    // seconds — and goes to the tooltip and to data-exp. expShort is what the cell renders.
    //
    // The cell used to render expText, and at 360px a `truncate` cut it to
    // "10/5/2026 7:39:…", which is worse than showing less: a half-printed clock reads as
    // corrupted data rather than as an elided one. Dropping the time entirely is the right
    // trade because the line directly underneath already carries the number a reseller
    // actually acts on — "(29d 23h remaining)" — so the clock was never the answer to a
    // question anyone was asking, only the date is, and the date fits in nine characters.
    let expText = 'Lifetime (No Expiry)';
    let expShort = expText;
    let remainingText = '';
    if (c.expires_at && c.expires_at !== '0001-01-01T00:00:00Z') {
      const expDate = new Date(c.expires_at);
      expText = expDate.toLocaleDateString() + ' ' + expDate.toLocaleTimeString();
      expShort = expDate.toLocaleDateString();
      const diffMs = expDate - new Date();
      if (diffMs > 0) {
        const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        remainingText = `(${days}d ${hours}h remaining)`;
      } else {
        remainingText = '(Expired)';
      }
    }

    // Two addresses, two jobs (the operator's own algorithm, Phase B):
    //   /sub/<token> is the subscriber's page — the link you hand out, and it is
    //     read-only by itself, so a leaked link moves nobody's binding.
    //   /ip/<token>  is the registration API — it demands the registration
    //     secret, which travels out-of-band (the Bot Card carries it).
    // Reg Link hands out the page; the Bot Card adds the API URL and the secret
    // so the subscriber can actually move their binding.
    const subUrl = `${currentOrigin}/sub/${c.token}`;
    const regApiUrl = `${currentOrigin}/ip/${c.token}`;
    // The first address on file, for pre-filling the "set IP" dialog. At most one is
    // ever stored — see SetClientIP and registerIP, which both replace rather than
    // append, because a subscriber is identified by the address they are on now.
    const currentIP = (c.allowed_ips && c.allowed_ips.length > 0) ? c.allowed_ips[0] : '';

    // Whitelisted IPs HTML tags.
    //
    // Every server-supplied value below goes through escapeHTML. This card is
    // assigned with innerHTML, and a client's name, note and UUID are free text that
    // the operator — or anything holding the API key, such as the Telegram
    // provisioner — can set to whatever it likes. Records written before the address
    // was validated may also hold arbitrary text where an IP belongs. Without
    // escaping, one such value renders as live markup inside the authenticated panel,
    // and a value in a double-quoted attribute does not even need a `<`: closing the
    // quote is enough to add an event handler.
    // The remove button is a `×` glyph, and a glyph is sized by its own font metrics:
    // this one measured 6.6 x 16.5 CSS px on a phone. WCAG 2.2 SC 2.5.8 puts the floor
    // for a touch target at 24 x 24, so it failed on the shorter axis by a factor of
    // three and a half — and it is the control that un-whitelists a paying subscriber.
    // A `w-6 h-6` inline-flex box is exactly 24 x 24 whatever the glyph inside does,
    // because the size no longer comes from the text; `leading-none` keeps the `×`
    // optically centred once the box stops hugging it. The chip grows to fit, which is
    // the trade being made on purpose: one address chip per line on a 360px screen is
    // better than a delete button nobody can hit without zooming.
    let ipsHtml = '';
    if (c.allowed_ips && c.allowed_ips.length > 0) {
      ipsHtml = c.allowed_ips.map(ip => `
        <span class="inline-flex items-center gap-1 ps-2 pe-0.5 py-0.5 rounded-md bg-slate-950 border border-cyan-500/30 text-[11px] font-mono text-cyan-300">
          <span>${escapeHTML(ip)}</span>
          <button class="remove-client-ip-btn inline-flex items-center justify-center w-6 h-6 rounded hover:text-red-400 hover:bg-red-500/10 transition leading-none" data-id="${escapeHTML(c.id)}" data-ip="${escapeHTML(ip)}" title="Remove IP" aria-label="Remove IP ${escapeHTML(ip)}">×</button>
        </span>
      `).join('');
    } else {
      ipsHtml = '<span class="text-slate-500 text-[11px] italic">No IPs registered yet (Share link below)</span>';
    }

    // Traffic. This card is what a reseller looks at to answer "how much of their plan
    // has this subscriber used", and until now it answered in megabytes only — a 40 GB
    // plan reported "41287.3 MB", which nobody can read against a limit in GB. It also
    // showed the used figure with no relation to the limit at all, so the one number
    // that decides whether to renew had to be worked out by hand every time.
    const usedBytes = (typeof c.traffic_used_bytes === 'number' && isFinite(c.traffic_used_bytes) && c.traffic_used_bytes > 0)
      ? c.traffic_used_bytes
      : 0;
    const limitGB = (typeof c.traffic_limit_gb === 'number' && isFinite(c.traffic_limit_gb) && c.traffic_limit_gb > 0)
      ? c.traffic_limit_gb
      : 0;
    const limitText = limitGB > 0 ? `${limitGB} GB` : 'Unlimited';

    let usedText = `Used: ${formatBytes(usedBytes)}`;
    let usedClass = 'text-slate-500';
    if (limitGB > 0) {
      const pct = Math.min(999, Math.round((usedBytes / (limitGB * 1024 * 1024 * 1024)) * 100));
      usedText = `Used: ${formatBytes(usedBytes)} · ${pct}%`;
      // Amber is the warning a reseller can act on before the subscriber calls. Red is
      // not derived from that percentage: c.quota_exceeded is the daemon's own verdict,
      // the same one the resolver enforces with, and 100% here is a rounded figure that
      // can read as full while the account is still being answered.
      if (pct >= 80) usedClass = 'text-amber-400 font-bold';
      if (c.quota_exceeded === true) usedClass = 'text-red-400 font-bold';
    }

    // When the volume comes back, straight from the server. The cycle name alone is
    // not the answer an operator needs — "monthly" on an account anchored to the 31st
    // means the 28th in February — and working it out here would be a second
    // implementation of the clamped-month arithmetic that only the daemon can settle.
    let cycleHtml = '';
    if (c.next_traffic_reset) {
      const next = new Date(c.next_traffic_reset);
      if (!isNaN(next.getTime())) {
        cycleHtml = `<div class="text-emerald-400/80 text-[9px] inline-flex items-center gap-1" title="Volume resets automatically (${escapeHTML(c.traffic_reset_cycle || '')})"><i data-feather="rotate-cw" class="w-2.5 h-2.5"></i>${escapeHTML(next.toLocaleDateString())}</div>`;
      }
    }

    const queriesText = (typeof c.total_queries === 'number' && isFinite(c.total_queries))
      ? c.total_queries.toLocaleString()
      : '—';

    // Two bugs lived on this one line. Go marshals a never-set time.Time as
    // "0001-01-01T00:00:00Z", which is a perfectly truthy string, so a subscriber who
    // has never sent a query was reported as last seen at midnight — the expiry field
    // right next to it already guarded for exactly this value. And the time was
    // rendered with toLocaleTimeString() alone, so "last seen 3:04 PM" was
    // indistinguishable between this afternoon and three weeks ago.
    let lastSeenText = 'Never';
    if (c.last_seen && c.last_seen !== '0001-01-01T00:00:00Z') {
      const seen = new Date(c.last_seen);
      if (!isNaN(seen.getTime())) {
        const ageMin = Math.floor((Date.now() - seen.getTime()) / 60000);
        if (ageMin < 1) lastSeenText = 'just now';
        else if (ageMin < 60) lastSeenText = `${ageMin}m ago`;
        else if (ageMin < 1440) lastSeenText = `${Math.floor(ageMin / 60)}h ago`;
        else lastSeenText = `${Math.floor(ageMin / 1440)}d ago`;
      }
    }

    const card = document.createElement('div');
    card.className = 'glass-panel p-4 sm:p-5 flex flex-col justify-between space-y-4 border border-slate-800 hover:border-cyan-500/40 transition';
    card.innerHTML = `
      <div>
        <!-- Card Header -->
        <!-- min-w-0/flex-1 on the text block and shrink-0 on the buttons are
             load-bearing on a phone. The Slug is one unbreakable 64-character
             token, so without min-w-0 it sets the block's minimum width at
             ~345px — wider than the whole header on a 375px screen — and the
             flex row pushed the edit/pause/delete group clean off the right
             edge of the viewport, unreachable. The slug line truncates like
             the UUID row below it does, with the full value kept on the title. -->
        <div class="flex items-start justify-between gap-2 mb-2 pb-2 border-b border-slate-800/80">
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="text-sm font-bold text-white font-heading">${escapeHTML(c.name)}</h4>
              ${statusBadge}
              ${policyBadge}
            </div>
            <div class="text-[10px] text-slate-400 font-mono mt-0.5 truncate" title="Code: ${escapeHTML(c.id)} · Slug: ${escapeHTML(c.token)}">
              Code: <span class="text-amber-300 font-bold">${escapeHTML(c.id)}</span> · Slug: <span class="text-slate-500">${escapeHTML(c.token)}</span>
            </div>
          </div>

          <div class="flex items-center gap-1 shrink-0">
            <button class="edit-client-btn p-1.5 rounded-lg bg-slate-900 hover:bg-cyan-500/20 text-slate-400 hover:text-cyan-300 border border-slate-800 transition" data-id="${escapeHTML(c.id)}" title="Edit Client">
              <i data-feather="edit-2" class="w-3.5 h-3.5"></i>
            </button>
            <button class="toggle-client-btn p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-cyan-400 border border-slate-800 transition" data-id="${escapeHTML(c.id)}" data-enabled="${!c.enabled}" title="${c.enabled ? 'Disable Client' : 'Enable Client'}">
              <i data-feather="${c.enabled ? 'pause' : 'play'}" class="w-3.5 h-3.5"></i>
            </button>
            <button class="delete-client-btn p-1.5 rounded-lg bg-slate-900 hover:bg-red-500/20 text-slate-400 hover:text-red-400 border border-slate-800 transition" data-id="${escapeHTML(c.id)}" data-name="${escapeHTML(c.name)}" title="Delete Client">
              <i data-feather="trash-2" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </div>

        <!-- UUID Row -->
        <!-- shrink-0 on the copy button is load-bearing next to the truncating UUID: the
             row is justify-between with a flexible middle child, so without it the button
             is the first thing the layout takes width from when a long UUID and a narrow
             phone compete. A 6x6 box puts it at exactly the 24px WCAG 2.2 SC 2.5.8 floor,
             up from the 16x16 that p-0.5 around a 12px icon produced — and this is the
             control a reseller uses most, because the UUID is what goes into the
             subscriber's config. -->
        <div class="flex items-center justify-between text-[10px] font-mono bg-slate-950/80 px-2.5 py-1.5 rounded-lg border border-slate-800/80 mb-2.5">
          <span class="text-slate-500 font-semibold">UUID:</span>
          <span class="text-cyan-300 truncate max-w-[180px] sm:max-w-[210px] select-all" title="${escapeHTML(c.uuid)}">${escapeHTML(c.uuid) || 'N/A'}</span>
          <button class="copy-uuid-btn inline-flex items-center justify-center w-6 h-6 shrink-0 rounded text-slate-400 hover:text-cyan-300 hover:bg-cyan-500/10 transition ms-1" data-uuid="${escapeHTML(c.uuid)}" title="Copy UUID" aria-label="Copy UUID">
            <i data-feather="copy" class="w-3 h-3"></i>
          </button>
        </div>

        <!-- Whitelisted IPs Row -->
        <!-- The 10px label gave this button a 15px-tall hit area — wide enough to hit by
             accident, short enough to miss on purpose. A 24px min-height reaches the
             floor without moving the text, and the negative inline-end margin cancels the
             new padding so the label still sits flush with the row's edge; the hit area
             grows outward into the gutter rather than pushing the layout around. -->
        <div class="space-y-1.5 mb-3">
          <div class="flex items-center justify-between text-[11px]">
            <span class="text-slate-400 font-semibold">Registered IP (Max 1):</span>
            <button class="add-ip-prompt-btn text-cyan-400 hover:text-cyan-300 text-[10px] font-mono flex items-center justify-center gap-0.5 min-h-[24px] px-1.5 -me-1.5 rounded hover:bg-cyan-500/10 transition" data-id="${escapeHTML(c.id)}" data-ip="${escapeHTML(currentIP)}">
              + Set IP Manually
            </button>
          </div>
          <div class="flex flex-wrap gap-1.5">
            ${ipsHtml}
          </div>
        </div>

        <!-- Expiration & Metrics -->
        <div class="grid grid-cols-3 gap-2 text-[10px] font-mono bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
          <div>
            <span class="text-slate-500 uppercase">Plan Expiry</span>
            <div class="text-slate-200 font-bold truncate" title="${escapeHTML(expText)}">${escapeHTML(expShort)}</div>
            <div class="text-emerald-400 text-[9px]">${escapeHTML(remainingText)}</div>
          </div>
          <div>
            <span class="text-slate-500 uppercase">Traffic Limit</span>
            <div class="text-amber-300 font-bold">${limitText}</div>
            <div class="${usedClass} text-[9px]">${usedText}</div>
            ${cycleHtml}
          </div>
          <div>
            <span class="text-slate-500 uppercase">Queries</span>
            <div class="text-cyan-300 font-bold">${queriesText}</div>
            <div class="text-slate-500 text-[9px]">Last seen: ${lastSeenText}</div>
          </div>
        </div>
      </div>

      <!-- Quick Action Buttons -->
      <div class="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-xs">
        <button class="copy-reg-link-btn py-1.5 px-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[11px] font-bold font-heading flex items-center justify-center gap-1 transition truncate" data-url="${escapeHTML(subUrl)}">
          <i data-feather="link" class="w-3 h-3 flex-shrink-0"></i>
          <span>Reg Link</span>
        </button>

        <button class="copy-telegram-card-btn py-1.5 px-2 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[11px] font-bold font-heading flex items-center justify-center gap-1 transition truncate"
          data-id="${escapeHTML(c.id)}" data-name="${escapeHTML(c.name)}" data-exp="${escapeHTML(expText)}" data-url="${escapeHTML(subUrl)}" data-reg-url="${escapeHTML(regApiUrl)}" data-secret="${escapeHTML(c.register_secret || '')}" data-ip="${escapeHTML(dnsPrimaryIP)}" data-uuid="${escapeHTML(c.uuid)}">
          <i data-feather="send" class="w-3 h-3 flex-shrink-0"></i>
          <span>Bot Card</span>
        </button>

        <button class="renew-client-btn py-1.5 px-2 rounded-lg bg-slate-900 hover:bg-emerald-500/20 text-slate-300 hover:text-emerald-400 border border-slate-800 text-[11px] font-bold font-heading flex items-center justify-center gap-1 transition truncate" data-id="${escapeHTML(c.id)}">
          <i data-feather="clock" class="w-3 h-3 flex-shrink-0"></i>
          <span>+30 Days</span>
        </button>
      </div>
    `;

    listContainer.appendChild(card);
  });

  safeFeatherReplace();
}

// Generate the Telegram provisioning card for a subscriber.
//
// The card is the out-of-band channel the Phase B design depends on: the /sub/
// page is read-only on its own, so the registration secret has to reach the
// subscriber somewhere other than the portal link. It used to be a Shelcan-
// style message that named the retired /ip/ link as if it were the subscriber
// page and printed the literal string "دی ان اس اختصاصی شما :" with nothing
// after it — an operator copying it sent a link that has been an API since
// v2.1, next to an empty field.
//
// Four pieces now, each with a job: where to manage the subscription, the
// secret, the address to point their console at, and the API endpoint for a
// scripted client. The secret is printed because this text is written by an
// authenticated operator into a private chat with their customer.
function generateClientTelegramMessage(clientId, clientName, expStr, subUrl, regApiUrl, secret, dnsIP) {
  const serverLine = dnsIP || '(server address not configured)';
  const secretLine = secret ? secret : '(no secret on file — regenerate it in the panel)';
  return `🎮 اکانت SmartDNS شما آماده است

🔹 کد کاربری : ${clientId}
🔹 تاریخ انقضای پلن : ${expStr}

📄 لینک پنل اشتراک شما (وضعیت، حجم و تمدید):
${subUrl}

📶 دی ان اس اختصاصی شما :
🔹 Primary : ${serverLine}
🔹 Secondary : 1.1.1.1

مراحل ثبت آیپی :
1️⃣ گوشی موبایل و کنسول بازی را به یک اینترنت مشترک وصل کنید .
2️⃣ بدون فیلترشکن، لینک پنل اشتراک بالا را باز کنید .
3️⃣ رمز ثبت زیر را وارد کرده و دکمهٔ «ثبت آیپی من» را بزنید .
❌ در صورت عدم ثبت آیپی، DNS برای شما متصل نخواهد شد ❌

🔑 رمز ثبت آیپی (Registration Secret) :
${secretLine}

🔗 آدرس API ثبت آیپی (برای اتوماسیون):
${regApiUrl}`;
}

// Attach Client View Event Listeners
function initClientEventListeners() {
  // Add Client Modal handlers. The form is reset on every open, so a half-filled
  // create attempt abandoned with the × never seeds the next one.
  const addModal = document.getElementById('add-client-modal');
  const openBtn = document.getElementById('open-add-client-btn');
  if (openBtn) {
    openBtn.onclick = () => {
      resetAddClientForm();
      addModal?.classList.remove('hidden');
    };
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
      const initIP = document.getElementById('client-initial-ip')?.value.trim();

      // The whole plan in one request. Until these fields were on this form, the
      // volume had to be added afterwards by reopening the account in the edit modal —
      // and between the two steps the subscriber was live with no limit at all, with
      // nothing on screen saying so. The policies are on the form for the same
      // reason: an account created inheriting everything and corrected later is live
      // with the wrong rules for the whole gap between the two writes.
      const trafficGB = parseFloat(document.getElementById('client-traffic-input')?.value) || 0;
      const cycle = document.getElementById('client-traffic-cycle')?.value || '';
      const maxDevices = parseInt(document.getElementById('client-max-devices')?.value, 10) || 0;

      // The exact moment the picker answered, sent as RFC 3339 like the edit form
      // sends its expiry. An empty field is a lifetime plan and omits the key, which
      // the server reads as "not chosen" rather than as the zero time.
      const expiryVal = document.getElementById('add-client-expiry')?.value || '';
      let expiresAtISO = '';
      if (expiryVal) {
        const parsed = new Date(expiryVal);
        if (!isNaN(parsed.getTime())) expiresAtISO = parsed.toISOString();
      }

      try {
        const res = await fetch(api('/api/clients/add'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
          body: JSON.stringify({
            name: name,
            expires_at: expiresAtISO || undefined,
            initial_ip: initIP,
            traffic_limit_gb: trafficGB,
            traffic_reset_cycle: cycle,
            max_devices: maxDevices,
            custom_policies: addPolicyPicker.get()
          })
        });

        if (res.ok) {
          const client = await res.json().catch(() => ({}));
          addModal?.classList.add('hidden');
          resetAddClientForm();
          showToast('Client account created!', 'success');
          // The create response is the one moment the register link id and the
          // registration secret are both in hand (Phase B: the link displays,
          // the secret writes). Hand them to the created-modal instead of
          // letting the operator go hunting through the card's Bot Card — the
          // secret field there reads the LIST response, which is fine, but the
          // natural next action after creating a subscriber is sending them
          // their credentials, not navigating away to find them.
          showClientCreatedModal(client);
          await loadClients();
        } else {
          // The server's own reason, not a generic failure. A rejected cycle name and
          // a duplicate IP are both 400 here, and the difference is the whole of what
          // the operator has to fix.
          showToast(await errorMessage(res, 'Failed to create client'), 'error');
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
      const res = await fetch(api('/api/access/mode'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify({ allow_all: allowAll })
      });

      if (res.ok) {
        showToast(isEnforced ? 'Whitelist mode enforced (Only registered clients)' : 'Open public mode activated', 'info');
        loadClients();
      }
    } catch (e) {
      showToast('Failed to update access mode', 'error');
    }
  });

  // Search input live filter. Debounced (v2.2.0 perf pass): every keystroke
  // rebuilt the entire clients grid — one innerHTML card per subscriber plus
  // a document-wide icon sweep — which on a large roster made typing feel
  // like lag. 150 ms collapses a burst of keys into one rebuild.
  let clientSearchTimer = null;
  document.getElementById('client-search-input')?.addEventListener('input', () => {
    if (!clientsDataCache) return;
    clearTimeout(clientSearchTimer);
    clientSearchTimer = setTimeout(() => renderClientsView(clientsDataCache), 150);
  });

  // The "Clear search" button in the no-match state. Delegated on the container, not bound
  // after each render, because the container's innerHTML is replaced on every keystroke —
  // a listener attached to the button itself would be discarded by the next one.
  document.getElementById('clients-list')?.addEventListener('click', (e) => {
    if (!e.target.closest('.clear-client-search-btn')) return;
    const input = document.getElementById('client-search-input');
    if (!input) return;
    input.value = '';
    if (clientsDataCache) renderClientsView(clientsDataCache);
    input.focus();
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
      const exp = cardBtn.dataset.exp;
      const subUrl = cardBtn.dataset.url;
      const regApiUrl = cardBtn.dataset.regUrl;
      const secret = cardBtn.dataset.secret;
      const ip = cardBtn.dataset.ip;
      const msg = generateClientTelegramMessage(id, cardBtn.dataset.name, exp, subUrl, regApiUrl, secret, ip);
      copyText(msg, cardBtn);
      showToast('Persian client card copied for Telegram!', 'success');
      return;
    }

    // 3. Renew Client (+30 Days)
    const renewBtn = e.target.closest('.renew-client-btn');
    if (renewBtn) {
      await clientAction(
        '/api/clients/renew',
        { id: renewBtn.dataset.id, extend_days: 30 },
        'Client plan extended by 30 days!',
        'success'
      );
      return;
    }

    // 4. Toggle Client
    const toggleBtn = e.target.closest('.toggle-client-btn');
    if (toggleBtn) {
      const enabled = toggleBtn.dataset.enabled === 'true';
      await clientAction(
        '/api/clients/toggle',
        { id: toggleBtn.dataset.id, enabled: enabled },
        `Client ${enabled ? 'enabled' : 'disabled'}`
      );
      return;
    }

    // 5. Delete Client
    const delBtn = e.target.closest('.delete-client-btn');
    if (delBtn) {
      const id = delBtn.dataset.id;
      const name = delBtn.dataset.name;
      const ok = await confirmAction({
        destructive: true,
        title: 'Delete this subscriber?',
        hint: 'PERMANENT — THE ACCOUNT AND ITS TRAFFIC HISTORY ARE GONE',
        // The name is operator-supplied free text and reaches the dialog through
        // textContent, so a name containing markup is shown, not run.
        message: `${name} (${id})\n\nTheir subscription link stops working immediately and their whitelisted address stops resolving. There is no undo — a new account gets a new ID, a new UUID and a new link.`,
        confirmText: 'DELETE SUBSCRIBER',
      });
      if (!ok) return;
      await clientAction('/api/clients/delete', { id: id }, 'Client deleted');
      return;
    }

    // 6. Set the client's whitelisted address
    const addIpBtn = e.target.closest('.add-ip-prompt-btn');
    if (addIpBtn) {
      const id = addIpBtn.dataset.id;
      const current = addIpBtn.dataset.ip || '';
      const ip = await promptForValue({
        title: 'Set the whitelisted address',
        label: 'IPv4 or IPv6 address',
        placeholder: '2.189.86.32',
        value: current,
        // "Set", not "add": the backend stores one address per subscriber and
        // replaces it, because a subscriber is identified by the address they are
        // on right now and their ISP moves it. The old copy said "add", so an
        // operator entering a second address believed they had two.
        message: current
          ? `This replaces the address on file (${current}). A subscriber has one address at a time — the resolver answers whichever one is stored here.`
          : 'A subscriber has one address at a time. The resolver answers the address stored here and refuses every other source.',
        confirmText: 'SAVE ADDRESS',
        validate: (value) => {
          if (!value) return 'Enter an address, or press Cancel to leave it unchanged.';
          if (!isProbablyIP(value)) return 'That is not an IP address. Expected something like 2.189.86.32 or 2001:db8::1.';
          return '';
        },
      });
      if (!ip) return;
      await clientAction('/api/clients/add_ip', { id: id, ip: ip }, `Whitelisted ${ip}`, 'success');
      return;
    }

    // 7. Remove Whitelisted IP
    const remIpBtn = e.target.closest('.remove-client-ip-btn');
    if (remIpBtn) {
      const id = remIpBtn.dataset.id;
      const ip = remIpBtn.dataset.ip;
      const ok = await confirmAction({
        destructive: true,
        title: 'Remove this address?',
        hint: 'THE SUBSCRIBER STOPS RESOLVING IMMEDIATELY',
        message: `${ip}\n\nThis is the only address on file for the account, so removing it leaves nothing whitelisted and every query from them is refused until an address is set again — theirs or one they register from the portal.`,
        confirmText: 'REMOVE ADDRESS',
      });
      if (!ok) return;
      await clientAction('/api/clients/remove_ip', { id: id, ip: ip }, 'IP removed from client');
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

// Copy-to-clipboard, by delegation.
//
// The four copyable boxes in the setup guide used to carry an inline click-handler
// attribute that called copyText with the referenced element's innerText. That works,
// and it is also the reason the Content-Security-Policy still has to allow
// 'unsafe-inline' in script-src — a policy that permits inline script permits any
// inline script an injection manages to place, which is most of what a CSP is there
// to stop. Every inline handler has to go before that can be tightened, so they are
// being converted rather than left alone.
//
// One listener on document is also simply more robust than an attribute per element:
// it keeps working when a view is re-rendered, and a new copyable box becomes markup
// only. The element declares what to copy with data-copy-target="<id>".
function copyFromTarget(host) {
  const id = host.getAttribute('data-copy-target');
  const source = id ? document.getElementById(id) : null;
  // Read the referenced element, not the host: the host also contains the copy icon,
  // and on a box whose text is an IP address a stray glyph is not obvious in the
  // clipboard but is fatal when pasted into a DNS field.
  const text = ((source || host).innerText || '').trim();
  if (text) copyText(text, host);
}

document.addEventListener('click', (e) => {
  const host = e.target.closest('[data-copy-target]');
  if (host) copyFromTarget(host);
});

// The boxes are exposed as buttons, so they have to answer what a button answers.
// Space needs preventDefault or the page scrolls out from under the copy; older
// WebKit reports it as 'Spacebar'.
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;
  const host = e.target.closest?.('[data-copy-target]');
  if (!host) return;
  e.preventDefault();
  copyFromTarget(host);
});

// =======================================================
// IN-APP DIALOGS (a promise-based confirm / prompt)
// =======================================================
// window.confirm and window.prompt block the event loop, so the live event
// stream and every chart on the page freeze until the operator answers. Worse,
// a browser is allowed to suppress them outright: once Chrome's "prevent this
// page from creating additional dialogs" box is ticked, confirm() returns false
// and prompt() returns null without asking anyone. A suppressed confirm() turned
// "delete this client" into a silent no-op and a suppressed prompt() into "no IP
// entered" — both indistinguishable from the operator pressing Cancel, on a
// panel whose whole job is destructive administrative actions.
//
// showDialog resolves to true/false for a confirm and to the trimmed string or
// null for a prompt. It never rejects, so a caller still reads as
// `if (!await confirmAction({...})) return;`.
let activeDialog = null;
let dialogSeq = 0;

function showDialog(opts) {
  const o = opts || {};
  const isPrompt = o.kind === 'prompt';
  const cancelValue = isPrompt ? null : false;

  return new Promise((resolve) => {
    // One at a time: a second call while one is open cancels the first rather
    // than stacking two backdrops, two focus traps and two Escape handlers.
    if (activeDialog) activeDialog.finish();

    const returnFocusTo = document.activeElement;
    const seq = ++dialogSeq;
    // Both branches spell every class out in full. A composed name like
    // `border-${accent}-500/40` is invisible to Tailwind's content scanner and
    // would simply be absent from the built stylesheet.
    const tone = o.destructive
      ? {
          icon: 'alert-triangle',
          panel: 'glass-panel p-6 w-full max-w-md border border-red-500/40 shadow-2xl shadow-red-500/10',
          badge: 'w-10 h-10 rounded-xl bg-red-500/20 flex items-center justify-center text-red-400 border border-red-500/30 shrink-0',
          hint: 'text-xs text-red-400 font-mono',
          submit: 'flex-1 py-3 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-700 hover:to-rose-700 text-onfill font-bold rounded-lg transition duration-200 shadow-lg shadow-red-500/20 text-sm font-heading',
        }
      : {
          icon: 'help-circle',
          panel: 'glass-panel p-6 w-full max-w-md border border-cyan-500/40 shadow-2xl shadow-cyan-500/10',
          badge: 'w-10 h-10 rounded-xl bg-cyan-500/20 flex items-center justify-center text-cyan-400 border border-cyan-500/30 shrink-0',
          hint: 'text-xs text-cyan-400 font-mono',
          submit: 'flex-1 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 text-slate-950 font-bold rounded-lg transition duration-200 shadow-lg shadow-cyan-500/20 text-sm font-heading',
        };
    const backdrop = document.createElement('div');
    backdrop.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md px-4';

    const panel = document.createElement('div');
    panel.className = tone.panel;
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    panel.setAttribute('aria-labelledby', `dialog-title-${seq}`);
    panel.setAttribute('aria-describedby', `dialog-msg-${seq}`);

    const header = document.createElement('div');
    header.className = 'flex items-center gap-3 mb-4';
    const badge = document.createElement('div');
    badge.className = tone.badge;
    badge.setAttribute('aria-hidden', 'true');
    badge.innerHTML = `<i data-feather="${tone.icon}"></i>`;
    const headings = document.createElement('div');
    const title = document.createElement('h2');
    title.id = `dialog-title-${seq}`;
    title.className = 'text-lg font-bold text-white tracking-wide font-heading';
    title.textContent = o.title || 'Confirm';
    headings.appendChild(title);
    if (o.hint) {
      const hint = document.createElement('p');
      hint.className = tone.hint;
      hint.textContent = o.hint;
      headings.appendChild(hint);
    }
    header.appendChild(badge);
    header.appendChild(headings);

    // textContent, not innerHTML: these messages name a client, and a client name
    // is free text that an operator or any API-key holder can set.
    const message = document.createElement('p');
    message.id = `dialog-msg-${seq}`;
    message.className = 'text-xs text-slate-300 leading-relaxed mb-5 whitespace-pre-line';
    message.textContent = o.message || '';

    const form = document.createElement('form');
    form.className = 'space-y-4';
    form.noValidate = true;
    let input = null;
    let errorLine = null;
    if (isPrompt) {
      const field = document.createElement('div');
      const label = document.createElement('label');
      label.className = 'block text-xs font-semibold text-slate-400 mb-1';
      label.setAttribute('for', `dialog-input-${seq}`);
      label.textContent = o.label || 'VALUE';
      input = document.createElement('input');
      input.id = `dialog-input-${seq}`;
      input.type = o.mask ? 'password' : 'text';
      input.className = 'w-full px-4 py-2.5 rounded-lg bg-slate-950/80 border border-slate-700 text-white focus:outline-none focus:border-cyan-400 text-sm font-mono';
      input.value = o.value || '';
      input.autocomplete = 'off';
      input.spellcheck = false;
      if (o.placeholder) input.placeholder = o.placeholder;
      if (o.maxlength) input.maxLength = o.maxlength;
      if (o.inputMode) input.inputMode = o.inputMode;
      errorLine = document.createElement('p');
      errorLine.id = `dialog-error-${seq}`;
      errorLine.className = 'mt-1.5 text-[11px] text-red-400 leading-relaxed hidden';
      // assertive, not polite: this text explains why the button the operator
      // just pressed did nothing, and a polite region waits for a quiet moment
      // that a modal with a single input never provides.
      errorLine.setAttribute('role', 'alert');
      errorLine.setAttribute('aria-live', 'assertive');
      input.setAttribute('aria-describedby', errorLine.id);
      field.appendChild(label);
      field.appendChild(input);
      field.appendChild(errorLine);
      form.appendChild(field);
    }

    const row = document.createElement('div');
    row.className = 'flex gap-3';
    const cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.className = 'px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold rounded-lg transition duration-200 text-sm font-heading';
    cancelBtn.textContent = o.cancelText || 'CANCEL';
    const submitBtn = document.createElement('button');
    submitBtn.type = 'submit';
    submitBtn.className = tone.submit;
    submitBtn.textContent = o.confirmText || (isPrompt ? 'SAVE' : 'CONFIRM');
    row.appendChild(cancelBtn);
    row.appendChild(submitBtn);
    form.appendChild(row);
    panel.appendChild(header);
    panel.appendChild(message);
    panel.appendChild(form);
    backdrop.appendChild(panel);
    document.body.appendChild(backdrop);
    // The backdrop is already on screen at this point and none of the handlers below are wired
    // yet, so an exception here would leave a dialog with no working buttons, no Escape and no
    // resolve — a modal the operator cannot get out of. safeFeatherReplace is the same call with
    // that outcome removed.
    safeFeatherReplace();

    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (activeDialog === handle) activeDialog = null;
      document.removeEventListener('keydown', onKeydown, true);
      backdrop.remove();
      // Hand focus back to whatever opened this, or a keyboard operator is
      // returned to the top of the document with no idea which row they were on.
      if (returnFocusTo && document.contains(returnFocusTo) && typeof returnFocusTo.focus === 'function') {
        try { returnFocusTo.focus(); } catch (e) { /* the element went away */ }
      }
      resolve(result === undefined ? cancelValue : result);
    };
    const handle = { finish };
    activeDialog = handle;

    const onKeydown = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        finish();
        return;
      }
      if (e.key !== 'Tab') return;
      // A real trap, not just a wrap: focus that has already escaped the panel
      // (a click on the backdrop, a browser-restored focus) is pulled back in.
      const focusables = panel.querySelectorAll('button:not([disabled]), input:not([disabled]), select, textarea, [href]');
      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const inside = panel.contains(document.activeElement);
      if (e.shiftKey && (!inside || document.activeElement === first)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (!inside || document.activeElement === last)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeydown, true);
    cancelBtn.addEventListener('click', () => finish());
    // Only a press that lands on the backdrop itself, never one that bubbled up
    // from inside the panel.
    backdrop.addEventListener('mousedown', (e) => {
      if (e.target === backdrop) finish();
    });

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!isPrompt) {
        finish(true);
        return;
      }
      const value = (input.value || '').trim();
      const problem = typeof o.validate === 'function'
        ? o.validate(value)
        : (value ? '' : 'This field cannot be empty.');
      if (problem) {
        // The dialog stays open with the bad value still in it. A native prompt()
        // could only close and be reopened empty, which is why the old IP entry
        // had no validation at all: there was nowhere to put the complaint.
        errorLine.textContent = problem;
        errorLine.classList.remove('hidden');
        input.setAttribute('aria-invalid', 'true');
        input.focus();
        input.select();
        return;
      }
      finish(value);
    });

    if (isPrompt) {
      input.addEventListener('input', () => {
        errorLine.classList.add('hidden');
        input.removeAttribute('aria-invalid');
      });
    }

    // A destructive dialog opens with Cancel focused, so a stray Enter or Space
    // left over from activating the button cannot confirm it.
    if (input) input.focus();
    else if (o.destructive) cancelBtn.focus();
    else submitBtn.focus();
  });
}

function confirmAction(opts) {
  return showDialog(Object.assign({ kind: 'confirm' }, opts));
}

function promptForValue(opts) {
  return showDialog(Object.assign({ kind: 'prompt' }, opts));
}

function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'glass-panel px-4 py-2.5 rounded-xl border flex items-center gap-2.5 shadow-2xl text-xs font-semibold text-white pointer-events-auto transition-all duration-300 transform translate-y-2 opacity-0';

  // The dot and the label are built as nodes, and the label is set with
  // textContent. This used to be `innerHTML = \`...<span>${msg}</span>\``, and msg
  // is very often not a literal: errorMessage() returns whatever string the
  // response carried, so any handler that echoed part of a request back in its
  // error body could put live markup into the authenticated dashboard.
  const dot = document.createElement('span');
  dot.setAttribute('aria-hidden', 'true');
  const label = document.createElement('span');
  label.textContent = msg === null || msg === undefined ? '' : String(msg);

  if (type === 'success') {
    toast.classList.add('border-emerald-500/50', 'bg-slate-950/90');
    dot.className = 'w-2 h-2 rounded-full bg-emerald-400 animate-pulse shrink-0';
  } else if (type === 'error') {
    toast.classList.add('border-red-500/50', 'bg-slate-950/90');
    dot.className = 'w-2 h-2 rounded-full bg-red-400 shrink-0';
  } else if (type === 'warning') {
    // "It worked, but not the part you were hoping for." The TLS endpoint is the case
    // this exists for: the domain is saved and issuance did not start, which is neither
    // a success nor a failed request.
    toast.classList.add('border-amber-500/50', 'bg-slate-950/90');
    dot.className = 'w-2 h-2 rounded-full bg-amber-400 shrink-0';
  } else {
    toast.classList.add('border-cyan-500/50', 'bg-slate-950/90');
    dot.className = 'w-2 h-2 rounded-full bg-cyan-400 shrink-0';
  }

  toast.appendChild(dot);
  toast.appendChild(label);

  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  // 2.5 s is right for "Saved" and far too short for a reason. The TLS endpoint answers
  // with a whole sentence naming something only the operator can fix — certbot is not
  // installed, port 80 is held — and a message that disappears before it can be read is
  // the same as no message. So the linger follows the length of what is being said.
  const linger = label.textContent.length > 70 ? 9000 : 2500;

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => {
      if (toast.parentElement) toast.parentElement.removeChild(toast);
    }, 300);
  }, linger);
}


  // =======================================================
  // EDIT CLIENT MODAL EVENT LISTENERS (Advanced Client Controls)
  // =======================================================

  // The selectable policies, fetched from the daemon instead of transcribed here.
  //
  // This used to be a 26-entry object literal copied from matcher.PresetRuleKeys by
  // hand, and a copy of a Go map in a JS literal is something no test and no compiler
  // can check. It had already drifted: four labels here were shorter than the ones the
  // resolver uses, so the panel and the daemon named the same category two ways. The
  // worse direction was silence — a preset added on the Go side was invisible to this
  // picker until somebody remembered to retype it, which is how enable_soundcloud
  // spent a release unselectable.
  //
  // Order comes from the server (see matcher.policyCatalogOrder), because a picker
  // filled from a Go map reshuffles on every open.
  let policyCatalog = [];
  let policyLabels = {};
  let policyCatalogError = '';
  let policyCatalogPromise = null;

  // Fetched once per page load, lazily: an operator who never opens the edit modal
  // never pays for it. The promise itself is the cache, so two callers racing on modal
  // open share one request.
  function loadPolicyCatalog() {
    if (policyCatalogPromise) return policyCatalogPromise;
    policyCatalogPromise = (async () => {
      try {
        const res = await fetch(api('/api/policies'), {
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (!res.ok) throw new Error(`http ${res.status}`);
        const data = await res.json();
        const list = Array.isArray(data.catalog) ? data.catalog : [];
        // A daemon too old to send a catalogue is the one case where an empty list is
        // not an error worth blocking on — but it is still an empty picker, so say so
        // rather than leave the operator looking at "No matching policies found".
        if (list.length === 0) throw new Error('empty catalog');
        policyCatalog = list.filter(e => e && typeof e.key === 'string' && e.key !== '');
        policyLabels = {};
        policyCatalog.forEach(e => { policyLabels[e.key] = e.label || e.key; });
        policyCatalogError = '';
      } catch (e) {
        // Deliberately not falling back to a bundled list. A stale copy that disagrees
        // with the resolver is what this change removed; showing nothing and saying why
        // is worse for one session and better every session after it.
        policyCatalog = [];
        policyCatalogError = 'Could not load the policy list from the server.';
        policyCatalogPromise = null; // let the next open retry
      }
      return policyCatalog;
    })();
    return policyCatalogPromise;
  }

  // =======================================================
  // ANT-DESIGN MULTI-SELECT & HIGHLIGHTING FOR POLICIES
  // =======================================================
  // One picker per form. The create and the edit modals both offer policy
  // selection now, and a single module-level selection array they both wrote
  // through meant the chips an operator attached while editing one subscriber
  // would be sitting in the create form the next time it opened — and silently
  // sold to whoever was created next.
  //
  // The catalogue itself stays shared: one fetch, lazily, for both pickers.
  function createPolicyMultiselect(ids) {
    const box = document.getElementById(ids.box);
    const dropdown = document.getElementById(ids.dropdown);
    const search = document.getElementById(ids.search);
    const tags = document.getElementById(ids.tags);
    let selected = [];

    const noop = { get: () => [], set: () => {}, reset: () => {} };
    if (!box || !dropdown) return noop;

    function renderTags() {
      if (!tags) return;
      if (selected.length === 0) {
        tags.innerHTML = '<span class="text-slate-500 text-[11px] italic py-0.5">Inheriting all global policies</span>';
      } else {
        tags.innerHTML = selected.map(p => {
          // Every value here is server-supplied now — the label from the catalogue, the
          // raw key from the client record when the catalogue does not know it (a policy
          // stored by a newer build, or one that has since been removed).
          const label = policyLabels[p] || p;
          return `
          <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-cyan-950/80 border border-cyan-500/40 text-[10px] font-semibold text-cyan-200">
            <span>${escapeHTML(label)}</span>
            <button type="button" class="remove-policy-tag-btn hover:text-red-400 ms-1 text-slate-400" data-policy="${escapeHTML(p)}"
              title="Remove policy" aria-label="Remove policy"><i data-feather="x" class="w-3 h-3"></i></button>
          </span>
        `;
        }).join('');
        // The ✕ this button used to hold was its accessible name as well as its icon; an
        // <i> has neither, so the label moved into title/aria-label — which i18n.js
        // translates — and the glyph has to be drawn, because nothing else in this
        // function redraws.
        safeFeatherReplace();
      }
      renderDropdown(search ? search.value : '');
    }

    function renderDropdown(filterText = '') {
      const q = (filterText || '').toLowerCase().trim();

      if (policyCatalog.length === 0) {
        dropdown.innerHTML = policyCatalogError
          ? `<div class="p-3 text-center text-red-400 text-xs">${escapeHTML(policyCatalogError)}</div>`
          : '<div class="p-3 text-center text-slate-500 text-xs">Loading policies…</div>';
        return;
      }

      const matched = policyCatalog.filter(e => {
        const label = e.label || e.key;
        return label.toLowerCase().includes(q) || e.key.toLowerCase().includes(q);
      });

      if (matched.length === 0) {
        dropdown.innerHTML = '<div class="p-3 text-center text-slate-500 text-xs">No matching policies found</div>';
        return;
      }

      // Every interpolation below is server-supplied, so every one is escaped. The keys
      // and labels are the daemon's, and a policy key reaches the store from the REST API
      // without a charset check — see TestPortalEscapesCustomPolicies, which covers the
      // same value arriving on the subscriber's page.
      dropdown.innerHTML = matched.map(e => {
        const k = e.key;
        const label = e.label || k;
        const isSelected = selected.includes(k);
        // A sinkholing category takes domains away instead of routing them. Marked,
        // because "FamilySafe Protection" beside twenty games reads like one more game.
        const kindDot = e.blocking
          ? '<span class="w-1.5 h-1.5 rounded-full bg-red-400" title="Blocks (sinkholes) these domains"></span>'
          : `<span class="w-1.5 h-1.5 rounded-full ${isSelected ? 'bg-cyan-400' : 'bg-slate-600'}"></span>`;

        if (isSelected) {
          return `
          <div class="policy-option-item flex items-center justify-between px-3 py-2 bg-blue-600/25 border-s-2 border-blue-400 text-blue-200 cursor-pointer hover:bg-blue-600/35 transition text-xs font-semibold" data-key="${escapeHTML(k)}">
            <div class="flex items-center gap-2">
              ${kindDot}
              <span>${escapeHTML(label)}</span>
            </div>
            <i data-feather="check" class="w-3.5 h-3.5 text-blue-400 shrink-0"></i>
          </div>
        `;
        } else {
          return `
          <div class="policy-option-item flex items-center justify-between px-3 py-2 text-slate-300 hover:bg-slate-800/80 cursor-pointer transition text-xs" data-key="${escapeHTML(k)}">
            <div class="flex items-center gap-2">
              ${kindDot}
              <span>${escapeHTML(label)}</span>
            </div>
            <i data-feather="plus" class="w-3.5 h-3.5 text-slate-600 shrink-0"></i>
          </div>
        `;
        }
      }).join('');
      // border-s-2 rather than border-l-2, so the marker stays on the reading edge in
      // Persian, and the two glyphs are drawn here because this list is rebuilt on every
      // keystroke in the search box and nothing downstream redraws it.
      safeFeatherReplace();
    }

    box.addEventListener('click', (e) => {
      e.stopPropagation();
      if (e.target.closest('.remove-policy-tag-btn')) return;
      dropdown.classList.toggle('hidden');
      if (!dropdown.classList.contains('hidden')) {
        if (search) search.focus();
        // Renders "Loading policies…" first, then again with the real list. Awaiting
        // before the first render would leave the dropdown blank on a slow request,
        // which reads as "there are no policies".
        renderDropdown(search ? search.value : '');
        loadPolicyCatalog().then(() => {
          renderDropdown(search ? search.value : '');
        });
      }
    });

    if (search) {
      search.addEventListener('input', (e) => {
        dropdown.classList.remove('hidden');
        renderDropdown(e.target.value);
      });
      search.addEventListener('focus', () => {
        dropdown.classList.remove('hidden');
        renderDropdown(search.value);
        loadPolicyCatalog().then(() => {
          renderDropdown(search.value);
        });
      });
    }

    dropdown.addEventListener('click', (e) => {
      e.stopPropagation();
      const option = e.target.closest('.policy-option-item');
      if (!option) return;
      const key = option.getAttribute('data-key');
      if (!key) return;

      if (selected.includes(key)) {
        selected = selected.filter(p => p !== key);
      } else {
        selected.push(key);
      }
      renderTags();
      if (search) search.focus();
    });

    document.addEventListener('click', (e) => {
      if (!box.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.add('hidden');
      }
    });

    const selectAllBtn = document.getElementById(ids.selectAll);
    if (selectAllBtn) {
      selectAllBtn.addEventListener('click', async () => {
        // Awaited, because "select all" on an unloaded catalogue would silently select
        // nothing and then render "Inheriting all global policies" — the exact opposite
        // of what was asked for.
        await loadPolicyCatalog();
        selected = policyCatalog.map(e => e.key);
        if (selected.length === 0) {
          showToast(policyCatalogError || 'No policies available to select', 'error');
        }
        renderTags();
      });
    }

    const clearAllBtn = document.getElementById(ids.clearAll);
    if (clearAllBtn) {
      clearAllBtn.addEventListener('click', () => {
        selected = [];
        renderTags();
      });
    }

    // Delegated, because the tags are re-rendered on every change. Scoped to this
    // picker's own chips container so the instance's document-level listener above
    // is the only other one that sees the click.
    document.addEventListener('click', (e) => {
      const removeTagBtn = e.target.closest('.remove-policy-tag-btn');
      if (removeTagBtn && tags && tags.contains(removeTagBtn)) {
        const p = removeTagBtn.getAttribute('data-policy');
        selected = selected.filter(item => item !== p);
        renderTags();
      }
    });

    return {
      get: () => [...selected],
      // set() also prefetches the catalogue: the tags fall back to the raw key until
      // it arrives, so an operator who only glances at the attached policies should
      // read "Riot Games & Valorant", not "enable_riot".
      set: (arr) => {
        selected = Array.isArray(arr) ? [...arr] : [];
        renderTags();
        loadPolicyCatalog().then(() => renderTags());
      },
      reset: () => {
        selected = [];
        if (search) search.value = '';
        dropdown.classList.add('hidden');
        renderTags();
      }
    };
  }

  const editPolicyPicker = createPolicyMultiselect({
    box: 'policies-multiselect-box',
    dropdown: 'policies-dropdown-list',
    search: 'policies-search-input',
    tags: 'edit-client-policies-tags',
    selectAll: 'edit-client-policies-select-all',
    clearAll: 'edit-client-policies-clear-all'
  });

  const addPolicyPicker = createPolicyMultiselect({
    box: 'add-policies-multiselect-box',
    dropdown: 'add-policies-dropdown-list',
    search: 'add-policies-search-input',
    tags: 'add-client-policies-tags',
    selectAll: 'add-client-policies-select-all',
    clearAll: 'add-client-policies-clear-all'
  });

  // =======================================================
  // ANT-DESIGN STYLE GREGORIAN DATETIME PICKER
  // =======================================================
  // One picker per form, for the same reason the policy multiselect is a factory:
  // the create form and the edit form both carry an expiry now, and a shared set
  // of selection variables would have the calendar in one modal showing the date
  // the other modal last confirmed.
  const MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  function createExpiryDatePicker(ids) {
    const popup = document.getElementById(ids.popup);
    const openBtn = document.getElementById(ids.openBtn);
    const expiryInput = document.getElementById(ids.expiryInput);
    const monthYearLabel = document.getElementById(ids.monthLabel);
    const daysGrid = document.getElementById(ids.daysGrid);
    const hourSelect = document.getElementById(ids.hourSelect);
    const minuteSelect = document.getElementById(ids.minuteSelect);
    const confirmBtn = document.getElementById(ids.confirmBtn);
    const setNowBtn = document.getElementById(ids.setNowBtn);
    const clearBtn = document.getElementById(ids.clearBtn);

    const noop = { applyDefaultDays: () => {}, clear: () => {} };
    if (!popup || !daysGrid || !hourSelect || !minuteSelect) return noop;

    let selYear = 0;
    let selMonth = 0; // 0-indexed
    let selDay = 0;
    let selHour = 0;
    let selMinute = 0;

    function renderCalendarGrid() {
      if (!monthYearLabel || !daysGrid) return;
      monthYearLabel.innerText = `${MONTH_NAMES[selMonth]} ${selYear}`;

      hourSelect.value = selHour;
      minuteSelect.value = selMinute;

      const firstDayIndex = new Date(selYear, selMonth, 1).getDay();
      const daysInMonth = new Date(selYear, selMonth + 1, 0).getDate();
      const daysInPrevMonth = new Date(selYear, selMonth, 0).getDate();

      let gridHTML = '';

      // Previous month padding days
      for (let i = firstDayIndex - 1; i >= 0; i--) {
        gridHTML += `<div class="p-1.5 text-slate-700 text-[11px] pointer-events-none">${daysInPrevMonth - i}</div>`;
      }

      const today = new Date();
      // Current month days
      for (let d = 1; d <= daysInMonth; d++) {
        const isSelected = (d === selDay);
        const isToday = (today.getFullYear() === selYear && today.getMonth() === selMonth && today.getDate() === d);

        if (isSelected) {
          gridHTML += `<button type="button" class="dp-day-btn p-1.5 rounded-lg bg-blue-600 text-onfill font-bold shadow-md shadow-blue-500/30 text-xs" data-day="${d}">${d}</button>`;
        } else if (isToday) {
          gridHTML += `<button type="button" class="dp-day-btn p-1.5 rounded-lg border border-cyan-400 text-cyan-300 hover:bg-slate-800 text-xs font-bold" data-day="${d}">${d}</button>`;
        } else {
          gridHTML += `<button type="button" class="dp-day-btn p-1.5 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition text-xs" data-day="${d}">${d}</button>`;
        }
      }

      daysGrid.innerHTML = gridHTML;
    }

    // Reads the field this picker owns, or defaults a month out — the same default
    // the create form seeds and the preset select used to ship.
    function parseInputToState() {
      const val = expiryInput ? expiryInput.value.trim() : '';
      if (val) {
        const d = new Date(val.replace(' ', 'T'));
        if (!isNaN(d.getTime())) {
          selYear = d.getFullYear();
          selMonth = d.getMonth();
          selDay = d.getDate();
          selHour = d.getHours();
          selMinute = d.getMinutes();
          return;
        }
      }
      const d = new Date(Date.now() + 30 * 24 * 3600 * 1000);
      selYear = d.getFullYear();
      selMonth = d.getMonth();
      selDay = d.getDate();
      selHour = d.getHours();
      selMinute = d.getMinutes();
    }

    function applyToInput() {
      if (!expiryInput) return;
      const pad = (n) => String(n).padStart(2, '0');
      expiryInput.value = `${selYear}-${pad(selMonth + 1)}-${pad(selDay)} ${pad(selHour)}:${pad(selMinute)}:00`;
    }

    // Populate hours (00-23) and minutes (00-59)
    hourSelect.innerHTML = Array.from({length: 24}, (_, i) => {
      const h = String(i).padStart(2, '0');
      return `<option value="${i}">${h}</option>`;
    }).join('');
    minuteSelect.innerHTML = Array.from({length: 60}, (_, i) => {
      const m = String(i).padStart(2, '0');
      return `<option value="${i}">${m}</option>`;
    }).join('');
    parseInputToState();
    renderCalendarGrid();

    const toggleDatepicker = () => {
      popup.classList.toggle('hidden');
      if (!popup.classList.contains('hidden')) {
        parseInputToState();
        renderCalendarGrid();
      }
    };

    popup.addEventListener('click', (e) => {
      e.stopPropagation();
    });

    if (openBtn) {
      openBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleDatepicker();
      });
    }

    if (expiryInput) {
      expiryInput.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleDatepicker();
      });
    }

    document.getElementById(ids.prevYear)?.addEventListener('click', () => {
      selYear--;
      renderCalendarGrid();
    });
    document.getElementById(ids.nextYear)?.addEventListener('click', () => {
      selYear++;
      renderCalendarGrid();
    });
    document.getElementById(ids.prevMonth)?.addEventListener('click', () => {
      selMonth--;
      if (selMonth < 0) { selMonth = 11; selYear--; }
      renderCalendarGrid();
    });
    document.getElementById(ids.nextMonth)?.addEventListener('click', () => {
      selMonth++;
      if (selMonth > 11) { selMonth = 0; selYear++; }
      renderCalendarGrid();
    });

    daysGrid.addEventListener('click', (e) => {
      const btn = e.target.closest('.dp-day-btn');
      if (btn) {
        selDay = parseInt(btn.getAttribute('data-day'), 10);
        renderCalendarGrid();
      }
    });

    hourSelect.addEventListener('change', (e) => { selHour = parseInt(e.target.value, 10); });
    minuteSelect.addEventListener('change', (e) => { selMinute = parseInt(e.target.value, 10); });

    setNowBtn?.addEventListener('click', () => {
      const future = new Date(Date.now() + 30 * 24 * 3600 * 1000);
      selYear = future.getFullYear();
      selMonth = future.getMonth();
      selDay = future.getDate();
      selHour = future.getHours();
      selMinute = future.getMinutes();
      renderCalendarGrid();
      applyToInput();
    });

    confirmBtn?.addEventListener('click', () => {
      applyToInput();
      popup.classList.add('hidden');
    });

    clearBtn?.addEventListener('click', () => {
      if (expiryInput) expiryInput.value = '';
      popup.classList.add('hidden');
    });

    document.addEventListener('click', (e) => {
      if (!popup.contains(e.target) && e.target !== openBtn && e.target !== expiryInput) {
        popup.classList.add('hidden');
      }
    });

    return {
      // The create form's opening default: a plan expiring a month out.
      applyDefaultDays(days) {
        const d = new Date(Date.now() + days * 24 * 3600 * 1000);
        selYear = d.getFullYear();
        selMonth = d.getMonth();
        selDay = d.getDate();
        selHour = d.getHours();
        selMinute = d.getMinutes();
        renderCalendarGrid();
        applyToInput();
      },
      clear: () => {
        if (expiryInput) expiryInput.value = '';
        popup.classList.add('hidden');
      }
    };
  }

  const editDatePicker = createExpiryDatePicker({
    popup: 'datepicker-popup',
    openBtn: 'open-datepicker-btn',
    expiryInput: 'edit-client-expiry',
    monthLabel: 'dp-month-year-label',
    daysGrid: 'dp-days-grid',
    hourSelect: 'dp-hour-select',
    minuteSelect: 'dp-minute-select',
    confirmBtn: 'dp-confirm-btn',
    setNowBtn: 'dp-set-now-btn',
    clearBtn: 'edit-client-clear-expiry-btn',
    prevYear: 'dp-prev-year',
    nextYear: 'dp-next-year',
    prevMonth: 'dp-prev-month',
    nextMonth: 'dp-next-month'
  });

  const addDatePicker = createExpiryDatePicker({
    popup: 'add-datepicker-popup',
    openBtn: 'add-open-datepicker-btn',
    expiryInput: 'add-client-expiry',
    monthLabel: 'add-dp-month-year-label',
    daysGrid: 'add-dp-days-grid',
    hourSelect: 'add-dp-hour-select',
    minuteSelect: 'add-dp-minute-select',
    confirmBtn: 'add-dp-confirm-btn',
    setNowBtn: 'add-dp-set-now-btn',
    clearBtn: 'add-client-clear-expiry-btn',
    prevYear: 'add-dp-prev-year',
    nextYear: 'add-dp-next-year',
    prevMonth: 'add-dp-prev-month',
    nextMonth: 'add-dp-next-month'
  });

  // The create form's blank slate: the fields the browser's reset() covers plus
  // the two components that live outside it — the readonly expiry field and the
  // policy picker's chips.
  function resetAddClientForm() {
    const form = document.getElementById('add-client-form');
    if (form) form.reset();
    addDatePicker.applyDefaultDays(30);
    addPolicyPicker.reset();
  }

  // showClientCreatedModal puts the just-minted credentials on screen. The
  // secret lives only in this closure and the readonly input's value — no
  // localStorage, no URL, and the input is type=password until the operator
  // deliberately reveals it, so a screen-share or a passer-by sees a masked
  // field by default. The link is built from the cached subscription origin,
  // the same source the Reg Link button uses, never from window.location.
  function showClientCreatedModal(client) {
    const modal = document.getElementById('client-created-modal');
    const nameEl = document.getElementById('created-client-name');
    const linkEl = document.getElementById('created-register-link');
    const secretEl = document.getElementById('created-register-secret');
    const toggleBtn = document.getElementById('toggle-created-secret-btn');
    if (!modal || !client) return;

    if (nameEl) nameEl.textContent = client.name || client.id || 'client';
    const origin = currentConfig?.subscription_origin || '';
    // /sub/ is the page a subscriber opens (status, quota, IP registration);
    // /ip/ is the API endpoint the portal's register button posts to. The
    // Reg Link button on the client card made this distinction in v2.1 —
    // this popup was still handing out the API URL.
    if (linkEl) linkEl.value = client.token && origin ? `${origin}/sub/${client.token}` : '(no origin configured — set the public address in Settings)';
    if (secretEl) {
      secretEl.value = client.register_secret || '(no secret in response)';
      secretEl.type = 'password';
    }
    if (toggleBtn) toggleBtn.textContent = 'Show';

    const copyLink = document.getElementById('copy-created-link-btn');
    const copySecret = document.getElementById('copy-created-secret-btn');
    if (copyLink) {
      copyLink.onclick = () => copyText(linkEl ? linkEl.value : '', copyLink);
    }
    if (copySecret) {
      copySecret.onclick = () => copyText(secretEl ? secretEl.value : '', copySecret);
    }
    if (toggleBtn) {
      toggleBtn.onclick = () => {
        if (!secretEl) return;
        const masked = secretEl.type === 'password';
        secretEl.type = masked ? 'text' : 'password';
        toggleBtn.textContent = masked ? 'Hide' : 'Show';
      };
    }
    const doneBtn = document.getElementById('close-client-created-done-btn');
    if (doneBtn) doneBtn.onclick = () => modal.classList.add('hidden');
    // The × in the corner: data-modal-close names it, so Escape and a backdrop
    // click reach it — it needs its own handler or those paths click a dead
    // button.
    const closeBtn = document.getElementById('close-client-created-btn');
    if (closeBtn) closeBtn.onclick = () => modal.classList.add('hidden');

    modal.classList.remove('hidden');
    // The modal a11y observer moves focus to the first focusable control when
    // the class flips; nothing to do here but let it.
  }

  function formatToDateTimeString(dateStr) {
    if (!dateStr || dateStr === '0001-01-01T00:00:00Z' || dateStr.startsWith('0001')) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return '';
      const pad = (n) => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:00`;
    } catch (e) {
      return '';
    }
  }

  const editClientModal = document.getElementById('edit-client-modal');
  const closeEditClientBtn = document.getElementById('close-edit-client-btn');
  const cancelEditClientBtn = document.getElementById('cancel-edit-client-btn');
  const editClientForm = document.getElementById('edit-client-form');
  const regenUUIDBtn = document.getElementById('edit-client-regen-uuid');
  const regenSecretBtn = document.getElementById('edit-client-regen-secret');
  const resetTrafficBtn = document.getElementById('edit-client-reset-traffic-btn');
  const enabledCheckbox = document.getElementById('edit-client-enabled');
  const statusLabel = document.getElementById('edit-client-status-label');

  if (closeEditClientBtn) {
    closeEditClientBtn.addEventListener('click', () => {
      if (editClientModal) editClientModal.classList.add('hidden');
    });
  }

  if (cancelEditClientBtn) {
    cancelEditClientBtn.addEventListener('click', () => {
      if (editClientModal) editClientModal.classList.add('hidden');
    });
  }

  if (enabledCheckbox && statusLabel) {
    enabledCheckbox.addEventListener('change', () => {
      if (enabledCheckbox.checked) {
        statusLabel.innerText = 'ACTIVE';
        statusLabel.className = 'text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 font-bold';
      } else {
        statusLabel.innerText = 'DISABLED';
        statusLabel.className = 'text-[10px] px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 font-bold';
      }
    });
  }

  // Open Edit Client Modal from Card Click
  document.addEventListener('click', (e) => {
    const editBtn = e.target.closest('.edit-client-btn');
    if (editBtn) {
      const clientId = editBtn.getAttribute('data-id');
      if (!clientsDataCache || !clientsDataCache.clients) return;
      const client = clientsDataCache.clients.find(c => c.id === clientId);
      if (!client) return;

      document.getElementById('edit-client-id').value = client.id;
      document.getElementById('edit-client-name').value = client.name || '';
      document.getElementById('edit-client-uuid').value = client.uuid || '';
      document.getElementById('edit-client-secret').value = client.register_secret || '';
      document.getElementById('edit-client-ip').value = (client.allowed_ips && client.allowed_ips.length > 0) ? client.allowed_ips[0] : '';
      document.getElementById('edit-client-traffic').value = client.traffic_limit_gb || '';
      document.getElementById('edit-client-max-devices').value = client.max_devices || '';
      // The stored cycle, normalised to the empty option when the record predates
      // cycles or carries a name this build does not offer. A <select> handed an
      // unknown value silently shows its first option, so reopening the modal on such
      // a record and saving would rewrite the cycle to "never" without being asked.
      const cycleSelect = document.getElementById('edit-client-traffic-cycle');
      if (cycleSelect) {
        const stored = client.traffic_reset_cycle || '';
        const known = Array.prototype.some.call(cycleSelect.options, (o) => o.value === stored);
        cycleSelect.value = known ? stored : '';
      }
      document.getElementById('edit-client-expiry').value = formatToDateTimeString(client.expires_at);
      document.getElementById('edit-client-note').value = client.note || '';

      if (enabledCheckbox) {
        enabledCheckbox.checked = client.enabled !== false;
        enabledCheckbox.dispatchEvent(new Event('change'));
      }

      // set() renders the chips from the raw keys immediately and prefetches the
      // catalogue so they read as labels: an operator who only glances at the
      // attached policies should read "Riot Games & Valorant", not "enable_riot".
      editPolicyPicker.set(Array.isArray(client.custom_policies) ? client.custom_policies : []);

      if (editClientModal) editClientModal.classList.remove('hidden');
      safeFeatherReplace();
    }

    // Copy UUID to clipboard
    const copyUuidBtn = e.target.closest('.copy-uuid-btn');
    if (copyUuidBtn) {
      const uuid = copyUuidBtn.getAttribute('data-uuid');
      if (uuid) {
        navigator.clipboard.writeText(uuid);
        showToast('UUID copied to clipboard!', 'success');
      }
    }
  });

  // Regenerate UUID Button inside Edit Modal
  if (regenUUIDBtn) {
    regenUUIDBtn.addEventListener('click', async () => {
      const clientId = document.getElementById('edit-client-id').value;
      if (!clientId) return;
      try {
        const res = await fetch(api(`/api/clients/${clientId}/regenerate-uuid`), {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (res.ok) {
          const data = await res.json();
          document.getElementById('edit-client-uuid').value = data.uuid;
          showToast('New UUID generated!', 'success');
        }
      } catch (e) {
        showToast('Failed to regenerate UUID', 'error');
      }
    });
  }

  // Regenerate Register Secret inside Edit Modal (Phase B): the out-of-band
  // credential dies with this click, so the subscriber needs the new value
  // through the same channel the original came from.
  if (regenSecretBtn) {
    regenSecretBtn.addEventListener('click', async () => {
      const clientId = document.getElementById('edit-client-id').value;
      if (!clientId) return;
      try {
        const res = await fetch(api(`/api/clients/${clientId}/regenerate-register-secret`), {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (res.ok) {
          const data = await res.json();
          document.getElementById('edit-client-secret').value = data.register_secret;
          showToast('New registration secret generated!', 'success');
        } else {
          showToast(await errorMessage(res, 'Failed to regenerate the secret'), 'error');
        }
      } catch (e) {
        showToast('Failed to regenerate the secret', 'error');
      }
    });
  }

  // Reset Traffic Button inside Edit Modal
  if (resetTrafficBtn) {
    resetTrafficBtn.addEventListener('click', async () => {
      const clientId = document.getElementById('edit-client-id').value;
      if (!clientId) return;
      try {
        const res = await fetch(api(`/api/clients/${clientId}/reset-traffic`), {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (res.ok) {
          showToast('Client traffic counter reset to 0!', 'success');
          loadClients();
        } else {
          showToast('Failed to reset traffic counter', 'error');
        }
      } catch (e) {
        showToast('Network error resetting traffic', 'error');
      }
    });
  }

  // Submit Edit Client Form
  if (editClientForm) {
    editClientForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const clientId = document.getElementById('edit-client-id').value;
      if (!clientId) return;

      const name = document.getElementById('edit-client-name').value.trim();
      const uuid = document.getElementById('edit-client-uuid').value.trim();
      const ip = document.getElementById('edit-client-ip').value.trim();
      const trafficGB = parseFloat(document.getElementById('edit-client-traffic').value) || 0;
      const cycle = document.getElementById('edit-client-traffic-cycle')?.value || '';
      const maxDevices = parseInt(document.getElementById('edit-client-max-devices')?.value, 10) || 0;
      const expiryVal = document.getElementById('edit-client-expiry').value;
      const note = document.getElementById('edit-client-note').value.trim();
      const isEnabled = enabledCheckbox ? enabledCheckbox.checked : true;

      let expiresAtISO = '0001-01-01T00:00:00Z';
      if (expiryVal) {
        const parsed = new Date(expiryVal);
        if (!isNaN(parsed.getTime())) {
          expiresAtISO = parsed.toISOString();
        }
      }

      const payload = {
        name: name,
        uuid: uuid,
        allowed_ip: ip,
        traffic_limit_gb: trafficGB,
        max_devices: maxDevices,
        // Sent on every save, including as "" — the field is a pointer on the server,
        // so omitting it means "leave the cycle alone" and there would then be no way
        // to turn a cycle back off from this form.
        traffic_reset_cycle: cycle,
        expires_at: expiresAtISO,
        enabled: isEnabled,
        note: note,
        custom_policies: editPolicyPicker.get()
      };

      try {
        const res = await fetch(api(`/api/clients/${clientId}`), {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify(payload)
        });

        if (res.ok) {
          showToast('Client configuration updated successfully!', 'success');
          if (editClientModal) editClientModal.classList.add('hidden');
          loadClients();
        } else {
          // "Invalid traffic reset cycle", "IP already assigned to another client",
          // "UUID already in use" — each of those is 400 with a different fix, and the
          // generic message here used to send the operator back to guess which.
          showToast(await errorMessage(res, 'Failed to update client details'), 'error');
        }
      } catch (err) {
        showToast('Network error updating client', 'error');
      }
    });
  }

// =======================================================
// SELF-UPDATE (v2.6): check the main-branch version, then apply a
// SHA256-verified binary swap + restart. Data is preserved and backed up.
// =======================================================
async function checkForUpdate() {
  try {
    const res = await fetch(api('/api/update/check'), { headers: { 'Authorization': 'Bearer ' + authToken } });
    if (!res.ok) return;
    const st = await res.json();
    if (st && st.update_available && st.supported) showUpdateAvailable(st);
  } catch (e) { /* an offline check is non-fatal — no badge, no error */ }
}

let hdnsUpdateBtn = null;
function showUpdateAvailable(st) {
  if (!hdnsUpdateBtn) {
    const btn = document.createElement('button');
    btn.id = 'update-available-btn';
    btn.type = 'button';
    btn.className = 'mt-1 inline-flex items-center gap-1.5 text-[10px] font-bold px-2 py-1 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30 transition';
    btn.addEventListener('click', () => openUpdateModal(st));
    const anchor = document.getElementById('app-version-badge');
    if (anchor && anchor.parentElement) anchor.parentElement.appendChild(btn);
    else document.body.appendChild(btn);
    hdnsUpdateBtn = btn;
  }
  hdnsUpdateBtn.innerHTML = `<i data-feather="download-cloud" class="w-3 h-3"></i> Update &rarr; v${escapeHTML(st.latest)}`;
  hdnsUpdateBtn.classList.remove('hidden');
  safeFeatherReplace();
}
let hdnsUpdateModal = null;
function openUpdateModal(st) {
  if (hdnsUpdateModal) hdnsUpdateModal.remove();
  const backdrop = document.createElement('div');
  backdrop.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md px-4';
  backdrop.innerHTML = `
    <div class="glass-panel p-6 w-full max-w-md border border-cyan-500/40 shadow-2xl shadow-cyan-500/10" role="dialog" aria-modal="true" aria-labelledby="hdns-update-title">
      <div class="flex items-center gap-3 mb-4">
        <div class="w-10 h-10 rounded-xl bg-cyan-500/20 flex items-center justify-center text-cyan-400 border border-cyan-500/30 shrink-0"><i data-feather="download-cloud"></i></div>
        <div>
          <h2 id="hdns-update-title" class="text-lg font-bold text-white font-heading">Update available</h2>
          <p class="text-xs text-cyan-400 font-mono">v${escapeHTML(st.current)} &rarr; v${escapeHTML(st.latest)}${st.codename ? ' · ' + escapeHTML(st.codename) : ''}</p>
        </div>
      </div>
      <p class="text-sm text-slate-300 mb-4">The new binary is downloaded from GitHub, its SHA-256 is verified against the release checksums, your data is backed up, and the service restarts on the new version. Subscribers, clients and settings are preserved.</p>
      <div id="hdns-update-progress-wrap" class="hidden mb-4">
        <div class="h-2 w-full rounded-full bg-slate-800 overflow-hidden"><div id="hdns-update-bar" class="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300" style="width:0%"></div></div>
        <p id="hdns-update-msg" class="text-xs text-slate-400 mt-1 font-mono">Starting…</p>
      </div>
      <div class="flex gap-3">
        <button id="hdns-update-cancel" type="button" class="flex-1 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold rounded-lg text-sm">Cancel</button>
        <button id="hdns-update-go" type="button" class="flex-1 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 text-slate-950 font-bold rounded-lg text-sm">Update now</button>
      </div>
    </div>`;
  document.body.appendChild(backdrop);
  hdnsUpdateModal = backdrop;
  safeFeatherReplace();
  const close = () => { backdrop.remove(); hdnsUpdateModal = null; };
  backdrop.querySelector('#hdns-update-cancel').addEventListener('click', close);
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(); });
  backdrop.querySelector('#hdns-update-go').addEventListener('click', () => applyUpdate(backdrop));
}
async function applyUpdate(modal) {
  const go = modal.querySelector('#hdns-update-go');
  const cancel = modal.querySelector('#hdns-update-cancel');
  const wrap = modal.querySelector('#hdns-update-progress-wrap');
  const bar = modal.querySelector('#hdns-update-bar');
  const msg = modal.querySelector('#hdns-update-msg');
  const lock = (on) => { go.disabled = on; go.classList.toggle('opacity-50', on); };
  lock(true);
  wrap.classList.remove('hidden');

  try {
    const res = await fetch(api('/api/update/apply'), { method: 'POST', headers: { 'Authorization': 'Bearer ' + authToken } });
    if (!res.ok) {
      msg.textContent = await errorMessage(res, 'Could not start the update');
      lock(false);
      return;
    }
  } catch (e) {
    msg.textContent = 'Network error starting the update';
    lock(false);
    return;
  }

  const poll = setInterval(async () => {
    let p;
    try {
      const r = await fetch(api('/api/update/status'), { headers: { 'Authorization': 'Bearer ' + authToken }, cache: 'no-store' });
      p = await r.json();
    } catch (e) {
      // The restart drops the connection — that is the success path, not a failure.
      clearInterval(poll);
      bar.style.width = '100%';
      msg.textContent = 'Restarting on the new version… this page will reload automatically.';
      waitForServerBack();
      return;
    }
    bar.style.width = (p.percent || 0) + '%';
    msg.textContent = p.message || p.phase || '';
    if (p.phase === 'error') {
      clearInterval(poll);
      msg.textContent = 'Update failed: ' + (p.error || 'unknown error');
      cancel.textContent = 'Close';
    } else if (p.restarting) {
      clearInterval(poll);
      bar.style.width = '100%';
      msg.textContent = 'Restarting on the new version… this page will reload automatically.';
      waitForServerBack();
    }
  }, 1500);
}

function waitForServerBack() {
  let tries = 0;
  const probe = setInterval(async () => {
    tries++;
    try {
      const r = await fetch(api('/api/update/check'), { headers: { 'Authorization': 'Bearer ' + authToken }, cache: 'no-store' });
      if (r.ok || r.status === 401) { clearInterval(probe); location.reload(); return; }
    } catch (e) { /* still restarting */ }
    if (tries > 40) { clearInterval(probe); location.reload(); }
  }, 3000);
}
