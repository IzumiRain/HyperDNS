// Subscriber portal behaviour.
//
// This file exists because the portal's script used to be an inline <script> block
// inside a Go string constant in internal/web/portal.go, and its handlers were
// onclick attributes on fifteen elements. Both are the reason script-src still has
// to allow 'unsafe-inline' — and a policy that permits inline script permits
// whatever inline script an injection manages to place, which is most of what the
// CSP is there to stop. Served from /js/portal.js it is 'self', cacheable, gzipped,
// and shared by every subscriber visit instead of re-sent inside every page.
//
// Everything is delegated from document, so the markup only has to declare intent:
// data-copy on anything copyable, data-tab on a guide tab, data-sync on the sync
// button, data-expires on the countdown.
//
// It also shows no string of its own. One file is served to a Persian and an English
// reader alike and it cannot ask the server which one is reading it, so every message
// it displays is rendered onto a data- attribute by the template and read back from
// there. That is not only about translation: two of them are glued to a number this
// file recomputes after a sync, and reading the same bundle field Go used for the
// first paint is what stops the wording shifting under the subscriber when they
// press the button.

(function () {
  'use strict';

  var toastTimer = null;

  // The three tones are CSS state classes, not glyphs in the string. The toast's text is
  // written with textContent because it interpolates data-copied out of the markup, and
  // prepending an emoji would mean building HTML out of an attribute value on the one
  // page whose URL is itself a bearer token. A masked ::before draws the same icon with
  // nothing parsed.
  var TONES = ['is-ok', 'is-warn', 'is-bad'];

  function toastEl() {
    return document.getElementById('toast');
  }

  // msg('sync-ok') reads data-msg-sync-ok. Returns '' for a name the markup does not
  // carry, and showToast then declines to open an empty bar.
  function msg(name) {
    var el = toastEl();
    return (el && el.getAttribute('data-msg-' + name)) || '';
  }

  function showToast(text, tone) {
    var el = toastEl();
    if (!el || !text) return;
    el.textContent = text;
    TONES.forEach(function (c) {
      el.classList.toggle(c, c === tone);
    });
    el.classList.add('is-shown');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      el.classList.remove('is-shown');
    }, 2600);
  }

  // The clipboard, with a fallback that is not optional here.
  //
  // navigator.clipboard only exists in a secure context, and this portal is
  // normally served over plain http on a VPS address — so on the page where the
  // whole point is copying a DNS address, the async API is absent for most
  // subscribers. The previous code called navigator.clipboard.writeText without
  // awaiting it or checking for it, then showed "کپی شد!" unconditionally: the
  // subscriber was told the copy succeeded and their clipboard was untouched.
  // Nothing here reports success it did not get.
  function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(
        function () {
          return true;
        },
        function () {
          return legacyCopy(text);
        }
      );
    }
    return Promise.resolve(legacyCopy(text));
  }

  // execCommand('copy') is deprecated and is also the only thing that works over
  // http. The textarea is positioned off-screen rather than hidden because a
  // display:none or visibility:hidden element cannot be selected.
  function legacyCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    var ok = false;
    try {
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      ok = document.execCommand('copy');
    } catch (e) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  function copyFrom(host) {
    var text = host.getAttribute('data-copy') || '';
    if (!text) return;
    // Each copyable element names its own confirmation — "Primary DNS copied", not a
    // generic one — because four of them sit next to each other and the subscriber's
    // question is which of the four they just got.
    var done = host.getAttribute('data-copied') || msg('copied');
    writeClipboard(text).then(function (ok) {
      if (ok) showToast(done, 'is-ok');
      else showToast(msg('copy-fail'), 'is-warn');
    });
  }

  /* --- Device guide tabs ---------------------------------------------------- */

  function tabButtons() {
    return Array.prototype.slice.call(document.querySelectorAll('[data-tab]'));
  }

  function selectTab(name) {
    tabButtons().forEach(function (btn) {
      var on = btn.getAttribute('data-tab') === name;
      btn.classList.toggle('is-active', on);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
      // Only the selected tab stays in the tab order; the rest are reached with
      // the arrow keys, which is what a tablist is expected to do.
      btn.setAttribute('tabindex', on ? '0' : '-1');
    });
    document.querySelectorAll('[data-panel]').forEach(function (panel) {
      panel.classList.toggle('is-hidden', panel.getAttribute('data-panel') !== name);
    });
  }

  // Arrow keys move along the tablist. The list is inside dir="rtl", so
  // ArrowLeft advances and ArrowRight goes back — the key that points at the next
  // tab visually is the one that should select it.
  function activate(btn) {
    if (!btn) return;
    selectTab(btn.getAttribute('data-tab'));
    // Focus follows selection: the newly selected tab is the only one left in the
    // tab order, so leaving focus on the old one would strand it.
    btn.focus();
  }

  document.addEventListener('keydown', function (e) {
    var tab = e.target.closest ? e.target.closest('[data-tab]') : null;
    if (!tab) return;
    var btns = tabButtons();
    var i = btns.indexOf(tab);
    if (i < 0) return;
    var rtl = (document.documentElement.getAttribute('dir') || '') === 'rtl';
    var forward = rtl ? 'ArrowLeft' : 'ArrowRight';
    var back = rtl ? 'ArrowRight' : 'ArrowLeft';
    if (e.key === forward) activate(btns[(i + 1) % btns.length]);
    else if (e.key === back) activate(btns[(i - 1 + btns.length) % btns.length]);
    else if (e.key === 'Home') activate(btns[0]);
    else if (e.key === 'End') activate(btns[btns.length - 1]);
    else return;
    e.preventDefault();
  });

  document.addEventListener('click', function (e) {
    if (!e.target.closest) return;
    var copy = e.target.closest('[data-copy]');
    if (copy) {
      copyFrom(copy);
      return;
    }
    var tab = e.target.closest('[data-tab]');
    if (tab) {
      selectTab(tab.getAttribute('data-tab'));
      return;
    }
    var reg = e.target.closest('[data-reg]');
    if (reg) runRegister(reg);
  });

  /* --- Expiry countdown ----------------------------------------------------- */

  // The three boxes used to be server-rendered numbers with ids that promised a
  // countdown and never moved: a subscriber who left the tab open watched "0 روز
  // 4 ساعت" stay at four hours past midnight. data-expires is a unix second, 0 for
  // a lifetime plan (in which case the markup renders a single ∞ cell instead and
  // there is nothing here to update).
  function tickCountdown() {
    var host = document.querySelector('[data-expires]');
    if (!host) return;
    var at = parseInt(host.getAttribute('data-expires'), 10);
    if (!at) return;

    var left = at - Math.floor(Date.now() / 1000);
    if (left < 0) left = 0;
    var parts = {
      'cd-days': Math.floor(left / 86400),
      'cd-hours': Math.floor(left / 3600) % 24,
      'cd-mins': Math.floor(left / 60) % 60,
    };
    Object.keys(parts).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.textContent = String(parts[id]);
    });
  }

  /* --- Quota display, shared by first paint and every sync ------------------ */

  var MB = 1024 * 1024;

  // Mirrors renderIPResultPage's formatting exactly. Two places format the same
  // figures because one of them has to run before any script does; if they drift,
  // the numbers appear to change when the subscriber presses sync.
  //
  // `exceeded` is the daemon's own verdict, passed in rather than derived from the
  // two numbers above. Deriving it here would put the enforcement rule in a second
  // place, and the copy that runs on the subscriber's phone is the one that would be
  // wrong about a limit large enough to lose precision.
  function renderQuota(usedBytes, limitGB, exceeded) {
    var display = document.getElementById('traffic-display');
    var fill = document.getElementById('traffic-fill');
    var left = document.getElementById('traffic-remaining');
    var pill = document.getElementById('quota-pill');
    var usedMB = usedBytes / MB;
    var usedGB = usedMB / 1024;

    if (pill) pill.classList.toggle('is-gone', !exceeded);

    if (!limitGB || limitGB <= 0) {
      if (display) display.textContent = usedMB.toFixed(2) + ' MB / Unlimited';
      if (left) left.textContent = left.getAttribute('data-unlimited') || '';
      if (fill) fill.style.width = '0%';
      return;
    }

    var percent = (usedGB / limitGB) * 100;
    if (percent > 100) percent = 100;
    var remaining = limitGB - usedGB;
    if (remaining < 0) remaining = 0;

    if (display) display.textContent = usedGB.toFixed(2) + ' GB / ' + limitGB.toFixed(1) + ' GB';
    // "%.2f GB %s" in Go, the same three pieces in the same order here.
    if (left) left.textContent = remaining.toFixed(2) + ' GB ' + (left.getAttribute('data-word') || '');
    if (fill) fill.style.width = percent.toFixed(1) + '%';
  }

  /* --- The sync button ------------------------------------------------------- */

  // /api/sub/<token>/sync re-binds the caller's current address to the subscription
  // and answers with the whole record. The old handler read one field of that
  // answer — detected_ip — and left the quota bar and the countdown showing what
  // the page had been rendered with, so a subscriber who pressed sync to check
  // their usage was shown a stale figure by the very action meant to refresh it.
  function runRegister(btn) {
    var url = btn.getAttribute('data-reg');
    if (!url || btn.getAttribute('aria-busy') === 'true') return;
    var secretEl = document.getElementById('register-secret');
    var secret = secretEl ? secretEl.value.trim() : '';
    if (!secret) {
      showToast(msg('register-fail'), 'is-bad');
      return;
    }
    btn.setAttribute('aria-busy', 'true');

    // The one write the portal offers: the out-of-band secret is what stands
    // between a leaked link and the subscription's binding (Mantis C-03).
    // Without an explicit ip field the server binds the address it sees this
    // request from — the 1-click flow.
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ secret: secret })
    })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          return { ok: res.ok, data: data };
        });
      })
      .then(function (r) {
        if (!r.ok) {
          // The API answers with a machine-readable reason beside its English
          // text; this file renders the subscriber's own language from it. A
          // single generic "wrong secret" for every refusal is what made a
          // lapsed plan, a spent allowance, or an address held by another
          // subscription all read as a typo — and sent the subscriber to fix
          // the one thing that was never wrong.
          //
          // The named calls are deliberate rather than a loop over the reason:
          // each one is a literal the consistency test can find, so a renamed
          // bundle field or a dropped attribute is caught here instead of
          // showing up as a silently empty toast.
          var reason = (r.data && r.data.reason) || '';
          if (reason === 'suspended') {
            showToast(msg('reason-suspended'), 'is-bad');
          } else if (reason === 'expired') {
            showToast(msg('reason-expired'), 'is-bad');
          } else if (reason === 'quota') {
            showToast(msg('reason-quota'), 'is-bad');
          } else if (reason === 'conflict') {
            showToast(msg('reason-conflict'), 'is-bad');
          } else if (reason === 'invalid') {
            showToast(msg('reason-invalid'), 'is-bad');
          } else {
            showToast(msg('register-denied'), 'is-bad');
          }
          return;
        }
        var ip = document.getElementById('detected-ip');
        if (ip && r.data.detected_ip) ip.textContent = r.data.detected_ip;
        if (ip && r.data.bound_ip) ip.textContent = r.data.bound_ip;
        renderQuota(
          Number(r.data.traffic_used_bytes) || 0,
          Number(r.data.traffic_limit_gb) || 0,
          r.data.quota_exceeded === true
        );
        showToast(msg('register-ok'), 'is-ok');
        if (secretEl) secretEl.value = '';
      })
      .catch(function () {
        showToast(msg('register-fail'), 'is-bad');
      })
      .then(function () {
        btn.removeAttribute('aria-busy');
      });
  }

  /* --- Boot ------------------------------------------------------------------ */

  // The script tag is at the end of <body>, so the document is parsed by now and
  // there is no DOMContentLoaded to wait for. The countdown is refreshed on a
  // 30-second interval rather than a 1-second one: the smallest unit shown is a
  // minute, so a second-by-second timer would wake the phone sixty times to write
  // the same three numbers.
  tickCountdown();
  setInterval(tickCountdown, 30000);

  // A phone suspends timers while the tab is in the background; the countdown is
  // stale the moment the subscriber comes back to it.
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) tickCountdown();
  });
})();
