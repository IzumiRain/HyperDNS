package web

import (
	"io"
	"net/http"
	"strconv"
)

// The public root page (v2.1, Phase 2).
//
// The bare panel domain used to serve the admin SPA shell, so anyone opening
// "/" learned the product, saw the sign-in form, and could fingerprint the
// build from its bundle URLs. The root now serves this page instead: a small,
// self-contained Matrix-inspired landing with no external assets, no
// operational data, and no links of any kind — in particular nothing that
// names the hidden admin namespace, which Phase 3 moves below the generated
// admin path.
//
// Deliberate constraints, all pinned by landing_test.go:
//   - one constant, no template: there is nothing to interpolate, and a
//     template would be a place for a caller to interpolate the wrong thing;
//   - no <link>, <img>, <script src> or fetch: the page must render with zero
//     further requests, so it can never leak the visit through a subrequest
//     nor break when the operator serves the panel from a host with no static
//     assets routed at root;
//   - no credential-adjacent words anywhere in the body ("login",
//     "dashboard", "admin", "/api/", bundle names): the exit gate asserts
//     their absence case-insensitively, so even an HTML comment must not carry
//     them;
//   - accessibility basics: a real <title>, a single <h1>, body copy at
//     ~15:1 and secondary copy at ~7:1 against black (both past WCAG AA), a
//     prefers-reduced-motion CSS branch that hides the canvas and shows a
//     static glyph block instead, the same check in JS before the loop
//     starts, and a <noscript> paragraph so the page still says its name with
//     scripting off.
//
// The global middleware already wraps this response with no-store, noindex,
// the shared security headers and CSP. The inline <style> and <script> below
// are covered by the 'unsafe-inline' allowances the dashboard still needs
// (see contentSecurityPolicy in server.go); they introduce no new source.
const landingPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark">
<meta name="robots" content="noindex, nofollow">
<title>HyperDNS</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  background: #000;
  color: #00ff41;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  min-height: 100dvh;
  overflow: hidden;
}
#matrix {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  display: block;
}
.brand {
  position: relative;
  text-align: center;
  padding: 0 1.5rem;
}
.brand h1 {
  margin: 0;
  font-size: clamp(2rem, 8vw, 4rem);
  font-weight: 700;
  letter-spacing: .35em;
  text-indent: .35em;
  text-shadow: 0 0 18px rgba(0, 255, 65, .55);
}
.brand p.sub {
  margin: 1rem 0 0;
  font-size: 1rem;
  letter-spacing: .15em;
  color: #00b324;
}
.brand p.static-fallback {
  display: none;
  margin: 1.5rem auto 0;
  max-width: 34rem;
  font-size: .85rem;
  line-height: 1.7;
  letter-spacing: .2em;
  color: #00b324;
  word-break: break-all;
}
@media (prefers-reduced-motion: reduce) {
  #matrix { display: none; }
  .brand p.static-fallback { display: block; }
}
</style>
</head>
<body data-landing="matrix">
<canvas id="matrix" aria-hidden="true"></canvas>
<main class="brand">
<h1>HyperDNS</h1>
<p class="sub">quiet node</p>
<p class="static-fallback" aria-hidden="true">01001000 01111001 01110000 01100101 01110010 01000100 01001110 01010011</p>
</main>
<noscript><p style="position:relative;text-align:center;color:#00ff41">HyperDNS</p></noscript>
<script>
(function () {
  try {
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  } catch (e) { return; }
  var canvas = document.getElementById('matrix');
  if (!canvas || !canvas.getContext) return;
  var ctx = canvas.getContext('2d');
  if (!ctx) return;
  var glyphs = '01';
  var fontSize = 16;
  var drops = [];
  var width = 0, height = 0;
  function resize() {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    var cols = Math.max(1, Math.floor(width / fontSize));
    drops = [];
    for (var i = 0; i < cols; i++) drops[i] = Math.floor(Math.random() * -40);
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, width, height);
  }
  resize();
  window.addEventListener('resize', resize);
  var last = 0;
  var hidden = false;
  document.addEventListener('visibilitychange', function () { hidden = document.hidden; });
  function frame(now) {
    requestAnimationFrame(frame);
    if (hidden) return;
    if (now - last < 80) return;
    last = now;
    ctx.fillStyle = 'rgba(0, 0, 0, 0.08)';
    ctx.fillRect(0, 0, width, height);
    ctx.font = fontSize + 'px monospace';
    for (var i = 0; i < drops.length; i++) {
      var ch = glyphs.charAt(Math.floor(Math.random() * glyphs.length));
      ctx.fillStyle = Math.random() < 0.025 ? '#ccffd9' : '#00ff41';
      ctx.fillText(ch, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > height && Math.random() > 0.976) drops[i] = 0;
      drops[i]++;
    }
  }
  requestAnimationFrame(frame);
})();
</script>
</body>
</html>
`

// serveLandingPage answers GET/HEAD on the public root with the Matrix
// landing page. Every other verb is refused with an explicit Allow, in the
// same shape as the SPA and asset handlers, so the method-guard walk in
// method_guard_test.go and the Allow-header proof in method_allow_test.go
// keep covering this route.
func (ws *WebServer) serveLandingPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(landingPageHTML)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, landingPageHTML)
}
