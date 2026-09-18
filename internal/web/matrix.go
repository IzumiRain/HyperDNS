package web

import (
	"fmt"
	"net/http"
)

// handleMatrix renders a Matrix Digital Rain cyberpunk landing page
func (ws *WebServer) handleMatrix(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	pubIP := ws.cfg.Server.PublicIP
	if pubIP == "" {
		pubIP = "127.0.0.1"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HyperDNS — System Gateway</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;700;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #000; overflow: hidden; font-family: 'JetBrains Mono', monospace; color: #00f0ff; }
    canvas { position: absolute; top: 0; left: 0; width: 100%%; height: 100%%; z-index: 1; opacity: 0.85; }
    .overlay { position: relative; z-index: 10; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; text-align: center; }
    .matrix-box { background: rgba(3, 7, 18, 0.88); backdrop-filter: blur(16px); border: 1px solid rgba(0, 240, 255, 0.4); box-shadow: 0 0 40px rgba(0, 240, 255, 0.2); border-radius: 20px; padding: 32px 24px; max-width: 520px; width: 100%%; }
    .glow-title { font-family: 'Chakra Petch', sans-serif; text-shadow: 0 0 20px rgba(0, 240, 255, 0.8), 0 0 40px rgba(0, 240, 255, 0.4); }
    .portal-btn { font-family: 'Chakra Petch', sans-serif; background: linear-gradient(90deg, #00f0ff, #3b82f6); box-shadow: 0 0 25px rgba(0, 240, 255, 0.4); transition: all 0.3s ease; }
    .portal-btn:hover { transform: translateY(-2px); box-shadow: 0 0 40px rgba(0, 240, 255, 0.7); }
    .scanline { position: fixed; top: 0; left: 0; width: 100%%; height: 100%%; background: linear-gradient(rgba(18, 16, 16, 0) 50%%, rgba(0, 0, 0, 0.25) 50%%), linear-gradient(90deg, rgba(255, 0, 0, 0.02), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.02)); z-index: 20; background-size: 100%% 3px, 6px 100%%; pointer-events: none; }
  </style>
</head>
<body>
  <div class="scanline"></div>
  <canvas id="matrixCanvas"></canvas>

  <div class="overlay">
    <div class="matrix-box space-y-6">
      
      <!-- Logo & Header -->
      <div class="space-y-2">
        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-xs font-bold text-cyan-300">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
          <span>SYSTEM OPERATIONAL · ZERO-PACKET-LOSS</span>
        </div>
        <h1 class="text-3xl sm:text-4xl font-extrabold text-white glow-title tracking-wider mt-2">HyperDNS</h1>
        <p class="text-xs text-cyan-300 font-mono tracking-widest uppercase">Autonomous Gaming & Anti-Sanction Smart Gateway</p>
      </div>

      <!-- Node Stats -->
      <div class="grid grid-cols-2 gap-2 text-left text-xs bg-black/60 p-3.5 rounded-xl border border-cyan-950">
        <div>
          <span class="text-slate-500 text-[10px] uppercase">Node IP</span>
          <div class="text-white font-bold">%s</div>
        </div>
        <div>
          <span class="text-slate-500 text-[10px] uppercase">Architecture</span>
          <div class="text-emerald-400 font-bold">Go 1.26 Multi-Thread</div>
        </div>
        <div class="mt-1">
          <span class="text-slate-500 text-[10px] uppercase">Protocols</span>
          <div class="text-purple-300 font-bold">UDP · TCP · DoH · DoT</div>
        </div>
        <div class="mt-1">
          <span class="text-slate-500 text-[10px] uppercase">Latency</span>
          <div class="text-cyan-400 font-bold">&lt; 1.0 ms (In-Memory)</div>
        </div>
      </div>

      <!-- Action Portal Buttons -->
      <div class="space-y-2.5 pt-2">
        <a href="/dashboard" class="portal-btn w-full py-3 px-6 rounded-xl text-slate-950 font-extrabold text-sm flex items-center justify-center gap-2 block tracking-wider">
          <span>ACCESS DASHBOARD</span>
          <span>&rarr;</span>
        </a>
        <div class="text-[11px] text-slate-500">
          Or manage node via terminal: <code class="text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">hdns</code>
        </div>
      </div>

    </div>
  </div>

  <script>
    const canvas = document.getElementById('matrixCanvas');
    const ctx = canvas.getContext('2d');

    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    const chars = '0123456789ABCDEFHYPERDNSGAMINGVALORANTCODSTEAMPUBGROIOX';
    const fontSize = 14;
    let columns = Math.floor(canvas.width / fontSize);
    let drops = Array(columns).fill(1);

    function draw() {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.06)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = '#00f0ff';
      ctx.font = fontSize + 'px monospace';

      for (let i = 0; i < drops.length; i++) {
        const text = chars.charAt(Math.floor(Math.random() * chars.length));
        ctx.fillStyle = Math.random() > 0.9 ? '#ffffff' : (Math.random() > 0.5 ? '#00f0ff' : '#10b981');
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
    }
    setInterval(draw, 35);
  </script>
</body>
</html>`, pubIP)

	_, _ = w.Write([]byte(html))
}
