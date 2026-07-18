package relay

import "net/http"

// statusPage serves a small, self-contained landing page at "/". The relay is a
// headless JSON API — this exists purely so a human who pastes the URL into a
// browser sees something intentional ("it's online, and it's an endpoint, not a
// site to log into") instead of a bare 401 from the entitlement gate. It's
// public (no token), like /v1/health.
func (s *Server) statusPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(statusHTML))
}

const statusHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hive relay</title>
<style>
  :root {
    --bg: #f7f7f6; --panel: #ffffff; --ink: #1a1a1a; --mist: #f0f0ef;
    --line: #e3e3e0; --muted: #6b6b6b; --accent: #3b6ef5; --ok: #22a05a;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #121212; --panel: #1b1b1b; --ink: #ececec; --mist: #222;
      --line: #2c2c2c; --muted: #9a9a9a; --accent: #7f9cff; --ok: #35c07a;
    }
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    display: grid; place-items: center; padding: 24px;
    background: var(--bg); color: var(--ink);
    font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  .card {
    width: 100%; max-width: 460px; background: var(--panel);
    border: 1px solid var(--line); border-radius: 20px; padding: 28px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  }
  .row { display: flex; align-items: center; gap: 10px; }
  h1 { font-size: 20px; margin: 0; letter-spacing: -0.01em; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--ok);
         box-shadow: 0 0 0 4px color-mix(in srgb, var(--ok) 22%, transparent); }
  .status { margin-left: auto; font-size: 13px; color: var(--ok); font-weight: 600; }
  p { color: var(--muted); margin: 16px 0 0; }
  .note {
    margin-top: 18px; padding: 12px 14px; background: var(--mist);
    border: 1px solid var(--line); border-radius: 12px; font-size: 13px; color: var(--muted);
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
         background: var(--mist); padding: 1px 5px; border-radius: 6px; font-size: 12.5px; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .foot { margin-top: 20px; font-size: 12px; color: var(--muted); }
</style>
</head>
<body>
  <main class="card">
    <div class="row">
      <span class="dot" aria-hidden="true"></span>
      <h1>Hive relay</h1>
      <span class="status">online</span>
    </div>
    <p>
      This is a <strong>content-blind sync relay</strong> for
      <a href="https://github.com/honeyhive-ai/hive">Hive</a> — an API endpoint,
      not a website to log into. It forwards end-to-end-encrypted traffic between
      devices and never sees plaintext.
    </p>
    <div class="note">
      Point Hive at this URL under <strong>Settings → Team</strong> and paste an
      access token issued by your relay admin. Browsing here directly needs no
      token; everything else does.
    </div>
    <p class="foot">Health check: <code>/v1/health</code></p>
  </main>
</body>
</html>`
