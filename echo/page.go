package echo

const navigationPlaceholder = "__TLS_FORGE_NAVIGATION__"
const http1NavigationPlaceholder = "__TLS_FORGE_HTTP1_NAVIGATION__"

// capturePage is served at "/". It has one job beyond being readable: report
// what the HTTP layer cannot.
//
// The handshake and the headers arrive on the wire, but the high-entropy client
// hints do not — a browser only sends sec-ch-ua-arch, -bitness, -model and
// -platform-version after a server has asked for them with Accept-CH, and even
// then only some of them. getHighEntropyValues() returns all of them for the
// asking, from the browser itself, which is the only source that cannot be
// wrong about the machine it is running on.
//
// Everything is inline. The page is served over a self-signed certificate that
// the browser has been told to ignore; loading a script from anywhere else would
// mean a second connection with a second trust decision, for no gain.
const capturePage = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>tls-forge capture</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --bg:#fff; --muted:#666; --line:#e3e3e3; --ok:#0a7d32; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e8e8; --bg:#141414; --muted:#9b9b9b; --line:#2c2c2c; --ok:#4ade80; }
  }
  body { margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
         font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  main { max-width:52rem; margin:0 auto; }
  h1 { font-size:1.25rem; margin:0 0 .25rem; }
  p.sub { color:var(--muted); margin:0 0 2rem; }
  table { width:100%; border-collapse:collapse; margin-bottom:1.5rem; }
  th { text-align:left; font-weight:600; width:11rem; vertical-align:top; padding:.45rem .75rem .45rem 0;
       border-bottom:1px solid var(--line); color:var(--muted); font-size:13px; }
  td { padding:.45rem 0; border-bottom:1px solid var(--line);
       font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; word-break:break-all; }
  .status { color:var(--ok); font-weight:600; }
  a { color:inherit; }
</style>
<main>
  <h1>tls-forge capture</h1>
  <p class="sub" id="status">measuring this browser…</p>
  <table id="out"></table>
  <p class="sub">Full detail: <a href="/api/all">/api/all</a></p>
</main>
<script>
(async () => {
  const status = document.getElementById('status');
  const http1Navigation = '__TLS_FORGE_HTTP1_NAVIGATION__';
  if (http1Navigation) {
    window.location.replace(http1Navigation);
    return;
  }
  const data = navigator.userAgentData;
  // Every field is optional: userAgentData is Chromium-only, and
  // getHighEntropyValues rejects rather than degrades when a hint is refused.
  let hints = {};
  if (data) {
    try {
      hints = await data.getHighEntropyValues([
        'architecture', 'bitness', 'model', 'platformVersion',
        'uaFullVersion', 'fullVersionList', 'wow64', 'formFactors',
      ]);
    } catch (e) { hints = {}; }
  }

  const payload = {
    user_agent: navigator.userAgent,
    languages: Array.from(navigator.languages || []),
    platform: hints.platform || (data && data.platform) || '',
    mobile: !!(data && data.mobile),
    brands: (data && data.brands) || [],
    full_version_list: hints.fullVersionList || [],
    architecture: hints.architecture || '',
    bitness: hints.bitness || '',
    model: hints.model || '',
    platform_version: hints.platformVersion || '',
    ua_full_version: hints.uaFullVersion || '',
    wow64: !!hints.wow64,
    form_factors: hints.formFactors || [],
    device_memory: navigator.deviceMemory || 0,
    hardware_concurrency: navigator.hardwareConcurrency || 0,
  };

  let capture;
  try {
    const res = await fetch('/collect?navigation=__TLS_FORGE_NAVIGATION__', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    capture = await res.json();
  } catch (e) {
    status.textContent = 'could not report to the server: ' + e.message;
    return;
  }

  const rows = [
    ['JA4', capture.tls.ja4],
    ['JA3 hash', capture.tls.ja3_hash],
    ['ALPN', (capture.tls.alpn || []).join(', ')],
    ['session resumed', String(capture.tls.session_resumed)],
    ['HTTP/2', capture.http2 ? capture.http2.akamai_fingerprint : '(not negotiated)'],
    ['header order', capture.http2 ? capture.http2.header_order.join(', ') : ''],
    ['user-agent', payload.user_agent],
    ['platform', payload.platform + ' ' + payload.platform_version],
    ['architecture', payload.architecture + ' ' + payload.bitness],
  ];
  document.getElementById('out').innerHTML = rows
    .map(([k, v]) => '<tr><th>' + k + '</th><td>' + (v || '—')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;') + '</td></tr>')
    .join('');
  status.innerHTML = '<span class="status">captured.</span> ' +
    'You can close this tab — the command line has the result.';
})();
</script>
`
