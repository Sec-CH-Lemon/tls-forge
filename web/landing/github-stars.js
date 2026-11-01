(() => {
  const counts = [...document.querySelectorAll('[data-github-star-count]')];
  const links = [...document.querySelectorAll('[data-github-star-link]')];
  if (!counts.length || !links.length) return;

  const cacheKey = 'tls-forge.github-stars.v1';
  const cacheAge = 30 * 60 * 1000;
  const exact = new Intl.NumberFormat('en-US');
  const compact = new Intl.NumberFormat('en-US', {notation: 'compact', maximumFractionDigits: 1});

  const show = value => {
    if (!Number.isSafeInteger(value) || value < 0) return false;
    const label = `${exact.format(value)} ${value === 1 ? 'star' : 'stars'}`;
    for (const count of counts) count.textContent = compact.format(value);
    for (const link of links) {
      link.setAttribute('aria-label', `View TLS Forge on GitHub, ${label} (opens in a new tab)`);
    }
    return true;
  };

  let cached;
  try {
    cached = JSON.parse(localStorage.getItem(cacheKey));
    if (cached && show(cached.count)) {
      const age = Date.now() - cached.time;
      if (Number.isFinite(age) && age >= 0 && age < cacheAge) return;
    }
  } catch { /* The visible count remains available without storage. */ }

  const refresh = async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch('https://api.github.com/repos/Sec-CH-Lemon/tls-forge/stargazers/count', {
        headers: {Accept: 'application/vnd.github+json'},
        signal: controller.signal,
      });
      if (!response.ok) return;
      const result = await response.json();
      if (!show(result.count)) return;
      try {
        localStorage.setItem(cacheKey, JSON.stringify({count: result.count, time: Date.now()}));
      } catch { /* A storage failure does not affect the counter. */ }
    } catch { /* Retain the last known count when GitHub is unavailable. */ }
    finally { clearTimeout(timeout); }
  };

  const schedule = () => setTimeout(() => {
    if ('requestIdleCallback' in window) requestIdleCallback(refresh, {timeout: 5000});
    else refresh();
  }, 2000);
  if (document.readyState === 'complete') schedule();
  else addEventListener('load', schedule, {once: true});
})();
