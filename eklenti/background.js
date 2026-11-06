// Kalkan tarayıcı koruması: her sayfa açılışında alan adını bilgisayardaki Kalkan'a sorar.
const KALKAN = 'http://127.0.0.1:47615';
const cache = new Map();   // alan adı -> {v, t}

async function check(host) {
  const c = cache.get(host);
  if (c && Date.now() - c.t < 10 * 60 * 1000) return c.v;
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 1500);
    const r = await fetch(`${KALKAN}/check?h=${encodeURIComponent(host)}`, { signal: ctl.signal });
    clearTimeout(timer);
    const v = await r.json();
    cache.set(host, { v, t: Date.now() });
    if (cache.size > 2000) cache.clear();
    await chrome.storage.session.set({ connected: Date.now() });
    return v;
  } catch (e) {
    return null;    // Kalkan kapalıysa tarayıcı normal çalışır
  }
}

async function allowed(host) {
  const { allow = [] } = await chrome.storage.session.get('allow');
  return allow.includes(host);
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0) return;
  let url;
  try { url = new URL(d.url); } catch (e) { return; }
  if (!/^https?:$/.test(url.protocol)) return;
  const host = url.hostname.toLowerCase();
  if (await allowed(host)) return;
  const v = await check(host);
  if (!v || !v.blocked) return;
  const page = chrome.runtime.getURL('uyari.html') + '?' + new URLSearchParams({
    u: d.url, h: host, r: v.reason || '', c: v.category || '', w: v.warn_only ? '1' : '0' });
  chrome.tabs.update(d.tabId, { url: page });
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === 'allow') {
    chrome.storage.session.get('allow').then(({ allow = [] }) => {
      allow.push(msg.host);
      chrome.storage.session.set({ allow }).then(() => reply({ ok: true }));
    });
    return true;
  }
  if (msg.type === 'status') {
    fetch(`${KALKAN}/ping`).then(r => r.json()).then(j => reply({ ok: !!j.ok })).catch(() => reply({ ok: false }));
    return true;
  }
  if (msg.type === 'check') {
    check(msg.host).then(v => reply(v));
    return true;
  }
});
