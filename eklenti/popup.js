(async () => {
  const conn = document.getElementById('conn');
  const site = document.getElementById('site');
  const st = await chrome.runtime.sendMessage({ type: 'status' });
  conn.innerHTML = st && st.ok ? '<span class="pill ok">KORUMA AÇIK</span> Bilgisayardaki Kalkan ile bağlı.'
    : '<span class="pill warn">BAĞLI DEĞİL</span> Kalkan çalışmıyor; site kontrolü yapılamıyor.';
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host = '';
  try { host = new URL(tab.url).hostname; } catch (e) { return; }
  if (!host || !st || !st.ok) return;
  const v = await chrome.runtime.sendMessage({ type: 'check', host });
  const h = document.createElement('div');
  h.className = 'host';
  h.textContent = host;
  const p = document.createElement('div');
  if (v && v.blocked) {
    p.innerHTML = `<span class="pill ${v.warn_only ? 'warn' : 'bad'}">${v.warn_only ? 'TAKLİT OLABİLİR' : 'TEHLİKELİ'}</span> `;
    p.append(document.createTextNode(v.reason || ''));
  } else {
    p.innerHTML = '<span class="pill ok">LİSTELERDE YOK</span> Bu site bilinen zararlı listelerinde değil.';
  }
  site.append(h, p);
})();
