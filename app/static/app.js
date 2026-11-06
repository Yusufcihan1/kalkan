/* Kalkan arayüzü: tek sayfa, sade JS. Ajanla /api/run üzerinden konuşur. */
'use strict';
const T = new URLSearchParams(location.search).get('t') || '';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const state = { page: 'durum', status: null, ai: { mode: 'sohbet' }, scanView: null };

function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function ago(ts) {
  if (!ts) return '';
  const s = Date.now() / 1000 - ts;
  if (s < 60) return 'az önce';
  if (s < 3600) return Math.floor(s / 60) + ' dk önce';
  if (s < 86400) return Math.floor(s / 3600) + ' saat önce';
  if (s < 86400 * 30) return Math.floor(s / 86400) + ' gün önce';
  return new Date(ts * 1000).toLocaleDateString('tr-TR');
}
function when(ts) { return ts ? new Date(ts * 1000).toLocaleString('tr-TR', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : ''; }
function size(n) { if (n == null) return ''; const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i]; }
const LEVEL_TR = { tehdit: 'TEHDİT', supheli: 'ŞÜPHELİ', istenmeyen: 'İSTENMEYEN', bilgi: 'BİLGİ', iyi: 'İYİ', guvenli: 'GÜVENLİ', bilinmiyor: 'BİLİNMİYOR' };

async function api(op, args = {}) {
  const r = await fetch('/api/run?t=' + encodeURIComponent(T), { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Token': T }, body: JSON.stringify({ op, args }) });
  const j = await r.json().catch(() => ({ error: 'Yanıt okunamadı (' + r.status + ')' }));
  if (!r.ok || j.error) throw new Error(j.error || ('Hata ' + r.status));
  return j.result;
}
async function waitJob(id, onProg) {
  for (;;) {
    const r = await fetch('/api/job/' + id + '?t=' + encodeURIComponent(T), { headers: { 'X-Token': T } });
    const j = await r.json();
    if (onProg) onProg(j);
    if (j.status === 'done') return j.result;
    if (j.status === 'error') throw new Error(j.error);
    if (j.status === 'cancelled') throw new Error('İptal edildi');
    await sleep(600);
  }
}
async function runJob(op, args, onProg) {
  const { job } = await api(op, args);
  return waitJob(job, onProg);
}
/* Claude işleri: anahtar yoksa önce anahtarı ister, sonra işi yeniden dener. */
async function aiJob(op, args, onProg) {
  try { return await runJob(op, args, onProg); }
  catch (e) {
    if (String(e.message).includes('API_ANAHTARI_YOK')) {
      const ok = await askKey();
      if (ok) return runJob(op, args, onProg);
      throw new Error('Claude için API anahtarı gerekiyor.');
    }
    throw e;
  }
}

function toast(msg, err) {
  const t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), err ? 7000 : 4000);
}
async function act(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(typeof okMsg === 'function' ? okMsg(r) : okMsg); return r; }
  catch (e) { toast(e.message, true); return undefined; }
}
function dialog(html, onMount) {
  const d = $('#dlg');
  d.innerHTML = html;
  d.showModal();
  if (onMount) onMount(d);
  return d;
}
function confirmBox(title, text, okLabel = 'Tamam', danger = false) {
  return new Promise(res => {
    const d = dialog(`<h2>${esc(title)}</h2><p class="sub">${esc(text)}</p><div class="actions"><button class="btn" data-x="0">Vazgeç</button><button class="btn ${danger ? 'danger' : 'primary'}" data-x="1">${esc(okLabel)}</button></div>`);
    d.onclick = e => { const x = e.target.closest('[data-x]'); if (x) { d.close(); res(x.dataset.x === '1'); } };
  });
}
function askKey() {
  return new Promise(res => {
    const d = dialog(`<h2>Claude API anahtarı</h2>
      <p class="sub">Claude ile yapılan işler (Bu dosya ne?, dolandırıcılık kontrolü, asistan, rapor) için kendi anahtarın gerekiyor.
      <a href="#" id="k-link">console.anthropic.com</a> → API Keys → Create Key. Anahtar Windows Kimlik Bilgisi Yöneticisi'nde saklanır.
      API kullanımı Claude aboneliğinden ayrı ücretlendirilir.</p>
      <input type="password" id="k-in" placeholder="sk-ant-..." style="width:100%;margin-top:10px" autocomplete="off">
      <div class="actions"><button class="btn" data-x="0">Vazgeç</button><button class="btn ai solid" data-x="1">Kaydet</button></div>`);
    $('#k-link', d).onclick = e => { e.preventDefault(); api('open_settings', { uri: 'https://console.anthropic.com/settings/keys' }); };
    d.onclick = async e => {
      const x = e.target.closest('[data-x]');
      if (!x) return;
      if (x.dataset.x === '0') { d.close(); return res(false); }
      x.disabled = true; x.innerHTML = '<span class="spinner"></span> Deneniyor';
      try { await runJob('ai_key_set', { key: $('#k-in', d).value }); d.close(); toast('Anahtar kaydedildi'); res(true); }
      catch (err) { toast(err.message, true); x.disabled = false; x.textContent = 'Kaydet'; }
    };
  });
}

const ICON = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/>',
  spark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.5l1.8 5.2 5.2 1.8-5.2 1.8L12 17.5l-1.8-5.2L5 10.5l5.2-1.8z"/></svg>',
  folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true"><path d="M3.5 7.5a2 2 0 012-2h4l2 2h7a2 2 0 012 2v8a2 2 0 01-2 2h-13a2 2 0 01-2-2z"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M19.5 12a7.5 7.5 0 11-2.2-5.3M19.5 4.5v4h-4"/></svg>',
};
const sw = (on, attrs = '') => `<button class="switch" role="switch" aria-checked="${on ? 'true' : 'false'}" ${attrs}></button>`;

/* ================================================================ gezinme */
const PAGES = {};
async function go(page, opts) {
  state.page = page;
  $$('.nav').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  const main = $('#main');
  main.scrollTop = 0;
  main.innerHTML = '<div class="page"><div class="empty"><span class="spinner"></span></div></div>';
  try { await PAGES[page](main, opts || {}); }
  catch (e) { main.innerHTML = `<div class="page"><div class="banner bad">${esc(e.message)}</div></div>`; }
}
$$('.nav').forEach(b => b.onclick = () => go(b.dataset.page));
$('#quiet-switch').onclick = async () => {
  const on = $('#quiet-switch').getAttribute('aria-checked') !== 'true';
  await act(() => api('quiet_set', { on }), on ? 'Sessiz mod açık: uyarılar bildirime düşer' : 'Sessiz mod kapalı');
  refreshStatus();
};

async function refreshStatus() {
  try {
    const s = await api('status');
    state.status = s;
    const bd = $('#b-durum'), bt = $('#b-tarama');
    bd.textContent = s.alerts; bd.classList.toggle('hidden', !s.alerts);
    const nf = s.open_threats + s.open_warnings;
    bt.textContent = s.scan_job ? '…' : nf; bt.classList.toggle('hidden', !(nf || s.scan_job));
    bt.style.background = s.scan_job ? '#0B6E5B' : '';
    $('#quiet-switch').setAttribute('aria-checked', s.quiet_manual ? 'true' : 'false');
    $('#quiet-label').textContent = s.quiet && !s.quiet_manual ? 'Sessiz (tam ekran)' : 'Sessiz mod';
    if (state.page === 'durum') updateDurum(s);
    return s;
  } catch (e) { return null; }
}
setInterval(refreshStatus, 4000);

/* ================================================================ Durum */
const HERO = {
  korunuyor: { t: 'Korunuyorsun', p: 'Tara' },
  dikkat: { t: 'Dikkatini isteyen şeyler var', p: 'Gözden geçir' },
  tehdit: { t: 'Tehdit bulundu', p: 'Tehdidi gör' },
};
function heroText(s) {
  const ls = s.last_scan;
  const scanTxt = ls && ls.finished ? `Son ${ls.kind === 'deep' ? 'derin' : 'hızlı'} tarama ${ago(ls.finished)}, ${ls.findings ? ls.findings + ' bulgu' : 'tehdit bulunmadı'}.` : 'Henüz tarama yapılmadı.';
  if (s.level === 'tehdit') return `${s.open_threats ? s.open_threats + ' tehdit karantinaya alınmayı bekliyor. ' : ''}${s.alerts ? s.alerts + ' uyarı yanıt bekliyor.' : ''}`;
  if (s.level === 'dikkat') {
    const parts = [];
    if (s.alerts) parts.push(`${s.alerts} uyarı yanıt bekliyor`);
    if (s.open_warnings) parts.push(`son taramada ${s.open_warnings} şüpheli bulgu var`);
    const off = Object.entries(s.layers).filter(([, l]) => !l.on).map(([k]) => ({ realtime: 'anlık koruma', ransom: 'fidye kalkanı', web: 'web koruması', defender: 'Defender kuralları' }[k]));
    if (off.length) parts.push(off.join(', ') + ' kapalı');
    if (s.score && s.score.open && s.score.open.length) parts.push(`${s.score.open.length} güvenlik önerisi var`);
    const t = parts.join('; ');
    return t.charAt(0).toLocaleUpperCase('tr-TR') + t.slice(1) + '. ' + scanTxt;
  }
  return scanTxt + ' Anlık koruma, fidye kalkanı ve web koruması açık.';
}
function heroHTML(s) {
  const h = HERO[s.level];
  const icon = ICON.shield + (s.level === 'korunuyor' ? '<path d="M8.5 12.5l2.5 2.5 4.5-5"/>' : '<path d="M12 8v5M12 16v.5"/>') + '</svg>';
  const primary = s.scan_job ? '<button class="btn primary big" data-go="tarama">Tarama sürüyor…</button>'
    : s.level === 'korunuyor' ? '<button class="btn primary big" data-scan="quick">Hızlı tara</button>'
      : `<button class="btn primary big" data-go="${s.alerts ? 'durum-alerts' : s.open_threats || s.open_warnings ? 'tarama' : 'koruma'}">${h.p}</button>`;
  return `<section class="hero ${s.level}" aria-label="Koruma durumu"><div class="disc">${icon}</div>
    <div class="txt"><h1>${h.t}</h1><p>${esc(heroText(s))}</p></div>
    <div class="row">${primary}${s.scan_job ? '' : '<button class="btn big" data-scan="deep">Derin tara</button>'}</div></section>`;
}
const LAYERS = [
  ['realtime', 'Anlık koruma', 'Yeni programlar, indirilenler ve USB bellekler anında taranır.'],
  ['ransom', 'Fidye kalkanı', 'Tuzak dosyalar, şifreleme izleme, anlık görüntü ve yedek kasası.'],
  ['web', 'Web koruma', 'DNS filtresi tüm programlarda zararlı ve sahte siteleri engeller.'],
  ['defender', 'Defender kuralları', 'Saldırı yüzeyi kuralları, ağ koruması ve istenmeyen yazılım engeli.'],
];
function layersHTML(s) {
  return LAYERS.map(([k, name, desc]) => {
    const l = s.layers[k];
    return `<div class="card layer"><div class="row between"><span class="name">${name}</span>${sw(l.on, `data-layer="${k}" aria-label="${name}"`)}</div>
      <span class="desc">${desc}</span><span class="stat ${l.on ? '' : 'off'}">${esc(l.on ? l.stat : 'Kapalı · ' + l.stat)}</span></div>`;
  }).join('');
}
async function alertsHTML() {
  const alerts = await api('alerts');
  if (!alerts.length) return '';
  return `<section class="stack" aria-label="Uyarılar" id="alerts-sec"><div class="section-title"><h2>Yanıt bekleyen uyarılar</h2></div>` +
    alerts.map(a => `<div class="finding"><span class="tag ${a.level}">${LEVEL_TR[a.level] || ''}</span>
      <div class="body"><span class="title">${esc(a.title)}</span><span class="why">${esc(a.text)}</span><span class="note">${ago(a.time)}</span></div>
      <div class="row">${a.actions.map(([k, l], i) => `<button class="btn sm ${k === 'explain' ? 'ai' : i === 0 ? 'dark' : ''}" data-alert="${a.id}" data-act="${k}">${esc(l)}</button>`).join('')}</div></div>`).join('') + '</section>';
}
function engFoot(s) {
  const n = { defender: 'Defender', clamav: 'ClamAV', yara: 'YARA', bazaar: 'MalwareBazaar', virustotal: 'VirusTotal' };
  return '<span>Motorlar:</span>' + Object.entries(s.engines).map(([k, e]) =>
    `<span><span class="dot ${e.on && e.ok ? '' : e.on ? 'warn' : 'off'}"></span><b>${n[k]}</b> ${e.on ? (e.ok ? 'hazır' : k === 'bazaar' || k === 'virustotal' ? 'anahtar yok' : 'kurulmadı') : 'kapalı'}</span>`).join('');
}
PAGES.durum = async (main) => {
  const s = state.status || await refreshStatus() || await api('status');
  const sc = s.score || {};
  const open = (sc.open || []).slice(0, 2);
  main.innerHTML = `<div class="page">
    <div id="hero">${heroHTML(s)}</div>
    ${s.update ? `<div class="banner info row between"><span>Kalkan ${esc(s.update)} hazır (şu an ${esc(s.version)}). Ayarların ve karantina korunur.</span><button class="btn sm primary" data-update="1">Güncelle</button></div>` : ''}
    ${!s.admin ? '<div class="banner warn">Kalkan yönetici yetkisi olmadan çalışıyor: bazı korumalar (DNS filtresi, Defender kuralları, sıkılaştırma) uygulanamaz. Kalkan\'ı kapatıp yeniden aç.</div>' : ''}
    <div id="alerts-wrap">${await alertsHTML()}</div>
    <section class="stack" aria-labelledby="kt"><div class="section-title"><h2 id="kt">Koruma katmanları</h2><span class="sub" id="layer-count"></span></div>
      <div class="grid" id="layers">${layersHTML(s)}</div></section>
    <div class="grid2">
      <section class="card"><div class="row" style="gap:16px"><div class="score-ring" style="--p:${sc.score || 0}"><span>${sc.score ?? '–'}</span></div>
        <div class="stack" style="gap:2px"><h2>Güvenlik puanı</h2><span class="sub">${open.length ? (sc.open.length + ' öneri var') : sc.score != null ? 'Önerilen ayarların hepsi yerinde' : 'Denetleniyor…'}</span></div></div>
        <div>${open.map(t => `<div class="list-row"><span class="t">${esc(t)}</span><button class="btn sm" data-go="sikilastirma">Düzelt</button></div>`).join('')}</div></section>
      <section class="card"><div class="row" style="color:var(--ai)">${ICON.spark}<h2 style="color:var(--ink)">Bir şeyden şüphelendin mi?</h2></div>
        <label class="sub" for="ask">Mesaj, link ya da ekran görüntüsü yapıştır; Claude ne olduğunu açıklasın.</label>
        <div class="input-row"><input id="ask" type="text" placeholder="Ör. kargo SMS'indeki link"><button class="btn ai solid" id="ask-go">Sor</button></div></section>
    </div>
    <footer class="engines-foot" id="eng">${engFoot(s)}</footer>
    <div class="row" style="justify-content:center"><span class="note">Kalkan ${esc(s.version)}</span><button class="btn sm" id="upd-check-home">Güncellemeleri denetle</button></div></div>`;
  $('#upd-check-home').onclick = async () => {
    const b = $('#upd-check-home'); b.disabled = true; b.innerHTML = '<span class="spinner"></span>';
    const r = await act(() => api('update_check'));
    b.disabled = false; b.textContent = 'Güncellemeleri denetle';
    if (!r) return;
    if (r.available) installUpdate(b); else toast(`En son sürümü kullanıyorsun (${r.current}).`);
  };
  $('#layer-count').textContent = `${Object.values(s.layers).filter(l => l.on).length} katmanın ${Object.keys(s.layers).length}'ü açık`;
  $('#ask-go').onclick = () => { const v = $('#ask').value.trim(); state.ai = { mode: 'dolandirici', text: v }; go('asistan'); };
  $('#ask').onkeydown = e => { if (e.key === 'Enter') $('#ask-go').click(); };
  bindCommon(main);
};
function updateDurum(s) {
  const h = $('#hero'); if (!h) return;
  h.innerHTML = heroHTML(s);
  const l = $('#layers'); if (l) l.innerHTML = layersHTML(s);
  const e = $('#eng'); if (e) e.innerHTML = engFoot(s);
  if (s.alerts !== state._alerts) { state._alerts = s.alerts; alertsHTML().then(x => { const w = $('#alerts-wrap'); if (w) { w.innerHTML = x; } }); }
  const c = $('#layer-count'); if (c) c.textContent = `${Object.values(s.layers).filter(l => l.on).length} katmanın ${Object.keys(s.layers).length}'ü açık`;
}
async function toggleLayer(k, on) {
  if (k === 'realtime') await api('settings_set', { patch: { realtime: { processes: on, downloads: on, usb: on } } });
  if (k === 'ransom') await api('settings_set', { patch: { ransom: { canaries: on, burst: on, snapshots: on } } });
  if (k === 'web') {
    toast(on ? 'DNS filtresi kuruluyor…' : 'DNS filtresi kapatılıyor…');
    await api('dns_set', { on });
  }
  if (k === 'defender') {
    if (on && !await confirmBox('Defender kuralları açılsın mı?', 'Önerilen 16 saldırı yüzeyi kuralı, ağ koruması ve istenmeyen yazılım engeli açılır. Bazı eski makrolu belgeler ya da yönetim araçları engellenebilir; istersen Koruma sayfasından tek tek kapatabilirsin.', 'Aç')) return;
    await api('defender_set', { what: 'recommended', mode: on ? 'on' : 'off' });
  }
}
/* Ortak tıklama işleyicisi: data-go, data-scan, data-layer, data-alert */
function bindCommon(root) {
  root.onclick = async e => {
    const g = e.target.closest('[data-go]');
    if (g) { if (g.dataset.go === 'durum-alerts') { $('#alerts-sec')?.scrollIntoView({ behavior: 'smooth' }); return; } return go(g.dataset.go); }
    const sc = e.target.closest('[data-scan]');
    if (sc) { await act(() => api('scan_start', { kind: sc.dataset.scan })); await refreshStatus(); return go('tarama'); }
    const ly = e.target.closest('[data-layer]');
    if (ly) {
      const on = ly.getAttribute('aria-checked') !== 'true';
      ly.disabled = true;
      await act(() => toggleLayer(ly.dataset.layer, on), on ? 'Açıldı' : 'Kapatıldı');
      ly.disabled = false;
      await refreshStatus();
      return;
    }
    const al = e.target.closest('[data-alert]');
    if (al) return alertAction(al.dataset.alert, al.dataset.act, al);
    const up = e.target.closest('[data-update]');
    if (up) return installUpdate(up);
  };
}
async function installUpdate(btn) {
  if (!await confirmBox('Kalkan güncellensin mi?', 'Yeni sürüm indirilip eski sürümün üzerine kurulur. Ayarların, karantina ve yedek kasası korunur. Kalkan birkaç saniye kapanıp yeniden açılır.', 'Güncelle')) return;
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>'; }
  const r = await act(() => runJob('update_install', {}, j => { if (btn && j.message) btn.textContent = j.message.replace('İndiriliyor… ', ''); }));
  if (r) { toast(r.message); if (r.message.includes('kuruluyor')) setTimeout(() => window.close(), 1500); }
  else if (btn) { btn.disabled = false; btn.textContent = 'Güncelle'; }
}
async function alertAction(id, action, btn) {
  if (action === 'explain') return explainJob('alert_explain', { id });
  btn && (btn.disabled = true);
  await act(() => api('alert_resolve', { id, action }), r => r.message);
  state._alerts = -1;
  refreshStatus();
}

/* ================================================================ Claude sonuç kartı */
const VERDICT_TR = { zararli: 'Zararlı', supheli: 'Şüpheli', istenmeyen: 'İstenmeyen', temiz: 'Temiz görünüyor', belirsiz: 'Kesin değil', dolandirici: 'Dolandırıcılık', guvenli: 'Güvenli görünüyor' };
function fileResultHTML(r) {
  const f = r.file || {};
  const origin = f.origin && (f.origin.HostUrl || f.origin.ReferrerUrl);
  return `<div class="stack" style="gap:4px"><span class="ai-head">BU DOSYA NE?</span><h2 class="mono" style="font-size:16px">${esc(f.name)}</h2>
    <span class="note mono">${esc(f.path || '')} · ${size(f.size)} · ${esc(f.signer || 'imzasız')}</span>${origin ? `<span class="note">İndirildiği yer: ${esc(origin)}</span>` : ''}</div>
    <div class="verdict ${r.verdict}"><b>KARAR</b><span>${esc(VERDICT_TR[r.verdict] || r.verdict)}: ${esc(r.headline)}</span></div>
    <div class="stack"><h3 style="font-size:14px">Neden böyle düşünüyorum</h3><ul class="plain">${(r.reasons || []).map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>
    <div class="stack"><h3 style="font-size:14px">Ne yapmalısın</h3><ol class="plain">${(r.what_to_do || []).map(x => `<li>${esc(x)}</li>`).join('')}</ol></div>
    ${(r.engine_results?.hits || []).length ? `<div class="note">Motorlar: ${r.engine_results.hits.map(h => esc(h.engine + ': ' + h.name)).join(' · ')}</div>` : ''}
    <p class="note">Claude'a dosyanın kendisi değil, yalnız özeti gitti (imza, içindeki metinler, çağırdığı işlevler, motor sonuçları; betiklerde ilk 30 KB). Kesin hükmü motorlar verir; Claude açıklar. Güven: ${esc({ yuksek: 'yüksek', orta: 'orta', dusuk: 'düşük' }[r.confidence] || '')}</p>`;
}
async function explainJob(op, args) {
  const d = dialog(`<div class="stack"><span class="ai-head">CLAUDE İNCELİYOR</span><div class="row"><span class="spinner"></span><span id="ex-msg" class="sub">Dosyanın özeti çıkarılıyor…</span></div></div>`);
  try {
    const r = await aiJob(op, args, j => { const m = $('#ex-msg'); if (m && j.message) m.textContent = j.message; });
    d.innerHTML = `<div class="stack" style="gap:14px">${fileResultHTML(r)}<div class="actions"><button class="btn" id="ex-close">Kapat</button></div></div>`;
    d.style.width = 'min(640px, 94vw)';
    $('#ex-close').onclick = () => d.close();
  } catch (e) { d.close(); toast(e.message, true); }
}

/* ================================================================ Tarama */
const SCAN_TR = { quick: 'Hızlı tarama', deep: 'Derin tarama', custom: 'Özel tarama', usb: 'USB taraması' };
const ACTION_TR = { quarantine: 'Karantinaya al', remove_autorun: 'Kaydı sil', disable_task: 'Görevi kapat', disable_service: 'Servisi kapat', remove_wmi: 'Aboneliği sil', remove_policy: 'Politikayı kaldır', fix_hosts: "Hosts'u düzelt", reset_proxy: "Proxy'yi sıfırla", reset_dns: "DNS'i sıfırla", kill: 'Süreci kapat', open_extensions: 'Eklentiyi kaldır' };
function findingHTML(f) {
  const acts = (f.actions || []).filter(a => a !== 'info');
  const done = f.status !== 'open';
  return `<article class="finding ${done ? 'done' : ''}"><span class="tag ${f.level}">${LEVEL_TR[f.level] || ''}</span>
    <div class="body"><span class="title">${esc(f.title)}</span><span class="mono ellipsis" title="${esc(f.path)}">${esc(f.path)}</span>
      ${f.command && f.command !== f.path ? `<span class="mono ellipsis note" title="${esc(f.command)}">${esc(f.command)}</span>` : ''}
      <span class="why">${esc(f.why)}${f.signer ? ' · İmzalayan: ' + esc(f.signer) : ''}</span>${done ? `<span class="result">${esc(f.result || (f.status === 'ignored' ? 'Yok sayıldı' : 'Giderildi'))}</span>` : ''}</div>
    ${done ? '' : `<div class="row"><button class="btn sm ai" data-fx="${esc(f.id)}">${ICON.spark}Bu ne?</button>
      ${acts.slice(1).map(a => `<button class="btn sm" data-fa="${esc(f.id)}" data-a="${a}">${ACTION_TR[a] || a}</button>`).join('')}
      ${acts[0] ? `<button class="btn sm dark" data-fa="${esc(f.id)}" data-a="${acts[0]}">${ACTION_TR[acts[0]] || acts[0]}</button>` : ''}
      <button class="btn link" data-fa="${esc(f.id)}" data-a="ignore">Yok say</button></div>`}</article>`;
}
PAGES.tarama = async (main) => {
  const s = await api('status');
  if (s.scan_job) return scanProgress(main, s.scan_job);
  const last = await api('last_scan');
  const findings = (last?.findings || []);
  const open = findings.filter(f => f.status === 'open');
  main.innerHTML = `<div class="page">
    <div class="page-head"><h1>Tarama</h1></div>
    <div class="scan-options">
      <button class="scan-opt" data-scan="quick"><span class="t">Hızlı tarama</span><span class="d">Otomatik başlayanlar, çalışan programlar, sürücüler, ağ ayarları ve zararlıların en çok saklandığı klasörler. Birkaç dakika.</span></button>
      <button class="scan-opt" data-scan="deep"><span class="t">Derin tarama</span><span class="d">Hızlı taramaya ek olarak tüm disklerdeki bütün dosyalar. Diskin büyüklüğüne göre uzun sürebilir.</span></button>
      <button class="scan-opt" id="scan-custom"><span class="t">Dosya ya da klasör seç</span><span class="d">Yalnız seçtiğin yeri tarar. USB bellekler takıldığında kendiliğinden taranır.</span></button>
    </div>
    ${last ? `<section class="stack"><div class="section-title"><h2>Son tarama: ${SCAN_TR[last.kind] || ''} · ${when(last.finished)}</h2>
      <span class="sub">${last.files} dosya · ${findings.length} bulgu${last.cancelled ? ' · yarıda kesildi' : ''}</span></div>
      ${(last.notes || []).map(n => `<div class="banner info">${esc(n)}</div>`).join('')}
      ${findings.length ? findings.map(findingHTML).join('') : '<div class="card empty">Hiçbir tehdit bulunmadı.</div>'}
      ${findings.length ? `<div class="dark-bar"><span>Sade dille bir rapor ister misin? Claude bulguları açıklar ve neyin güvenle kaldırılabileceğini söyler.</span>
        <div class="row"><button class="btn ai" id="report">${ICON.spark}Claude raporu</button>${open.some(f => (f.actions || [])[0] && f.level !== 'bilgi') ? '<button class="btn mint" id="fix-all">Hepsini gider</button>' : ''}</div></div>` : ''}
    </section>` : ''}</div>`;
  bindCommon(main);
  bindFindings(main);
  $('#scan-custom').onclick = async () => {
    const choice = await new Promise(res => { const d = dialog(`<h2>Ne taransın?</h2><div class="actions"><button class="btn" data-k="file">Dosya</button><button class="btn primary" data-k="folder">Klasör</button></div>`); d.onclick = e => { const k = e.target.closest('[data-k]'); if (k) { d.close(); res(k.dataset.k); } }; });
    const r = await act(() => api('pick', { kind: choice }));
    if (r && r.path) { await act(() => api('scan_start', { kind: 'custom', paths: [r.path] })); go('tarama'); }
  };
  const rep = $('#report'); if (rep) rep.onclick = () => { state.ai = { mode: 'rapor', autorun: true }; go('asistan'); };
  const fa = $('#fix-all');
  if (fa) fa.onclick = async () => {
    const list = open.filter(f => (f.actions || [])[0] && f.level !== 'bilgi' && f.actions[0] !== 'open_extensions');
    if (!await confirmBox('Hepsi giderilsin mi?', `${list.length} bulguya önerilen işlem uygulanacak (karantina, kaydı silme, görevi kapatma…). Hepsi Karantina ve Geçmiş'ten geri alınabilir.`, 'Gider')) return;
    let n = 0;
    for (const f of list) { try { await api('finding_action', { id: f.id, action: f.actions[0] }); n++; } catch (e) { toast(f.title + ': ' + e.message, true); } }
    toast(`${n} bulgu giderildi`); go('tarama');
  };
};
function bindFindings(root) {
  root.addEventListener('click', async e => {
    const x = e.target.closest('[data-fx]');
    if (x) return explainJob('finding_explain', { id: x.dataset.fx });
    const b = e.target.closest('[data-fa]');
    if (!b) return;
    b.disabled = true;
    const r = await act(() => api('finding_action', { id: b.dataset.fa, action: b.dataset.a }), r => r.message);
    if (r) { refreshStatus(); if (state.page === 'tarama' && !state.scanView) go('tarama'); } else b.disabled = false;
  });
}
async function scanProgress(main, jobId) {
  state.scanView = jobId;
  main.innerHTML = `<div class="page"><section class="card" style="padding:26px;gap:18px" aria-label="Tarama ilerlemesi">
      <div class="row between"><div class="stack" style="gap:4px"><h1 id="sp-title" style="font-family:var(--display);font-size:28px;letter-spacing:-.02em">Tarama sürüyor</h1><span class="sub" id="sp-sub"></span></div>
        <div class="row"><button class="btn" id="sp-pause">Duraklat</button><button class="btn danger-ghost" id="sp-stop">Durdur</button></div></div>
      <div class="progress" role="progressbar" aria-label="Tarama ilerlemesi"><div id="sp-bar" style="width:0"></div></div>
      <span class="mono ellipsis note" id="sp-path"></span><div class="chips" id="sp-phases"></div></section>
    <section class="stack"><div class="section-title"><h2 id="sp-fh">Henüz bulgu yok</h2><span class="sub">Hiçbir şey sen onaylamadan silinmez</span></div><div class="stack" id="sp-findings"></div></section></div>`;
  bindFindings(main);
  let paused = false;
  $('#sp-pause').onclick = async () => { paused = !paused; await api('job_pause', { id: jobId, on: paused }); $('#sp-pause').textContent = paused ? 'Sürdür' : 'Duraklat'; };
  $('#sp-stop').onclick = async () => { if (await confirmBox('Tarama durdurulsun mu?', 'Şimdiye kadarki bulgular saklanır.', 'Durdur', true)) api('job_cancel', { id: jobId }); };
  let lastCount = -1;
  try {
    await waitJob(jobId, j => {
      if (state.page !== 'tarama' || state.scanView !== jobId) throw new Error('__left');
      const r = j.result || {};
      $('#sp-title').textContent = (SCAN_TR[r.kind] || 'Tarama') + (j.status === 'paused' ? ' duraklatıldı' : ' sürüyor');
      $('#sp-bar').style.width = Math.round(j.progress * 100) + '%';
      $('#sp-sub').textContent = `%${Math.round(j.progress * 100)} · ${r.files || 0} dosya tarandı · ${Math.round((Date.now() / 1000 - j.started) / 60)} dk`;
      $('#sp-path').textContent = j.message || '';
      $('#sp-phases').innerHTML = (r.phases || []).map(p => `<span class="chip ${p.state === 'done' ? 'done' : p.state === 'now' ? 'now' : ''}">${p.state === 'done' ? '✓' : p.state === 'now' ? '●' : '○'} ${esc(p.label)}</span>`).join('');
      const fs = r.findings || [];
      if (fs.length !== lastCount) {
        lastCount = fs.length;
        $('#sp-fh').textContent = fs.length ? `Şimdiye kadar ${fs.length} bulgu` : 'Henüz bulgu yok';
        $('#sp-findings').innerHTML = fs.map(findingHTML).join('');
      }
    });
  } catch (e) { if (e.message === '__left') return; if (e.message !== 'İptal edildi') toast(e.message, true); }
  state.scanView = null;
  await refreshStatus();
  if (state.page === 'tarama') go('tarama');
}

/* ================================================================ Koruma */
const MODE_TR = { kapali: 'Kapalı', denetle: 'Yalnız kaydet', uyar: 'Uyar', engelle: 'Engelle' };
PAGES.koruma = async (main) => {
  const [st, def, vault] = await Promise.all([api('settings_get'), api('defender_status'), api('vault_info')]);
  const rt = st.realtime, rs = st.ransom;
  const row = (label, desc, on, attrs) => `<div class="list-row"><div class="main"><span class="t">${label}</span><span class="d">${desc}</span></div>${sw(on, attrs)}</div>`;
  main.innerHTML = `<div class="page"><div class="page-head"><h1>Koruma</h1></div>
    <div class="grid2">
      <section class="card"><h2>Anlık koruma</h2><div>
        ${row('Yeni programlar', 'Başlayan her program motorlardan geçer; tehditse durdurulur, şüpheliyse dondurulup sana sorulur.', rt.processes, 'data-set="realtime.processes"')}
        ${row('İndirilenler', 'İndirilenler klasörüne gelen her dosya anında taranır.', rt.downloads, 'data-set="realtime.downloads"')}
        ${row('USB bellekler', 'Takılan bellek kendiliğinden taranır.', rt.usb, 'data-set="realtime.usb"')}
        ${row('Tam ekranda sessiz', 'Oyun, film ya da sunum sırasında uyarılar bildirime düşer, zamanlanmış taramalar bekler.', rt.quiet_auto, 'data-set="realtime.quiet_auto"')}</div></section>
      <section class="card"><h2>Fidye kalkanı</h2><div>
        ${row('Tuzak dosyalar', 'Belgeler, Masaüstü ve Resimler\'e gizli yem dosyalar konur; dokunan program anında dondurulur.', rs.canaries, 'data-set="ransom.canaries"')}
        ${row('Şifreleme izleme', 'Kısa sürede çok dosyayı değiştiren ya da uzantısını değiştiren program yakalanır.', rs.burst, 'data-set="ransom.burst"')}
        ${row('Günlük anlık görüntü', 'Her gün diskin gölge kopyası alınır; saldırıdan sonra dosyalar buradan geri gelir.', rs.snapshots, 'data-set="ransom.snapshots"')}
        ${row('Yedek kasası', 'Seçtiğin klasörlerin saatlik, sürümlü yedeği. Kasaya yalnız Kalkan yazabilir.', rs.vault, 'data-set="ransom.vault"')}</div></section>
    </div>
    <section class="card"><div class="card-head"><h2>Yedek kasası</h2><div class="row"><button class="btn sm" id="v-add">${ICON.folder}Klasör ekle</button><button class="btn sm primary" id="v-run">Şimdi yedekle</button></div></div>
      <span class="sub">${vault.time ? `Son yedek ${ago(vault.time)} · ${vault.files || 0} dosya · ${size(vault.bytes || 0)} (sınır ${st.vault_limit_gb} GB)` : 'Henüz yedek alınmadı.'}</span>
      <div>${(vault.folders || []).map(f => `<div class="list-row"><span class="mono">${esc(f)}</span><button class="btn sm danger-ghost" data-vrm="${esc(f)}">Çıkar</button></div>`).join('') || '<div class="sub">Yedeklenecek klasör seçilmedi. Önemli belgelerinin olduğu klasörleri ekle.</div>'}</div>
      <div class="input-row"><input type="text" id="v-q" placeholder="Kasada dosya ara (ad ya da klasör)"><button class="btn" id="v-search">Ara</button></div><div id="v-res"></div></section>
    <section class="card"><div class="card-head"><div class="stack" style="gap:2px"><h2>Microsoft Defender katmanları</h2><span class="sub">Windows'un içinde var ama varsayılan olarak kapalı olan kurumsal korumalar.</span></div>
      ${def.available ? `<div class="row"><button class="btn sm" id="d-off">Hepsini kapat</button><button class="btn sm primary" id="d-rec">Önerilenleri aç</button></div>` : ''}</div>
      ${def.available ? `
      <div class="list-row"><div class="main"><span class="t">Ağ koruması</span><span class="d">Zararlı sitelere tüm programlarda bağlantıyı Defender keser.</span></div>${modeSel('network', def.network, ['kapali', 'denetle', 'engelle'])}</div>
      <div class="list-row"><div class="main"><span class="t">İstenmeyen yazılım engeli</span><span class="d">Reklam yazılımı, araç çubuğu, gizli madenci gibi programlar.</span></div>${modeSel('pua', def.pua, ['kapali', 'denetle', 'engelle'])}</div>
      <div class="list-row"><div class="main"><span class="t">Klasör koruması</span><span class="d">Belgeler, Resimler, Masaüstü gibi klasörlere yalnız güvenilen programlar yazabilir. Kendi geliştirme araçların engellenirse aşağıdan izin ver.</span></div>${modeSel('cfa', def.cfa, ['kapali', 'denetle', 'engelle'])}</div>
      ${def.cfa !== 'kapali' ? `<div class="stack" style="padding-left:12px"><span class="sub">Klasörlere yazmasına izin verilen programlar:</span>${(def.cfa_apps || []).map(p => `<div class="row between"><span class="mono">${esc(p)}</span><button class="btn sm danger-ghost" data-cfarm="${esc(p)}">Kaldır</button></div>`).join('') || '<span class="note">Yok</span>'}<div><button class="btn sm" id="cfa-add">Program ekle</button></div></div>` : ''}
      <h3 style="font-size:14px;margin-top:8px">Saldırı yüzeyi kuralları · ${def.asr_on} / ${def.asr_total} açık</h3>
      <div>${def.rules.map(r => `<div class="list-row"><div class="main"><span class="t">${esc(r.name)}${r.recommended ? '' : ' <span class="tag bilgi">dikkat</span>'}</span><span class="d">${esc(r.desc)}</span></div>${modeSel('rule', r.mode, ['kapali', 'denetle', 'uyar', 'engelle'], r.id)}</div>`).join('')}</div>
      <div class="row"><button class="btn sm" id="d-blocks">Defender'ın son engellediklerini göster</button></div><div id="d-blocks-res"></div>`
      : '<div class="banner warn">Defender ayarları okunamadı. Defender kapalı olabilir ya da başka bir antivirüs etkin.</div>'}
    </section></div>`;
  main.onclick = async e => {
    const s = e.target.closest('[data-set]');
    if (s) {
      const [grp, key] = s.dataset.set.split('.');
      const on = s.getAttribute('aria-checked') !== 'true';
      const r = await act(() => api('settings_set', { patch: { [grp]: { [key]: on } } }), on ? 'Açıldı' : 'Kapatıldı');
      if (r) s.setAttribute('aria-checked', on ? 'true' : 'false');
      return refreshStatus();
    }
    const rm = e.target.closest('[data-vrm]');
    if (rm) { await act(() => api('vault_folders', { folders: (vault.folders || []).filter(f => f !== rm.dataset.vrm) })); return go('koruma'); }
    const cr = e.target.closest('[data-cfarm]');
    if (cr) { await act(() => api('defender_set', { what: 'cfa_remove', path: cr.dataset.cfarm }), 'Kaldırıldı'); return go('koruma'); }
    const vr = e.target.closest('[data-vrestore]');
    if (vr) { await act(() => api('vault_restore', { path: vr.dataset.vrestore, time: parseFloat(vr.dataset.t) }), r => r.ok ? 'Geri yüklendi' : 'Geri yüklenemedi'); return; }
  };
  main.onchange = async e => {
    const m = e.target.closest('select[data-mode]');
    if (!m) return;
    m.disabled = true;
    await act(() => api('defender_set', { what: m.dataset.mode, mode: m.value, id: m.dataset.id }), 'Uygulandı');
    m.disabled = false; refreshStatus();
  };
  $('#v-add').onclick = async () => { const r = await act(() => api('pick', { kind: 'folder' })); if (r?.path) { await act(() => api('vault_folders', { folders: [...(vault.folders || []), r.path] }), 'Klasör eklendi'); go('koruma'); } };
  $('#v-run').onclick = async () => { const b = $('#v-run'); b.disabled = true; b.innerHTML = '<span class="spinner"></span> Yedekleniyor'; await act(() => runJob('vault_backup', {}), r => `${r.copied} dosya yedeklendi`); go('koruma'); };
  $('#v-search').onclick = async () => {
    const res = await act(() => api('vault_search', { text: $('#v-q').value }));
    $('#v-res').innerHTML = !res ? '' : res.length ? res.map(r => `<div class="list-row"><div class="main"><span class="mono ellipsis">${esc(r.path)}</span><span class="d">${r.versions.length} sürüm</span></div><div class="row">${r.versions.slice(-3).reverse().map(v => `<button class="btn sm" data-vrestore="${esc(r.path)}" data-t="${v.time}">${when(v.time)}</button>`).join('')}</div></div>`).join('') : '<div class="sub">Bulunamadı.</div>';
  };
  if (def.available) {
    $('#d-rec').onclick = async () => { await act(() => api('defender_set', { what: 'recommended', mode: 'on' }), 'Önerilen kurallar açıldı'); go('koruma'); };
    $('#d-off').onclick = async () => { if (await confirmBox('Defender katmanları kapatılsın mı?', 'Saldırı yüzeyi kuralları ve ağ koruması kapanır.', 'Kapat', true)) { await act(() => api('defender_set', { what: 'recommended', mode: 'off' }), 'Kapatıldı'); go('koruma'); } };
    const ca = $('#cfa-add'); if (ca) ca.onclick = async () => { const r = await act(() => api('pick', { kind: 'file' })); if (r?.path) { await act(() => api('defender_set', { what: 'cfa_allow', path: r.path }), 'İzin verildi'); go('koruma'); } };
    $('#d-blocks').onclick = async () => {
      $('#d-blocks-res').innerHTML = '<span class="spinner"></span>';
      const b = await act(() => api('defender_blocks'));
      $('#d-blocks-res').innerHTML = !b ? '' : b.length ? b.map(x => `<div class="list-row"><div class="main"><span class="t">${esc({ asr: 'Kural', cfa: 'Klasör koruması', network: 'Ağ koruması', threat: 'Tehdit' }[x.kind] || x.kind)} ${esc(x.verb)}: ${esc(x.rule || x.threat || '')}</span><span class="d mono">${esc(x.process || '')} ${esc(x.path || '')}</span></div><span class="note">${esc(new Date(x.time).toLocaleString('tr-TR'))}</span></div>`).join('') : '<div class="sub">Son 3 günde engelleme yok.</div>';
    };
  }
};
function modeSel(what, cur, opts, id) {
  return `<select class="mode" data-mode="${what}" ${id ? `data-id="${id}"` : ''} aria-label="Mod">${opts.map(o => `<option value="${o}" ${o === cur ? 'selected' : ''}>${MODE_TR[o]}</option>`).join('')}</select>`;
}

/* ================================================================ İnternet */
PAGES.internet = async (main) => {
  const [dns, ext, st] = await Promise.all([api('dns_status'), api('extension'), api('settings_get')]);
  const lists = dns.lists || {};
  main.innerHTML = `<div class="page"><div class="page-head"><h1>İnternet</h1></div>
    <div class="grid">
      <div class="card"><div class="row between"><span class="t" style="font-weight:600;font-size:15px">DNS filtresi</span>${sw(dns.on, 'id="dns-sw" aria-label="DNS filtresi"')}</div>
        <span style="font-family:var(--display);font-size:26px;font-weight:700">${dns.on ? dns.stats.blocked : '–'}</span>
        <span class="sub">${dns.on ? `Bugün engellenen istek (${dns.stats.queries} sorgudan). ` : 'Kapalı. '}${(lists.tehdit || 0).toLocaleString('tr-TR')} zararlı alan adı listede.</span>
        ${dns.error ? `<div class="banner bad">${esc(dns.error)}</div>` : ''}
        <div class="row between"><span class="sub">Reklam ve izleyicileri de engelle</span>${sw(st.web.ads, 'id="ads-sw" aria-label="Reklam engeli"')}</div></div>
      <div class="card"><div class="row between"><span style="font-weight:600;font-size:15px">Tarayıcı eklentisi</span><span class="tag ${ext.connected ? 'iyi' : 'bilgi'}">${ext.connected ? 'BAĞLI' : 'KURULU DEĞİL'}</span></div>
        <span class="sub">Sahte siteleri, taklit banka/e-Devlet adreslerini ve sayfa içi dolandırıcılığı tarayıcıda yakalar.</span>
        <div class="row"><button class="btn sm" id="ext-how">Nasıl kurulur?</button></div></div>
      <div class="card"><div class="row between"><span style="font-weight:600;font-size:15px">Wi-Fi ve modem</span></div>
        <span class="sub" id="wifi-sum">Şifreleme, modemde açık kapılar ve DNS ele geçirilmesi kontrol edilir.</span>
        <div class="row"><button class="btn sm primary" id="wifi-go">Kontrol et</button><button class="btn sm" id="lan-go">Ağdaki cihazlar</button></div></div>
    </div>
    <div id="wifi-res"></div>
    <section class="card"><div class="card-head"><h2>Şu an internete bağlı programlar</h2><button class="btn sm" id="conn-ref">${ICON.refresh}Yenile</button></div>
      <div id="conns"><span class="spinner"></span></div><p class="note">IP konum verisi: DB-IP (db-ip.com), CC BY 4.0.</p></section>
    <section class="card" id="blocked-card"><h2>İnterneti kesilen programlar</h2><div id="blocked"></div></section>
    <section class="card"><div class="card-head"><h2>Son engellenen siteler</h2></div>
      <div class="chips">${(dns.recent || []).map(r => `<span class="tag ${r.category === 'tehdit' ? 'tehdit' : 'bilgi'}" style="font-weight:500;font-size:12px;padding:6px 12px">${esc(r.host)} · ${r.category === 'tehdit' ? 'zararlı/oltalama' : 'reklam/izleyici'} <button class="btn link" style="min-height:20px" data-allow="${esc(r.host)}" title="Bu siteye izin ver">izin ver</button></span>`).join('') || '<span class="sub">Henüz engellenen site yok.</span>'}</div>
      ${(st.dns_allow || []).length ? `<span class="sub">İzin verilenler: ${st.dns_allow.map(h => `${esc(h)} <button class="btn link" data-unallow="${esc(h)}">kaldır</button>`).join(', ')}</span>` : ''}</section></div>`;
  $('#dns-sw').onclick = async e => {
    const on = e.currentTarget.getAttribute('aria-checked') !== 'true';
    e.currentTarget.disabled = true;
    toast(on ? 'DNS filtresi kuruluyor (listeler ilk seferde indirilir)…' : 'Kapatılıyor…');
    await act(() => api('dns_set', { on }), on ? 'DNS filtresi açık' : 'DNS filtresi kapalı');
    refreshStatus(); go('internet');
  };
  $('#ads-sw').onclick = async e => { const on = e.currentTarget.getAttribute('aria-checked') !== 'true'; await act(() => api('settings_set', { patch: { web: { ads: on } } }), on ? 'Reklam engeli açık' : 'Reklam engeli kapalı'); go('internet'); };
  $('#ext-how').onclick = () => extensionHelp(ext);
  $('#wifi-go').onclick = async () => {
    const b = $('#wifi-go'); b.disabled = true; b.innerHTML = '<span class="spinner"></span> Kontrol ediliyor';
    const r = await act(() => runJob('wifi_check', {}));
    b.disabled = false; b.textContent = 'Kontrol et';
    if (!r) return;
    $('#wifi-sum').textContent = r.wifi.ssid ? `${r.wifi.ssid} · ${r.wifi.auth || ''} · ${r.wifi.cipher || ''}` : 'Kablolu bağlantı';
    $('#wifi-res').innerHTML = `<section class="card"><h2>Ağ kontrolü</h2>${r.findings.length ? r.findings.map(f => `<div class="list-row"><div class="main"><span class="t"><span class="tag ${f.level}">${LEVEL_TR[f.level]}</span> ${esc(f.title)}</span><span class="d">${esc(f.why)}</span></div></div>`).join('') : '<div class="banner info">Sorun bulunmadı.</div>'}
      <span class="sub">Modem: ${esc(r.gateway || '?')} · açık kapılar: ${r.open_ports.map(p => esc(p.port + ' ' + p.name)).join(', ') || 'yok'}</span></section>`;
  };
  $('#lan-go').onclick = async () => {
    const b = $('#lan-go'); b.disabled = true; b.innerHTML = '<span class="spinner"></span> Aranıyor';
    const r = await act(() => runJob('lan_devices', {}));
    b.disabled = false; b.textContent = 'Ağdaki cihazlar';
    if (!r) return;
    $('#wifi-res').innerHTML = `<section class="card"><h2>Ağdaki cihazlar · ${r.length}</h2><div class="table-wrap"><table><thead><tr><th scope="col">IP</th><th scope="col">Ad</th><th scope="col">MAC</th><th scope="col"></th></tr></thead><tbody>
      ${r.map(d => `<tr><td class="mono">${esc(d.ip)}</td><td>${esc(d.name || '—')}</td><td class="mono">${esc(d.mac)}</td><td>${d.gateway ? '<span class="tag bilgi">MODEM</span>' : d.me ? '<span class="tag iyi">BU BİLGİSAYAR</span>' : d.random_mac ? '<span class="tag bilgi">telefon olabilir</span>' : ''}</td></tr>`).join('')}</tbody></table></div>
      <p class="note">Tanımadığın bir cihaz görüyorsan Wi-Fi şifreni değiştir.</p></section>`;
  };
  main.addEventListener('click', async e => {
    const a = e.target.closest('[data-allow]');
    if (a) { await act(() => api('dns_allow', { host: a.dataset.allow, add: true }), 'İzin verildi'); return go('internet'); }
    const u = e.target.closest('[data-unallow]');
    if (u) { await act(() => api('dns_allow', { host: u.dataset.unallow, add: false }), 'Kaldırıldı'); return go('internet'); }
    const bl = e.target.closest('[data-block]');
    if (bl) { if (await confirmBox('İnterneti kesilsin mi?', bl.dataset.block, 'Kes', true)) { await act(() => api('block_app', { path: bl.dataset.block }), 'Programın interneti kesildi'); loadConns(); loadBlocked(); } return; }
    const ub = e.target.closest('[data-unblock]');
    if (ub) { await act(() => api('unblock_app', { name: ub.dataset.unblock }), 'İnternet erişimi geri verildi'); loadBlocked(); }
  });
  $('#conn-ref').onclick = loadConns;
  loadConns(); loadBlocked();
};
async function loadConns() {
  const el = $('#conns'); if (!el) return;
  el.innerHTML = '<span class="spinner"></span>';
  try {
    const rows = await api('connections');
    const sus = rows.filter(r => r.state === 'tehdit' || r.state === 'supheli').length;
    el.innerHTML = `<span class="sub">${new Set(rows.map(r => r.app)).size} program · ${sus ? sus + ' dikkat isteyen bağlantı' : 'şüpheli bağlantı yok'}</span><div class="table-wrap"><table><thead><tr><th scope="col">Program</th><th scope="col">Bağlandığı yer</th><th scope="col">Ülke</th><th scope="col">Durum</th><th scope="col"><span class="hidden">İşlem</span></th></tr></thead><tbody>
      ${rows.slice(0, 120).map(r => `<tr class="${r.state === 'tehdit' || r.state === 'supheli' ? 'bad' : ''}"><td style="font-weight:600" title="${esc(r.path)}">${esc(r.app)}</td><td class="mono" title="${esc(r.ip + ':' + r.port)}">${esc(r.host || r.ip + ':' + r.port)}</td><td>${esc(r.country)}</td>
      <td><span class="tag ${r.state}" title="${esc(r.why)}">${LEVEL_TR[r.state] || r.state.toUpperCase()}</span></td><td style="text-align:right">${r.path ? `<button class="btn sm" data-block="${esc(r.path)}">İnternetini kes</button>` : ''}</td></tr>`).join('')}</tbody></table></div>`;
  } catch (e) { el.innerHTML = `<div class="banner warn">${esc(e.message)}</div>`; }
}
async function loadBlocked() {
  const el = $('#blocked'); if (!el) return;
  try {
    const b = await api('blocked_apps');
    $('#blocked-card').classList.toggle('hidden', !b.length);
    el.innerHTML = b.map(x => `<div class="list-row"><span class="mono">${esc(x.Program || x.Name)}</span><button class="btn sm" data-unblock="${esc(x.Name)}">Geri ver</button></div>`).join('');
  } catch (e) { $('#blocked-card')?.classList.add('hidden'); }
}
function extensionHelp(ext) {
  const d = dialog(`<h2>Tarayıcı eklentisini kur</h2>
    <ol class="plain"><li>Aşağıdan tarayıcının eklenti sayfasını aç.</li><li>Sağ üstteki (Edge'de sol alttaki) <b>Geliştirici modu</b>'nu aç.</li>
    <li><b>Paketlenmemiş öğe yükle</b>'ye bas ve açılan Kalkan eklenti klasörünü seç.</li><li>Kalkan simgesi araç çubuğunda görünür; İnternet sayfasında "Bağlı" yazar.</li></ol>
    <p class="note">Mağazada yayımlanmadığı için şimdilik elle kuruluyor. Klasör: <span class="mono">${esc(ext.dir)}</span></p>
    <div class="actions"><button class="btn" data-b="folder">Klasörü aç</button><button class="btn" data-b="chrome">Chrome</button><button class="btn primary" data-b="edge">Edge</button></div>`);
  d.onclick = e => { const b = e.target.closest('[data-b]'); if (!b) return; if (b.dataset.b === 'folder') api('extension', { open: true }); else { api('extension', { open: true, browser: b.dataset.b }); } };
}

/* ================================================================ Sıkılaştırma */
PAGES.sikilastirma = async (main) => {
  main.innerHTML = `<div class="page"><div class="page-head"><h1>Sıkılaştırma</h1></div>
    <section class="card" id="score-card"><div class="row"><span class="spinner"></span><span class="sub">Güvenlik ayarları denetleniyor…</span></div></section>
    <section class="card"><div class="card-head"><div class="stack" style="gap:2px"><h2>Program güncellikleri</h2><span class="sub">Eski sürümler bilinen açıklar taşır. Tarayıcılar, arşiv ve PDF programları önce gelir.</span></div><button class="btn sm primary" id="wg-go">Güncellemeleri ara</button></div><div id="wg"></div></section>
    <div class="grid2">
      <section class="card"><h2>Şifre sızıntı kontrolü</h2><span class="sub">Şifren sızdırılmış listelerde var mı? Şifre bilgisayardan çıkmaz: yalnız parmak izinin ilk 5 harfi sorulur.</span>
        <div class="input-row"><input type="password" id="pw" placeholder="Şifreni yaz" autocomplete="off"><button class="btn" id="pw-go">Kontrol et</button></div><div id="pw-res"></div></section>
      <section class="card" id="priv"><span class="spinner"></span></section>
    </div></div>`;
  runJob('harden_checks', {}).then(renderScore).catch(e => { $('#score-card').innerHTML = `<div class="banner warn">${esc(e.message)}</div>`; });
  loadPrivacy();
  $('#pw-go').onclick = async () => {
    const v = $('#pw').value; if (!v) return;
    const r = await act(() => api('pwned', { password: v }));
    $('#pw').value = '';
    if (r) $('#pw-res').innerHTML = r.count ? `<div class="banner bad">Bu şifre sızdırılmış listelerde <b>${r.count.toLocaleString('tr-TR')}</b> kez geçiyor. Kullandığın her yerde hemen değiştir.</div>` : '<div class="banner info">Bu şifre bilinen sızıntılarda yok. Yine de her sitede farklı şifre kullan.</div>';
  };
  $('#pw').onkeydown = e => { if (e.key === 'Enter') $('#pw-go').click(); };
  $('#wg-go').onclick = async () => {
    const b = $('#wg-go'); b.disabled = true; b.innerHTML = '<span class="spinner"></span> Aranıyor (1 dk sürebilir)';
    const r = await act(() => runJob('winget_list', {}));
    b.disabled = false; b.textContent = 'Yeniden ara';
    if (!r) return;
    $('#wg').innerHTML = r.length ? r.map(p => `<div class="list-row"><div class="main"><span class="t">${esc(p.name)} ${p.security ? '<span class="tag supheli">GÜVENLİK</span>' : ''}</span><span class="d mono">${esc(p.version)} → ${esc(p.available)}</span></div><button class="btn sm" data-wg="${esc(p.id)}">Güncelle</button></div>`).join('') : '<div class="banner info">Tüm programlar güncel.</div>';
  };
  main.onclick = async e => {
    const f = e.target.closest('[data-fix]');
    if (f) {
      if (f.dataset.fix.startsWith('settings:')) return api('open_settings', { uri: f.dataset.fix.slice(9) });
      f.disabled = true;
      const r = await act(() => api('harden_fix', { key: f.dataset.key }), r => r.message);
      if (r) runJob('harden_checks', {}).then(renderScore); else f.disabled = false;
      return;
    }
    const w = e.target.closest('[data-wg]');
    if (w) { w.disabled = true; w.innerHTML = '<span class="spinner"></span>'; const r = await act(() => runJob('winget_upgrade', { id: w.dataset.wg }), 'Güncellendi'); w.outerHTML = r ? '<span class="tag iyi">GÜNCEL</span>' : '<span class="tag tehdit">OLMADI</span>'; return; }
    const p = e.target.closest('[data-priv]');
    if (p) { const on = p.getAttribute('aria-checked') !== 'true'; await act(() => api('privacy_set', { key: p.dataset.priv, private: on }), 'Uygulandı'); loadPrivacy(); }
  };
};
function renderScore(r) {
  const el = $('#score-card'); if (!el) return;
  const bad = r.items.filter(i => i.ok === false);
  el.innerHTML = `<div class="row" style="gap:20px"><div class="score-ring big" style="--p:${r.score}"><span>${r.score}</span></div><div class="stack" style="gap:4px"><h2>Güvenlik puanı</h2><span class="sub">${bad.length ? `${bad.length} madde düzeltilince puan ${Math.min(100, r.score + bad.reduce((a, b) => a + b.gain, 0))}'a çıkar.` : 'Önerilen ayarların hepsi yerinde.'}</span></div></div>
    <div>${r.items.map(i => `<div class="list-row"><div class="main"><span class="t">${i.ok === true ? '<span class="dot"></span>' : i.ok === false ? '<span class="dot warn"></span>' : '<span class="dot off"></span>'}${esc(i.title)}</span><span class="d">${esc(i.desc)}${i.detail ? ' · ' + esc(i.detail) : ''}${i.ok == null ? ' · denetlenemedi' : ''}</span></div>
      ${i.ok === false ? (i.fix === 'fix' ? `<button class="btn sm primary" data-fix="fix" data-key="${i.key}">Düzelt</button>` : i.fix.startsWith('settings:') ? `<button class="btn sm" data-fix="${esc(i.fix)}">Ayarı aç</button>` : '') : ''}</div>`).join('')}</div>`;
}
async function loadPrivacy() {
  const el = $('#priv'); if (!el) return;
  const p = await api('privacy');
  el.innerHTML = `<h2>Gizlilik ayarları</h2><div>${p.items.filter(i => i.private !== null).map(i => `<div class="list-row"><div class="main"><span class="t">${esc(i.title)}</span><span class="d">${esc(i.desc)}</span></div>${sw(i.private, `data-priv="${i.key}" aria-label="${esc(i.title)}"`)}</div>`).join('')}</div>
    <h3 style="font-size:14px">Kamerayı ve mikrofonu son kullananlar</h3>${p.devices.length ? p.devices.slice(0, 8).map(d => `<div class="list-row"><div class="main"><span class="t">${esc(d.app)} ${d.active ? '<span class="tag tehdit">ŞU AN</span>' : ''}</span><span class="d">${esc(d.device)} · ${ago(d.time)}</span></div></div>`).join('') : '<span class="sub">Kayıt yok.</span>'}`;
}

/* ================================================================ Asistan */
const MODES = [['sohbet', 'Sohbet'], ['dosya', 'Dosya analizi'], ['dolandirici', 'Dolandırıcılık'], ['rapor', 'Tarama raporu']];
PAGES.asistan = async (main) => {
  const ai = state.ai;
  const key = await api('ai_key_status');
  main.innerHTML = `<div class="page"><div class="page-head"><h1>Asistan</h1>
      <div class="seg" role="group" aria-label="Asistan modu">${MODES.map(([k, l]) => `<button data-mode="${k}" class="${ai.mode === k ? 'on' : ''}" aria-pressed="${ai.mode === k}">${l}</button>`).join('')}</div></div>
    ${key.set ? '' : '<div class="banner info">Claude araçları kendi API anahtarınla çalışır. İlk kullanımda anahtar istenecek.</div>'}
    <div id="ai-body"></div></div>`;
  $$('[data-mode]', main).forEach(b => b.onclick = () => { state.ai = { mode: b.dataset.mode }; go('asistan'); });
  const body = $('#ai-body');
  if (ai.mode === 'sohbet') return aiChat(body);
  if (ai.mode === 'dosya') return aiFile(body);
  if (ai.mode === 'dolandirici') return aiScam(body);
  return aiReport(body);
};
async function aiChat(body) {
  body.innerHTML = `<section class="card"><div class="chat" id="chat"></div>
    <div class="input-row"><input type="text" id="c-in" placeholder="Ör. Bilgisayarım son günlerde tuhaf davranıyor, neye bakmalıyım?"><button class="btn ai solid" id="c-go">Gönder</button></div>
    <div class="row between"><span class="note">Claude bilgisayarına yalnız bakabilir (süreçler, otomatik başlayanlar, bağlantılar, geçmiş). Önerdiği her işlem için sen düğmeye basarsın.</span><button class="btn link" id="c-reset">Yeni sohbet</button></div></section>`;
  const render = st => {
    const c = $('#chat'); if (!c) return;
    c.innerHTML = st.messages.length ? st.messages.map(m => m.role === 'proposal'
      ? `<div class="proposal"><span class="tag ai">ÖNERİ</span><b>${esc(m.label)}</b><span class="r">${esc(m.reason)}</span>${m.status === 'open' ? `<div><button class="btn sm ai solid" data-prop="${m.id}">${esc(m.label)}</button></div>` : `<span class="result note">${esc(m.result || 'Yapıldı')}</span>`}</div>`
      : `<div class="bubble ${m.role}">${esc(m.text)}</div>`).join('') : '<div class="empty">Bilgisayarınla ilgili her şeyi sorabilirsin: "Şu an internete bağlanan şüpheli bir şey var mı?", "Bu hafta neler engellendi?"</div>';
    c.scrollTop = c.scrollHeight;
  };
  render(await api('ai_chat_state'));
  const send = async () => {
    const v = $('#c-in').value.trim(); if (!v) return;
    $('#c-in').value = ''; $('#c-go').disabled = true;
    const st = await api('ai_chat_state');
    st.messages.push({ role: 'user', text: v }, { role: 'assistant', text: '…' });
    render(st);
    try {
      render(await aiJob('ai_chat', { text: v }, j => { const bs = $$('.bubble.assistant'); const last = bs[bs.length - 1]; if (last && last.textContent.startsWith('…') && j.message) last.textContent = '… ' + j.message; }));
    } catch (e) { toast(e.message, true); render(await api('ai_chat_state')); }
    $('#c-go').disabled = false;
  };
  $('#c-go').onclick = send;
  $('#c-in').onkeydown = e => { if (e.key === 'Enter') send(); };
  $('#c-reset').onclick = async () => { render(await api('ai_chat_reset')); };
  body.onclick = async e => {
    const p = e.target.closest('[data-prop]');
    if (!p) return;
    p.disabled = true;
    await act(() => api('ai_proposal', { id: p.dataset.prop }), r => r.message);
    render(await api('ai_chat_state')); refreshStatus();
  };
}
async function aiFile(body) {
  body.innerHTML = `<section class="card"><span class="ai-head">BU DOSYA NE?</span><h2>Bir dosya seç; Claude ne olduğunu açıklasın</h2>
    <span class="sub">Kalkan dosyayı motorlardan geçirir, özetini çıkarır ve Claude'a yalnız bu özeti gönderir.</span>
    <div class="row"><button class="btn ai solid" id="f-pick">Dosya seç</button></div><div id="f-res" class="stack" style="gap:14px"></div></section>`;
  $('#f-pick').onclick = async () => {
    const r = await act(() => api('pick', { kind: 'file' }));
    if (!r?.path) return;
    const out = $('#f-res');
    out.innerHTML = `<div class="row"><span class="spinner"></span><span class="sub" id="f-msg">Hazırlanıyor…</span></div>`;
    try {
      const res = await aiJob('ai_explain', { path: r.path }, j => { const m = $('#f-msg'); if (m && j.message) m.textContent = j.message; });
      out.innerHTML = fileResultHTML(res) + (res.verdict === 'zararli' || res.verdict === 'supheli' ? `<div class="row"><button class="btn danger" id="f-q">Karantinaya al</button></div>` : '');
      const q = $('#f-q');
      if (q) q.onclick = async () => { const ok = await act(() => api('ai_quarantine', { path: r.path }), 'Karantinaya alındı'); if (ok) q.remove(); };
    } catch (e) { out.innerHTML = `<div class="banner bad">${esc(e.message)}</div>`; }
  };
}
async function aiScam(body) {
  body.innerHTML = `<section class="card"><span class="ai-head">DOLANDIRICILIK KONTROLÜ</span><h2>Şüphelendiğin mesajı, linki ya da ekran görüntüsünü ver</h2>
    <textarea id="s-text" placeholder="SMS'i, e-postayı ya da linki buraya yapıştır…">${esc(state.ai.text || '')}</textarea>
    <div class="drop" id="s-drop">Ekran görüntüsünü buraya sürükle ya da <b>Ctrl+V</b> ile yapıştır<div id="s-img"></div></div>
    <div class="row"><button class="btn ai solid" id="s-go">Kontrol et</button></div><div id="s-res" class="stack" style="gap:12px"></div></section>`;
  let img = null;
  const setImg = file => {
    if (!file || !file.type.startsWith('image/')) return;
    const fr = new FileReader();
    fr.onload = () => { img = { data: fr.result.split(',')[1], type: file.type }; $('#s-img').innerHTML = `<img class="thumb" alt="Yapıştırılan ekran görüntüsü" src="${fr.result}">`; };
    fr.readAsDataURL(file);
  };
  const drop = $('#s-drop');
  drop.ondragover = e => { e.preventDefault(); drop.classList.add('over'); };
  drop.ondragleave = () => drop.classList.remove('over');
  drop.ondrop = e => { e.preventDefault(); drop.classList.remove('over'); setImg(e.dataTransfer.files[0]); };
  document.onpaste = e => { if (state.page !== 'asistan' || state.ai.mode !== 'dolandirici') return; const f = [...(e.clipboardData?.files || [])][0]; if (f) { e.preventDefault(); setImg(f); } };
  const run = async () => {
    const text = $('#s-text').value;
    const out = $('#s-res');
    out.innerHTML = `<div class="row"><span class="spinner"></span><span class="sub" id="s-msg">Linkler kontrol ediliyor…</span></div>`;
    try {
      const r = await aiJob('ai_scam', { text, image: img?.data || '', image_type: img?.type || 'image/png' }, j => { const m = $('#s-msg'); if (m && j.message) m.textContent = j.message; });
      out.innerHTML = `<div class="verdict ${r.verdict}"><b>${esc((VERDICT_TR[r.verdict] || r.verdict).toUpperCase())}</b><span>${esc(r.headline)}</span></div>
        <ul class="plain">${r.reasons.map(x => `<li>${esc(x)}</li>`).join('')}</ul><div class="banner info"><b>Ne yapmalı:</b> ${esc(r.what_to_do)}</div>
        ${(r.links || []).map(l => `<div class="note mono">${esc(l.host)} · ${l.domain_age_days != null ? l.domain_age_days + ' günlük alan adı' : 'yaşı bilinmiyor'} · ${esc(l.kalkan_lists)}</div>`).join('')}`;
    } catch (e) { out.innerHTML = `<div class="banner bad">${esc(e.message)}</div>`; }
  };
  $('#s-go').onclick = run;
  if (state.ai.text) { state.ai.text = ''; run(); }
}
async function aiReport(body) {
  const last = await api('last_scan');
  body.innerHTML = `<section class="card"><span class="ai-head">TARAMA RAPORU</span>
    <h2>${last ? `Son tarama: ${SCAN_TR[last.kind]} · ${when(last.finished)} · ${last.findings.length} bulgu` : 'Henüz tarama yok'}</h2>
    <div class="row"><button class="btn ai solid" id="r-go" ${last ? '' : 'disabled'}>Raporu hazırla</button></div><div id="r-res" class="stack" style="gap:12px"></div></section>`;
  const run = async () => {
    const out = $('#r-res');
    out.innerHTML = `<div class="row"><span class="spinner"></span><span class="sub">Claude bulguları okuyor…</span></div>`;
    try {
      const r = await aiJob('ai_report', {});
      const byId = Object.fromEntries((last.findings || []).map(f => [f.id, f]));
      out.innerHTML = `<p style="font-size:15px;line-height:1.55;margin:0">${esc(r.summary)}</p>
        ${r.items.map(i => { const f = byId[i.finding_id] || {}; return `<div class="list-row"><div class="main"><span class="t"><span class="tag ${f.level || 'bilgi'}">${LEVEL_TR[f.level] || ''}</span> ${esc(f.title || '')}</span><span class="d">${esc(i.plain)} ${esc(i.recommendation)}</span></div><span class="tag ${i.safe_to_remove ? 'iyi' : 'supheli'}">${i.safe_to_remove ? 'KALDIRMAK GÜVENLİ' : 'DİKKAT'}</span></div>`; }).join('')}
        ${r.steps.length ? `<h3 style="font-size:14px">Yapılacaklar</h3><ol class="plain">${r.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
        <div><button class="btn" data-go="tarama">Bulgulara git</button></div>`;
      bindCommon(out);
    } catch (e) { out.innerHTML = `<div class="banner bad">${esc(e.message)}</div>`; }
  };
  $('#r-go').onclick = run;
  if (state.ai.autorun && last) { state.ai.autorun = false; run(); }
}

/* ================================================================ Karantina */
PAGES.karantina = async (main) => {
  const [q, undo] = await Promise.all([api('quarantine_list'), api('undo_list')]);
  main.innerHTML = `<div class="page"><div class="page-head"><h1>Karantina</h1><span class="sub">Karantinadaki dosyalar şifrelenmiş olarak saklanır ve çalışamaz.</span></div>
    <section class="stack">${q.length ? q.map(m => `<div class="finding"><span class="tag tehdit">KARANTİNA</span><div class="body"><span class="title">${esc(m.name)}</span><span class="mono ellipsis">${esc(m.path)}</span><span class="why">${esc(m.detection || m.reason)} · ${when(m.time)} · ${size(m.size)}</span></div>
      <div class="row"><button class="btn sm ai" data-qx="${m.id}">${ICON.spark}Bu ne?</button><button class="btn sm" data-qr="${m.id}">Geri yükle</button><button class="btn sm danger-ghost" data-qd="${m.id}">Kalıcı sil</button></div></div>`).join('') : '<div class="card empty">Karantina boş.</div>'}</section>
    ${undo.length ? `<section class="card"><h2>Geri alınabilir işlemler</h2><div>${undo.slice(0, 30).map((u, i) => `<div class="list-row"><div class="main"><span class="t">${esc({ reg: 'Kayıt silindi: ' + (u.value || ''), task: 'Görev kapatıldı: ' + (u.task || ''), service: 'Servis kapatıldı: ' + (u.service || ''), file: 'Dosya düzeltildi: ' + (u.path || ''), proxy: 'Proxy sıfırlandı', wmi: 'WMI aboneliği silindi: ' + (u.name || '') }[u.type] || u.type)}</span><span class="d">${when(u.time)}</span></div>${u.type !== 'wmi' ? `<button class="btn sm" data-undo="${i}">Geri al</button>` : ''}</div>`).join('')}</div></section>` : ''}</div>`;
  main.onclick = async e => {
    const x = e.target.closest('[data-qx]'); if (x) return explainJob('quarantine_explain', { id: x.dataset.qx });
    const r = e.target.closest('[data-qr]');
    if (r && await confirmBox('Geri yüklensin mi?', 'Dosya eski yerine döner ve Kalkan ona bir daha dokunmaz. Yalnız güvendiğin dosyalar için yap.', 'Geri yükle')) { await act(() => api('quarantine_restore', { id: r.dataset.qr }), x => 'Geri yüklendi: ' + x.path); return go('karantina'); }
    const d = e.target.closest('[data-qd]');
    if (d && await confirmBox('Kalıcı olarak silinsin mi?', 'Bu işlem geri alınamaz.', 'Sil', true)) { await act(() => api('quarantine_delete', { id: d.dataset.qd }), 'Silindi'); return go('karantina'); }
    const u = e.target.closest('[data-undo]');
    if (u) { await act(() => api('undo', { index: +u.dataset.undo }), 'Geri alındı'); go('karantina'); }
  };
};

/* ================================================================ Geçmiş */
const KIND_TR = { tarama: 'Tarama', karantina: 'Karantina', uyari: 'Uyarı', dns: 'DNS filtresi', eklenti: 'Tarayıcı', indirilen: 'İndirilen', usb: 'USB', defender: 'Defender', sikilastirma: 'Sıkılaştırma', gizlilik: 'Gizlilik', kasa: 'Yedek kasası', goruntu: 'Anlık görüntü', fidye: 'Fidye kalkanı', guncelleme: 'Güncelleme', ajan: 'Kalkan', giderme: 'Giderme', ag: 'Ağ', asistan: 'Asistan' };
PAGES.gecmis = async (main, opts) => {
  const filter = opts.filter || '';
  const ev = await api('events', { limit: 400 });
  const shown = ev.filter(e => !filter || (filter === 'tehdit' ? ['tehdit', 'supheli'].includes(e.level) : e.kind === filter));
  const F = [['', 'Hepsi'], ['tehdit', 'Tehditler'], ['tarama', 'Taramalar'], ['dns', 'Engellenen siteler'], ['indirilen', 'İndirilenler']];
  main.innerHTML = `<div class="page"><div class="page-head"><h1>Geçmiş</h1><div class="seg">${F.map(([k, l]) => `<button class="${k === filter ? 'on' : ''}" data-f="${k}">${l}</button>`).join('')}</div></div>
    <section class="card">${shown.length ? shown.slice(0, 250).map(e => `<div class="list-row"><div class="main"><span class="t"><span class="tag ${e.level}">${esc(KIND_TR[e.kind] || e.kind)}</span> ${esc(e.title)}</span>${e.detail?.text ? `<span class="d">${esc(e.detail.text)}</span>` : e.detail?.path ? `<span class="d mono ellipsis">${esc(e.detail.path)}</span>` : ''}</div><span class="note" style="white-space:nowrap">${when(e.time)}</span></div>`).join('') : '<div class="empty">Kayıt yok.</div>'}</section></div>`;
  $$('[data-f]', main).forEach(b => b.onclick = () => go('gecmis', { filter: b.dataset.f }));
};

/* ================================================================ Ayarlar */
PAGES.ayarlar = async (main) => {
  const [key, eng, st] = await Promise.all([api('ai_key_status'), api('engines'), api('settings_get')]);
  const days = ['Pazartesi', 'Salı', 'Çarşamba', 'Perşembe', 'Cuma', 'Cumartesi', 'Pazar'];
  const sch = st.schedule;
  main.innerHTML = `<div class="page"><div class="page-head"><h1>Ayarlar</h1></div>
    <section class="card"><h2>Claude (yapay zekâ)</h2>
      <div class="list-row"><div class="main"><span class="t">API anahtarı</span><span class="d">${key.set ? 'Kayıtlı: ' + esc(key.hint) : 'Kayıtlı değil'} · Bu oturumda ${key.usage.calls} istek, yaklaşık $${key.usage.cost}</span></div><div class="row">${key.set ? '<button class="btn sm danger-ghost" id="k-del">Sil</button>' : ''}<button class="btn sm ai solid" id="k-set">${key.set ? 'Değiştir' : 'Anahtar ekle'}</button></div></div>
      <span class="note">Model: Claude Sonnet 5.5. Dosyaların kendisi gönderilmez, yalnız özeti.</span></section>
    <section class="card"><h2>Tarama motorları</h2><div>
      <div class="list-row"><div class="main"><span class="t">Microsoft Defender</span><span class="d">Windows'un kendi motoru; şüpheli bulgularda ikinci görüş olarak kullanılır.</span></div><span class="tag iyi">HAZIR</span></div>
      <div class="list-row"><div class="main"><span class="t">ClamAV</span><span class="d">${eng.clamav.installed ? (eng.clamav.db ? 'İmzalar ' + ago(eng.clamav.db) + ' güncellendi' : 'İmzalar indirilmedi') : 'Kurulu değil. İlk kurulumda ~225 MB program ve ~300 MB imza indirilir.'} · Tarama sırasında ~1 GB bellek kullanır.</span></div>
        <div class="row">${eng.clamav.installed ? '<button class="btn sm" data-upd="clamav">Güncelle</button>' : '<button class="btn sm primary" data-upd="clamav">Kur</button>'}${sw(eng.clamav.on, 'data-eng="clamav" aria-label="ClamAV"')}</div></div>
      <div class="list-row"><div class="main"><span class="t">YARA kuralları</span><span class="d">${eng.yara.ready ? `${(eng.yara.rules || 0).toLocaleString('tr-TR')} kural (YARA Forge ${esc(eng.yara.release || '')}) · ${ago(eng.yara.updated)}` : 'İndirilmedi'}</span></div><div class="row"><button class="btn sm" data-upd="yara">Güncelle</button>${sw(eng.yara.on, 'data-eng="yara" aria-label="YARA"')}</div></div>
      <div class="list-row"><div class="main"><span class="t">MalwareBazaar (abuse.ch)</span><span class="d">Dosyanın parmak izi bilinen zararlılar arasında aranır. Ücretsiz anahtar: auth.abuse.ch</span></div><div class="row"><button class="btn sm" data-sec="abusech_key">${eng.bazaar.key ? 'Anahtarı değiştir' : 'Anahtar ekle'}</button>${sw(eng.bazaar.on, 'data-eng="bazaar" aria-label="MalwareBazaar"')}</div></div>
      <div class="list-row"><div class="main"><span class="t">VirusTotal</span><span class="d">70+ antivirüsün sonucu; yalnız parmak izi gönderilir. Ücretsiz anahtar dakikada 4 sorgu.</span></div><div class="row"><button class="btn sm" data-sec="virustotal_key">${eng.virustotal.key ? 'Anahtarı değiştir' : 'Anahtar ekle'}</button>${sw(eng.virustotal.on, 'data-eng="virustotal" aria-label="VirusTotal"')}</div></div>
      <div class="list-row"><div class="main"><span class="t">ClamAV hep açık kalsın</span><span class="d">Anlık korumada da ClamAV kullanılır; ~1 GB bellek sürekli dolu kalır.</span></div>${sw(st.engines.clamav_resident, 'data-eng="clamav_resident" aria-label="ClamAV hep açık"')}</div></div>
      <div class="row"><button class="btn sm" data-upd="all">Tüm listeleri ve kuralları güncelle</button></div><div id="upd-msg" class="sub"></div></section>
    <section class="card"><h2>Zamanlanmış tarama</h2><div>
      <div class="list-row"><div class="main"><span class="t">Her gün hızlı tarama</span><span class="d">Saat <input type="number" min="0" max="23" id="qh" value="${sch.quick_hour}" style="width:70px;min-height:32px"> civarında</span></div>${sw(sch.quick, 'data-sch="quick" aria-label="Günlük hızlı tarama"')}</div>
      <div class="list-row"><div class="main"><span class="t">Haftada bir derin tarama</span><span class="d"><select id="dd" class="mode">${days.map((d, i) => `<option value="${i}" ${i == sch.deep_day ? 'selected' : ''}>${d}</option>`).join('')}</select></span></div>${sw(sch.deep, 'data-sch="deep" aria-label="Haftalık derin tarama"')}</div>
      <div class="list-row"><div class="main"><span class="t">Yalnız bilgisayar boştayken</span><span class="d">5 dakika dokunulmayınca başlar; 3 saat boş kalmazsa yine de başlar.</span></div>${sw(sch.idle_only, 'data-sch="idle_only" aria-label="Boştayken"')}</div></div></section>
    <section class="card"><h2>Hariç tutulanlar</h2><span class="sub">Bu klasör ve dosyalara tarama ve anlık koruma dokunmaz. Geliştirme klasörlerin için kullanabilirsin.</span>
      <div>${(st.exclusions || []).map(x => `<div class="list-row"><span class="mono">${esc(x)}</span><button class="btn sm danger-ghost" data-exrm="${esc(x)}">Kaldır</button></div>`).join('') || '<span class="note">Yok</span>'}</div>
      <div class="row"><button class="btn sm" id="ex-folder">Klasör ekle</button><button class="btn sm" id="ex-file">Dosya ekle</button></div></section>
    <section class="card"><div class="card-head"><h2>Hakkında</h2><button class="btn sm" id="upd-check">Güncellemeleri denetle</button></div><span class="sub">Kalkan ${esc((state.status || {}).version || '')} · Açık kaynak (MIT). Motorlar: Microsoft Defender, ClamAV (GPLv2), YARA-X ve YARA Forge kuralları, abuse.ch, VirusTotal, LOLDrivers, HaGeZi ve malware-filter listeleri, DB-IP.</span></section></div>`;
  $('#k-set').onclick = async () => { if (await askKey()) go('ayarlar'); };
  $('#upd-check').onclick = async () => {
    const b = $('#upd-check'); b.disabled = true; b.innerHTML = '<span class="spinner"></span>';
    const r = await act(() => api('update_check'));
    b.disabled = false; b.textContent = 'Güncellemeleri denetle';
    if (!r) return;
    if (r.available) installUpdate(b); else toast(`En son sürümü kullanıyorsun (${r.current}).`);
  };
  const kd = $('#k-del'); if (kd) kd.onclick = async () => { await act(() => runJob('ai_key_set', { key: '' }), 'Anahtar silindi'); go('ayarlar'); };
  const saveSch = patch => act(() => api('settings_set', { patch: { schedule: patch } }), 'Kaydedildi');
  $('#qh').onchange = e => saveSch({ quick_hour: Math.max(0, Math.min(23, +e.target.value || 0)) });
  $('#dd').onchange = e => saveSch({ deep_day: +e.target.value });
  main.onclick = async e => {
    const en = e.target.closest('[data-eng]');
    if (en) { const on = en.getAttribute('aria-checked') !== 'true'; const r = await act(() => api('settings_set', { patch: { engines: { [en.dataset.eng]: on } } }), on ? 'Açıldı' : 'Kapatıldı'); if (r) en.setAttribute('aria-checked', String(on)); return; }
    const sc = e.target.closest('[data-sch]');
    if (sc) { const on = sc.getAttribute('aria-checked') !== 'true'; const r = await saveSch({ [sc.dataset.sch]: on }); if (r) sc.setAttribute('aria-checked', String(on)); return; }
    const up = e.target.closest('[data-upd]');
    if (up) {
      const which = up.dataset.upd === 'all' ? ['lists', 'yara', 'loldrivers', 'geoip'].concat(eng.clamav.installed ? ['clamav'] : []) : [up.dataset.upd];
      up.disabled = true; up.innerHTML = '<span class="spinner"></span>';
      const r = await act(() => runJob('engines_update', { which }, j => { const m = $('#upd-msg'); if (m) m.textContent = j.message || ''; }));
      if (r) toast(r.errors.length ? 'Bazıları güncellenemedi: ' + r.errors.join('; ') : 'Güncellendi', !!r.errors.length);
      return go('ayarlar');
    }
    const sec = e.target.closest('[data-sec]');
    if (sec) {
      const name = sec.dataset.sec;
      const d = dialog(`<h2>${name === 'abusech_key' ? 'abuse.ch Auth-Key' : 'VirusTotal API anahtarı'}</h2><p class="sub">${name === 'abusech_key' ? 'auth.abuse.ch adresinden ücretsiz hesapla alınır.' : 'virustotal.com hesabında API Key bölümünden alınır.'} Boş bırakıp kaydedersen silinir.</p>
        <input type="password" id="sec-in" style="width:100%" autocomplete="off"><div class="actions"><button class="btn" data-x="0">Vazgeç</button><button class="btn primary" data-x="1">Kaydet</button></div>`);
      d.onclick = async ev => { const x = ev.target.closest('[data-x]'); if (!x) return; if (x.dataset.x === '1') await act(() => api('secret_set', { name, value: $('#sec-in', d).value }), 'Kaydedildi'); d.close(); go('ayarlar'); };
      return;
    }
    const rm = e.target.closest('[data-exrm]');
    if (rm) { await act(() => api('settings_set', { patch: { exclusions: (st.exclusions || []).filter(x => x !== rm.dataset.exrm) } })); return go('ayarlar'); }
  };
  const addEx = async kind => { const r = await act(() => api('pick', { kind })); if (r?.path) { await act(() => api('settings_set', { patch: { exclusions: [...(st.exclusions || []), r.path] } }), 'Eklendi'); go('ayarlar'); } };
  $('#ex-folder').onclick = () => addEx('folder');
  $('#ex-file').onclick = () => addEx('file');
};

/* ================================================================ başlangıç */
window.addEventListener('hashchange', () => { const h = location.hash.slice(1); if (PAGES[h]) go(h); });
(async () => {
  await refreshStatus();
  const hash = location.hash.slice(1);
  go(PAGES[hash] ? hash : 'durum');
})();
