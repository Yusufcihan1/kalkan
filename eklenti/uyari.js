const q = new URLSearchParams(location.search);
const host = q.get('h') || '';
const warnOnly = q.get('w') === '1';
document.getElementById('h').textContent = host;
if (warnOnly) {
  document.getElementById('box').classList.add('warn');
  document.getElementById('t').textContent = 'Bu site taklit olabilir';
  document.getElementById('r').textContent = (q.get('r') || '') + ' Şifre, kart ya da T.C. kimlik bilgisi girme. Kurumun adresini kendin yazarak git.';
} else {
  document.getElementById('r').textContent = 'Kalkan bu siteyi ' + ({ tehdit: 'zararlı yazılım ya da oltalama', reklam: 'reklam ve izleme' }[q.get('c')] || 'tehlikeli') +
    ' listesinde buldu. ' + (q.get('r') || '');
}
document.getElementById('back').onclick = () => { if (history.length > 2) history.go(-2); else location.href = 'about:blank'; };
document.getElementById('go').onclick = async () => {
  await chrome.runtime.sendMessage({ type: 'allow', host });
  location.href = q.get('u');
};
