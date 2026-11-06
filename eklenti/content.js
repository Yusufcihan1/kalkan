// Sayfa içi dolandırıcılık: sahte "virüs bulundu / bilgisayarınız kilitlendi / destek hattını arayın" sayfaları.
(() => {
  const text = (document.body?.innerText || '').slice(0, 20000);
  if (text.length < 40) return;
  const patterns = [
    /bilgisayar(ın)?ız(a)? (virüs|kilitlen|engellen|hack)/i, /virüs (bulundu|tespit edildi)/i, /windows (defender|güvenlik) (uyarı|alarm)/i,
    /microsoft (destek|teknik destek)/i, /lisansınız (sona erdi|geçersiz)/i, /hesabınız (askıya|bloke|kapatıl)/i,
    /your (computer|pc) (has been|is) (locked|infected|blocked)/i, /virus(es)? (detected|found)/i, /call (microsoft|windows|apple) support/i,
    /do not (close|restart|shut down) (this|your)/i, /trojan|spyware|pornographic spyware/i,
    /tebrikler.{0,40}(kazandınız|ödül)/i, /iade(niz)? (için|almak için).{0,40}(kart|iban)/i, /son \d+ (dakika|saat).{0,40}(işlem|ödeme)/i,
  ];
  const hits = patterns.filter(p => p.test(text)).length;
  const phone = /(\+?\d[\d\s\-().]{8,}\d)/.test(text) && /(ara|arayın|call|destek hattı|toll.?free)/i.test(text);
  if (hits < 2 && !(hits >= 1 && phone)) return;
  const bar = document.createElement('div');
  bar.setAttribute('role', 'alert');
  bar.style.cssText = 'position:fixed;inset:0 0 auto 0;z-index:2147483647;background:#B42318;color:#fff;font:600 15px/1.5 "Segoe UI",system-ui,sans-serif;' +
    'padding:14px 20px;display:flex;gap:16px;align-items:center;justify-content:space-between;box-shadow:0 4px 20px rgba(0,0,0,.3)';
  const msg = document.createElement('span');
  msg.textContent = 'Kalkan: Bu sayfa dolandırıcılık olabilir. Gerçek bir uyarı ya da kurum seni telefonla aramaya, kart bilgisi girmeye ya da program indirmeye zorlamaz. Sekmeyi kapat.';
  const btn = document.createElement('button');
  btn.textContent = 'Kapat';
  btn.style.cssText = 'background:#fff;color:#B42318;border:0;border-radius:10px;padding:8px 16px;font:inherit;cursor:pointer;flex-shrink:0';
  btn.onclick = () => bar.remove();
  bar.append(msg, btn);
  document.documentElement.appendChild(bar);
})();
