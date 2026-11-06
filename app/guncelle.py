"""Uygulamalarım güncelleme denetimi (PDF Stüdyo, Kalkan, PC Turbo aynı dosyayı kullanır).

Sitedeki apps.json'dan uygulamanın son sürümünü okur; yeniyse kurulum dosyasını indirir, SHA-256 ile doğrular,
eski sürümün üzerine sessizce kurar ve uygulamayı yeniden başlatır. Ayarlar ve veriler korunur."""
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request

SITE = os.environ.get("UYGULAMALARIM_SITE") or "https://yusufcihan1.github.io/uygulamalarim/apps.json"
UA = {"User-Agent": "Uygulamalarim-Guncelleme/1.0", "Cache-Control": "no-cache"}


def _ver(v):
    out = []
    for part in str(v).split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits or 0))
    return tuple(out + [0] * (4 - len(out)))


def check(app_id, current, timeout=8):
    """Yeni sürüm varsa {version, download, size, sha256, description}, yoksa None."""
    req = urllib.request.Request(SITE, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        apps = json.loads(r.read().decode("utf-8-sig"))
    app = next((a for a in apps if a.get("id") == app_id), None)
    if not app or _ver(app.get("version", "0")) <= _ver(current):
        return None
    return {k: app.get(k) for k in ("version", "download", "size", "sha256", "description", "date", "name")}


def download(info, progress=None):
    """Kurulum dosyasını indirir ve doğrular; dosya yolunu döner."""
    folder = os.path.join(tempfile.gettempdir(), "uygulamalarim-guncelleme")
    os.makedirs(folder, exist_ok=True)
    dest = os.path.join(folder, os.path.basename(info["download"]))
    h = hashlib.sha256()
    req = urllib.request.Request(info["download"], headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r, open(dest + ".part", "wb") as f:
        total = int(r.headers.get("Content-Length") or info.get("size") or 0)
        got = 0
        while True:
            b = r.read(1 << 18)
            if not b:
                break
            f.write(b)
            h.update(b)
            got += len(b)
            if progress and total:
                progress(got / total)
    if info.get("sha256") and h.hexdigest() != info["sha256"]:
        os.remove(dest + ".part")
        raise RuntimeError("İndirilen dosya doğrulanamadı (SHA-256 uyuşmuyor). Tekrar dene.")
    os.replace(dest + ".part", dest)
    return dest


def install(installer, restart=None, delay=2):
    """Kurulumu uygulamadan bağımsız bir süreçte başlatır: önce uygulamanın kapanmasını bekler, sessizce kurar,
    sonra 'restart' komutunu (ör. ['C:\\...\\app.exe'] ya da ['schtasks', '/run', '/tn', 'Kalkan']) çalıştırır.
    Çağıran uygulama bundan hemen sonra kapanmalı."""
    def q(s):
        return '"' + s + '"'
    # timeout komutu konsolsuz süreçte çalışmıyor; bekleme için ping kullanılır.
    steps = [f"ping -n {int(delay) + 1} 127.0.0.1 >nul",
             f"{q(installer)} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"]
    if restart:
        steps.append('start "" ' + " ".join(q(a) if (" " in a or not a) else a for a in restart))
    flags = 0x00000008 | 0x00000200 | 0x08000000   # DETACHED_PROCESS | NEW_PROCESS_GROUP | NO_WINDOW
    # /s /c "...": cmd dıştaki tırnakları atar, içini olduğu gibi çalıştırır (Python'un kaçış eklemesi olmaz).
    subprocess.Popen(f'cmd.exe /s /c "{" & ".join(steps)}"', creationflags=flags, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
