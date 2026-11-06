"""Sistem sıkılaştırma: güvenlik puanı ve düzeltmeler, program güncelliği (winget), şifre sızıntısı, gizlilik ayarları."""
import hashlib
import os
import re
import time
import urllib.request
import winreg

import core
from core import UserError
from deep import reg_get

HKLM, HKCU = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER


def reg_set(hive, path, name, value, typ=winreg.REG_DWORD):
    with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        winreg.SetValueEx(k, name, 0, typ, value)


# ---------------------------------------------------------------- güvenlik puanı

def _bitlocker():
    d = core.ps_json("Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop | Select-Object ProtectionStatus,VolumeStatus,EncryptionPercentage", timeout=60)
    if d is None:
        code, out = core.run(["manage-bde", "-status", os.environ.get("SystemDrive", "C:")], timeout=60)
        if "Protection On" in out or "Koruma Açık" in out:
            return True
        return None if code else False
    return str(d.get("ProtectionStatus")) in ("1", "On")


def _secure_boot():
    v = reg_get(HKLM, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    return None if v is None else bool(v)


def _smb1():
    v = core.ps_json("(Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol", timeout=60)
    if isinstance(v, bool):
        return v
    start = reg_get(HKLM, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    return start is not None and start != 4


def _firewall():
    d = core.as_list(core.ps_json("Get-NetFirewallProfile | Select-Object Name,Enabled", timeout=60))
    if not d:
        return None
    return all(str(p.get("Enabled")) in ("1", "True", "true") or p.get("Enabled") is True for p in d)


def _defender_rt():
    d = core.ps_json("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusSignatureAge", timeout=60) or {}
    if not d:
        return None, None
    return bool(d.get("RealTimeProtectionEnabled")), d.get("AntivirusSignatureAge")


def _last_update_days():
    d = core.ps_json("$s=New-Object -ComObject Microsoft.Update.Session; $h=$s.CreateUpdateSearcher(); $n=$h.GetTotalHistoryCount();"
                     "if($n -gt 0){ ($h.QueryHistory(0,[Math]::Min($n,50)) | Where-Object { $_.ResultCode -eq 2 } | "
                     "Sort-Object Date -Descending | Select-Object -First 1).Date.ToString('o') }", timeout=90)
    if not d or not isinstance(d, str):
        return None
    try:
        import datetime
        t = datetime.datetime.fromisoformat(d.replace("Z", "+00:00"))
        return (datetime.datetime.now(t.tzinfo) - t).days
    except ValueError:
        return None


def _guest_enabled():
    d = core.ps_json("Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Select-Object -ExpandProperty Enabled", timeout=30)
    return bool(d) if isinstance(d, bool) else None


def _hvci():
    v = reg_get(HKLM, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
    return bool(v) if v is not None else False


def _smartscreen():
    v = reg_get(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled")
    pol = reg_get(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    if pol is not None:
        return bool(pol)
    return (v or "Warn").lower() != "off"


CHECKS = [
    # anahtar, başlık, ağırlık, açıklama, düzeltme türü
    ("defender", "Defender anlık koruması", 15, "Windows'un kendi antivirüsü açık olmalı.", "settings:windowsdefender://threat"),
    ("firewall", "Güvenlik duvarı", 10, "Tüm ağ profillerinde güvenlik duvarı açık olmalı.", "fix"),
    ("updates", "Windows güncellemeleri", 12, "Son 30 günde güncelleme yüklenmiş olmalı.", "settings:ms-settings:windowsupdate"),
    ("uac", "Kullanıcı Hesabı Denetimi (UAC)", 12, "Programlar yönetici yetkisi isterken sana sorulmalı.", "fix"),
    ("bitlocker", "BitLocker disk şifreleme", 10, "Bilgisayar çalınırsa dosyaların okunamaz.", "settings:ms-settings:deviceencryption"),
    ("secureboot", "Güvenli Önyükleme", 8, "Açılışta çalışan zararlılara (bootkit) karşı.", "info"),
    ("smb1", "SMBv1 kapalı", 8, "WannaCry'ın yayıldığı eski dosya paylaşım protokolü.", "fix"),
    ("rdp", "Uzak Masaüstü kapalı", 6, "Kullanmıyorsan dışarıdan bağlanma kapısını kapat.", "fix"),
    ("hvci", "Bellek bütünlüğü", 6, "Çekirdeğe kötü sürücü yüklenmesini zorlaştırır.", "settings:windowsdefender://coreisolation"),
    ("smartscreen", "SmartScreen", 5, "İndirilen bilinmeyen programlar için uyarı.", "fix"),
    ("guest", "Konuk hesabı kapalı", 3, "Parolasız konuk hesabı kapalı olmalı.", "fix"),
    ("autoplay", "Otomatik kullan (AutoPlay) kapalı", 3, "Takılan USB'den bir şey kendiliğinden açılmamalı.", "fix"),
    ("remote_assist", "Uzaktan Yardım kapalı", 2, "Dolandırıcıların sık kullandığı uzaktan yardım isteği.", "fix"),
]


def security_checks():
    rt, sig_age = _defender_rt()
    upd = _last_update_days()
    vals = {
        "defender": rt,
        "firewall": _firewall(),
        "updates": None if upd is None else upd <= 30,
        "uac": reg_get(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1) == 1 and
               reg_get(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5) != 0,
        "bitlocker": _bitlocker(),
        "secureboot": _secure_boot(),
        "smb1": None if _smb1() is None else not _smb1(),
        "rdp": reg_get(HKLM, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1) == 1,
        "hvci": _hvci(),
        "smartscreen": _smartscreen(),
        "guest": None if _guest_enabled() is None else not _guest_enabled(),
        "autoplay": reg_get(HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", "DisableAutoplay", 0) == 1
                    or reg_get(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0) == 255,
        "remote_assist": reg_get(HKLM, r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 1) == 0,
    }
    details = {"updates": f"Son güncelleme {upd} gün önce" if upd is not None else "",
               "defender": f"İmzalar {sig_age} günlük" if isinstance(sig_age, int) and sig_age < 1000 else ""}
    items, total, got = [], 0, 0
    for key, title, weight, desc, fix in CHECKS:
        ok = vals.get(key)
        if ok is not None:
            total += weight
            got += weight if ok else 0
        items.append({"key": key, "title": title, "ok": ok, "weight": weight, "desc": desc, "fix": fix,
                      "detail": details.get(key, "")})
    score = round(100 * got / total) if total else 0
    gain = {}
    for it in items:
        if it["ok"] is False:
            gain[it["key"]] = round(100 * it["weight"] / total) if total else 0
    for it in items:
        it["gain"] = gain.get(it["key"], 0)
    core.write_json(os.path.join(core.DATA_DIR, "puan.json"), {"score": score, "time": time.time(),
                                                                "open": [i["title"] for i in items if i["ok"] is False]})
    return {"score": score, "items": items}


def cached_score():
    return core.read_json(os.path.join(core.DATA_DIR, "puan.json"), None)


def fix(key):
    if not core.is_admin():
        raise UserError("Bu düzeltme için Kalkan'ın yönetici olarak çalışması gerekiyor.")
    if key == "firewall":
        core.ps("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
        msg = "Güvenlik duvarı açıldı"
    elif key == "uac":
        reg_set(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1)
        reg_set(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5)
        msg = "UAC açıldı (yeniden başlatınca etkin)"
    elif key == "smb1":
        core.ps("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; "
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue", timeout=300)
        msg = "SMBv1 kapatıldı (yeniden başlatınca tam etkili)"
    elif key == "rdp":
        reg_set(HKLM, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1)
        msg = "Uzak Masaüstü kapatıldı"
    elif key == "smartscreen":
        reg_set(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Warn", winreg.REG_SZ)
        msg = "SmartScreen açıldı"
    elif key == "guest":
        core.ps("Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Disable-LocalUser")
        msg = "Konuk hesabı kapatıldı"
    elif key == "autoplay":
        reg_set(HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", "DisableAutoplay", 1)
        reg_set(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255)
        msg = "Otomatik kullan kapatıldı"
    elif key == "remote_assist":
        reg_set(HKLM, r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 0)
        msg = "Uzaktan Yardım kapatıldı"
    else:
        raise UserError("Bu madde otomatik düzeltilemiyor; Windows ayarı açılacak.")
    core.event("sikilastirma", "iyi", msg)
    return msg


def open_settings(uri):
    core.launch_unelevated(["explorer.exe", uri])


# ---------------------------------------------------------------- program güncellikleri

SECURITY_RELEVANT = re.compile(r"(chrome|firefox|edge|brave|opera|7-?zip|winrar|java|jre|jdk|adobe|acrobat|reader|zoom|"
                               r"vlc|notepad\+\+|putty|winscp|filezilla|teamviewer|anydesk|python|node|git|openssl|"
                               r"thunderbird|discord|telegram|whatsapp|skype|steam|office|libreoffice|foxit|qbittorrent|"
                               r"vmware|virtualbox|docker|powershell|dotnet|\.net|visual c\+\+|webview)", re.I)


def winget_upgrades():
    code, out = core.run(["winget", "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"],
                         timeout=240)
    lines = [ln.rstrip() for ln in out.replace("\r", "\n").split("\n")]
    # Başlık satırını ve altındaki çizgiyi bul; sütun konumları başlıktan okunur (dil bağımsız).
    idx = next((i for i, ln in enumerate(lines) if re.match(r"^-{10,}$", ln.strip())), None)
    if idx is None or idx == 0:
        return []
    header = lines[idx - 1]
    cols = [m.start() for m in re.finditer(r"\S+", header)]
    if len(cols) < 4:
        return []
    items = []
    for ln in lines[idx + 1:]:
        if not ln.strip() or re.match(r"^\d+ (upgrades|yükseltme|güncelleştirme)", ln.strip(), re.I) or len(ln) < cols[2]:
            if items and not ln.strip():
                break
            continue

        def col(i):
            end = cols[i + 1] if i + 1 < len(cols) else None
            return ln[cols[i]:end].strip()
        try:
            name, pid, ver, avail = col(0), col(1), col(2), col(3)
        except IndexError:
            continue
        if not pid or " " in pid:
            continue
        items.append({"name": name, "id": pid, "version": ver, "available": avail,
                      "security": bool(SECURITY_RELEVANT.search(name + " " + pid))})
    items.sort(key=lambda x: (not x["security"], x["name"].lower()))
    return items


def winget_upgrade(job, pid):
    job.update(0.1, f"{pid} güncelleniyor")
    code, out = core.run(["winget", "upgrade", "--id", pid, "-e", "--silent", "--accept-package-agreements",
                          "--accept-source-agreements", "--disable-interactivity"], timeout=1800)
    ok = code == 0 or "Successfully installed" in out or "Başarıyla yüklendi" in out
    if not ok:
        raise UserError("Güncelleme tamamlanamadı: " + (out.strip().splitlines() or ["?"])[-1][:200])
    core.event("sikilastirma", "iyi", f"Güncellendi: {pid}")
    return {"id": pid}


# ---------------------------------------------------------------- şifre sızıntısı (k-anonimlik)

def pwned_count(password):
    sha = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{prefix}",
                                 headers={"User-Agent": f"Kalkan/{core.VERSION}", "Add-Padding": "true"})
    with urllib.request.urlopen(req, timeout=20) as r:
        for line in r.read().decode().splitlines():
            h, _, n = line.partition(":")
            if h == suffix:
                return int(n)
    return 0


# ---------------------------------------------------------------- gizlilik ayarları

PRIVACY = [
    ("ads_id", "Reklam kimliğini kapat", "Uygulamaların seni reklam için tanıması.", HKCU,
     r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, 1),
    ("tailored", "Kişiye özel reklamları kapat", "Tanılama verilerinle öneri ve reklam.", HKCU,
     r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0, 1),
    ("telemetry", "Tanılama verisini en aza indir", "Microsoft'a yalnız zorunlu tanılama verisi gider.", HKLM,
     r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 1, None),
    ("activity", "Etkinlik geçmişini kapat", "Açtığın dosya ve uygulamaların zaman çizelgesi.", HKLM,
     r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0, None),
    ("start_ads", "Başlat menüsü önerilerini kapat", "Başlat'ta ve kilit ekranında reklam ve öneriler.", HKCU,
     r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338388Enabled", 0, 1),
    ("silent_apps", "Sessiz uygulama yüklemeyi kapat", "Windows'un sana sormadan önerilen uygulamaları kurması.", HKCU,
     r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 0, 1),
    ("web_search", "Başlat aramasında Bing'i kapat", "Bilgisayarda aradıkların internete gider.", HKCU,
     r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1, None),
    ("location", "Konum erişimini kapat", "Hiçbir uygulama konumunu okuyamaz.", HKLM,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", "Deny", "Allow"),
]


def privacy_status():
    out = []
    for key, title, desc, hive, path, name, private_val, _ in PRIVACY:
        v = reg_get(hive, path, name)
        out.append({"key": key, "title": title, "desc": desc, "private": v == private_val})
    out.append({"key": "devices", "title": "Kamera ve mikrofon", "desc": "Son kullanan uygulamalar aşağıda.", "private": None})
    return {"items": out, "devices": device_usage()}


def set_privacy(key, private):
    item = next((p for p in PRIVACY if p[0] == key), None)
    if not item:
        raise UserError("Bilinmeyen ayar")
    _, title, _, hive, path, name, private_val, public_val = item
    if hive == HKLM and not core.is_admin():
        raise UserError("Bu ayar için yönetici yetkisi gerekiyor.")
    if private:
        reg_set(hive, path, name, private_val, winreg.REG_SZ if isinstance(private_val, str) else winreg.REG_DWORD)
    elif public_val is None:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except OSError:
            pass
    else:
        reg_set(hive, path, name, public_val, winreg.REG_SZ if isinstance(public_val, str) else winreg.REG_DWORD)
    core.event("gizlilik", "bilgi", f"{title}: " + ("gizli" if private else "varsayılan"))


def device_usage():
    """Kamerayı ve mikrofonu son kullanan uygulamalar (Windows'un kendi kaydından)."""
    out = []
    for dev, label in (("webcam", "Kamera"), ("microphone", "Mikrofon")):
        for hive in (HKCU,):
            base = rf"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{dev}"
            for sub in ("", "\\NonPackaged"):
                try:
                    with winreg.OpenKey(hive, base + sub) as k:
                        i = 0
                        while True:
                            try:
                                name = winreg.EnumKey(k, i)
                            except OSError:
                                break
                            i += 1
                            if name == "NonPackaged":
                                continue
                            start = reg_get(hive, base + sub + "\\" + name, "LastUsedTimeStart", 0) or 0
                            stop = reg_get(hive, base + sub + "\\" + name, "LastUsedTimeStop", 0) or 0
                            if not start:
                                continue
                            t = start / 1e7 - 11644473600
                            app = name.replace("#", "\\") if sub else name.split("_")[0]
                            out.append({"device": label, "app": os.path.basename(app) if sub else app, "path": app if sub else "",
                                        "time": t, "active": bool(start and not stop or stop < start)})
                except OSError:
                    continue
    out.sort(key=lambda x: -x["time"])
    return out[:20]
