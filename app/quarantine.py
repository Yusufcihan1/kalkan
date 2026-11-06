"""Karantina ve bulguları giderme işlemleri (her işlem geri alınabilir biçimde kaydedilir)."""
import json
import os
import re
import shutil
import time
import uuid
import winreg

import core
from core import QUAR_DIR, UserError

XOR = 0xA5   # karantinadaki dosya çalıştırılamaz ve başka antivirüsleri tetiklemez


def _xor_copy(src, dst):
    with open(src, "rb") as f, open(dst, "wb") as out:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            out.write(bytes(x ^ XOR for x in b))


def _meta_path(qid):
    return os.path.join(QUAR_DIR, qid + ".json")


def quarantine_file(path, reason="", detection="", source="tarama"):
    if not os.path.isfile(path):
        raise UserError(f"Dosya bulunamadı: {path}")
    os.makedirs(QUAR_DIR, exist_ok=True)
    core.kill_by_path(path)
    qid = uuid.uuid4().hex[:16]
    sha = core.sha256_file(path)
    _xor_copy(path, os.path.join(QUAR_DIR, qid + ".bin"))
    for attempt in range(5):
        try:
            os.remove(path)
            break
        except PermissionError:
            core.kill_by_path(path)
            time.sleep(0.4)
    else:
        os.remove(os.path.join(QUAR_DIR, qid + ".bin"))
        raise UserError("Dosya kullanımda olduğu için karantinaya alınamadı. Bilgisayarı yeniden başlatıp tekrar dene.")
    meta = {"id": qid, "path": path, "name": os.path.basename(path), "sha256": sha, "size": os.path.getsize(os.path.join(QUAR_DIR, qid + ".bin")),
            "time": time.time(), "reason": reason, "detection": detection, "source": source}
    core.write_json(_meta_path(qid), meta)
    core.event("karantina", "tehdit", f"Karantinaya alındı: {meta['name']}", {"path": path, "detection": detection, "id": qid})
    return meta


def list_quarantine():
    out = []
    try:
        names = os.listdir(QUAR_DIR)
    except OSError:
        return out
    for n in names:
        if n.endswith(".json"):
            m = core.read_json(os.path.join(QUAR_DIR, n))
            if m:
                out.append(m)
    return sorted(out, key=lambda m: -m.get("time", 0))


def restore(qid, trust=True):
    m = core.read_json(_meta_path(qid))
    if not m:
        raise UserError("Karantina kaydı bulunamadı.")
    dest = m["path"]
    if os.path.exists(dest):
        base, ext = os.path.splitext(dest)
        dest = f"{base} (geri yüklendi){ext}"
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    _xor_copy(os.path.join(QUAR_DIR, qid + ".bin"), dest)
    os.remove(os.path.join(QUAR_DIR, qid + ".bin"))
    os.remove(_meta_path(qid))
    if trust and m.get("sha256"):
        s = core.settings()
        hashes = list(dict.fromkeys(s.get("trusted_hashes", []) + [m["sha256"]]))
        core.save_settings({"trusted_hashes": hashes})
    core.event("karantina", "bilgi", f"Karantinadan geri yüklendi: {m['name']}", {"path": dest})
    return dest


def delete(qid):
    for ext in (".bin", ".json"):
        try:
            os.remove(os.path.join(QUAR_DIR, qid + ext))
        except OSError:
            pass


# ---------------------------------------------------------------- giderme işlemleri

UNDO_FILE = os.path.join(core.DATA_DIR, "geri_al.json")
HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}


def _remember(entry):
    log = core.read_json(UNDO_FILE, [])
    entry["time"] = time.time()
    log.insert(0, entry)
    core.write_json(UNDO_FILE, log[:300])


def remove_autorun(t):
    hive, key, value = HIVES[t["hive"]], t["key"], t["value"]
    with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
        data, typ = winreg.QueryValueEx(k, value)
        winreg.DeleteValue(k, value)
    _remember({"type": "reg", "hive": t["hive"], "key": key, "value": value, "data": data, "regtype": typ})
    return f"'{value}' başlangıç kaydı silindi"


def disable_task(t):
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()
    svc = win32com.client.Dispatch("Schedule.Service")
    svc.Connect()
    task = svc.GetFolder("\\").GetTask(t["task"])
    task.Enabled = False
    try:
        task.Stop(0)
    except Exception:
        pass
    _remember({"type": "task", "task": t["task"]})
    return f"'{t['name']}' görevi kapatıldı"


def disable_service(t):
    name = t.get("service")
    if not name:
        raise UserError("Bu sürücünün servis kaydı bulunamadı; elle kaldırılması gerekiyor.")
    path = rf"SYSTEM\CurrentControlSet\Services\{name}"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
        old = winreg.QueryValueEx(k, "Start")[0]
        winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, 4)
    core.run(["sc.exe", "stop", name], timeout=30)
    _remember({"type": "service", "service": name, "start": old})
    return f"'{name}' servisi durduruldu ve kapatıldı (yeniden başlatınca tam etkili)"


def remove_wmi(t):
    cls, name = t["wmi_class"], t["name"]
    script = (f"$c = Get-CimInstance -Namespace root\\subscription -ClassName {cls} | Where-Object Name -eq '{name.replace(chr(39), '')}';"
              "Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding | "
              "Where-Object { $_.Consumer.Name -eq $c.Name } | Remove-CimInstance; $c | Remove-CimInstance")
    code, out = core.ps(script, timeout=60)
    if code:
        raise UserError("WMI aboneliği silinemedi: " + out[:200])
    _remember({"type": "wmi", "name": name, "command": t.get("command")})
    return f"'{name}' WMI aboneliği silindi"


def remove_policy(t):
    hive, key = HIVES[t["hive"]], t["key"]
    with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
        if t.get("value"):
            data, typ = winreg.QueryValueEx(k, t["value"])
            winreg.DeleteValue(k, t["value"])
            _remember({"type": "reg", "hive": t["hive"], "key": key, "value": t["value"], "data": data, "regtype": typ})
        else:
            i = 0
            while True:
                try:
                    n, v, typ = winreg.EnumValue(k, i)
                except OSError:
                    break
                if v == t.get("data"):
                    winreg.DeleteValue(k, n)
                    _remember({"type": "reg", "hive": t["hive"], "key": key, "value": n, "data": v, "regtype": typ})
                    break
                i += 1
    return "Tarayıcı politikası kaldırıldı (tarayıcıyı yeniden başlat)"


def fix_hosts(t):
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    backup = os.path.join(core.QUAR_DIR, f"hosts-{int(time.time())}.yedek")
    shutil.copy2(path, backup)
    bad = set(t.get("lines", []))
    new = "\n".join(("# Kalkan kapattı: " + ln) if ln in bad else ln for ln in text.splitlines()) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    core.run(["ipconfig", "/flushdns"], timeout=20)
    _remember({"type": "file", "path": path, "backup": backup})
    return "Hosts dosyasındaki yönlendirmeler kapatıldı (yedek alındı)"


def reset_proxy(t):
    key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    old = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
        for n in ("ProxyEnable", "ProxyServer", "AutoConfigURL"):
            try:
                old[n] = winreg.QueryValueEx(k, n)
            except OSError:
                continue
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        try:
            winreg.DeleteValue(k, "AutoConfigURL")
        except OSError:
            pass
    core.run(["netsh", "winhttp", "reset", "proxy"], timeout=20)
    _remember({"type": "proxy", "old": {k: [v[0], v[1]] for k, v in old.items()}})
    return "Proxy ayarları sıfırlandı"


def reset_dns(t):
    idx = t.get("index")
    code, out = core.ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(idx)} -ResetServerAddresses", timeout=60)
    if code:
        raise UserError("DNS sıfırlanamadı: " + out[:200])
    core.run(["ipconfig", "/flushdns"], timeout=20)
    return "DNS ayarı otomatik (modemden) olarak sıfırlandı"


def kill(t):
    pid = int(t.get("pid") or 0)
    if pid <= 4 or not core.kill_process(pid):
        raise UserError("Süreç kapatılamadı (zaten kapanmış olabilir).")
    return "Süreç kapatıldı"


def open_extensions(t):
    url = {"Chrome": "chrome://extensions", "Edge": "edge://extensions", "Brave": "brave://extensions",
           "Opera": "opera://extensions"}.get(t.get("browser"), "edge://extensions")
    exe = {"Chrome": "chrome.exe", "Edge": "msedge.exe", "Brave": "brave.exe", "Opera": "opera.exe"}.get(t.get("browser"), "msedge.exe")
    core.launch_unelevated(["cmd.exe", "/c", "start", "", exe, url])
    return "Eklenti sayfası açıldı: eklentiyi oradan kaldır"


ACTIONS = {"remove_autorun": remove_autorun, "disable_task": disable_task, "disable_service": disable_service,
           "remove_wmi": remove_wmi, "remove_policy": remove_policy, "fix_hosts": fix_hosts, "reset_proxy": reset_proxy,
           "reset_dns": reset_dns, "kill": kill, "open_extensions": open_extensions}
ACTION_LABELS = {"quarantine": "Karantinaya al", "remove_autorun": "Kaydı sil", "disable_task": "Görevi kapat",
                 "disable_service": "Servisi kapat", "remove_wmi": "Aboneliği sil", "remove_policy": "Politikayı kaldır",
                 "fix_hosts": "Hosts'u düzelt", "reset_proxy": "Proxy'yi sıfırla", "reset_dns": "DNS'i sıfırla",
                 "kill": "Süreci kapat", "open_extensions": "Eklentiyi kaldır", "info": "Bilgi"}


def apply(finding, action):
    """Bir bulguya işlem uygular. Karantinada kalıcılık kaydı da temizlenir."""
    t = finding.get("target") or {}
    if action == "quarantine":
        path = finding.get("path") if os.path.isfile(finding.get("path") or "") else t.get("path")
        if not path or not os.path.isfile(path):
            raise UserError("Karantinaya alınacak dosya bulunamadı.")
        hits = finding.get("hits") or []
        m = quarantine_file(path, finding.get("why", ""), ", ".join(f"{h['engine']}: {h['name']}" for h in hits) or finding.get("title", ""))
        extra = ""
        if finding.get("kind") == "autorun":
            try:
                fn = {"registry": remove_autorun, "task": disable_task, "service": disable_service}.get(t.get("type"))
                if fn:
                    extra = "; " + fn(t)
            except Exception:
                pass
        return f"{m['name']} karantinaya alındı{extra}"
    fn = ACTIONS.get(action)
    if not fn:
        raise UserError("Bu bulgu için otomatik işlem yok.")
    msg = fn(t)
    core.event("giderme", "bilgi", msg, {"finding": finding.get("title")})
    return msg


def undo_list():
    return core.read_json(UNDO_FILE, [])


def undo(index):
    log = core.read_json(UNDO_FILE, [])
    if not 0 <= index < len(log):
        raise UserError("Geri alınacak kayıt yok.")
    e = log.pop(index)
    if e["type"] == "reg":
        with winreg.CreateKey(HIVES[e["hive"]], e["key"]) as k:
            winreg.SetValueEx(k, e["value"], 0, e["regtype"], e["data"])
    elif e["type"] == "task":
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        svc = win32com.client.Dispatch("Schedule.Service")
        svc.Connect()
        svc.GetFolder("\\").GetTask(e["task"]).Enabled = True
    elif e["type"] == "service":
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{e['service']}", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, e["start"])
    elif e["type"] == "file":
        shutil.copy2(e["backup"], e["path"])
    elif e["type"] == "proxy":
        key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
            for n, (v, typ) in e["old"].items():
                winreg.SetValueEx(k, n, 0, typ, v)
    else:
        raise UserError("Bu işlem geri alınamıyor.")
    core.write_json(UNDO_FILE, log)
    return "Geri alındı"
