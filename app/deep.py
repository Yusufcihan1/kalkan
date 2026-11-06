"""Derin tarama: kalıcılık noktaları, imzalar ve sürücüler, çalışan süreçler, hosts/DNS/proxy, tarayıcı eklentileri."""
import ctypes
import ctypes.wintypes as wt
import glob
import ipaddress
import json
import os
import re
import shlex
import time
import winreg

import core
import engines
from core import ENGINE_DIR

WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
SYS32 = core.norm(os.path.join(WINDIR, "System32"))
SYSWOW = core.norm(os.path.join(WINDIR, "SysWOW64"))
USER_WRITABLE = [core.norm(p) for p in (os.environ.get("TEMP", ""), os.environ.get("APPDATA", ""),
                                         os.environ.get("LOCALAPPDATA", ""), os.environ.get("PUBLIC", ""),
                                         os.path.join(core.HOME, "Downloads"), r"C:\ProgramData", r"C:\Users\Public",
                                         os.path.join(WINDIR, "Temp")) if p]


def in_user_writable(path):
    p = core.norm(path)
    return any(p.startswith(d + "\\") for d in USER_WRITABLE)


def expand(path):
    return os.path.expandvars(path.strip().strip('"')) if path else ""


def command_target(cmd):
    """Bir komut satırındaki çalıştırılabilir dosyanın yolu."""
    if not cmd:
        return ""
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith("\\??\\"):
        cmd = cmd[4:]
    low = cmd.lower()
    if low.startswith("\\systemroot\\"):
        cmd = WINDIR + cmd[11:]
    elif low.startswith("system32\\") or low.startswith("syswow64\\"):
        cmd = os.path.join(WINDIR, cmd)
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd.strip('"')
    m = re.match(r"(.+?\.(?:exe|dll|com|bat|cmd|vbs|js|ps1|scr|sys|cpl|hta|msc|lnk))\b", cmd, re.I)
    if m:
        p = m.group(1)
        if not os.path.isabs(p):
            for base in (os.path.join(WINDIR, "System32"), WINDIR):
                if os.path.isfile(os.path.join(base, p)):
                    return os.path.join(base, p)
        return p
    first = cmd.split(" ", 1)[0]
    if first.startswith("\\??\\"):
        first = first[4:]
    if first.lower().startswith("\\systemroot\\"):
        first = os.path.join(WINDIR, first[12:])
    elif first.lower().startswith("system32\\"):
        first = os.path.join(WINDIR, first)
    return first


SUSPICIOUS_CMD = [
    (re.compile(r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I), "Gizlenmiş (base64) PowerShell komutu"),
    (re.compile(r"-w(indowstyle)?\s+h(idden)?", re.I), "Gizli pencereyle PowerShell"),
    (re.compile(r"\b(iex|invoke-expression)\b.*(downloadstring|webclient|invoke-webrequest|irm|iwr)", re.I), "İnternetten kod indirip çalıştırıyor"),
    (re.compile(r"\bmshta(\.exe)?\s+(https?:|vbscript:|javascript:)", re.I), "mshta ile uzaktan betik"),
    (re.compile(r"\bcertutil(\.exe)?\b.*-(decode|urlcache)", re.I), "certutil ile indirme/çözme"),
    (re.compile(r"\bbitsadmin(\.exe)?\b.*/transfer", re.I), "bitsadmin ile indirme"),
    (re.compile(r"\bregsvr32(\.exe)?\b.*/i:https?", re.I), "regsvr32 ile uzaktan betik (Squiblydoo)"),
    (re.compile(r"\brundll32(\.exe)?\s+[^,]*\\(appdata|temp|programdata|users\\public)\\", re.I), "Kullanıcı klasöründen rundll32"),
    (re.compile(r"\b(wscript|cscript)(\.exe)?\b.*\\(appdata|temp|programdata|users\\public)\\", re.I), "Kullanıcı klasöründen betik"),
    (re.compile(r"\bvssadmin\b.*delete\s+shadows|\bwmic\b.*shadowcopy\s+delete|\bbcdedit\b.*recoveryenabled\s+no", re.I), "Yedekleri silen komut (fidye yazılımı belirtisi)"),
]

MASQUERADE = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
              "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "explorer.exe", "rundll32.exe",
              "lsm.exe", "dwm.exe", "ctfmon.exe", "sihost.exe", "runtimebroker.exe", "searchindexer.exe", "taskmgr.exe"}


def finding(kind, level, title, why, path="", target=None, actions=None, extra=None):
    f = {"id": f"{kind}:{core.norm(path) or title}"[:300], "kind": kind, "level": level, "title": title, "why": why,
         "path": path, "target": target or {}, "actions": actions or [], "hits": []}
    if extra:
        f.update(extra)
    return f


def assess_file(path, origin, sigcache=None):
    """Bir kalıcılık noktasının hedef dosyasını sezgisel olarak değerlendirir: (seviye, nedenler, imza)."""
    reasons = []
    if not path or not os.path.isfile(path):
        return None, [], {}
    sig = engines.SIG.check(path) if path.lower().endswith((".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl")) else {}
    name = os.path.basename(path).lower()
    p = core.norm(path)
    if name in MASQUERADE and not (p.startswith(SYS32 + "\\") or p.startswith(SYSWOW + "\\") or p == core.norm(os.path.join(WINDIR, "explorer.exe"))):
        reasons.append(f"Windows dosyası adını ({name}) taşıyor ama {os.path.dirname(path)} klasöründe")
    if sig and not sig.get("valid") and in_user_writable(path):
        reasons.append("İmzasız ve kullanıcı klasöründen başlıyor")
    if sig and sig.get("status") in ("HashMismatch", "NotTrusted"):
        reasons.append("İmzası bozuk ya da güvenilmeyen bir sertifikayla")
    if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|com)$", name):
        reasons.append("Çift uzantı (belge gibi görünen program)")
    level = None
    if reasons:
        level = "tehdit" if any("Windows dosyası" in r for r in reasons) else "supheli"
    return level, reasons, sig


# ---------------------------------------------------------------- kalıcılık noktaları

RUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
]
HIVE_NAME = {winreg.HKEY_LOCAL_MACHINE: "HKLM", winreg.HKEY_CURRENT_USER: "HKCU"}


def reg_values(hive, path):
    out = []
    try:
        with winreg.OpenKey(hive, path) as k:
            i = 0
            while True:
                try:
                    name, val, typ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out.append((name, val, typ))
                i += 1
    except OSError:
        pass
    return out


def reg_get(hive, path, name, default=None):
    try:
        with winreg.OpenKey(hive, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


def autoruns():
    """Bilgisayar açılınca çalışan her şey: [{type, name, location, command, path}]"""
    items = []
    for hive, path in RUN_KEYS:
        for name, val, _ in reg_values(hive, path):
            if isinstance(val, str):
                items.append({"type": "registry", "name": name or "(Varsayılan)", "location": f"{HIVE_NAME[hive]}\\{path}",
                              "command": val, "path": command_target(val), "hive": HIVE_NAME[hive], "key": path, "value": name})
    wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    for vname, normal in (("Shell", "explorer.exe"), ("Userinit", r"c:\windows\system32\userinit.exe,")):
        v = reg_get(winreg.HKEY_LOCAL_MACHINE, wl, vname)
        if v and v.strip().lower() not in (normal, normal.rstrip(","), "explorer.exe,") :
            items.append({"type": "winlogon", "name": vname, "location": f"HKLM\\{wl}", "command": v,
                          "path": command_target(v.split(",")[-2] if vname == "Userinit" and v.count(",") > 1 else v),
                          "hive": "HKLM", "key": wl, "value": vname, "unusual": True})
    v = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs")
    if v and v.strip():
        items.append({"type": "appinit", "name": "AppInit_DLLs", "location": "HKLM\\...\\Windows", "command": v,
                      "path": command_target(v.split(",")[0]), "unusual": True})
    ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo) as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                dbg = reg_get(winreg.HKEY_LOCAL_MACHINE, ifeo + "\\" + sub, "Debugger")
                if dbg:
                    items.append({"type": "ifeo", "name": sub, "location": f"HKLM\\{ifeo}\\{sub}", "command": dbg,
                                  "path": command_target(dbg), "hive": "HKLM", "key": ifeo + "\\" + sub, "value": "Debugger",
                                  "unusual": True})
    except OSError:
        pass
    for folder in (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")):
        for f in glob.glob(os.path.join(folder, "*")):
            if f.lower().endswith("desktop.ini"):
                continue
            target = f
            if f.lower().endswith(".lnk"):
                target = lnk_target(f) or f
            items.append({"type": "startup", "name": os.path.basename(f), "location": folder, "command": target,
                          "path": target, "file": f})
    items += scheduled_tasks()
    items += services()
    items += wmi_persistence()
    return items


def lnk_target(lnk):
    try:
        import win32com.client
        sh = win32com.client.Dispatch("WScript.Shell")
        sc = sh.CreateShortcut(lnk)
        return (sc.TargetPath + (" " + sc.Arguments if sc.Arguments else "")).strip()
    except Exception:
        return ""


def scheduled_tasks():
    items = []
    try:
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        svc = win32com.client.Dispatch("Schedule.Service")
        svc.Connect()
        stack = [svc.GetFolder("\\")]
        while stack:
            folder = stack.pop()
            try:
                for sub in folder.GetFolders(0):
                    stack.append(sub)
            except Exception:
                pass
            try:
                tasks = folder.GetTasks(1)   # gizli görevler dahil
            except Exception:
                continue
            for t in tasks:
                try:
                    defn = t.Definition
                    for a in defn.Actions:
                        if a.Type != 0:   # yalnız "program çalıştır"
                            continue
                        cmd = f'"{a.Path}" {a.Arguments or ""}'.strip()
                        items.append({"type": "task", "name": t.Name, "location": folder.Path, "command": cmd,
                                      "path": command_target(a.Path), "task": t.Path, "enabled": bool(t.Enabled),
                                      "hidden": bool(defn.Settings.Hidden), "author": defn.RegistrationInfo.Author or ""})
                except Exception:
                    continue
    except Exception as e:
        core.log_error("scheduled_tasks", e)
    return items


def services():
    items = []
    base = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                path = base + "\\" + name
                img = reg_get(winreg.HKEY_LOCAL_MACHINE, path, "ImagePath")
                typ = reg_get(winreg.HKEY_LOCAL_MACHINE, path, "Type", 0) or 0
                start = reg_get(winreg.HKEY_LOCAL_MACHINE, path, "Start", 4)
                if not img or start == 4:
                    continue
                kind = "driver" if typ in (1, 2) else "service" if typ & 0x30 else None
                if not kind:
                    continue
                if typ & 0x30 and "svchost.exe" in img.lower():
                    dll = reg_get(winreg.HKEY_LOCAL_MACHINE, path + "\\Parameters", "ServiceDll") or img
                    target = expand(dll)
                else:
                    target = command_target(img)
                items.append({"type": kind, "name": name, "location": f"HKLM\\{path}", "command": img, "path": target,
                              "display": reg_get(winreg.HKEY_LOCAL_MACHINE, path, "DisplayName", name), "start": start,
                              "service": name})
    except OSError:
        pass
    return items


def wmi_persistence():
    items = []
    try:
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        w = win32com.client.GetObject("winmgmts:\\\\.\\root\\subscription")
        for cls in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
            for c in w.ExecQuery(f"select * from {cls}"):
                cmd = getattr(c, "CommandLineTemplate", None) or getattr(c, "ScriptText", None) or getattr(c, "ScriptFileName", "") or ""
                if c.Name == "SCM Event Log Consumer":
                    continue
                items.append({"type": "wmi", "name": c.Name, "location": f"root\\subscription\\{cls}", "command": cmd[:500],
                              "path": command_target(cmd) if cls == "CommandLineEventConsumer" else "", "wmi_class": cls,
                              "unusual": True})
    except Exception:
        pass
    return items


def judge_autorun(it):
    """Bir kalıcılık noktasını değerlendirir; sorun yoksa None."""
    path = it.get("path") or ""
    cmd = it.get("command") or ""
    reasons, level = [], None
    for rx, why in SUSPICIOUS_CMD:
        if rx.search(cmd):
            reasons.append(why)
            level = "tehdit" if "fidye" in why or "İnternetten" in why else "supheli"
    if it.get("type") == "service":
        # Microsoft imzalı Windows servislerini atla (hız).
        if core.norm(path).startswith(SYS32 + "\\") and not reasons:
            return None
    if it.get("type") == "task" and core.norm(path).startswith(SYS32 + "\\") and not reasons and \
            not re.search(r"(powershell|mshta|wscript|cscript|rundll32|regsvr32|cmd)\.exe", path, re.I):
        return None
    flevel, freasons, sig = assess_file(path, it.get("type"))
    reasons += freasons
    if flevel and (not level or engines.LEVEL_RANK.get(flevel, 0) > engines.LEVEL_RANK.get(level, 0)):
        level = flevel
    if it.get("type") == "task" and it.get("hidden") and (in_user_writable(path) or reasons) \
            and not (sig and engines.trusted_signer(sig) and not reasons):
        reasons.append("Gizli zamanlanmış görev")
        level = level or "supheli"
    if it.get("type") == "task" and re.search(r"(onedrive|google|microsoft|update|chrome|edge|adobe)", it.get("name", ""), re.I) \
            and in_user_writable(path) and sig and not sig.get("valid"):
        reasons.append("Tanınmış bir uygulamanın adını taşıyor ama imzasız ve kullanıcı klasöründe")
        level = "supheli" if level != "tehdit" else level
    if it.get("type") in ("ifeo", "appinit", "winlogon"):
        reasons.append({"ifeo": f"{it.get('name')} açılınca onun yerine {os.path.basename(path) or it.get('command')} çalışıyor (IFEO Debugger yönlendirmesi)",
                        "appinit": "Her programa DLL enjekte eden AppInit_DLLs ayarı dolu",
                        "winlogon": "Windows oturum açma kabuğu değiştirilmiş"}[it["type"]])
        level = level or "supheli"
        if it.get("type") == "ifeo" and re.search(r"(mpcmdrun|msmpeng|mpuxsrv|securityhealth|smartscreen|mrt|taskmgr|"
                                                    r"procexp|autoruns|regedit|mbam|kalkan|avp|ekrn|bdagent)", it.get("name", ""), re.I):
            reasons.append("Bir güvenlik ya da sistem aracı bu yolla çalışamaz hale getirilmiş; zararlıların korumayı kapatma yöntemidir")
            level = "tehdit"
    if it.get("type") == "wmi":
        reasons.append("WMI olay aboneliği: gizli kalıcılık için sık kullanılır")
        level = level or "supheli"
    if not reasons:
        return None
    return level or "supheli", reasons, sig


def autorun_findings(job=None, lo=0.0, hi=1.0):
    items = autoruns()
    out = []
    for i, it in enumerate(items):
        if job and i % 10 == 0:
            job.update(lo + (hi - lo) * i / max(1, len(items)), f"Otomatik başlayanlar: {it.get('name')}")
        try:
            j = judge_autorun(it)
        except Exception:
            j = None
        if not j:
            continue
        level, reasons, sig = j
        kind_tr = {"registry": "Başlangıç kaydı", "task": "Zamanlanmış görev", "service": "Servis", "driver": "Sürücü",
                   "startup": "Başlangıç klasörü", "wmi": "WMI aboneliği", "ifeo": "IFEO yönlendirmesi",
                   "appinit": "AppInit_DLLs", "winlogon": "Winlogon"}.get(it["type"], it["type"])
        actions = {"registry": ["remove_autorun"], "task": ["disable_task"], "service": ["disable_service"],
                   "driver": ["disable_service"], "startup": ["quarantine"], "wmi": ["remove_wmi"], "ifeo": ["remove_autorun"],
                   "winlogon": ["info"], "appinit": ["info"]}.get(it["type"], [])
        if it.get("path") and os.path.isfile(it["path"]) and "quarantine" not in actions and not core.norm(it["path"]).startswith(SYS32):
            actions.append("quarantine")
        disp = it.get("display") or it["name"]
        if str(disp).startswith("@") or "%" in str(disp):
            disp = it["name"]
        out.append(finding("autorun", level, f"{kind_tr}: {disp}", "; ".join(reasons),
                           path=it.get("path") or it.get("location"), target=it, actions=actions,
                           extra={"command": it.get("command", "")[:400], "signer": (sig or {}).get("signer", "")}))
    return out, items


# ---------------------------------------------------------------- sürücüler ve LOLDrivers

LOL_FILE = os.path.join(ENGINE_DIR, "loldrivers.json")


def update_loldrivers(job=None):
    tmp = os.path.join(ENGINE_DIR, "drivers_full.json")
    core.download("https://www.loldrivers.io/api/drivers.json", tmp, timeout=120)
    with open(tmp, encoding="utf-8") as f:
        data = json.load(f)
    hashes = {}
    for d in data:
        cat = d.get("Category", "")
        for s in d.get("KnownVulnerableSamples") or []:
            h = (s.get("SHA256") or "").lower()
            if h:
                hashes[h] = {"name": s.get("Filename") or (d.get("Tags") or ["?"])[0], "category": cat}
    core.write_json(LOL_FILE, {"time": time.time(), "hashes": hashes})
    os.remove(tmp)
    return len(hashes)


_lol = None


def loldrivers():
    global _lol
    if _lol is None:
        _lol = core.read_json(LOL_FILE, {}).get("hashes", {})
    return _lol


def loaded_drivers():
    psapi = ctypes.WinDLL("psapi")
    arr = (ctypes.c_void_p * 2048)()
    needed = wt.DWORD()
    if not psapi.EnumDeviceDrivers(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed)):
        return []
    out = []
    psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
    for i in range(needed.value // ctypes.sizeof(ctypes.c_void_p)):
        buf = ctypes.create_unicode_buffer(520)
        if arr[i] and psapi.GetDeviceDriverFileNameW(arr[i], buf, 520):
            p = buf.value
            if p.startswith("\\SystemRoot\\"):
                p = os.path.join(WINDIR, p[12:])
            elif p.startswith("\\??\\"):
                p = p[4:]
            out.append(p)
    return out


def driver_findings(service_items, job=None):
    lol = loldrivers()
    paths = set(loaded_drivers())
    paths |= {it["path"] for it in service_items if it.get("type") == "driver" and it.get("path")}
    out = []
    for p in sorted(paths):
        if not os.path.isfile(p):
            continue
        try:
            h = core.sha256_file(p)
        except OSError:
            continue
        if h in lol:
            info = lol[h]
            level = "tehdit" if "malicious" in info["category"].lower() else "supheli"
            out.append(finding("driver", level, f"Zafiyetli sürücü: {os.path.basename(p)}",
                               "LOLDrivers listesinde: saldırganlar bu sürücüyle korumaları kapatabilir"
                               + (" (zararlı olarak bilinen sürücü)" if level == "tehdit" else ""),
                               path=p, actions=["disable_service"],
                               target={"service": next((it["service"] for it in service_items if it.get("type") == "driver"
                                                        and core.norm(it.get("path")) == core.norm(p)), None)}))
        else:
            if core.norm(p).startswith(SYS32 + "\\"):
                continue    # Windows'un kendi sürücüleri katalogla imzalı; tek tek denetlemek yanlış alarm üretir
            sig = engines.SIG.check(p)
            if sig.get("status") not in ("Valid", "Error", "UnknownError") and not sig.get("os"):
                out.append(finding("driver", "supheli", f"İmzasız sürücü: {os.path.basename(p)}",
                                   "Çekirdekte çalışan bir sürücünün geçerli imzası yok", path=p, actions=["info"]))
    return out


# ---------------------------------------------------------------- çalışan süreçler

def process_findings(job=None):
    out = []
    snap = core.process_snapshot()
    try:
        import psutil
    except ImportError:
        psutil = None
    seen = set()
    for pid, (ppid, name, _, _) in snap.items():
        if pid <= 4:
            continue
        path = core.process_path(pid)
        if not path or core.norm(path) in seen:
            continue
        seen.add(core.norm(path))
        if core.is_excluded(path):
            continue
        level, reasons, sig = assess_file(path, "process")
        cmd = ""
        if psutil and (level or name.lower() in ("powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe",
                                                   "rundll32.exe", "regsvr32.exe", "cmd.exe")):
            try:
                cmd = " ".join(psutil.Process(pid).cmdline())
            except Exception:
                cmd = ""
            for rx, why in SUSPICIOUS_CMD:
                if rx.search(cmd):
                    reasons.append(why)
                    level = "supheli" if level != "tehdit" else level
        parent = snap.get(ppid, (0, ""))[1].lower()
        if name.lower() in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe") and \
                parent in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "msaccess.exe"):
            reasons.append(f"{parent} bir komut kabuğu başlatmış (makro saldırısı belirtisi)")
            level = "tehdit"
        if reasons:
            out.append(finding("process", level or "supheli", f"Çalışan süreç: {name}", "; ".join(reasons), path=path,
                               target={"pid": pid}, actions=["kill", "quarantine"],
                               extra={"command": cmd[:400], "signer": (sig or {}).get("signer", "")}))
    return out


# ---------------------------------------------------------------- hosts, DNS, proxy, tarayıcı politikaları

KNOWN_DNS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google", "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS", "94.140.14.14": "AdGuard",
    "94.140.15.15": "AdGuard", "195.175.39.39": "Türk Telekom", "195.175.39.40": "Türk Telekom",
    "212.156.4.1": "Türk Telekom", "212.156.4.20": "Türk Telekom", "193.192.98.8": "TurkNet", "193.192.98.9": "TurkNet",
    "212.252.114.8": "Turkcell Superonline", "212.252.114.9": "Turkcell Superonline", "195.87.122.10": "Vodafone",
    "100.100.100.100": "Tailscale", "77.88.8.8": "Yandex", "76.76.2.0": "Control D", "45.90.28.0": "NextDNS",
}
SENSITIVE_DOMAINS = re.compile(r"(google|microsoft|windowsupdate|live\.com|bing|facebook|instagram|apple|paypal|"
                               r"turkiye\.gov\.tr|edevlet|ziraat|isbank|garanti|akbank|yapikredi|halkbank|vakifbank|"
                               r"qnb|denizbank|enpara|ing\.com|teb\.com|kuveytturk|papara|trendyol|hepsiburada|"
                               r"defender|kaspersky|eset|avast|avg|bitdefender|malwarebytes|norton|mcafee|virustotal)", re.I)


def hosts_findings():
    out = []
    path = os.path.join(WINDIR, r"System32\drivers\etc\hosts")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    bad = []
    for ln in lines:
        s = ln.split("#", 1)[0].strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        if ip in ("0.0.0.0", "127.0.0.1", "::1", "::", "0:0:0:0:0:0:0:0") and not any(SENSITIVE_DOMAINS.search(n) and
                                                                                       re.search(r"(defender|update|kaspersky|eset|avast|bitdefender|malwarebytes|virustotal)", n, re.I) for n in names):
            continue
        for n in names:
            if SENSITIVE_DOMAINS.search(n):
                bad.append((ip, n, ln))
    if bad:
        out.append(finding("hosts", "tehdit" if any(not b[0].startswith(("127.", "0.0.0.0", "::")) for b in bad) else "supheli",
                           "Hosts dosyası önemli siteleri yönlendiriyor",
                           "; ".join(f"{n} → {ip}" for ip, n, _ in bad[:6]) + (" …" if len(bad) > 6 else ""),
                           path=path, target={"lines": [b[2] for b in bad]}, actions=["fix_hosts"]))
    return out


def adapter_dns():
    """Etkin bağdaştırıcılar ve DNS sunucuları."""
    data = core.ps_json("Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } | "
                        "Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses", timeout=60) or []
    return core.as_list(data)


def dns_findings():
    out = []
    for a in adapter_dns():
        for ip in core.as_list(a.get("ServerAddresses")):
            try:
                addr = ipaddress.ip_address(ip.split("%")[0])
            except ValueError:
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local or ip in KNOWN_DNS:
                continue
            if str(addr).startswith(("fec0:", "fe80:")):
                continue
            out.append(finding("dns", "supheli", f"Bilinmeyen DNS sunucusu: {ip}",
                               f"'{a.get('InterfaceAlias')}' bağlantısı tanınmayan bir DNS sunucusu kullanıyor. "
                               "Kendin ya da internet sağlayıcın ayarlamadıysa trafiğin yönlendiriliyor olabilir.",
                               path=a.get("InterfaceAlias", ""), target={"index": a.get("InterfaceIndex"), "ip": ip},
                               actions=["reset_dns"]))
    return out


def proxy_findings():
    out = []
    key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    enabled = reg_get(winreg.HKEY_CURRENT_USER, key, "ProxyEnable", 0)
    server = reg_get(winreg.HKEY_CURRENT_USER, key, "ProxyServer", "")
    pac = reg_get(winreg.HKEY_CURRENT_USER, key, "AutoConfigURL", "")
    if enabled and server and not re.match(r"^(127\.0\.0\.1|localhost)", server):
        out.append(finding("proxy", "supheli", f"Sistem proxy'si açık: {server}",
                           "Tüm internet trafiğin bu sunucudan geçiyor. Sen ya da şirketin ayarlamadıysa kaldır.",
                           path=server, actions=["reset_proxy"]))
    if pac:
        out.append(finding("proxy", "supheli", "Otomatik proxy betiği (PAC) ayarlı",
                           f"Trafik {pac} betiğinin söylediği yere gidiyor. Tanımıyorsan kaldır.", path=pac,
                           actions=["reset_proxy"]))
    code, txt = core.run(["netsh", "winhttp", "show", "proxy"], timeout=20)
    m = re.search(r"Proxy Server\(s\)\s*:\s*(\S+)", txt)
    if m:
        out.append(finding("proxy", "supheli", f"WinHTTP proxy'si açık: {m.group(1)}",
                           "Windows servislerinin trafiği bu sunucudan geçiyor.", path=m.group(1), actions=["reset_proxy"]))
    return out


BROWSER_POLICIES = [
    (r"SOFTWARE\Policies\Google\Chrome", "Chrome"), (r"SOFTWARE\Policies\Microsoft\Edge", "Edge"),
    (r"SOFTWARE\Policies\BraveSoftware\Brave", "Brave"),
]


def policy_findings():
    out = []
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for path, browser in BROWSER_POLICIES:
            vals = {n: v for n, v, _ in reg_values(hive, path)}
            forced = [v for _, v, _ in reg_values(hive, path + r"\ExtensionInstallForcelist")]
            for name in ("DefaultSearchProviderSearchURL", "HomepageLocation", "ProxyServer", "ProxyPacUrl", "NewTabPageLocation"):
                if vals.get(name):
                    out.append(finding("policy", "istenmeyen", f"{browser}: '{name}' politikayla zorlanmış",
                                       f"Değer: {str(vals[name])[:120]}. Reklam yazılımları arama motorunu ve ana sayfayı böyle kilitler.",
                                       path=f"{HIVE_NAME[hive]}\\{path}", target={"hive": HIVE_NAME[hive], "key": path, "value": name},
                                       actions=["remove_policy"]))
            for v in forced:
                ext_id = str(v).split(";")[0]
                out.append(finding("policy", "supheli", f"{browser}: zorla kurulan eklenti ({ext_id})",
                                   "Bir eklenti politikayla zorla kuruluyor; kullanıcı kaldıramaz. Şirket bilgisayarı değilse şüpheli.",
                                   path=f"{HIVE_NAME[hive]}\\{path}\\ExtensionInstallForcelist",
                                   target={"hive": HIVE_NAME[hive], "key": path + r"\ExtensionInstallForcelist", "data": v},
                                   actions=["remove_policy"]))
    return out


# ---------------------------------------------------------------- tarayıcı eklentileri

BROWSER_DIRS = {
    "Chrome": os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Google\Chrome\User Data"),
    "Edge": os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Edge\User Data"),
    "Brave": os.path.join(os.environ.get("LOCALAPPDATA", ""), r"BraveSoftware\Brave-Browser\User Data"),
    "Opera": os.path.join(os.environ.get("APPDATA", ""), r"Opera Software\Opera Stable"),
}
STORE_UPDATE = ("clients2.google.com", "edge.microsoft.com", "extension-updates.opera.com")
RISKY_PERMS = {"<all_urls>", "http://*/*", "https://*/*", "*://*/*", "webRequest", "webRequestBlocking", "proxy",
               "nativeMessaging", "debugger", "cookies", "management", "declarativeNetRequest"}
ADWARE_NAMES = re.compile(r"(pdf ?convert|search ?(bar|tool|manager|protect)|coupon|shopping ?assist|weather ?(tab|now)|"
                          r"maps? ?(tab|now)|video ?download(er)? ?(pro|plus)|speed ?test ?(tab|pro)|safe ?search|"
                          r"new ?tab ?(theme|page) ?(pro|plus)|movie ?tab|package ?track(er|ing) ?tab)", re.I)


def _ext_name(manifest, ext_dir):
    name = manifest.get("name", "")
    if name.startswith("__MSG_"):
        key = name[6:-2]
        for loc in (manifest.get("default_locale", "en"), "en", "tr"):
            try:
                with open(os.path.join(ext_dir, "_locales", loc, "messages.json"), encoding="utf-8-sig") as f:
                    msgs = json.load(f)
                for k, v in msgs.items():
                    if k.lower() == key.lower():
                        return v.get("message", name)
            except (OSError, ValueError):
                continue
    return name


def browser_extensions():
    out = []
    for browser, root in BROWSER_DIRS.items():
        if not os.path.isdir(root):
            continue
        profiles = [root] if browser == "Opera" else [p for p in glob.glob(os.path.join(root, "*"))
                                                       if os.path.isdir(os.path.join(p, "Extensions"))]
        for prof in profiles:
            for ext_root in glob.glob(os.path.join(prof, "Extensions", "*")):
                versions = sorted(glob.glob(os.path.join(ext_root, "*")))
                if not versions:
                    continue
                mpath = os.path.join(versions[-1], "manifest.json")
                try:
                    with open(mpath, encoding="utf-8-sig") as f:
                        m = json.load(f)
                except (OSError, ValueError):
                    continue
                perms = set(m.get("permissions", [])) | set(m.get("host_permissions", []))
                for cs in m.get("content_scripts", []) or []:
                    perms |= set(cs.get("matches", []))
                out.append({"browser": browser, "profile": os.path.basename(prof), "id": os.path.basename(ext_root),
                            "name": _ext_name(m, versions[-1]), "version": m.get("version", ""),
                            "store": any(s in (m.get("update_url") or "") for s in STORE_UPDATE),
                            "risky": sorted(perms & RISKY_PERMS), "dir": ext_root})
    return out


def extension_findings():
    out = []
    for e in browser_extensions():
        reasons, level = [], None
        if ADWARE_NAMES.search(e["name"]):
            reasons.append("Adı reklam yazılımı eklentilerine benziyor")
            level = "istenmeyen"
        if not e["store"] and e["id"] not in ("nmmhkkegccagdldgiimedpiccmgmieda", "ghbmnnjooekpmoecnnnilnnbdlolhkhi") and \
                not e["name"].startswith("Kalkan"):
            reasons.append("Mağaza dışından kurulmuş")
            level = level or "supheli"
        if reasons and e["risky"]:
            reasons.append("Tüm sitelerde okuma/değiştirme izni var")
        if reasons:
            out.append(finding("extension", level, f"{e['browser']} eklentisi: {e['name']}", "; ".join(reasons),
                               path=e["dir"], target=e, actions=["open_extensions"]))
    return out


def network_settings_findings():
    out = []
    for fn in (hosts_findings, dns_findings, proxy_findings, policy_findings):
        try:
            out += fn()
        except Exception as e:
            core.log_error(fn.__name__, e)
    return out
