"""Kalkan çekirdeği: yollar, ayarlar, olay geçmişi, arka plan işleri, Windows yardımcıları."""
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import uuid

APP_NAME = "Kalkan"
VERSION = "1.0.1"
DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), APP_NAME)
ENGINE_DIR = os.path.join(DATA_DIR, "motorlar")
QUAR_DIR = os.path.join(DATA_DIR, "karantina")
VAULT_DIR = os.path.join(DATA_DIR, "kasa")
USER_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), APP_NAME)
FROZEN = getattr(sys, "frozen", False)
APP_DIR = os.path.dirname(sys.executable) if FROZEN else os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(getattr(sys, "_MEIPASS", APP_DIR), "static")
HOME = os.path.expanduser("~")
NO_WINDOW = 0x08000000

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
user32 = ctypes.WinDLL("user32", use_last_error=True)


class UserError(Exception):
    """Kullanıcıya olduğu gibi gösterilecek hata."""


def ensure_dirs():
    for d in (DATA_DIR, ENGINE_DIR, QUAR_DIR, VAULT_DIR, USER_DIR):
        os.makedirs(d, exist_ok=True)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def log_error(where, e=None):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(os.path.join(DATA_DIR, "hata.log"), "a", encoding="utf-8") as f:
            f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {where}\n{traceback.format_exc() if e else ''}")
    except OSError:
        pass


def friendly_error(e):
    if isinstance(e, UserError):
        return str(e)
    if "anthropic" in sys.modules:
        try:
            import anthropic
            if isinstance(e, anthropic.AuthenticationError):
                return "Claude API anahtarı geçersiz. Ayarlar'dan anahtarını kontrol et."
            if isinstance(e, anthropic.PermissionDeniedError):
                return "API anahtarının bu işleme izni yok."
            if isinstance(e, anthropic.RateLimitError):
                return "Claude şu an çok yoğun ya da kullanım sınırına ulaşıldı. Biraz sonra tekrar dene."
            if isinstance(e, anthropic.BadRequestError):
                msg = getattr(e, "message", str(e))
                if "credit" in msg.lower() or "balance" in msg.lower():
                    return "API hesabında kredi kalmamış. console.anthropic.com'dan bakiye ekle."
                return f"Claude isteği kabul etmedi: {msg[:300]}"
            if isinstance(e, anthropic.APIConnectionError):
                return "Claude'a bağlanılamadı. İnternet bağlantını kontrol et."
            if isinstance(e, anthropic.APIStatusError):
                return f"Claude sunucu hatası ({e.status_code}). Biraz sonra tekrar dene."
        except ImportError:
            pass
    if isinstance(e, PermissionError):
        return "Bu işlem için yetki yok. Kalkan yönetici olarak çalışmıyor olabilir."
    return f"Beklenmeyen hata: {type(e).__name__}: {str(e)[:300]}"


# ---------------------------------------------------------------- ayarlar

DEFAULTS = {
    "realtime": {"processes": True, "downloads": True, "usb": True, "quiet_auto": True},
    "ransom": {"canaries": True, "burst": True, "snapshots": True, "vault": True},
    "vault_folders": [],
    "vault_limit_gb": 20,
    "web": {"dns": False, "ads": False, "upstream": "auto"},
    "dns_allow": [],
    "quiet": False,
    "schedule": {"quick": True, "quick_hour": 13, "deep": True, "deep_day": 6, "idle_only": True},
    "engines": {"clamav": True, "yara": True, "bazaar": True, "virustotal": True, "clamav_resident": False},
    "exclusions": [],
    "trusted_hashes": [],
    "profile_ai": True,
}
_settings_lock = threading.Lock()
_settings = None


def settings():
    global _settings
    with _settings_lock:
        if _settings is None:
            _settings = json.loads(json.dumps(DEFAULTS))
            try:
                with open(os.path.join(DATA_DIR, "ayarlar.json"), encoding="utf-8") as f:
                    saved = json.load(f)
                for k, v in saved.items():
                    if isinstance(v, dict) and isinstance(_settings.get(k), dict):
                        _settings[k].update(v)
                    else:
                        _settings[k] = v
            except (OSError, ValueError):
                pass
        return _settings


def save_settings(patch=None):
    s = settings()
    with _settings_lock:
        for k, v in (patch or {}).items():
            if isinstance(v, dict) and isinstance(s.get(k), dict):
                s[k].update(v)
            else:
                s[k] = v
        tmp = os.path.join(DATA_DIR, "ayarlar.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=1)
        os.replace(tmp, os.path.join(DATA_DIR, "ayarlar.json"))
    return s


def state_file(name):
    return os.path.join(DATA_DIR, name)


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


# ---------------------------------------------------------------- olay geçmişi

_db_lock = threading.Lock()
_db = None


def db():
    global _db
    if _db is None:
        _db = sqlite3.connect(os.path.join(DATA_DIR, "gecmis.db"), check_same_thread=False)
        _db.execute("create table if not exists olay (id integer primary key, zaman real, tur text, seviye text,"
                    " baslik text, ayrinti text)")
        _db.execute("create index if not exists olay_zaman on olay(zaman)")
        _db.commit()
    return _db


def event(kind, level, title, detail=None):
    """Geçmişe bir satır ekler. level: tehdit | supheli | istenmeyen | bilgi | iyi"""
    try:
        with _db_lock:
            c = db()
            c.execute("insert into olay(zaman, tur, seviye, baslik, ayrinti) values (?,?,?,?,?)",
                      (time.time(), kind, level, title, json.dumps(detail or {}, ensure_ascii=False)))
            c.execute("delete from olay where zaman < ?", (time.time() - 180 * 86400,))
            c.commit()
    except Exception as e:
        log_error("event", e)


def events(limit=300, kind=None, since=0):
    with _db_lock:
        q = "select id, zaman, tur, seviye, baslik, ayrinti from olay where zaman >= ?"
        args = [since]
        if kind:
            q += " and tur = ?"
            args.append(kind)
        rows = db().execute(q + " order by zaman desc limit ?", args + [limit]).fetchall()
    return [{"id": r[0], "time": r[1], "kind": r[2], "level": r[3], "title": r[4], "detail": json.loads(r[5] or "{}")}
            for r in rows]


def count_events(kind, since, level=None):
    with _db_lock:
        q, args = "select count(*) from olay where tur = ? and zaman >= ?", [kind, since]
        if level:
            q += " and seviye = ?"
            args.append(level)
        return db().execute(q, args).fetchone()[0]


# ---------------------------------------------------------------- arka plan işleri

class Cancelled(Exception):
    pass


class Job:
    def __init__(self, kind, title=""):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.title = title
        self.progress = 0.0
        self.message = ""
        self.status = "running"
        self.result = None
        self.error = None
        self.cancelled = False
        self.paused = False
        self.started = time.time()
        self.finished = None

    def update(self, progress=None, message=None):
        while self.paused and not self.cancelled:
            time.sleep(0.3)
        if self.cancelled:
            raise Cancelled()
        if progress is not None:
            self.progress = max(0.0, min(1.0, progress))
        if message is not None:
            self.message = message

    def public(self):
        return {"id": self.id, "kind": self.kind, "title": self.title, "progress": round(self.progress, 4),
                "message": self.message, "status": "paused" if self.paused and self.status == "running" else self.status,
                "result": self.result, "error": self.error, "started": self.started, "finished": self.finished}


JOBS = {}


def start_job(kind, fn, *args, title=""):
    job = Job(kind, title)
    JOBS[job.id] = job

    def run():
        try:
            job.result = fn(job, *args)
            job.status = "done"
        except Cancelled:
            job.status = "cancelled"
        except Exception as e:
            job.status = "error"
            job.error = friendly_error(e)
            if not isinstance(e, UserError):
                log_error(f"job {kind}", e)
        job.finished = time.time()
        job.progress = 1.0 if job.status == "done" else job.progress
        for jid in [j for j, v in JOBS.items() if v.finished and time.time() - v.finished > 3600]:
            JOBS.pop(jid, None)

    threading.Thread(target=run, daemon=True, name=f"job-{kind}").start()
    return job


def running_job(kind):
    return next((j for j in JOBS.values() if j.kind == kind and j.status == "running"), None)


# ---------------------------------------------------------------- komut çalıştırma

def run(args, timeout=120, input_text=None):
    """Gizli pencereyle bir komut çalıştırır; (çıkış kodu, metin) döner."""
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW,
                           input=input_text.encode("utf-8") if input_text is not None else None)
    except subprocess.TimeoutExpired:
        return -1, "zaman aşımı"
    except OSError as e:
        return -1, str(e)
    out = p.stdout or b""
    for enc in ("utf-8", "cp857", "cp1254"):
        try:
            text = out.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = out.decode("utf-8", "replace")
    if p.returncode and p.stderr:
        text += "\n" + p.stderr.decode("utf-8", "replace")
    return p.returncode, text


def ps(script, timeout=120):
    """PowerShell betiği çalıştırır, çıktıyı metin olarak döner."""
    wrapped = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; " + script
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", wrapped],
               timeout=timeout)


def ps_json(script, timeout=120, default=None):
    """PowerShell çıktısını ConvertTo-Json ile alır. Tek nesne listeye çevrilmez."""
    code, out = ps(f"$r = & {{ {script} }}; if ($null -ne $r) {{ $r | ConvertTo-Json -Depth 6 -Compress }}", timeout)
    out = out.strip()
    try:
        return json.loads(out) if out else default
    except ValueError:
        pass
    starts = [i for i in (out.find("["), out.find("{")) if i >= 0]
    if not starts:
        return default
    try:
        return json.loads(out[min(starts):].strip())
    except ValueError:
        return default


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ---------------------------------------------------------------- dosyalar

def sha256_file(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        n = 0
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
            n += len(b)
            if limit and n >= limit:
                break
    return h.hexdigest()


def download(url, dest, job=None, label="İndiriliyor", lo=0.0, hi=1.0, timeout=60):
    """Dosyayı geçici adla indirir, bitince yerine koyar."""
    req = urllib.request.Request(url, headers={"User-Agent": f"Kalkan/{VERSION}"})
    tmp = dest + ".part"
    with urllib.request.urlopen(req, timeout=timeout) as r, open(tmp, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        got = 0
        while True:
            b = r.read(1 << 18)
            if not b:
                break
            f.write(b)
            got += len(b)
            if job:
                frac = got / total if total else 0.5
                job.update(lo + (hi - lo) * frac, f"{label}: {got // (1 << 20)} MB" + (f" / {total // (1 << 20)} MB" if total else ""))
    os.replace(tmp, dest)
    return dest


def http_json(url, data=None, headers=None, timeout=20, method=None):
    body = None
    h = {"User-Agent": f"Kalkan/{VERSION}"}
    h.update(headers or {})
    if isinstance(data, dict) and h.get("Content-Type") == "application/json":
        body = json.dumps(data).encode()
    elif isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace") or "null")


import urllib.parse  # noqa: E402  (http_json için)


def known_folder(name):
    """Kullanıcının asıl klasörleri (OneDrive'a taşınmış olabilir)."""
    ids = {"Desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
           "Pictures": "{33E28130-4E1E-4676-835A-98395C3BC3BB}", "Downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
           "Music": "{4BD8D571-6D19-48D3-BE97-422220080E43}", "Videos": "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}"}

    class GUID(ctypes.Structure):
        _fields_ = [("a", ctypes.c_ulong), ("b", ctypes.c_ushort), ("c", ctypes.c_ushort), ("d", ctypes.c_ubyte * 8)]

    g = GUID()
    ctypes.windll.ole32.CLSIDFromString(ids[name], ctypes.byref(g))
    p = ctypes.c_wchar_p()
    if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(p)) == 0:
        path = p.value
        ctypes.windll.ole32.CoTaskMemFree(p)
        return path
    return os.path.join(HOME, name)


def user_folders():
    return [f for f in (known_folder(n) for n in ("Desktop", "Documents", "Pictures", "Downloads", "Music", "Videos"))
            if f and os.path.isdir(f)]


def norm(path):
    return os.path.normcase(os.path.normpath(path)) if path else ""


def is_excluded(path):
    p = norm(path)
    for ex in settings().get("exclusions", []):
        e = norm(ex)
        if e and (p == e or p.startswith(e.rstrip("\\") + "\\")):
            return True
    return p.startswith(norm(DATA_DIR) + "\\") or p.startswith(norm(APP_DIR) + "\\")


# ---------------------------------------------------------------- süreçler

ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
kernel32.OpenProcess.restype = wt.HANDLE


def process_snapshot():
    """Tek çekirdek çağrısıyla tüm süreçler: {pid: (ppid, ad, yazılan_bayt, oluşturulma_100ns)}."""
    size = ctypes.c_ulong(1 << 20)
    while True:
        buf = ctypes.create_string_buffer(size.value)
        status = ntdll.NtQuerySystemInformation(5, buf, size, ctypes.byref(size)) & 0xFFFFFFFF
        if status != 0xC0000004:
            break
        size.value += 1 << 16
    if status != 0:
        return {}
    base = ctypes.addressof(buf)
    procs, off = {}, 0
    while True:
        a = base + off
        nxt = ctypes.c_ulong.from_address(a).value
        create = ctypes.c_longlong.from_address(a + 32).value
        name_len = ctypes.c_ushort.from_address(a + 56).value
        name_ptr = ctypes.c_void_p.from_address(a + 64).value
        pid = ctypes.c_void_p.from_address(a + 80).value or 0
        ppid = ctypes.c_void_p.from_address(a + 88).value or 0
        write = ctypes.c_longlong.from_address(a + 240).value   # WriteTransferCount
        name = ctypes.wstring_at(name_ptr, name_len // 2) if name_ptr else ""
        procs[pid] = (ppid, name, write, create)
        if not nxt:
            return procs
        off += nxt


def process_path(pid):
    h = kernel32.OpenProcess(0x1000, False, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = wt.DWORD(len(buf))
        return buf.value if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else ""
    finally:
        kernel32.CloseHandle(h)


def suspend_process(pid):
    h = kernel32.OpenProcess(0x0800, False, pid)   # PROCESS_SUSPEND_RESUME
    if not h:
        return False
    try:
        return ntdll.NtSuspendProcess(wt.HANDLE(h)) == 0
    finally:
        kernel32.CloseHandle(h)


def resume_process(pid):
    h = kernel32.OpenProcess(0x0800, False, pid)
    if not h:
        return False
    try:
        return ntdll.NtResumeProcess(wt.HANDLE(h)) == 0
    finally:
        kernel32.CloseHandle(h)


def kill_process(pid):
    h = kernel32.OpenProcess(0x0001, False, pid)   # PROCESS_TERMINATE
    if not h:
        return False
    try:
        return bool(kernel32.TerminateProcess(wt.HANDLE(h), 1))
    finally:
        kernel32.CloseHandle(h)


def kill_by_path(path):
    """Bu dosyadan çalışan tüm süreçleri kapatır."""
    target, n = norm(path), 0
    for pid in list(process_snapshot()):
        if pid > 4 and norm(process_path(pid)) == target and kill_process(pid):
            n += 1
    return n


# ---------------------------------------------------------------- oyun / sessiz mod

class RECT(ctypes.Structure):
    _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long), ("r", ctypes.c_long), ("b", ctypes.c_long)]


class MONITORINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong), ("rcMonitor", RECT), ("rcWork", RECT), ("dwFlags", ctypes.c_ulong)]


user32.GetForegroundWindow.restype = wt.HWND
user32.MonitorFromWindow.restype = wt.HANDLE
user32.GetShellWindow.restype = wt.HWND
user32.GetDesktopWindow.restype = wt.HWND


def fullscreen_app():
    """Ön plandaki pencere tüm ekranı kaplıyorsa (oyun, film, sunum) True."""
    hwnd = user32.GetForegroundWindow()
    if not hwnd or hwnd in (user32.GetShellWindow(), user32.GetDesktopWindow()):
        return False
    cls = ctypes.create_unicode_buffer(64)
    user32.GetClassNameW(hwnd, cls, 64)
    if cls.value in ("Progman", "WorkerW", "Shell_TrayWnd"):
        return False
    r = RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(r)):
        return False
    mi = MONITORINFO()
    mi.cbSize = ctypes.sizeof(MONITORINFO)
    if not user32.GetMonitorInfoW(user32.MonitorFromWindow(hwnd, 2), ctypes.byref(mi)):
        return False
    m = mi.rcMonitor
    return r.l <= m.l and r.t <= m.t and r.r >= m.r and r.b >= m.b


def quiet_now():
    s = settings()
    return bool(s.get("quiet")) or (s["realtime"].get("quiet_auto", True) and fullscreen_app())


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]


def idle_seconds():
    li = LASTINPUTINFO()
    li.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if not user32.GetLastInputInfo(ctypes.byref(li)):
        return 0
    return (kernel32.GetTickCount() - li.dwTime) / 1000.0


# ---------------------------------------------------------------- yetkisiz süreç başlatma

def launch_unelevated(args):
    """Yönetici olarak çalışırken bir programı normal kullanıcı yetkisiyle başlatır (explorer'ın jetonuyla).
    Olmazsa doğrudan başlatır."""
    if not is_admin():
        return subprocess.Popen(args)
    try:
        import win32api
        import win32con
        import win32process
        import win32security
        hwnd = user32.GetShellWindow()
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid.value)
        htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_DUPLICATE)
        dup = win32security.DuplicateTokenEx(htok, win32security.SecurityImpersonation, win32con.MAXIMUM_ALLOWED,
                                             win32security.TokenPrimary)

        class STARTUPINFO(ctypes.Structure):
            _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
                        ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                        ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                        ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                        ("hStdError", wt.HANDLE)]

        class PROCINFO(ctypes.Structure):
            _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(si)
        pi = PROCINFO()
        cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline(args))
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        ok = adv.CreateProcessWithTokenW(wt.HANDLE(int(dup)), 0, None, cmd, 0, None, None, ctypes.byref(si), ctypes.byref(pi))
        if ok:
            kernel32.CloseHandle(pi.hThread)
            kernel32.CloseHandle(pi.hProcess)
            return pi.dwProcessId
    except Exception as e:
        log_error("launch_unelevated", e)
    return subprocess.Popen(args).pid


def find_edge():
    for base in (os.environ.get("PROGRAMFILES(X86)"), os.environ.get("PROGRAMFILES"), os.environ.get("LOCALAPPDATA")):
        if base:
            p = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
            if os.path.isfile(p):
                return p
    return "msedge.exe"


EDGE_FLAGS = ["--no-first-run", "--no-default-browser-check", "--disable-sync", "--disable-background-networking",
              "--disable-features=Translate,msEdgeSidebarV2,msHubApps,msImplicitSignin,msEdgeSyncConsent,"
              "msEdgeSignInFRE,msShowSignInFlyout,msEdgeAutoSignIn,msSignInPromo,SigninInterception", "--lang=tr"]


def window_profile():
    return os.path.join(USER_DIR, "pencere")


def open_app_window(url, size=(1320, 860), position=None, profile=None):
    args = [find_edge(), f"--app={url}", f"--user-data-dir={profile or window_profile()}"] + EDGE_FLAGS
    args.append(f"--window-size={size[0]},{size[1]}")
    if position:
        args.append(f"--window-position={position[0]},{position[1]}")
    return launch_unelevated(args)


def work_area():
    r = RECT()
    user32.SystemParametersInfoW(0x30, 0, ctypes.byref(r), 0)   # SPI_GETWORKAREA
    return r.l, r.t, r.r, r.b
