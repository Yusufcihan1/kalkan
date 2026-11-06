"""Tarama motorları: Defender, ClamAV, YARA-X, MalwareBazaar, VirusTotal; imza denetimi ve dosya özellikleri."""
import io
import json
import math
import os
import re
import socket
import struct
import subprocess
import threading
import time
import zipfile

import keyring

import core
from core import ENGINE_DIR, UserError

KEYRING = "Kalkan"

# Taranmaya değer uzantılar (hızlı tarama ve yerinde koruma). Derin tarama tüm dosyalara bakar.
EXEC_EXT = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".msi", ".msix", ".appx", ".pif", ".efi"}
SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar",
              ".reg", ".inf", ".url", ".chm", ".iso", ".img", ".vhd", ".vhdx"}
DOC_EXT = {".doc", ".docm", ".xls", ".xlsm", ".xlsb", ".ppt", ".pptm", ".rtf", ".pdf", ".one", ".xll", ".docx", ".xlsx"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".cab", ".gz", ".tar", ".xz", ".bz2"}
RISKY_EXT = EXEC_EXT | SCRIPT_EXT | DOC_EXT | ARCHIVE_EXT
MAX_SCAN = 100 * 1024 * 1024


def secret(name):
    try:
        return keyring.get_password(KEYRING, name)
    except Exception:
        return None


def set_secret(name, value):
    if value:
        keyring.set_password(KEYRING, name, value)
    else:
        try:
            keyring.delete_password(KEYRING, name)
        except Exception:
            pass


# ---------------------------------------------------------------- imza denetimi (Authenticode + katalog)

_SIG_SCRIPT = r"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8
while (($l = [Console]::In.ReadLine()) -ne $null) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $l -ErrorAction Stop
    $n = ''; $sub = ''
    if ($s.SignerCertificate) { $n = $s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false); $sub = $s.SignerCertificate.Subject }
    $o = @{s = [string]$s.Status; n = $n; sub = $sub; os = [bool]$s.IsOSBinary}
  } catch { $o = @{s = 'Error'; n = ''; os = $false} }
  [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress)); [Console]::Out.Flush()
}
"""


class SigChecker:
    """Uzun ömürlü bir PowerShell süreci; her satıra bir dosya yolu yazılır, imza bilgisi okunur."""

    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None
        self.cache = {}

    def _start(self):
        self.proc = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _SIG_SCRIPT],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=core.NO_WINDOW,
            encoding="utf-8", errors="replace", bufsize=1)

    def check(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return {"status": "Missing", "signer": "", "os": False, "valid": False}
        key = (core.norm(path), st.st_size, int(st.st_mtime))
        if key in self.cache:
            return self.cache[key]
        with self.lock:
            for attempt in range(2):
                try:
                    if not self.proc or self.proc.poll() is not None:
                        self._start()
                    self.proc.stdin.write(path.replace("\n", " ") + "\n")
                    self.proc.stdin.flush()
                    line = self.proc.stdout.readline()
                    d = json.loads(line)
                    break
                except (OSError, ValueError):
                    self.proc = None
                    d = {"s": "Error", "n": "", "os": False}
        r = {"status": d.get("s", "Error"), "signer": d.get("n") or "", "subject": d.get("sub") or "", "os": bool(d.get("os")),
             "valid": d.get("s") == "Valid"}
        if len(self.cache) > 20000:
            self.cache.clear()
        self.cache[key] = r
        return r


SIG = SigChecker()

TRUSTED_SIGNERS = ("microsoft", "google llc", "mozilla", "apple inc", "adobe", "intel", "nvidia", "advanced micro devices",
                   "asustek", "realtek", "valve", "oracle", "dropbox", "zoom video", "discord", "spotify", "jetbrains",
                   "python software foundation", "github", "docker", "logitech", "dell", "lenovo", "hp inc", "anthropic",
                   "opera norway", "brave software", "electronic arts", "epic games", "riot games", "ubisoft",
                   "tailscale", "ookla", "videolan", "7-zip", "igor pavlov", "notepad++", "win.rar", "malwarebytes")


def trusted_signer(sig):
    text = (sig.get("signer", "") + " " + sig.get("subject", "")).lower()
    return bool(sig.get("valid")) and (sig.get("os") or any(t in text for t in TRUSTED_SIGNERS))


# ---------------------------------------------------------------- dosya özellikleri (Claude ve sezgiler için)

def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


SUSPICIOUS_IMPORTS = {
    "injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC",
                  "SetThreadContext", "NtUnmapViewOfSection", "RtlCreateUserThread"],
    "keylogging": ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState", "RegisterRawInputDevices"],
    "credentials": ["CryptUnprotectData", "CredEnumerateA", "CredEnumerateW", "LsaRetrievePrivateData", "MiniDumpWriteDump"],
    "anti_analysis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA"],
    "network": ["InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileA",
                "URLDownloadToFileW", "WinHttpOpen", "HttpSendRequestA", "HttpSendRequestW", "WSAStartup", "connect"],
    "crypto": ["CryptEncrypt", "BCryptEncrypt", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW"],
    "screen": ["BitBlt", "GetDC", "CreateCompatibleBitmap"],
    "persistence": ["RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW"],
}

STRING_PATTERNS = [
    ("url", re.compile(r"https?://[\w\-.:@/%?=&#~+]{6,200}", re.I)),
    ("telegram", re.compile(r"api\.telegram\.org/bot[\w:\-]+", re.I)),
    ("discord_webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/[\w/\-]+", re.I)),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")),
    ("registry", re.compile(r"(?:HKEY_|HKLM\\|HKCU\\|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)[\w\\ .\-]{4,160}", re.I)),
    ("command", re.compile(r"(?:powershell|cmd\.exe|schtasks|vssadmin|bcdedit|wevtutil|certutil|bitsadmin|mshta|rundll32|regsvr32|wmic)[^\x00\r\n]{0,160}", re.I)),
    ("wallet", re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")),
    ("browser_data", re.compile(r"(?:Login Data|Cookies|Web Data|Local State|wallet\.dat|logins\.json|key4\.db)", re.I)),
    ("ransom_note", re.compile(r"(?:your files (?:have been|are) encrypted|bitcoin|decrypt(?:ion)? (?:key|tool)|tor browser|\.onion)", re.I)),
]


def extract_strings(data, minlen=6, limit=4000):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append(m.group().decode("ascii"))
        if len(out) >= limit:
            break
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.append(m.group().decode("utf-16-le", "ignore"))
        if len(out) >= limit * 2:
            break
    return out


def interesting_strings(strings, cap=120):
    found = {}
    for s in strings:
        for kind, rx in STRING_PATTERNS:
            for m in rx.findall(s):
                lst = found.setdefault(kind, [])
                if m not in lst and len(lst) < 25:
                    lst.append(m)
    total = sum(len(v) for v in found.values())
    if total > cap:
        for k in found:
            found[k] = found[k][:max(3, cap // max(1, len(found)))]
    return found


def zone_identifier(path):
    """İndirilen dosyanın nereden geldiği (Mark of the Web)."""
    try:
        with open(path + ":Zone.Identifier", encoding="utf-8", errors="replace") as f:
            text = f.read(4000)
    except OSError:
        return {}
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip() in ("ZoneId", "HostUrl", "ReferrerUrl"):
                out[k.strip()] = v.strip()
    return out


def pe_info(path, data):
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                               pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception:
        return None
    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                imports.append(imp.name.decode("ascii", "ignore"))
    flags = {k: [f for f in v if f in imports] for k, v in SUSPICIOUS_IMPORTS.items()}
    flags = {k: v for k, v in flags.items() if v}
    sections = []
    for s in pe.sections:
        sections.append({"name": s.Name.rstrip(b"\x00").decode("ascii", "ignore"), "size": s.SizeOfRawData,
                         "entropy": round(s.get_entropy(), 2)})
    version = {}
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        version[k.decode("ascii", "ignore")] = v.decode("utf-8", "ignore")
    except Exception:
        pass
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "compiled": time.strftime("%Y-%m-%d", time.gmtime(pe.FILE_HEADER.TimeDateStamp)),
        "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "gui": pe.OPTIONAL_HEADER.Subsystem == 2,
        "import_count": len(imports),
        "suspicious_imports": flags,
        "sections": sections,
        "packed_hint": any(s["entropy"] > 7.2 for s in sections) or any(s["name"].lower().startswith(("upx", ".aspack", ".themida", ".vmp")) for s in sections),
        "version_info": {k: v for k, v in version.items() if k in ("CompanyName", "FileDescription", "OriginalFilename",
                                                                    "ProductName", "FileVersion", "InternalName")},
        "overlay": len(data) - pe.get_overlay_data_start_offset() if pe.get_overlay_data_start_offset() else 0,
    }


def file_features(path, max_bytes=32 * 1024 * 1024):
    """Dosyanın özeti: kendisi değil. Claude'a ve sezgisel değerlendirmeye gider."""
    st = os.stat(path)
    with open(path, "rb") as f:
        data = f.read(max_bytes)
    ext = os.path.splitext(path)[1].lower()
    feats = {"path": path, "name": os.path.basename(path), "size": st.st_size, "extension": ext,
             "sha256": core.sha256_file(path), "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
             "created": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_ctime)),
             "entropy": round(entropy(data[:4 * 1024 * 1024]), 2), "origin": zone_identifier(path)}
    if data[:2] == b"MZ":
        feats["pe"] = pe_info(path, data)
        feats["signature"] = SIG.check(path)
    elif ext in SCRIPT_EXT | {".txt", ".xml", ".html", ".htm", ".svg"}:
        text = data[:60000].decode("utf-8", "replace")
        feats["script_head"] = text[:30000]
        decoded = decode_powershell(text)
        if decoded:
            feats["decoded_payloads"] = decoded[:5]
    strings = extract_strings(data)
    feats["indicators"] = interesting_strings(strings)
    feats["double_extension"] = bool(re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|mp4|zip)\.(exe|scr|com|bat|cmd|js|vbs|lnk)$",
                                              path, re.I))
    return feats


def decode_powershell(text):
    """-EncodedCommand ve FromBase64String yüklerini çözer."""
    import base64
    out = []
    for m in re.finditer(r"(?:-e(?:nc(?:odedcommand)?)?\s+|FromBase64String\(\s*['\"])([A-Za-z0-9+/=]{24,})", text, re.I):
        blob = m.group(1)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except ValueError:
            continue
        for enc in ("utf-16-le", "utf-8"):
            try:
                s = raw.decode(enc)
                if sum(c.isprintable() for c in s) > len(s) * 0.85:
                    out.append(s[:4000])
                    break
            except UnicodeDecodeError:
                continue
    return out


# ---------------------------------------------------------------- Microsoft Defender

def mpcmdrun():
    plat = r"C:\ProgramData\Microsoft\Windows Defender\Platform"
    try:
        vers = sorted((d for d in os.listdir(plat) if os.path.isfile(os.path.join(plat, d, "MpCmdRun.exe"))), reverse=True)
        if vers:
            return os.path.join(plat, vers[0], "MpCmdRun.exe")
    except OSError:
        pass
    return os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")


def mpcmdrun_hijacked():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe") as k:
            return bool(winreg.QueryValueEx(k, "Debugger")[0])
    except OSError:
        return False


def defender_scan(path, timeout=300):
    if mpcmdrun_hijacked():
        # MpCmdRun yönlendirilmişse Defender'ı WMI üzerinden tara ve sonucu tehdit geçmişinden oku.
        start = time.time()
        p = path.replace("'", "''")
        core.ps(f"Start-MpScan -ScanType CustomScan -ScanPath '{p}'", timeout=timeout)
        data = core.ps_json(f"Get-MpThreatDetection | Where-Object {{ $_.Resources -like '*{os.path.basename(p)}*' }} | "
                            "ForEach-Object { [pscustomobject]@{Id=$_.ThreatID; T=$_.InitialDetectionTime.ToString('o')} }", timeout=60)
        names = []
        for d in core.as_list(data):
            th = core.ps_json(f"(Get-MpThreat -ThreatID {int(d['Id'])}).ThreatName", timeout=30)
            if th:
                names.append(str(th))
        return [{"engine": "Defender", "name": n, "level": "istenmeyen" if n.startswith("PUA") else "tehdit"} for n in names]
    code, out = core.run([mpcmdrun(), "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"], timeout=timeout)
    names = re.findall(r"Threat\s*:\s*(.+)", out)
    if code == 2 or names:
        return [{"engine": "Defender", "name": n.strip(), "level": "istenmeyen" if n.strip().startswith(("PUA", "PUADlManager")) else "tehdit"}
                for n in (names or ["Tehdit"])]
    return []


def defender_status():
    d = core.ps_json("Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,AntivirusSignatureVersion,"
                     "AntivirusSignatureLastUpdated,IsTamperProtected,BehaviorMonitorEnabled", timeout=60) or {}
    return d


# ---------------------------------------------------------------- ClamAV

CLAM_DIR = os.path.join(ENGINE_DIR, "clamav")
CLAM_DB = os.path.join(CLAM_DIR, "veritabani")
CLAM_PORT = 33310


class Clam:
    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None
        self.last_used = 0
        self.starting = False

    @property
    def installed(self):
        return os.path.isfile(os.path.join(CLAM_DIR, "clamd.exe"))

    @property
    def has_db(self):
        try:
            return any(f.endswith((".cvd", ".cld")) for f in os.listdir(CLAM_DB))
        except OSError:
            return False

    def db_version(self):
        try:
            newest = max(os.path.getmtime(os.path.join(CLAM_DB, f)) for f in os.listdir(CLAM_DB) if f.endswith((".cvd", ".cld")))
            return newest
        except (OSError, ValueError):
            return None

    def install(self, job=None):
        os.makedirs(CLAM_DIR, exist_ok=True)
        rel = core.http_json("https://api.github.com/repos/Cisco-Talos/clamav/releases/latest")
        asset = next(a for a in rel["assets"] if re.search(r"win\.x64\.zip$", a["name"]))
        tmp = os.path.join(ENGINE_DIR, "clamav.zip")
        core.download(asset["browser_download_url"], tmp, job, "ClamAV indiriliyor", 0.0, 0.35, timeout=120)
        with zipfile.ZipFile(tmp) as z:
            for info in z.infolist():
                name = info.filename.split("/", 1)[-1] if "/" in info.filename else info.filename
                if not name or info.is_dir() or name.lower().endswith(".pdb") or name.lower().startswith(("conf_examples", "include", "lib/")):
                    continue
                dest = os.path.join(CLAM_DIR, name.replace("/", os.sep))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with z.open(info) as src, open(dest, "wb") as out:
                    out.write(src.read())
        os.remove(tmp)
        self.write_conf()

    def write_conf(self):
        os.makedirs(CLAM_DB, exist_ok=True)
        with open(os.path.join(CLAM_DIR, "freshclam.conf"), "w", encoding="utf-8") as f:
            f.write(f"DatabaseDirectory {CLAM_DB}\nDatabaseMirror database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\n"
                    f"ConnectTimeout 60\nReceiveTimeout 600\nUpdateLogFile {os.path.join(CLAM_DIR, 'freshclam.log')}\n")
        with open(os.path.join(CLAM_DIR, "clamd.conf"), "w", encoding="utf-8") as f:
            f.write(f"DatabaseDirectory {CLAM_DB}\nTCPSocket {CLAM_PORT}\nTCPAddr 127.0.0.1\nMaxThreads 6\n"
                    "StreamMaxLength 100M\nMaxFileSize 100M\nMaxScanSize 200M\nMaxRecursion 12\nMaxFiles 5000\n"
                    "ReadTimeout 180\nIdleTimeout 300\nDetectPUA no\nHeuristicAlerts yes\nAlertBrokenExecutables no\n"
                    "ScanPE yes\nScanOLE2 yes\nScanPDF yes\nScanHTML yes\nScanArchive yes\nBytecode yes\n"
                    f"LogFile {os.path.join(CLAM_DIR, 'clamd.log')}\nLogFileMaxSize 5M\n")

    def update(self, job=None):
        if not self.installed:
            self.install(job)
        self.write_conf()
        if job:
            job.update(0.4, "ClamAV imzaları güncelleniyor (ilk seferde ~300 MB)")
        code, out = core.run([os.path.join(CLAM_DIR, "freshclam.exe"), f"--config-file={os.path.join(CLAM_DIR, 'freshclam.conf')}",
                              "--stdout"], timeout=1800)
        if not self.has_db:
            raise UserError("ClamAV imzaları indirilemedi: " + out.strip().splitlines()[-1][:200] if out.strip() else "ClamAV imzaları indirilemedi.")
        if self.running():
            self.command(b"zRELOAD\0", timeout=30)
        return out

    def running(self):
        try:
            return self.command(b"zPING\0", timeout=2).strip(b"\0") == b"PONG"
        except OSError:
            return False

    def ensure(self, wait=True):
        """clamd'ı başlatır (imzalar belleğe ~20-60 sn'de yüklenir)."""
        self.last_used = time.time()
        if self.running():
            return True
        if not (self.installed and self.has_db) or not core.settings()["engines"].get("clamav", True):
            return False
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                self.write_conf()
                self.proc = subprocess.Popen([os.path.join(CLAM_DIR, "clamd.exe"), f"--config-file={os.path.join(CLAM_DIR, 'clamd.conf')}",
                                              "--foreground"], creationflags=core.NO_WINDOW, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL, cwd=CLAM_DIR)
        if not wait:
            return False
        for _ in range(240):
            if self.running():
                return True
            if self.proc and self.proc.poll() is not None:
                return False
            time.sleep(0.5)
        return False

    def stop(self):
        try:
            self.command(b"zSHUTDOWN\0", timeout=3)
        except OSError:
            pass
        if self.proc:
            try:
                self.proc.wait(5)
            except Exception:
                self.proc.kill()
        self.proc = None

    def idle_check(self):
        if self.proc and not core.settings()["engines"].get("clamav_resident") and time.time() - self.last_used > 600:
            self.stop()

    def command(self, cmd, timeout=10):
        with socket.create_connection(("127.0.0.1", CLAM_PORT), timeout=timeout) as s:
            s.sendall(cmd)
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
            return b"".join(chunks)

    def scan(self, path):
        """INSTREAM ile tarar (Türkçe karakterli yollar ve kilitli klasörlerde sorunsuz)."""
        self.last_used = time.time()
        with socket.create_connection(("127.0.0.1", CLAM_PORT), timeout=180) as s:
            s.sendall(b"zINSTREAM\0")
            with open(path, "rb") as f:
                sent = 0
                while True:
                    b = f.read(1 << 16)
                    if not b or sent > MAX_SCAN:
                        break
                    s.sendall(struct.pack(">I", len(b)) + b)
                    sent += len(b)
            s.sendall(struct.pack(">I", 0))
            resp = b""
            while not resp.endswith(b"\0"):
                b = s.recv(4096)
                if not b:
                    break
                resp += b
        text = resp.strip(b"\0").decode("utf-8", "replace")
        if text.endswith("FOUND"):
            name = text.split(":", 1)[1].rsplit("FOUND", 1)[0].strip()
            level = "istenmeyen" if name.startswith("PUA.") else "supheli" if name.startswith("Heuristics.") else "tehdit"
            return [{"engine": "ClamAV", "name": name, "level": level}]
        return []


CLAM = Clam()


# ---------------------------------------------------------------- YARA-X

YARA_DIR = os.path.join(ENGINE_DIR, "yara")
YARA_BIN = os.path.join(YARA_DIR, "kurallar.bin")


class Yara:
    def __init__(self):
        self.rules = None

        self.lock = threading.Lock()
        self.meta = {}

    @property
    def ready(self):
        return self.load() is not None

    def load(self):
        if self.rules is None and os.path.isfile(YARA_BIN):
            with self.lock:
                if self.rules is None:
                    import yara_x
                    with open(YARA_BIN, "rb") as f:
                        self.rules = yara_x.Rules.deserialize_from(f)

        return self.rules

    def update(self, job=None):
        import yara_x
        os.makedirs(YARA_DIR, exist_ok=True)
        rel = core.http_json("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest")
        asset = next(a for a in rel["assets"] if a["name"] == "yara-forge-rules-core.zip")
        if job:
            job.update(None, "YARA kuralları indiriliyor")
        tmp = os.path.join(YARA_DIR, "core.zip")
        core.download(asset["browser_download_url"], tmp, timeout=120)
        with zipfile.ZipFile(tmp) as z:
            src = z.read(next(n for n in z.namelist() if n.endswith(".yar"))).decode("utf-8", "replace")
        os.remove(tmp)
        comp = yara_x.Compiler(relaxed_re_syntax=True)
        comp.add_source(src)
        rules = comp.build()
        with open(YARA_BIN + ".tmp", "wb") as f:
            rules.serialize_into(f)
        os.replace(YARA_BIN + ".tmp", YARA_BIN)
        core.write_json(os.path.join(YARA_DIR, "surum.json"), {"release": rel.get("tag_name"), "time": time.time(),
                                                                "rules": src.count("\nrule ") + src.count("\nprivate rule ")})
        with self.lock:
            self.rules = rules


    def info(self):
        return core.read_json(os.path.join(YARA_DIR, "surum.json"), {})

    def scan(self, path):
        # yara_x.Scanner iş parçacıkları arasında taşınamıyor; Rules.scan her çağrıda kendi tarayıcısını kurar.
        rules = self.load()
        if rules is None:
            return []
        try:
            with open(path, "rb") as f:
                data = f.read(64 * 1024 * 1024)
            res = rules.scan(data)
        except Exception:
            return []
        hits = []
        for r in res.matching_rules:
            meta = dict(r.metadata)
            score = int(meta.get("score", 60) or 60) if str(meta.get("score", "")).isdigit() else 60
            hits.append({"engine": "YARA", "name": r.identifier, "score": score,
                         "description": str(meta.get("description", ""))[:200],
                         "level": "supheli"})
        hits.sort(key=lambda h: -h["score"])
        return hits[:5]


YARA = Yara()


# ---------------------------------------------------------------- MalwareBazaar ve VirusTotal

_lookup_cache = {}


def bazaar_lookup(sha256):
    key = secret("abusech_key")
    if not key or not core.settings()["engines"].get("bazaar", True):
        return None
    ck = ("mb", sha256)
    if ck in _lookup_cache:
        return _lookup_cache[ck]
    try:
        d = core.http_json("https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": sha256},
                           headers={"Auth-Key": key}, timeout=15)
    except Exception:
        return None
    res = []
    if d and d.get("query_status") == "ok" and d.get("data"):
        item = d["data"][0]
        res = [{"engine": "MalwareBazaar", "name": item.get("signature") or ", ".join(item.get("tags") or []) or "Bilinen zararlı",
                "level": "tehdit", "first_seen": item.get("first_seen")}]
    _lookup_cache[ck] = res
    return res


_vt_times = []
_vt_lock = threading.Lock()


def virustotal_lookup(sha256, wait=False):
    key = secret("virustotal_key")
    if not key or not core.settings()["engines"].get("virustotal", True):
        return None
    ck = ("vt", sha256)
    if ck in _lookup_cache:
        return _lookup_cache[ck]
    with _vt_lock:   # ücretsiz anahtar: dakikada 4 sorgu
        now = time.time()
        _vt_times[:] = [t for t in _vt_times if now - t < 60]
        if len(_vt_times) >= 4:
            if not wait:
                return None
            time.sleep(60 - (now - _vt_times[0]) + 0.5)
        _vt_times.append(time.time())
    import urllib.error
    try:
        d = core.http_json(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key}, timeout=20)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            _lookup_cache[ck] = []
            return []
        return None
    except Exception:
        return None
    stats = d["data"]["attributes"].get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    name = (d["data"]["attributes"].get("popular_threat_classification") or {}).get("suggested_threat_label") or ""
    res = []
    if mal >= 5:
        res = [{"engine": "VirusTotal", "name": f"{mal}/{total} motor" + (f" · {name}" if name else ""), "level": "tehdit"}]
    elif mal >= 2:
        res = [{"engine": "VirusTotal", "name": f"{mal}/{total} motor", "level": "supheli"}]
    _lookup_cache[ck] = res
    return res


# ---------------------------------------------------------------- birleşik tarama

LEVEL_RANK = {"tehdit": 3, "supheli": 2, "istenmeyen": 1, "temiz": 0}


def worst(levels):
    return max(levels, key=lambda l: LEVEL_RANK.get(l, 0), default="temiz")


def scan_file(path, clam=True, yara=True, lookups=False, defender=False, sig=None):
    """Bir dosyayı motorlardan geçirir. Dönüş: {level, hits, sha256, signer}"""
    hits = []
    try:
        size = os.path.getsize(path)
    except OSError:
        return {"level": "temiz", "hits": [], "error": "okunamadı"}
    if size == 0:
        return {"level": "temiz", "hits": []}
    ext = os.path.splitext(path)[1].lower()
    is_pe = False
    try:
        with open(path, "rb") as f:
            is_pe = f.read(2) == b"MZ"
    except OSError:
        return {"level": "temiz", "hits": [], "error": "okunamadı"}
    sha = None
    if clam and size <= MAX_SCAN and CLAM.running():
        try:
            hits += CLAM.scan(path)
        except OSError:
            pass
    if yara and size <= 64 * 1024 * 1024 and (is_pe or ext in RISKY_EXT):
        hits += YARA.scan(path)
    if (is_pe or ext in SCRIPT_EXT) and (lookups or defender or any(h["level"] != "temiz" for h in hits)):
        sha = core.sha256_file(path)
        if sha in core.settings().get("trusted_hashes", []):
            return {"level": "temiz", "hits": [], "sha256": sha, "trusted": True}
        if lookups or hits:
            hits += bazaar_lookup(sha) or []
            if not any(h["engine"] == "MalwareBazaar" for h in hits):
                hits += virustotal_lookup(sha) or []
    if defender:
        hits += defender_scan(path)
    signer = None
    if hits and all(h["engine"] == "YARA" for h in hits):
        # Yalnız YARA gördüyse: düşük puanlı kurallar (paketleyici, karartıcı gibi yetenek kuralları) yanlış alarm üretir.
        hits = [h for h in hits if h.get("score", 0) >= 70]
    if is_pe and hits:
        sig = sig or SIG.check(path)
        signer = sig.get("signer")
        # Geçerli imzalı bir dosyada yalnız YARA eşleşmesi: yanlış alarm sayılır.
        if sig.get("valid") and all(h["engine"] == "YARA" for h in hits):
            hits = []
    level = worst(h["level"] for h in hits)
    # Tek başına YARA "şüpheli"; başka bir motor da görürse tehdit.
    if any(h["engine"] == "YARA" for h in hits) and any(h["engine"] != "YARA" and h["level"] == "tehdit" for h in hits):
        level = "tehdit"
    return {"level": level, "hits": hits, "sha256": sha, "signer": signer}


def engine_status():
    s = core.settings()["engines"]
    yi = YARA.info()
    return {
        "defender": {"name": "Defender", "on": True},
        "clamav": {"name": "ClamAV", "on": s.get("clamav", True), "installed": CLAM.installed, "db": CLAM.db_version(),
                   "running": CLAM.running() if CLAM.installed else False},
        "yara": {"name": "YARA", "on": s.get("yara", True), "ready": os.path.isfile(YARA_BIN), "rules": yi.get("rules"),
                 "updated": yi.get("time"), "release": yi.get("release")},
        "bazaar": {"name": "MalwareBazaar", "on": s.get("bazaar", True), "key": bool(secret("abusech_key"))},
        "virustotal": {"name": "VirusTotal", "on": s.get("virustotal", True), "key": bool(secret("virustotal_key"))},
    }
