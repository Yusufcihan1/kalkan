"""Anlık koruma: yeni süreçler, indirilenler, USB bellekler; fidye yazılımı kalkanı (tuzak dosyalar, şifreleme
izleme, anlık görüntüler, yedek kasası) ve uyarılar."""
import ctypes
import os
import random
import shutil
import string
import threading
import time
import uuid

import core
import deep
import engines
import quarantine

# ---------------------------------------------------------------- uyarılar

ALERTS = {}
ALERT_HOOK = [None]      # ajan bir açılır pencere gösterir
_alert_lock = threading.Lock()


def raise_alert(kind, level, title, text, actions, data=None, popup=True):
    """actions: [(anahtar, etiket)] — ilk eylem varsayılan."""
    a = {"id": uuid.uuid4().hex[:10], "kind": kind, "level": level, "title": title, "text": text, "actions": actions,
         "data": data or {}, "time": time.time(), "status": "open"}
    with _alert_lock:
        ALERTS[a["id"]] = a
        for k in [k for k, v in ALERTS.items() if v["status"] != "open" and time.time() - v["time"] > 86400]:
            ALERTS.pop(k, None)
    core.event("uyari", level, title, {"text": text, "alert": a["id"], **(data or {})})
    if popup and ALERT_HOOK[0]:
        try:
            ALERT_HOOK[0](a)
        except Exception as e:
            core.log_error("alert hook", e)
    return a


def open_alerts():
    return sorted((a for a in ALERTS.values() if a["status"] == "open"), key=lambda a: -a["time"])


def resolve_alert(aid, action):
    a = ALERTS.get(aid)
    if not a:
        raise core.UserError("Uyarı bulunamadı.")
    d = a["data"]
    msg = ""
    if action == "quarantine":
        pid = d.get("pid")
        if pid:
            core.kill_process(pid)
        if d.get("path") and os.path.isfile(d["path"]):
            quarantine.quarantine_file(d["path"], a["text"], d.get("detection", ""), source="anlik")
        msg = "Karantinaya alındı"
    elif action == "quarantine_restore":
        for pid in d.get("pids", []):
            core.kill_process(pid)
        for p in d.get("paths", []):
            if p and os.path.isfile(p) and not engines.SIG.check(p).get("valid"):
                try:
                    quarantine.quarantine_file(p, a["text"], "Fidye yazılımı davranışı", source="fidye")
                except Exception as e:
                    core.log_error("ransom quarantine", e)
        n = SHIELD.restore_changed(d.get("since", a["time"] - 60), d.get("files", []))
        msg = f"Program karantinada; {n} dosya geri yüklendi"
    elif action == "allow":
        for pid in d.get("pids", []) + ([d["pid"]] if d.get("pid") else []):
            core.resume_process(pid)
        for p in d.get("paths", []) + ([d["path"]] if d.get("path") else []):
            if p and os.path.isfile(p):
                try:
                    h = core.sha256_file(p)
                    s = core.settings()
                    core.save_settings({"trusted_hashes": list(dict.fromkeys(s.get("trusted_hashes", []) + [h]))})
                except OSError:
                    pass
        msg = "İzin verildi; bu programa bir daha dokunulmayacak"
    elif action == "restore_file":
        quarantine.restore(d["qid"])
        msg = "Dosya geri yüklendi"
    elif action == "kill_pid":
        core.kill_process(d.get("pid", 0))
        msg = "Süreç durduruldu"
    elif action == "dismiss":
        msg = "Kapatıldı"
    else:
        raise core.UserError("Bilinmeyen işlem")
    a["status"] = "done"
    a["result"] = msg
    core.event("uyari", "bilgi", f"{a['title']}: {msg}")
    return msg


# ---------------------------------------------------------------- süreç izleme

class ProcessWatch:
    def __init__(self):
        self.known = set()
        self.verdicts = {}      # (yol, boyut, mtime) -> sonuç
        self.checked = 0
        self.blocked = 0
        self.stop = False

    def run(self):
        snap = core.process_snapshot()
        self.known = set(snap)
        while not self.stop:
            time.sleep(0.25)
            if not core.settings()["realtime"].get("processes", True):
                continue
            try:
                snap = core.process_snapshot()
            except Exception:
                continue
            new = [pid for pid in snap if pid not in self.known]
            self.known = set(snap)
            for pid in new:
                try:
                    self.inspect(pid, snap)
                except Exception as e:
                    core.log_error("process inspect", e)

    def inspect(self, pid, snap):
        path = core.process_path(pid)
        if not path or core.is_excluded(path):
            return
        p = core.norm(path)
        if p.startswith(deep.SYS32 + "\\") or p.startswith(deep.SYSWOW + "\\"):
            name = os.path.basename(p)
            if name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
                self.check_parent(pid, name, snap)
            return
        try:
            st = os.stat(path)
        except OSError:
            return
        key = (p, st.st_size, int(st.st_mtime))
        if key in self.verdicts:
            v = self.verdicts[key]
        else:
            # İmzalı ve güvenilir programlar hızla geçer; diğerleri motorlardan geçer.
            sig = engines.SIG.check(path)
            if engines.trusted_signer(sig):
                v = {"level": "temiz", "hits": []}
            else:
                v = engines.scan_file(path, clam=True, yara=True, lookups=deep.in_user_writable(path), sig=sig)
            self.verdicts[key] = v
            self.checked += 1
        if v["level"] == "temiz":
            return
        name = os.path.basename(path)
        detection = ", ".join(f"{h['engine']}: {h['name']}" for h in v["hits"][:3])
        signed = engines.SIG.check(path).get("valid")
        if v["level"] == "tehdit" and not signed:
            core.kill_process(pid)
            try:
                m = quarantine.quarantine_file(path, "Çalışırken yakalandı", detection, source="anlik")
                self.blocked += 1
                raise_alert("process", "tehdit", f"Tehdit durduruldu: {name}",
                            f"{name} çalışmaya başladığı anda yakalandı ve karantinaya alındı. Algılayan: {detection}.",
                            [("dismiss", "Tamam"), ("restore_file", "Geri yükle"), ("explain", "Bu ne?")],
                            {"path": path, "detection": detection, "qid": m["id"]})
            except Exception as e:
                core.log_error("realtime quarantine", e)
        else:
            core.suspend_process(pid)
            raise_alert("process", v["level"], f"Şüpheli program donduruldu: {name}",
                        f"{name} başladı ve şüpheli bulundu ({detection}). Program sen karar verene kadar donduruldu.",
                        [("quarantine", "Karantinaya al"), ("explain", "Bu ne?"), ("allow", "Güveniyorum, izin ver")],
                        {"path": path, "pid": pid, "detection": detection})

    def check_parent(self, pid, name, snap):
        ppid = snap.get(pid, (0,))[0]
        parent = snap.get(ppid, (0, ""))[1].lower()
        if parent in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "msaccess.exe", "onenote.exe"):
            core.suspend_process(pid)
            raise_alert("process", "tehdit", f"{parent} bir komut kabuğu açtı",
                        f"{parent} az önce {name} başlattı. Bu, makrolu belge saldırılarının tipik adımıdır; süreç donduruldu.",
                        [("kill_pid", "Durdur"), ("explain", "Bu ne?"), ("allow", "İzin ver")], {"pid": pid, "parent": parent})


PROC = ProcessWatch()


# ---------------------------------------------------------------- dosya izleme (indirilenler, USB) ve fidye kalkanı

TEMP_SUFFIX = (".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload", "~")
DOC_TYPES = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv",
             ".jpg", ".jpeg", ".png", ".heic", ".gif", ".bmp", ".tif", ".tiff", ".psd", ".ai", ".svg", ".mp4", ".mov",
             ".mp3", ".wav", ".zip", ".rar", ".7z", ".pst", ".ost", ".accdb", ".mdb", ".sql", ".dwg", ".key", ".pages",
             ".numbers", ".epub", ".udf", ".xml", ".json"}
import re as _re
BUILD_DIRS = _re.compile(r"\\(build|obj|bin|out|target|dist|\.vs|x64|x86|debug|release|cmakefiles|node_modules|\.git|"
                         r"__pycache__|\.venv|venv|\.gradle|\.idea|\.next|\.cache|saved|intermediate|binaries)\\")


def removable_drives():
    out = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if mask & (1 << i):
            root = f"{letter}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 2:   # DRIVE_REMOVABLE
                out.append(root)
    return out


CANARY_NAMES = ["!!!0000_Faturalar.docx", "!!!0000_Banka_Ozeti.pdf", "~~zz_Muhasebe_2026.xlsx"]


def _fake_content(name):
    rnd = random.Random(name)
    head = {".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04", ".pdf": b"%PDF-1.7\n"}[os.path.splitext(name)[1]]
    return head + bytes(rnd.randrange(32, 127) for _ in range(6000))


class Shield:
    """Fidye yazılımı kalkanı ve dosya izleyici."""

    def __init__(self):
        self.observer = None
        self.events = []        # (zaman, yol, tür)
        self.lock = threading.Lock()
        self.canaries = {}
        self.pending = {}       # indirilen dosya -> son değişim
        self.last_trigger = 0
        self.usb_seen = set()
        self.write_base = {}
        import collections
        self.history = collections.deque()

    # -- tuzak dosyalar
    def place_canaries(self):
        if not core.settings()["ransom"].get("canaries", True):
            self.remove_canaries()
            return
        for folder in [core.known_folder(n) for n in ("Documents", "Desktop", "Pictures")]:
            if not folder or not os.path.isdir(folder):
                continue
            for name in CANARY_NAMES:
                p = os.path.join(folder, name)
                data = _fake_content(name)
                try:
                    if not os.path.isfile(p) or os.path.getsize(p) != len(data):
                        if os.path.isfile(p):
                            ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
                        with open(p, "wb") as f:
                            f.write(data)
                    ctypes.windll.kernel32.SetFileAttributesW(p, 0x2 | 0x4)   # gizli + sistem
                    self.canaries[core.norm(p)] = len(data)
                except OSError:
                    continue

    def remove_canaries(self):
        for p in list(self.canaries):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
                os.remove(p)
            except OSError:
                pass
        self.canaries.clear()

    # -- izleyici
    def start(self):
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        shield = self

        class H(FileSystemEventHandler):
            def on_any_event(self, ev):
                if ev.is_directory:
                    return
                path = getattr(ev, "dest_path", None) or ev.src_path
                shield.on_event(ev.event_type, ev.src_path, path)

        self.place_canaries()
        self.observer = Observer()
        handler = H()
        for folder in core.user_folders():
            try:
                self.observer.schedule(handler, folder, recursive=True)
            except Exception as e:
                core.log_error(f"watch {folder}", e)
        self.observer.daemon = True
        self.observer.start()
        threading.Thread(target=self.loop, daemon=True, name="shield").start()

    def on_event(self, kind, src, path):
        n = core.norm(src)
        now = time.time()
        if n in self.canaries or core.norm(path) in self.canaries:
            if kind in ("modified", "deleted", "moved"):
                try:
                    if kind == "modified" and os.path.getsize(src) == self.canaries.get(n):
                        with open(src, "rb") as f:
                            if f.read() == _fake_content(os.path.basename(src)):
                                return
                except OSError:
                    pass
                self.trigger(f"Tuzak dosyaya dokunuldu: {os.path.basename(src)}", [src])
            return
        if core.is_excluded(path):
            return
        if kind == "modified":
            # Windows erişim zamanını da "değişti" diye bildirir (ör. bir tarama dosyayı okuyunca): gerçekten yazıldı mı?
            try:
                if now - os.path.getmtime(src) > 15:
                    return
            except OSError:
                return
        if not BUILD_DIRS.search(core.norm(path)):
            with self.lock:
                self.events.append((now, path, kind, src))
                if len(self.events) > 5000:
                    self.events = self.events[-3000:]
        if kind in ("created", "modified", "moved") and core.settings()["realtime"].get("downloads", True):
            dl = core.norm(core.known_folder("Downloads"))
            if core.norm(path).startswith(dl + "\\") and not path.lower().endswith(TEMP_SUFFIX):
                self.pending[path] = now

    def loop(self):
        tick = 0
        while True:
            time.sleep(1)
            tick += 1
            try:
                if core.settings()["ransom"].get("burst", True):
                    self.sample_writes()
                self.check_burst()
                self.scan_pending()
                if tick % 3 == 0:
                    self.check_usb()
                if tick % 600 == 0:
                    self.place_canaries()
            except Exception as e:
                core.log_error("shield loop", e)

    def check_burst(self):
        """Fidye yazılımı belirtisi: kısa sürede çok sayıda BELGE değişir ya da belgelerin uzantısı bilinmeyen bir
        uzantıya döner (ör. rapor.docx → rapor.docx.locked). Derleme, kod ve geçici dosyalar sayılmaz."""
        if not core.settings()["ransom"].get("burst", True):
            return
        now = time.time()
        with self.lock:
            recent = [e for e in self.events if now - e[0] < 6 and e[2] in ("modified", "moved", "deleted")]
        docs = {core.norm(e[3]) for e in recent if os.path.splitext(e[3])[1].lower() in DOC_TYPES}
        renamed = [e for e in recent if e[2] == "moved" and os.path.splitext(e[3])[1].lower() in DOC_TYPES
                   and os.path.splitext(e[1])[1].lower() not in DOC_TYPES]
        if len(docs) >= 25 or len(renamed) >= 8:
            self.trigger(f"{len(docs)} belge 6 saniyede değişti" + (f", {len(renamed)} belgenin uzantısı değişti" if renamed else ""),
                         list(docs)[:300], need_culprit=True)

    def sample_writes(self):
        """Her saniye süreçlerin toplam yazdığı bayt: fidye yazılımı yakalanınca son saniyelerde kimin yazdığı bulunur."""
        snap = core.process_snapshot()
        self.history.append((time.time(), {pid: (v[2], v[3]) for pid, v in snap.items()}))
        while self.history and time.time() - self.history[0][0] > 15:
            self.history.popleft()

    def culprits(self):
        """Son ~12 saniyede belgeleri değiştiren, güvenilir imzası olmayan süreçler."""
        self.sample_writes()
        if len(self.history) < 2:
            return []
        first_seen = {}
        for t, snap in self.history:
            for pid, (w, created) in snap.items():
                first_seen.setdefault(pid, (t, w))
        now_snap = self.history[-1][1]
        rates = []
        for pid, (w, created) in now_snap.items():
            if pid <= 4 or pid == os.getpid() or pid not in first_seen:
                continue
            delta = w - first_seen[pid][1]
            if delta < 64 * 1024:
                continue
            path = core.process_path(pid)
            if not path or core.is_excluded(path) or "\\windowsapps\\" in path.lower():
                continue
            # Geçerli imzalı programlar (derleyiciler, eşitleme araçları, ofis programları) asla dondurulmaz.
            if engines.SIG.check(path).get("valid"):
                continue
            # Fidye yazılımı yeni bırakılmış/yeni başlamış bir programdır. Saatlerdir açık olan uygulamalar
            # (tarayıcı, mesajlaşma, geliştirme araçları) aynı anda diske yazsa bile şüpheli sayılmaz.
            started = created / 1e7 - 11644473600 if created else 0
            try:
                exe_age = time.time() - os.path.getmtime(path)
            except OSError:
                exe_age = 1e9
            if time.time() - started > 1800 and exe_age > 86400:
                continue
            rates.append((delta, pid, path))
        rates.sort(reverse=True)
        return rates[:3]

    def trigger(self, reason, files, need_culprit=False):
        now = time.time()
        if now - self.last_trigger < 20:
            return
        self.last_trigger = now
        bad = self.culprits()
        if need_culprit and not bad:
            # Yazan güvenilir bir program (ör. eşitleme, yedekleme): yalnız geçmişe yaz.
            core.event("fidye", "bilgi", f"Toplu dosya değişikliği: {reason}", {"files": files[:20]})
            return
        pids = [pid for _, pid, _ in bad]
        for pid in pids:
            core.suspend_process(pid)
        names = ", ".join(os.path.basename(p) for _, _, p in bad) or "bilinmeyen bir program"
        text = (f"{reason}. {names} donduruldu. Değişen dosyalar yedekten geri yüklenebilir."
                if bad else f"{reason}. Sorumlu program bulunamadı; dosyalarını kontrol et.")
        raise_alert("ransom", "tehdit", "Fidye yazılımı davranışı durduruldu" if bad else "Fidye yazılımı belirtisi",
                    text, [("quarantine_restore", "Karantinaya al ve geri yükle"), ("explain", "Bu ne?"),
                           ("allow", "Bu programa güveniyorum")] if bad else [("dismiss", "Tamam")],
                    {"pids": pids, "paths": [p for _, _, p in bad], "files": files[:500], "since": now - 10})
        if core.settings()["ransom"].get("snapshots", True):
            threading.Thread(target=create_snapshot, args=("fidye",), daemon=True).start()

    def scan_pending(self):
        now = time.time()
        ready = [p for p, t in list(self.pending.items()) if now - t > 2.5]
        for p in ready:
            self.pending.pop(p, None)
            if not os.path.isfile(p):
                continue
            ext = os.path.splitext(p)[1].lower()
            if ext not in engines.RISKY_EXT:
                continue
            threading.Thread(target=self.scan_download, args=(p,), daemon=True).start()

    def scan_download(self, p):
        if engines.CLAM.installed and engines.CLAM.has_db:
            engines.CLAM.ensure(wait=False)
        r = engines.scan_file(p, clam=True, yara=True, lookups=True)
        core.event("indirilen", "iyi" if r["level"] == "temiz" else r["level"], f"İndirilen tarandı: {os.path.basename(p)}",
                   {"path": p, "level": r["level"]})
        if r["level"] == "temiz":
            return
        detection = ", ".join(f"{h['engine']}: {h['name']}" for h in r["hits"][:3])
        name = os.path.basename(p)
        if r["level"] == "tehdit":
            m = quarantine.quarantine_file(p, "İndirilen dosya", detection, source="indirilen")
            raise_alert("download", "tehdit", f"İndirdiğin dosya zararlı: {name}",
                        f"Karantinaya alındı. Algılayan: {detection}.",
                        [("dismiss", "Tamam"), ("explain", "Bu ne?"), ("restore_file", "Geri yükle")],
                        {"path": p, "qid": m["id"], "detection": detection})
        else:
            raise_alert("download", r["level"], f"İndirdiğin dosya şüpheli: {name}",
                        f"Açmadan önce bir bak. Algılayan: {detection}.",
                        [("quarantine", "Karantinaya al"), ("explain", "Bu ne?"), ("dismiss", "Bırak")],
                        {"path": p, "detection": detection})

    def check_usb(self):
        drives = set(removable_drives())
        new = drives - self.usb_seen
        self.usb_seen = drives
        if not new or not core.settings()["realtime"].get("usb", True):
            return
        import scanner
        for d in new:
            core.event("usb", "bilgi", f"USB bellek takıldı: {d}")
            if not core.running_job("scan"):
                scanner.start_scan("usb", [d])

    def snapshot_writes(self):
        self.write_base = {pid: v[2] for pid, v in core.process_snapshot().items()}

    def restore_changed(self, since, files):
        """Değişen dosyaları önce kasadan, yoksa gölge kopyadan geri yükler. Şifrelenmiş halleri bir klasörde saklar."""
        restored = 0
        done = set()
        keep_dir = os.path.join(core.known_folder("Documents"), "Kalkan - şifrelenmiş dosyalar")
        for f in files:
            src = f
            ok = VAULT.restore_file(src, before=since) or restore_from_snapshot(src, before=since)
            if ok:
                restored += 1
                done.add(core.norm(src))
        # Aslı geri gelen dosyaların şifrelenmiş (uzantısı değişmiş) kopyalarını kenara al.
        with self.lock:
            moved = [e for e in self.events if e[0] >= since and e[2] == "moved"]
        for _, dest, _, src in moved:
            if core.norm(src) in done and os.path.isfile(dest) and os.path.splitext(dest)[1] != os.path.splitext(src)[1]:
                try:
                    os.makedirs(keep_dir, exist_ok=True)
                    shutil.move(dest, os.path.join(keep_dir, os.path.basename(dest)))
                except OSError:
                    pass
        core.event("fidye", "iyi", f"{restored} dosya geri yüklendi")
        return restored


SHIELD = Shield()


# ---------------------------------------------------------------- anlık görüntüler (VSS)

def create_snapshot(reason="zamanlanmış"):
    if not core.is_admin():
        return None
    code, out = core.ps("$r=(Get-WmiObject -List Win32_ShadowCopy).Create($env:SystemDrive + '\\','ClientAccessible');"
                        "$r.ReturnValue; $r.ShadowID", timeout=300)
    ok = out.strip().startswith("0")
    core.event("goruntu", "bilgi" if ok else "supheli", "Anlık görüntü alındı" if ok else "Anlık görüntü alınamadı",
               {"reason": reason, "out": out.strip()[:200]})
    return ok


def list_snapshots():
    data = core.ps_json("Get-CimInstance Win32_ShadowCopy | Select-Object ID,DeviceObject,VolumeName,"
                        "@{n='Time';e={$_.InstallDate.ToString('o')}}", timeout=60) or []
    return core.as_list(data)


def restore_from_snapshot(path, before=None):
    """Dosyanın en yeni gölge kopyasını (verilen zamandan önce) geri koyar."""
    drive, rel = os.path.splitdrive(path)
    snaps = [s for s in list_snapshots() if s.get("DeviceObject")]
    import datetime
    best = None
    for s in snaps:
        try:
            t = datetime.datetime.fromisoformat(s["Time"]).timestamp()
        except (KeyError, ValueError, TypeError):
            continue
        if before and t > before:
            continue
        if not best or t > best[0]:
            best = (t, s["DeviceObject"])
    if not best:
        return False
    src = best[1] + rel
    try:
        if os.path.isfile(src):
            shutil.copy2(src, path)
            return True
    except OSError:
        pass
    return False


# ---------------------------------------------------------------- yedek kasası

class Vault:
    """Seçilen klasörlerin sürümlü yedeği. Kasa klasörüne yalnız yöneticiler ve SYSTEM yazabilir."""

    def __init__(self):
        self.lock = threading.Lock()
        self.last_run = 0
        self.status = {}

    def index_path(self):
        return os.path.join(core.VAULT_DIR, "dizin.json")

    def secure(self):
        if core.is_admin():
            core.run(["icacls", core.VAULT_DIR, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
                     timeout=60)
            core.run(["icacls", core.QUAR_DIR, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
                     timeout=60)

    def backup(self, job=None):
        folders = core.settings().get("vault_folders", [])
        if not folders or not core.settings()["ransom"].get("vault", True):
            return {"copied": 0}
        with self.lock:
            idx = core.read_json(self.index_path(), {})
            copied, total_bytes = 0, 0
            limit = core.settings().get("vault_limit_gb", 20) * (1 << 30)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            for fi, folder in enumerate(folders):
                if not os.path.isdir(folder):
                    continue
                for root, dirs, files in os.walk(folder):
                    dirs[:] = [d for d in dirs if d.lower() not in ("node_modules", ".git", "__pycache__", ".venv", "venv")]
                    for name in files:
                        p = os.path.join(root, name)
                        try:
                            st = os.stat(p)
                        except OSError:
                            continue
                        if st.st_size > 512 * 1024 * 1024 or core.norm(p) in SHIELD.canaries:
                            continue
                        key = core.norm(p)
                        prev = idx.get(key)
                        if prev and prev["size"] == st.st_size and prev["mtime"] == int(st.st_mtime):
                            continue
                        rel = os.path.relpath(p, os.path.splitdrive(p)[0] + "\\")
                        dest = os.path.join(core.VAULT_DIR, "dosyalar", rel + f".{stamp}")
                        try:
                            os.makedirs(os.path.dirname(dest), exist_ok=True)
                            shutil.copy2(p, dest)
                        except OSError:
                            continue
                        versions = (prev or {}).get("versions", []) + [{"file": dest, "time": time.time(), "size": st.st_size}]
                        for old in versions[:-5]:     # dosya başına en çok 5 sürüm
                            try:
                                os.remove(old["file"])
                            except OSError:
                                pass
                        idx[key] = {"path": p, "size": st.st_size, "mtime": int(st.st_mtime), "versions": versions[-5:]}
                        copied += 1
                        total_bytes += st.st_size
                        if job and copied % 50 == 0:
                            job.update(fi / max(1, len(folders)), f"Yedekleniyor: {name}")
            core.write_json(self.index_path(), idx)
            self.prune(idx, limit)
            self.last_run = time.time()
            self.status = {"time": self.last_run, "files": len(idx), "copied": copied,
                           "bytes": sum(v["size"] for e in idx.values() for v in e.get("versions", []))}
            core.write_json(os.path.join(core.VAULT_DIR, "durum.json"), self.status)
        if copied:
            core.event("kasa", "iyi", f"Yedek kasası: {copied} dosya yedeklendi")
        return {"copied": copied}

    def prune(self, idx, limit):
        allv = sorted(((v["time"], k, v) for k, e in idx.items() for v in e.get("versions", [])), key=lambda x: x[0])
        total = sum(v["size"] for _, _, v in allv)
        for t, k, v in allv:
            if total <= limit:
                break
            if len(idx[k]["versions"]) <= 1:
                continue
            try:
                os.remove(v["file"])
            except OSError:
                pass
            idx[k]["versions"].remove(v)
            total -= v["size"]
        core.write_json(self.index_path(), idx)

    def info(self):
        st = core.read_json(os.path.join(core.VAULT_DIR, "durum.json"), {})
        return {"folders": core.settings().get("vault_folders", []), **st}

    def versions(self, path):
        idx = core.read_json(self.index_path(), {})
        return idx.get(core.norm(path), {}).get("versions", [])

    def restore_file(self, path, before=None, version_time=None):
        vs = self.versions(path)
        if version_time:
            vs = [v for v in vs if abs(v["time"] - version_time) < 1]
        elif before:
            vs = [v for v in vs if v["time"] <= before]
        if not vs:
            return False
        v = vs[-1]
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            shutil.copy2(v["file"], path)
            return True
        except OSError:
            return False

    def search(self, text, limit=200):
        idx = core.read_json(self.index_path(), {})
        t = text.lower()
        out = [{"path": e["path"], "versions": [{"time": v["time"], "size": v["size"]} for v in e["versions"]]}
               for k, e in idx.items() if t in k]
        return out[:limit]


VAULT = Vault()


def start_all():
    threading.Thread(target=PROC.run, daemon=True, name="procwatch").start()
    try:
        SHIELD.start()
    except Exception as e:
        core.log_error("shield start", e)
    VAULT.secure()
