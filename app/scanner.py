"""Hızlı, derin ve özel tarama işleri; son tarama sonuçları; motor güncellemeleri."""
import os
import queue
import string
import threading
import time
import ctypes

import core
import deep
import engines
import quarantine

LAST_FILE = os.path.join(core.DATA_DIR, "son_tarama.json")
IGNORE_FILE = os.path.join(core.DATA_DIR, "yoksay.json")
SKIP_DIRS = {"$recycle.bin", "system volume information", "winsxs", "$windows.~bt", "$windows.~ws", "$winreagent",
             "windowsapps", "node_modules", ".git", "__pycache__", "softwaredistribution", "driverstore", "assembly",
             "installer", "servicing", "catroot2", "logs", "prefetch", ".venv", "venv", "site-packages", ".tox",
             ".mypy_cache", ".pytest_cache", ".gradle", ".m2", ".cargo", ".rustup"}
INERT_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".mp4",
             ".mkv", ".avi", ".mov", ".wmv", ".webm", ".ttf", ".otf", ".woff", ".woff2", ".pyc", ".log", ".etl", ".evtx",
             ".db-wal", ".db-shm", ".ldb", ".blob", ".pak", ".dat", ".idx", ".tmp", ".cache", ".vhdx", ".pagefile"}

PHASES = [("autoruns", "Otomatik başlayanlar"), ("drivers", "İmzalar ve sürücüler"), ("processes", "Çalışan süreçler"),
          ("network", "Hosts, DNS, proxy"), ("extensions", "Tarayıcı eklentileri"), ("files", "Dosyalar")]


def fixed_drives():
    out = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if mask & (1 << i):
            root = f"{letter}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:   # DRIVE_FIXED
                out.append(root)
    return out


def walk(roots, deep_mode, stop, max_depth=None):
    """Taranacak dosyaları üretir. max_depth: hızlı taramada klasörlerin ne kadar derinine inileceği."""
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        stack = [(root, 0)]
        while stack and not stop():
            d, depth = stack.pop()
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                if e.name.lower() in SKIP_DIRS or core.is_excluded(e.path):
                                    continue
                                if e.is_junction() if hasattr(e, "is_junction") else False:
                                    continue
                                if max_depth is not None and depth >= max_depth:
                                    continue
                                stack.append((e.path, depth + 1))
                            elif e.is_file(follow_symlinks=False):
                                ext = os.path.splitext(e.name)[1].lower()
                                if deep_mode:
                                    if ext in INERT_EXT:
                                        continue
                                elif ext not in engines.RISKY_EXT:
                                    continue
                                if e.stat(follow_symlinks=False).st_size > engines.MAX_SCAN:
                                    continue
                                yield e.path
                        except OSError:
                            continue
            except OSError:
                continue


def quick_roots():
    env = os.environ
    roots = [core.known_folder("Downloads"), core.known_folder("Desktop"), env.get("TEMP", ""),
             os.path.join(env.get("SystemRoot", r"C:\Windows"), "Temp"),
             os.path.join(env.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
             os.path.join(env.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
             r"C:\Users\Public"]
    # AppData ve ProgramData'nın yalnız üst klasörleri: zararlılar en çok buraya yerleşir.
    shallow = []
    for base in (env.get("APPDATA", ""), env.get("LOCALAPPDATA", ""), env.get("PROGRAMDATA", "")):
        try:
            for e in os.scandir(base):
                if e.is_file():
                    shallow.append(e.path)
                elif e.is_dir() and e.name.lower() not in ("microsoft", "packages", "google", "mozilla", "nvidia", "intel",
                                                            "kalkan", "programs", "temp", "jetbrains", "docker", "npm-cache"):
                    try:
                        for f in os.scandir(e.path):
                            if f.is_file() and os.path.splitext(f.name)[1].lower() in engines.RISKY_EXT:
                                shallow.append(f.path)
                    except OSError:
                        pass
        except OSError:
            pass
    return [r for r in roots if r and os.path.isdir(r)] + shallow


def load_last():
    return core.read_json(LAST_FILE, None)


def save_last(res):
    core.write_json(LAST_FILE, res)


def ignored():
    return set(core.read_json(IGNORE_FILE, []))


def run_scan(job, kind, paths=None):
    """kind: quick | deep | custom | usb"""
    started = time.time()
    res = {"id": job.id, "kind": kind, "started": started, "finished": None, "files": 0, "findings": [],
           "phases": [{"key": k, "label": l, "state": "wait"} for k, l in PHASES], "engines": {}, "notes": []}
    if kind in ("custom", "usb"):
        res["phases"] = [p for p in res["phases"] if p["key"] == "files"]
    job.result = res
    ign = ignored()

    def phase(key, state):
        for p in res["phases"]:
            if p["key"] == key:
                p["state"] = state

    def add(fs):
        for f in fs:
            if f["id"] not in ign and not any(x["id"] == f["id"] for x in res["findings"]):
                f["status"] = "open"
                res["findings"].append(f)

    # ClamAV'ı arka planda ısıt (imzalar belleğe yüklenirken diğer aşamalar ilerler).
    clam_on = core.settings()["engines"].get("clamav", True) and engines.CLAM.installed and engines.CLAM.has_db
    if clam_on:
        threading.Thread(target=engines.CLAM.ensure, daemon=True).start()
    else:
        res["notes"].append("ClamAV kurulu değil: Ayarlar > Motorlar'dan kurulabilir.")
    if not engines.YARA.ready:
        res["notes"].append("YARA kuralları henüz indirilmedi.")
    extra_targets = []
    if kind in ("quick", "deep"):
        phase("autoruns", "now")
        job.update(0.01, "Otomatik başlayanlar inceleniyor")
        fs, items = deep.autorun_findings(job, 0.01, 0.10)
        add(fs)
        extra_targets += [it["path"] for it in items if it.get("path") and it.get("type") not in ("driver",)
                          and os.path.isfile(it["path"]) and deep.in_user_writable(it["path"])]
        phase("autoruns", "done")
        phase("drivers", "now")
        job.update(0.10, "Sürücüler LOLDrivers listesiyle karşılaştırılıyor")
        try:
            add(deep.driver_findings(items, job))
        except Exception as e:
            core.log_error("drivers", e)
        phase("drivers", "done")
        phase("processes", "now")
        job.update(0.15, "Çalışan süreçler inceleniyor")
        add(deep.process_findings(job))
        extra_targets += [p for p in (core.process_path(pid) for pid in core.process_snapshot() if pid > 4)
                          if p and deep.in_user_writable(p)]
        phase("processes", "done")
        phase("network", "now")
        job.update(0.20, "Hosts, DNS ve proxy ayarları")
        add(deep.network_settings_findings())
        phase("network", "done")
        phase("extensions", "now")
        job.update(0.22, "Tarayıcı eklentileri")
        add(deep.extension_findings())
        phase("extensions", "done")
    phase("files", "now")
    if kind == "quick":
        roots = quick_roots() + list(dict.fromkeys(extra_targets))
    elif kind == "deep":
        roots = list(dict.fromkeys(extra_targets)) + fixed_drives()
    else:
        roots = paths or []
    lo = 0.25 if kind in ("quick", "deep") else 0.0
    if clam_on and not engines.CLAM.running():
        job.update(lo, "ClamAV imzaları belleğe yükleniyor")
        engines.CLAM.ensure()
    res["engines"] = {"clamav": engines.CLAM.running(), "yara": engines.YARA.ready,
                      "bazaar": bool(engines.secret("abusech_key")), "virustotal": bool(engines.secret("virustotal_key"))}

    q = queue.Queue(maxsize=2000)
    found = [0]
    enum_done = threading.Event()
    stop = lambda: job.cancelled   # noqa: E731
    seen = set()

    def producer():
        for p in walk(roots, kind in ("deep", "usb", "custom"), stop, max_depth=3 if kind == "quick" else None):
            n = core.norm(p)
            if n in seen or core.is_excluded(p):
                continue
            seen.add(n)
            found[0] += 1
            while not job.cancelled:
                try:
                    q.put(p, timeout=0.5)
                    break
                except queue.Full:
                    continue
            if job.cancelled:
                break
        enum_done.set()

    lock = threading.Lock()
    current = [""]

    def worker():
        while True:
            try:
                p = q.get(timeout=0.3)
            except queue.Empty:
                if enum_done.is_set() or job.cancelled:
                    return
                continue
            current[0] = p
            try:
                while job.paused and not job.cancelled:
                    time.sleep(0.3)
                if job.cancelled:
                    return
                r = engines.scan_file(p, clam=True, yara=True, lookups=False)
                if r["level"] != "temiz":
                    hits = r["hits"]
                    lvl = r["level"]
                    title = next((h["name"] for h in hits if h["engine"] != "YARA"), None) or \
                        (hits[0].get("description") or hits[0]["name"] if hits else os.path.basename(p))
                    f = deep.finding("file", lvl, title, "Algılayan: " + ", ".join(sorted({h["engine"] for h in hits})),
                                     path=p, actions=["quarantine"], extra={"hits": hits, "signer": r.get("signer") or ""})
                    with lock:
                        add([f])
            except Exception as e:
                core.log_error(f"scan {p}", e)
            finally:
                with lock:
                    res["files"] += 1

    threading.Thread(target=producer, daemon=True).start()
    workers = [threading.Thread(target=worker, daemon=True) for _ in range(4)]
    for w in workers:
        w.start()
    while any(w.is_alive() for w in workers):
        total = max(found[0], 1)
        frac = res["files"] / total
        if not enum_done.is_set():
            frac = min(frac, 0.6)
        job.update(lo + (1 - lo) * 0.97 * frac, current[0])
        time.sleep(0.4)
    # Şüpheli bulgular için Defender ikinci görüşü (en fazla 15 dosya).
    for f in [x for x in res["findings"] if x["kind"] == "file" and x["level"] == "supheli"][:15]:
        if job.cancelled:
            break
        try:
            d = engines.defender_scan(f["path"], timeout=120)
            if d:
                f["hits"] = f.get("hits", []) + d
                f["level"] = "tehdit"
                f["why"] += ", Defender"
        except Exception:
            pass
    phase("files", "done")
    res["finished"] = time.time()
    res["cancelled"] = job.cancelled
    order = {"tehdit": 0, "supheli": 1, "istenmeyen": 2, "bilgi": 3}
    res["findings"].sort(key=lambda f: order.get(f["level"], 9))
    save_last(res)
    counts = {}
    for f in res["findings"]:
        counts[f["level"]] = counts.get(f["level"], 0) + 1
    title = {"quick": "Hızlı tarama", "deep": "Derin tarama", "custom": "Özel tarama", "usb": "USB taraması"}[kind]
    worst = engines.worst(f["level"] for f in res["findings"] if f["level"] in engines.LEVEL_RANK)
    core.event("tarama", worst if res["findings"] else "iyi",
               f"{title}: {res['files']} dosya, {len(res['findings'])} bulgu", {"scan": job.id, "counts": counts})
    if job.cancelled:
        raise core.Cancelled()
    return res


def start_scan(kind, paths=None):
    j = core.running_job("scan")
    if j:
        return j
    titles = {"quick": "Hızlı tarama", "deep": "Derin tarama", "custom": "Özel tarama", "usb": "USB taraması"}
    return core.start_job("scan", run_scan, kind, paths, title=titles.get(kind, "Tarama"))


def act_on_finding(fid, action):
    res = load_last() or {}
    f = next((x for x in res.get("findings", []) if x["id"] == fid), None)
    if not f:
        j = core.running_job("scan")
        if j and j.result:
            f = next((x for x in j.result.get("findings", []) if x["id"] == fid), None)
            res = j.result
    if not f:
        raise core.UserError("Bulgu bulunamadı (tarama yenilenmiş olabilir).")
    if action == "ignore":
        ids = core.read_json(IGNORE_FILE, [])
        if fid not in ids:
            ids.append(fid)
        core.write_json(IGNORE_FILE, ids)
        f["status"] = "ignored"
        msg = "Bu bulgu artık gösterilmeyecek"
    else:
        msg = quarantine.apply(f, action)
        f["status"] = "handled"
        f["result"] = msg
    if res.get("finished"):
        save_last(res)
    return msg


# ---------------------------------------------------------------- motor güncellemeleri

UPDATE_STATE = os.path.join(core.DATA_DIR, "guncelleme.json")


def update_engines(job, which=None):
    """which: None (gerekenler) ya da liste: clamav, yara, loldrivers, lists, geoip"""
    import netguard
    st = core.read_json(UPDATE_STATE, {})
    now = time.time()
    # ClamAV ilk açılışta kendiliğinden kurulur (başarısız olursa günde bir kez yeniden denenir).
    plan = which or [k for k, age in (("lists", 12 * 3600), ("yara", 3 * 86400), ("loldrivers", 7 * 86400),
                                      ("geoip", 20 * 86400), ("clamav", 86400))
                     if now - st.get(k, 0) > age and (k != "clamav" or engines.CLAM.installed
                                                      or now - st.get("clamav_tried", 0) > 86400)]
    if "clamav" in plan and not engines.CLAM.installed:
        st["clamav_tried"] = now
    done, errors = [], []
    for i, k in enumerate(plan):
        job.update(i / max(1, len(plan)), {"lists": "Site engel listeleri", "yara": "YARA kuralları", "loldrivers": "Zafiyetli sürücü listesi",
                                           "geoip": "IP konum verisi", "clamav": "ClamAV imzaları"}.get(k, k) + " güncelleniyor")
        try:
            if k == "clamav":
                if not core.settings()["engines"].get("clamav", True):
                    continue
                engines.CLAM.update(job)
            elif k == "yara":
                engines.YARA.update(job)
            elif k == "loldrivers":
                deep.update_loldrivers(job)
                deep._lol = None
            elif k == "lists":
                netguard.update_lists(job)
            elif k == "geoip":
                netguard.update_geoip(job)
            st[k] = time.time()
            done.append(k)
        except Exception as e:
            errors.append(f"{k}: {core.friendly_error(e)}")
            core.log_error(f"update {k}", e)
        core.write_json(UPDATE_STATE, st)
    if done:
        core.event("guncelleme", "bilgi", "Güncellendi: " + ", ".join(done), {"errors": errors})
    return {"done": done, "errors": errors}
