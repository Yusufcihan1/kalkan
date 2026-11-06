"""Kalkan ajanı: yönetici yetkisiyle arka planda çalışır. Anlık koruma, zamanlayıcı, simge, uyarı pencereleri ve
arayüzün konuştuğu yerel API (127.0.0.1, rastgele jeton, yalnız Kalkan penceresinden gelen istekler)."""
import json
import mimetypes
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import core
from core import UserError

TOKEN = os.environ.get("KALKAN_TOKEN") if os.environ.get("KALKAN_GELISTIRME") == "1" and os.environ.get("KALKAN_TOKEN") \
    else secrets.token_urlsafe(24)
SESSION_FILE = os.path.join(core.DATA_DIR, "oturum.json")
EXT_PORT = 47615
PORT = [0]
STARTED = time.time()
TRAY = [None]


# ---------------------------------------------------------------- durum özeti

def status_summary():
    import defender
    import engines
    import harden
    import netguard
    import realtime
    import scanner
    s = core.settings()
    last = scanner.load_last()
    alerts = realtime.open_alerts()
    open_threats = [f for f in (last or {}).get("findings", []) if f.get("status") == "open" and f["level"] == "tehdit"]
    open_warn = [f for f in (last or {}).get("findings", []) if f.get("status") == "open" and f["level"] in ("supheli", "istenmeyen")]
    score = harden.cached_score() or {}
    dstat = DEF_CACHE.get("data") or {}
    rt_on = s["realtime"].get("processes") and s["realtime"].get("downloads")
    ransom_on = s["ransom"].get("canaries") and s["ransom"].get("burst")
    layers = {
        "realtime": {"on": bool(rt_on), "stat": f"Bugün {realtime.PROC.checked} program denetlendi"},
        "ransom": {"on": bool(ransom_on), "stat": f"{len(s.get('vault_folders', []))} klasör yedekte" if s.get("vault_folders") else "Yedek kasası boş"},
        "web": {"on": netguard.DNS.applied, "stat": f"Bugün {netguard.DNS.stats['blocked']} engel" if netguard.DNS.applied else "DNS filtresi kapalı"},
        "defender": {"on": dstat.get("asr_on", 0) > 0, "stat": f"{dstat.get('asr_on', 0)} / {dstat.get('asr_total', 18)} kural açık" if dstat else "Denetleniyor"},
    }
    if any(a["level"] == "tehdit" for a in alerts) or open_threats:
        level = "tehdit"
    elif open_warn or alerts or score.get("open") or not all(l["on"] for l in layers.values()):
        level = "dikkat"
    else:
        level = "korunuyor"
    job = core.running_job("scan")
    return {
        "level": level, "layers": layers, "alerts": len(alerts), "open_threats": len(open_threats),
        "open_warnings": len(open_warn), "score": score, "quiet": core.quiet_now(), "quiet_manual": s.get("quiet", False),
        "last_scan": {k: last.get(k) for k in ("kind", "finished", "files", "cancelled")} | {"findings": len(last.get("findings", []))} if last else None,
        "scan_job": job.id if job else None, "admin": core.is_admin(), "version": core.VERSION,
        "engines": {k: {"on": v.get("on"), "ok": v.get("installed", True) and v.get("ready", True) and (v.get("key", True))}
                    for k, v in engines.engine_status().items()},
    }


DEF_CACHE = {"time": 0, "data": None}


def defender_cached(force=False):
    import defender
    if force or time.time() - DEF_CACHE["time"] > 300 or DEF_CACHE["data"] is None:
        try:
            DEF_CACHE["data"] = defender.status()
            DEF_CACHE["time"] = time.time()
        except Exception as e:
            core.log_error("defender status", e)
    return DEF_CACHE["data"] or {}


# ---------------------------------------------------------------- işlemler

def build_ops():
    import ai
    import defender
    import engines
    import harden
    import netguard
    import quarantine
    import realtime
    import scanner

    def job(kind, fn, title=""):
        return lambda a: {"job": core.start_job(kind, lambda j: fn(j, a), title=title).id}

    def settings_set(a):
        patch = a.get("patch") or {}
        allowed = {"realtime", "ransom", "web", "quiet", "schedule", "engines", "exclusions", "vault_folders", "vault_limit_gb", "dns_allow"}
        patch = {k: v for k, v in patch.items() if k in allowed}
        s = core.save_settings(patch)
        if "ransom" in patch:
            realtime.SHIELD.place_canaries()
        if "quiet" in patch:
            refresh_tray()
        return s

    def defender_set(a):
        k, v = a.get("what"), a.get("mode")
        if k == "rule":
            defender.set_rule(a["id"], v)
        elif k == "recommended":
            defender.enable_all_recommended() if v == "on" else defender.disable_all()
        elif k == "cfa":
            defender.set_cfa(v)
        elif k == "network":
            defender.set_network(v)
        elif k == "pua":
            defender.set_pua(v)
        elif k == "cfa_allow":
            defender.cfa_allow(a["path"])
        elif k == "cfa_remove":
            defender.cfa_remove(a["path"])
        return defender_cached(force=True)

    def secret_set(a):
        name = a.get("name")
        if name not in ("abusech_key", "virustotal_key"):
            raise UserError("Bilinmeyen anahtar")
        engines.set_secret(name, (a.get("value") or "").strip())
        return engines.engine_status()

    def pick(a):
        if a.get("kind") == "folder":
            p = core_dialog("folder")
        else:
            p = core_dialog("file")
        return {"path": p}

    def dns_set(a):
        netguard.set_dns_filter(bool(a.get("on")))
        return netguard.DNS.status()

    def dns_allow(a):
        s = core.settings()
        lst = [d for d in s.get("dns_allow", []) if d != a.get("host")]
        if a.get("add"):
            lst.append(a["host"].lower().strip("."))
        core.save_settings({"dns_allow": lst})
        netguard.DNS.cache.clear()
        core.run(["ipconfig", "/flushdns"], timeout=20)
        return {"allow": lst}

    def open_path(a):
        p = a.get("path", "")
        if os.path.exists(p):
            core.launch_unelevated(["explorer.exe", "/select," + p] if os.path.isfile(p) else ["explorer.exe", p])
        return {}

    def ext_info(a):
        d = os.path.join(core.APP_DIR if core.FROZEN else os.path.dirname(core.APP_DIR), "eklenti")
        if a.get("open") and os.path.isdir(d):
            core.launch_unelevated(["explorer.exe", d])
        if a.get("browser"):
            core.launch_unelevated(["cmd.exe", "/c", "start", "", "msedge.exe" if a["browser"] == "edge" else "chrome.exe",
                                    "edge://extensions" if a["browser"] == "edge" else "chrome://extensions"])
        return {"dir": d, "exists": os.path.isdir(d), "connected": time.time() - EXT_SEEN[0] < 600}

    def explain_alert(a):
        al = realtime.ALERTS.get(a.get("id"))
        if not al:
            raise UserError("Uyarı bulunamadı")
        d = al["data"]
        path = d.get("path") or (d.get("paths") or [None])[0]
        if d.get("qid"):
            m = core.read_json(os.path.join(core.QUAR_DIR, d["qid"] + ".json"), {})
            return {"job": core.start_job("ai", lambda j: explain_quarantined(j, m, al), title="Claude inceliyor").id}
        return {"job": core.start_job("ai", lambda j: ai.explain_file(j, path, {"alert": al["title"], "text": al["text"]}),
                                      title="Claude inceliyor").id}

    def explain_quarantined(j, m, al):
        # Karantinadaki dosyayı geçici olarak çözüp özetini çıkarır, sonra siler.
        import tempfile
        tmpdir = tempfile.mkdtemp(dir=core.QUAR_DIR)
        tmp = os.path.join(tmpdir, m.get("name", "dosya"))
        quarantine._xor_copy(os.path.join(core.QUAR_DIR, m["id"] + ".bin"), tmp)
        try:
            r = ai.explain_file(j, tmp, {"alert": al["title"] if al else "", "original_path": m.get("path"),
                                         "detection": m.get("detection")})
            r["file"]["path"] = m.get("path")
            return r
        finally:
            try:
                os.remove(tmp)
                os.rmdir(tmpdir)
            except OSError:
                pass

    def explain_q(a):
        m = core.read_json(os.path.join(core.QUAR_DIR, a.get("id", "") + ".json"))
        if not m:
            raise UserError("Karantina kaydı yok")
        return {"job": core.start_job("ai", lambda j: explain_quarantined(j, m, None), title="Claude inceliyor").id}

    def explain_finding(a):
        res = scanner.load_last() or {}
        f = next((x for x in res.get("findings", []) if x["id"] == a.get("id")), None)
        if not f:
            raise UserError("Bulgu bulunamadı")
        path = f.get("path") if os.path.isfile(f.get("path") or "") else (f.get("target") or {}).get("path")
        ctx = {k: f.get(k) for k in ("title", "why", "command", "kind", "level")}
        return {"job": core.start_job("ai", lambda j: ai.explain_file(j, path, ctx), title="Claude inceliyor").id}

    def quiet_set(a):
        core.save_settings({"quiet": bool(a.get("on"))})
        refresh_tray()
        return {"quiet": core.quiet_now()}

    def vault_folders(a):
        folders = [f for f in a.get("folders", []) if os.path.isdir(f)]
        core.save_settings({"vault_folders": folders})
        return realtime.VAULT.info()

    ops = {
        "status": lambda a: status_summary(),
        "alerts": lambda a: realtime.open_alerts(),
        "alert": lambda a: realtime.ALERTS.get(a.get("id")) or {},
        "alert_resolve": lambda a: {"message": realtime.resolve_alert(a["id"], a["action"])},
        "alert_explain": explain_alert,
        "last_scan": lambda a: scanner.load_last(),
        "scan_start": lambda a: {"job": scanner.start_scan(a.get("kind", "quick"), a.get("paths")).id},
        "finding_action": lambda a: {"message": scanner.act_on_finding(a["id"], a["action"])},
        "finding_explain": explain_finding,
        "quarantine_list": lambda a: quarantine.list_quarantine(),
        "quarantine_restore": lambda a: {"path": quarantine.restore(a["id"])},
        "quarantine_delete": lambda a: quarantine.delete(a["id"]) or {},
        "quarantine_explain": explain_q,
        "undo_list": lambda a: quarantine.undo_list(),
        "undo": lambda a: {"message": quarantine.undo(int(a["index"]))},
        "events": lambda a: core.events(int(a.get("limit", 300)), a.get("kind")),
        "settings_get": lambda a: core.settings(),
        "settings_set": settings_set,
        "quiet_set": quiet_set,
        "engines": lambda a: engines.engine_status(),
        "secret_set": secret_set,
        "engines_update": job("update", lambda j, a: scanner.update_engines(j, a.get("which")), "Motorlar güncelleniyor"),
        "defender_status": lambda a: defender_cached(force=bool(a.get("force"))),
        "defender_set": defender_set,
        "defender_blocks": lambda a: defender.recent_blocks(),
        "harden_checks": job("harden", lambda j, a: harden.security_checks(), "Güvenlik denetleniyor"),
        "harden_fix": lambda a: {"message": harden.fix(a["key"])},
        "open_settings": lambda a: harden.open_settings(a["uri"]) or {},
        "privacy": lambda a: harden.privacy_status(),
        "privacy_set": lambda a: harden.set_privacy(a["key"], bool(a.get("private"))) or harden.privacy_status(),
        "pwned": lambda a: {"count": harden.pwned_count(a.get("password", ""))},
        "winget_list": job("winget", lambda j, a: harden.winget_upgrades(), "Güncellemeler aranıyor"),
        "winget_upgrade": job("winget_up", lambda j, a: harden.winget_upgrade(j, a["id"]), "Program güncelleniyor"),
        "dns_status": lambda a: netguard.DNS.status(),
        "dns_set": dns_set,
        "dns_allow": dns_allow,
        "check_host": lambda a: netguard.check_host(a.get("host", "")),
        "connections": lambda a: netguard.connections(),
        "block_app": lambda a: {"rule": netguard.block_app(a["path"])},
        "unblock_app": lambda a: netguard.unblock_app(a["name"]) or {},
        "blocked_apps": lambda a: netguard.blocked_apps(),
        "wifi_check": job("wifi", lambda j, a: netguard.router_check(j), "Ağ kontrol ediliyor"),
        "lan_devices": job("lan", lambda j, a: netguard.lan_devices(j), "Ağdaki cihazlar aranıyor"),
        "vault_info": lambda a: realtime.VAULT.info(),
        "vault_folders": vault_folders,
        "vault_backup": job("vault", lambda j, a: realtime.VAULT.backup(j), "Yedekleniyor"),
        "vault_search": lambda a: realtime.VAULT.search(a.get("text", "")),
        "vault_restore": lambda a: {"ok": realtime.VAULT.restore_file(a["path"], version_time=a.get("time"))},
        "snapshots": lambda a: realtime.list_snapshots(),
        "snapshot_create": job("snapshot", lambda j, a: realtime.create_snapshot("elle"), "Anlık görüntü alınıyor"),
        "pick": pick,
        "open_path": open_path,
        "extension": ext_info,
        "ai_key_status": lambda a: ai.key_status(),
        "ai_key_set": job("ai_key", lambda j, a: ai.set_key(j, a.get("key")), "Anahtar deneniyor"),
        "ai_explain": job("ai", lambda j, a: ai.explain_file(j, a.get("path")), "Claude inceliyor"),
        "ai_scam": job("ai", lambda j, a: ai.scam_check(j, a.get("text", ""), a.get("image", ""), a.get("image_type", "image/png")), "Claude inceliyor"),
        "ai_chat": job("ai", lambda j, a: ai.chat(j, a.get("text", ""), bool(a.get("reset"))), "Claude düşünüyor"),
        "ai_chat_state": lambda a: ai.chat_state(),
        "ai_chat_reset": lambda a: ai.chat(None, "", reset=True),
        "ai_proposal": lambda a: {"message": ai.run_proposal(a["id"])},
        "ai_quarantine": lambda a: quarantine.quarantine_file(a["path"], "Claude incelemesinden sonra", "Kullanıcı kararı", source="asistan"),
        "ai_report": job("ai", lambda j, a: ai.scan_report(j), "Rapor hazırlanıyor"),
        "job_cancel": lambda a: _job_flag(a["id"], "cancelled", True),
        "job_pause": lambda a: _job_flag(a["id"], "paused", bool(a.get("on", True))),
        "jobs": lambda a: [j.public() for j in core.JOBS.values() if j.status == "running"],
    }
    if os.environ.get("KALKAN_GELISTIRME") == "1":
        ops["test_alert"] = lambda a: realtime.raise_alert(
            "download", "supheli", "İndirdiğin dosya şüpheli: deneme.exe", "Açmadan önce bir bak. Algılayan: YARA: Deneme_Kurali.",
            [("quarantine", "Karantinaya al"), ("explain", "Bu ne?"), ("dismiss", "Bırak")], {"path": ""}, popup=False)
    return ops


def _job_flag(jid, attr, val):
    j = core.JOBS.get(jid)
    if j:
        setattr(j, attr, val)
    return j.public() if j else {}


def core_dialog(kind):
    """Dosya/klasör seçme penceresi (ajanın kendi iş parçacığında)."""
    import queue
    q = queue.Queue()

    def run():
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            p = filedialog.askdirectory(title="Klasör seç") if kind == "folder" else filedialog.askopenfilename(title="Dosya seç")
            root.destroy()
            q.put(os.path.normpath(p) if p else "")
        except Exception:
            q.put("")
    threading.Thread(target=run, daemon=True).start()
    return q.get()


OPS = {}


# ---------------------------------------------------------------- istemci denetimi

_client_ok = {}


def client_allowed(port):
    """İsteği yapan süreç: Kalkan penceresinin Edge'i ya da Kalkan'ın kendisi olmalı."""
    import psutil
    if port in _client_ok and time.time() - _client_ok[port][1] < 30:
        return _client_ok[port][0]
    pid = None
    try:
        for c in psutil.net_connections(kind="tcp4"):
            if c.laddr and c.laddr.port == port and c.raddr and c.raddr.port == PORT[0]:
                pid = c.pid
                break
    except Exception:
        pid = None
    ok = False
    if pid:
        try:
            p = psutil.Process(pid)
            if pid == os.getpid():
                ok = True
            else:
                profile = ("--user-data-dir=" + core.USER_DIR).lower()   # ana pencere ve uyarı pencereleri
                chain = [p] + p.parents()[:3]
                for q in chain:
                    name = (q.name() or "").lower()
                    if name == "msedge.exe":
                        if any(arg.lower().startswith(profile) for arg in q.cmdline()):
                            ok = True
                            break
                    elif name in ("kalkan.exe", "python.exe") and q.pid == os.getpid():
                        ok = True
                        break
        except Exception:
            ok = False
    else:
        ok = True   # bağlantı tablosu okunamadıysa jeton yeterli
    if not ok:
        try:
            name = psutil.Process(pid).name() if pid else "?"
        except Exception:
            name = "?"
        core.log_error(f"API isteği reddedildi: süreç {pid} ({name})")
    _client_ok[port] = (ok, time.time())
    return ok


class Handler(BaseHTTPRequestHandler):
    server_version = "Kalkan"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", cache=False):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "max-age=3600" if cache else "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _auth(self, query):
        tok = self.headers.get("X-Token") or (query.get("t") or [""])[0]
        if not secrets.compare_digest(tok, TOKEN):
            return False
        if os.environ.get("KALKAN_GELISTIRME") == "1":
            return True
        return client_allowed(self.client_address[1])

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = unquote(u.path)
        if path.startswith("/api/"):
            if not self._auth(q):
                return self._send(403, {"error": "yetkisiz"})
            if path == "/api/ping":
                return self._send(200, {"ok": True})
            if path.startswith("/api/job/"):
                j = core.JOBS.get(path.split("/")[3])
                return self._send(200 if j else 404, j.public() if j else {"error": "yok"})
            return self._send(404, {"error": "yok"})
        return self._static(path)

    def _static(self, path):
        if path in ("", "/"):
            path = "/index.html"
        full = os.path.normpath(os.path.join(core.STATIC_DIR, path.lstrip("/")))
        if not full.startswith(os.path.normpath(core.STATIC_DIR)) or not os.path.isfile(full):
            return self._send(404, b"yok", "text/plain")
        with open(full, "rb") as f:
            data = f.read()
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        return self._send(200, data, ctype)

    def do_POST(self):
        u = urlparse(self.path)
        if not self._auth(parse_qs(u.query)):
            return self._send(403, {"error": "yetkisiz"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 40 * 1024 * 1024:
            return self._send(413, {"error": "çok büyük"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "geçersiz istek"})
        if u.path != "/api/run":
            return self._send(404, {"error": "yok"})
        op = body.get("op")
        fn = OPS.get(op)
        if not fn:
            return self._send(404, {"error": f"bilinmeyen işlem: {op}"})
        try:
            return self._send(200, {"result": fn(body.get("args") or {})})
        except UserError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            core.log_error(f"op {op}", e)
            return self._send(500, {"error": core.friendly_error(e)})


# ---------------------------------------------------------------- tarayıcı eklentisi için dar API

EXT_SEEN = [0]


class ExtHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        import netguard
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/check":
            EXT_SEEN[0] = time.time()
            r = netguard.check_host((q.get("h") or [""])[0][:253])
            if r.get("blocked"):
                core.event("eklenti", "tehdit" if r.get("category") == "tehdit" else "supheli",
                           f"Tarayıcıda uyarıldı: {r['host']}", {"reason": r.get("reason")})
            body = json.dumps({k: r.get(k) for k in ("blocked", "category", "reason", "warn_only")}).encode()
        elif u.path == "/ping":
            EXT_SEEN[0] = time.time()
            body = b'{"ok":true,"app":"Kalkan"}'
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------- pencereler ve simge

def app_url(page="", extra=""):
    return f"http://127.0.0.1:{PORT[0]}/{page}?t={TOKEN}{extra}"


def open_main_window():
    return core.open_app_window(app_url())


def show_alert_popup(alert):
    if core.quiet_now():
        tray_notify(alert["title"], alert["text"][:200])
        return
    l, t, r, b = core.work_area()
    w, h = 460, 360
    core.open_app_window(app_url("uyari.html", f"&id={alert['id']}"), size=(w, h), position=(r - w - 16, b - h - 16),
                         profile=os.path.join(core.USER_DIR, "uyari"))
    tray_notify(alert["title"], alert["text"][:200])


def tray_notify(title, text):
    icon = TRAY[0]
    if icon:
        try:
            icon.notify(text, title)
        except Exception:
            pass


def refresh_tray():
    if TRAY[0]:
        try:
            TRAY[0].update_menu()
        except Exception:
            pass


def start_tray(on_exit):
    try:
        import pystray
        from PIL import Image
        import scanner
        ico = os.path.join(core.STATIC_DIR, "icon.png")
        img = Image.open(ico) if os.path.isfile(ico) else Image.new("RGBA", (64, 64), (11, 110, 91, 255))
        menu = pystray.Menu(
            pystray.MenuItem("Kalkan'ı aç", lambda i, it: open_main_window(), default=True),
            pystray.MenuItem("Hızlı tara", lambda i, it: scanner.start_scan("quick")),
            pystray.MenuItem("Sessiz mod", lambda i, it: (core.save_settings({"quiet": not core.settings().get("quiet")}), refresh_tray()),
                             checked=lambda it: bool(core.settings().get("quiet"))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Kalkan'ı kapat", lambda i, it: on_exit()),
        )
        icon = pystray.Icon("Kalkan", img, "Kalkan: koruma açık", menu)
        TRAY[0] = icon
        icon.run_detached()
    except Exception as e:
        core.log_error("tray", e)


# ---------------------------------------------------------------- zamanlayıcı

SCHED_FILE = os.path.join(core.DATA_DIR, "zamanlayici.json")


def scheduler():
    import engines
    import harden
    import realtime
    import scanner
    st = core.read_json(SCHED_FILE, {})
    tick = 0
    while True:
        time.sleep(30)
        tick += 1
        try:
            now = time.time()
            today = time.strftime("%Y-%m-%d")
            lt = time.localtime()
            engines.CLAM.idle_check()
            if tick % 2 == 0:
                realtime.SHIELD.snapshot_writes()
            busy = core.running_job("scan") or core.running_job("update")
            if not busy and now - st.get("update_check", 0) > 3 * 3600:
                st["update_check"] = now
                core.start_job("update", lambda j: scanner.update_engines(j), title="Motorlar güncelleniyor")
            if now - st.get("vault", 0) > 3600 and core.settings().get("vault_folders"):
                st["vault"] = now
                threading.Thread(target=realtime.VAULT.backup, daemon=True).start()
            if core.settings()["ransom"].get("snapshots", True) and st.get("snapshot_day") != today and lt.tm_hour >= 11:
                st["snapshot_day"] = today
                threading.Thread(target=realtime.create_snapshot, daemon=True).start()
            if st.get("score_day") != today:
                st["score_day"] = today
                threading.Thread(target=harden.security_checks, daemon=True).start()
            if now - DEF_CACHE["time"] > 600:
                threading.Thread(target=defender_cached, daemon=True).start()
            sch = core.settings()["schedule"]
            idle_ok = (not sch.get("idle_only", True)) or core.idle_seconds() > 300
            if not busy and not core.quiet_now():
                late = lambda h: lt.tm_hour >= (h + 3) % 24   # noqa: E731  (boşta beklenmedi; 3 saat sonra yine de)
                if sch.get("deep") and lt.tm_wday == int(sch.get("deep_day", 6)) and st.get("deep_day") != today \
                        and lt.tm_hour >= int(sch.get("quick_hour", 13)) and (idle_ok or late(int(sch.get("quick_hour", 13)))):
                    st["deep_day"] = today
                    st["quick_day"] = today
                    scanner.start_scan("deep")
                elif sch.get("quick") and st.get("quick_day") != today and lt.tm_hour >= int(sch.get("quick_hour", 13)) \
                        and (idle_ok or late(int(sch.get("quick_hour", 13)))):
                    st["quick_day"] = today
                    scanner.start_scan("quick")
            core.write_json(SCHED_FILE, st)
        except Exception as e:
            core.log_error("scheduler", e)


# ---------------------------------------------------------------- başlatma ve kapatma

STOP = threading.Event()


def secure_data_dir():
    if not core.is_admin():
        return
    core.run(["icacls", core.DATA_DIR, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F",
              "*S-1-5-32-545:(OI)(CI)RX"], timeout=60)


def shutdown():
    import engines
    import netguard
    if STOP.is_set():
        return
    STOP.set()
    try:
        if netguard.DNS.applied:
            netguard.DNS.restore()
    except Exception as e:
        core.log_error("dns restore", e)
    try:
        engines.CLAM.stop()
    except Exception:
        pass
    try:
        os.remove(SESSION_FILE)
    except OSError:
        pass
    if TRAY[0]:
        try:
            TRAY[0].stop()
        except Exception:
            pass
    core.event("ajan", "bilgi", "Kalkan kapatıldı")


def run_agent(open_window=False):
    import netguard
    import realtime
    core.ensure_dirs()
    secure_data_dir()
    OPS.update(build_ops())
    dev_port = int(os.environ.get("KALKAN_PORT", "0")) if os.environ.get("KALKAN_GELISTIRME") == "1" else 0
    server = ThreadingHTTPServer(("127.0.0.1", dev_port), Handler)
    PORT[0] = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True, name="api").start()
    try:
        ext = ThreadingHTTPServer(("127.0.0.1", EXT_PORT), ExtHandler)
        threading.Thread(target=ext.serve_forever, daemon=True, name="ext").start()
    except OSError as e:
        core.log_error("ext server", e)
    core.write_json(SESSION_FILE, {"port": PORT[0], "token": TOKEN, "pid": os.getpid(), "started": STARTED})
    core.event("ajan", "bilgi", "Kalkan başladı", {"admin": core.is_admin()})
    realtime.ALERT_HOOK[0] = show_alert_popup
    realtime.start_all()
    # DNS filtresi açıksa (ya da önceki çalışmadan açık kaldıysa) yeniden kur.
    try:
        st = core.read_json(netguard.STATE_FILE, {}) or {}
        if core.settings()["web"].get("dns"):
            netguard.DNS.apply()
        elif st.get("applied"):
            netguard.DNS.restore()
    except Exception as e:
        core.log_error("dns start", e)
    threading.Thread(target=netguard.DNS.watch_networks, daemon=True, name="dnswatch").start()
    threading.Thread(target=scheduler, daemon=True, name="scheduler").start()
    threading.Thread(target=lambda: __import__("anthropic"), daemon=True).start()
    threading.Thread(target=defender_cached, daemon=True).start()
    start_tray(lambda: (shutdown(), os._exit(0)))
    if open_window:
        open_main_window()
    try:
        import win32api
        win32api.SetConsoleCtrlHandler(lambda ev: shutdown() or False, True)
    except Exception:
        pass
    _watch_session_end()
    try:
        while not STOP.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()


def _watch_session_end():
    """Oturum kapanırken / bilgisayar kapanırken DNS ayarını geri al (gizli bir pencere WM_QUERYENDSESSION alır)."""
    def run():
        try:
            import win32con
            import win32gui

            def proc(hwnd, msg, wparam, lparam):
                if msg in (win32con.WM_QUERYENDSESSION, win32con.WM_ENDSESSION):
                    shutdown()
                    return True
                return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)
            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = proc
            wc.lpszClassName = "KalkanOturum"
            win32gui.RegisterClass(wc)
            win32gui.CreateWindow("KalkanOturum", "Kalkan", 0, 0, 0, 0, 0, 0, 0, 0, None)
            win32gui.PumpMessages()
        except Exception as e:
            core.log_error("session watch", e)
    threading.Thread(target=run, daemon=True, name="session").start()
