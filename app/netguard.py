"""İnternet koruması: bilgisayarda çalışan DNS filtresi, site kontrolü (tarayıcı eklentisi için), bağlantı izleyici,
program başına internet engeli, Wi-Fi ve modem kontrolü."""
import collections
import ctypes
import gzip
import ipaddress
import os
import re
import shutil
import socket
import threading
import time
import winreg

import core
from core import ENGINE_DIR, UserError

LIST_DIR = os.path.join(ENGINE_DIR, "listeler")
LISTS = {
    "tehdit": [("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", "hagezi-tif.txt"),
               ("https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt", "oltalama.txt"),
               ("https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt", "urlhaus.txt")],
    "reklam": [("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt", "hagezi-light.txt")],
}
CATEGORY_TR = {"tehdit": "zararlı ya da oltalama", "reklam": "reklam / izleyici", "benzer": "taklit site"}


def update_lists(job=None):
    os.makedirs(LIST_DIR, exist_ok=True)
    for cat, items in LISTS.items():
        for url, name in items:
            core.download(url, os.path.join(LIST_DIR, name), timeout=90)
    BLOCK.load(force=True)
    if DNS.applied:
        core.run(["ipconfig", "/flushdns"], timeout=20)


class Blocklist:
    def __init__(self):
        self.sets = {}
        self.loaded = 0
        self.lock = threading.Lock()

    def load(self, force=False):
        if self.loaded and not force:
            return
        sets = {}
        for cat, items in LISTS.items():
            s = set()
            for _, name in items:
                try:
                    with open(os.path.join(LIST_DIR, name), encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line[0] in "#!":
                                continue
                            parts = line.split()
                            d = parts[1] if len(parts) > 1 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]
                            d = d.lower().strip(".")
                            if d.startswith("*."):
                                d = d[2:]
                            if "." in d and d not in ("localhost", "0.0.0.0"):
                                s.add(d)
                except OSError:
                    continue
            sets[cat] = s
        with self.lock:
            self.sets = sets
            self.loaded = time.time()

    def counts(self):
        return {k: len(v) for k, v in self.sets.items()}

    def match(self, host, ads=None):
        """(kategori, eşleşen alan) ya da None."""
        self.load()
        host = host.lower().strip(".")
        if ads is None:
            ads = core.settings()["web"].get("ads", False)
        allow = core.settings().get("dns_allow", [])
        labels = host.split(".")
        suffixes = [".".join(labels[i:]) for i in range(len(labels) - 1)]
        if any(s in allow for s in suffixes):
            return None
        for cat in ("tehdit", "reklam"):
            if cat == "reklam" and not ads:
                continue
            st = self.sets.get(cat, ())
            for s in suffixes:
                if s in st:
                    return cat, s
        return None


BLOCK = Blocklist()

# Türkiye'de sık taklit edilen kurumlar: alan adında geçiyor ama resmi alan adı değilse uyar.
BRANDS = {
    "edevlet": ["turkiye.gov.tr"], "e-devlet": ["turkiye.gov.tr"], "turkiye-gov": ["turkiye.gov.tr"],
    "ptt": ["ptt.gov.tr", "pttbank.gov.tr", "pttavm.com"], "pttkargo": ["ptt.gov.tr"],
    "ziraat": ["ziraatbank.com.tr", "ziraat.com.tr", "ziraatkatilim.com.tr"], "isbank": ["isbank.com.tr"],
    "garanti": ["garantibbva.com.tr", "garanti.com.tr", "garantibbvaemeklilik.com.tr"],
    "akbank": ["akbank.com", "akbank.com.tr"], "yapikredi": ["yapikredi.com.tr"], "halkbank": ["halkbank.com.tr"],
    "vakifbank": ["vakifbank.com.tr"], "denizbank": ["denizbank.com"], "enpara": ["enpara.com"], "qnb": ["qnb.com.tr"],
    "kuveytturk": ["kuveytturk.com.tr"], "papara": ["papara.com"], "trendyol": ["trendyol.com"],
    "hepsiburada": ["hepsiburada.com"], "sahibinden": ["sahibinden.com"], "n11": ["n11.com"], "yurtici": ["yurticikargo.com"],
    "arackargo": ["araskargo.com.tr"], "araskargo": ["araskargo.com.tr"], "mngkargo": ["mngkargo.com.tr"],
    "turkcell": ["turkcell.com.tr"], "vodafone": ["vodafone.com.tr"], "turktelekom": ["turktelekom.com.tr"],
    "sgk": ["sgk.gov.tr", "turkiye.gov.tr"], "gib": ["gib.gov.tr"], "ivd": ["gib.gov.tr"], "hgs": ["ptt.gov.tr", "turkiye.gov.tr"],
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "azure.com",
                                             "windows.com", "msn.com", "bing.com", "microsoft365.com", "xbox.com", "skype.com"],
    "apple": ["apple.com", "icloud.com"], "netflix": ["netflix.com"], "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"], "binance": ["binance.com", "binance.tr"], "btcturk": ["btcturk.com"],
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "rb.gy", "is.gd", "s.id", "shorturl.at", "t.co", "ow.ly"}


def lookalike(host):
    h = host.lower().strip(".")
    flat = h.replace("-", "").replace(".", "")
    for token, official in BRANDS.items():
        if token.replace("-", "") in flat:
            if any(h == o or h.endswith("." + o) for o in official):
                return None
            if token in ("ptt", "gib", "ivd", "hgs", "sgk", "qnb", "n11") and not re.search(rf"(^|[.\-]){token}([.\-]|$)", h):
                continue
            return {"brand": token, "official": official[0]}
    return None


def check_host(host):
    """Tarayıcı eklentisi ve Claude için: bir alan adının durumu."""
    host = (host or "").lower().strip(".")
    if not host or host in ("localhost",) or host.endswith(".local"):
        return {"host": host, "blocked": False}
    try:
        ipaddress.ip_address(host)
        return {"host": host, "blocked": False}
    except ValueError:
        pass
    m = BLOCK.match(host)
    if m:
        cat, d = m
        return {"host": host, "blocked": True, "category": cat, "reason": f"{d} {CATEGORY_TR[cat]} listesinde"}
    la = lookalike(host)
    if la:
        return {"host": host, "blocked": True, "category": "benzer", "warn_only": True,
                "reason": f"Adında '{la['brand']}' geçiyor ama resmi adres {la['official']}. Taklit bir site olabilir."}
    return {"host": host, "blocked": False, "shortener": host in SHORTENERS}


def domain_age_days(domain):
    """RDAP ile alan adının kayıt tarihi (anahtarsız, ücretsiz)."""
    parts = domain.lower().strip(".").split(".")
    cands = [".".join(parts[-3:]), ".".join(parts[-2:])] if len(parts) >= 3 and parts[-2] in ("com", "gov", "org", "net", "gen", "web") else [".".join(parts[-2:])]
    import datetime
    for d in cands:
        try:
            data = core.http_json(f"https://rdap.org/domain/{d}", timeout=12)
        except Exception:
            continue
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                try:
                    t = datetime.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    return d, (datetime.datetime.now(datetime.timezone.utc) - t).days
                except ValueError:
                    pass
    return None, None


# ---------------------------------------------------------------- DNS filtresi

STATE_FILE = os.path.join(core.DATA_DIR, "dns_durum.json")
SKIP_ADAPTERS = re.compile(r"(tailscale|vpn|wireguard|openvpn|hyper-v|virtualbox|vmware|wsl|loopback|zerotier|hamachi|"
                           r"vethernet|npcap|bluetooth|tap-|tun|cisco|fortinet|globalprotect|nordlynx|proton)", re.I)


class DnsFilter:
    def __init__(self):
        self.servers = []
        self.applied = False
        self.cache = {}
        self.ip_names = {}
        self.recent = collections.deque(maxlen=300)
        self.stats = {"queries": 0, "blocked": 0, "day": time.strftime("%Y-%m-%d")}
        self.error = ""
        self.upstreams = []
        self.lock = threading.Lock()

    # -- üst DNS: modemin DHCP ile verdiği, yoksa Quad9
    def detect_upstreams(self):
        mode = core.settings()["web"].get("upstream", "auto")
        if mode == "quad9":
            return ["9.9.9.9", "149.112.112.112"]
        if mode == "cloudflare":
            return ["1.1.1.1", "1.0.0.1"]
        ups = []
        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(k, i)
                    except OSError:
                        break
                    i += 1
                    for name in ("DhcpNameServer",):
                        try:
                            with winreg.OpenKey(k, sub) as s:
                                v = winreg.QueryValueEx(s, name)[0]
                        except OSError:
                            continue
                        for ip in re.split(r"[ ,]+", v or ""):
                            if ip and not ip.startswith("127.") and ip not in ups:
                                ups.append(ip)
        except OSError:
            pass
        return ups + ["9.9.9.9", "1.1.1.1"]

    def resolve_upstream(self, data):
        """Soruyu üst sunuculara aynı anda sorar, ilk gelen cevabı alır (eski/ulaşılamayan bir sunucu beklenmez)."""
        import select
        ups = (self.upstreams or self.detect_upstreams())[:4]
        socks = []
        try:
            for up in ups:
                try:
                    s = socket.socket(socket.AF_INET6 if ":" in up else socket.AF_INET, socket.SOCK_DGRAM)
                    s.setblocking(False)
                    s.sendto(data, (up, 53))
                    socks.append(s)
                except OSError:
                    continue
            deadline = time.time() + 3.0
            while socks and time.time() < deadline:
                ready, _, _ = select.select(socks, [], [], max(0.0, deadline - time.time()))
                for s in ready:
                    try:
                        resp, _ = s.recvfrom(65535)
                        if resp[:2] == data[:2]:
                            return resp
                    except OSError:
                        socks.remove(s)
                        s.close()
                if not ready:
                    break
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass
        return None

    def handle(self, data):
        from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE
        try:
            req = DNSRecord.parse(data)
        except Exception:
            return None
        q = req.q
        name = str(q.qname).rstrip(".").lower()
        today = time.strftime("%Y-%m-%d")
        if self.stats["day"] != today:
            self.stats = {"queries": 0, "blocked": 0, "day": today}
        self.stats["queries"] += 1
        hit = BLOCK.match(name) if name else None
        if hit:
            self.stats["blocked"] += 1
            cat, matched = hit
            self.recent.appendleft({"host": name, "category": cat, "time": time.time()})
            if cat == "tehdit":
                core.event("dns", "tehdit", f"Engellendi: {name}", {"category": cat, "match": matched})
            reply = req.reply()
            if q.qtype == QTYPE.A:
                reply.add_answer(RR(q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
            elif q.qtype == QTYPE.AAAA:
                reply.add_answer(RR(q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=60))
            else:
                reply.header.rcode = RCODE.NXDOMAIN
            return reply.pack()
        key = (name, q.qtype)
        c = self.cache.get(key)
        if c and c[0] > time.time():
            resp = DNSRecord.parse(c[1])
            resp.header.id = req.header.id
            return resp.pack()
        raw = self.resolve_upstream(data)
        if raw is None:
            reply = req.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply.pack()
        try:
            resp = DNSRecord.parse(raw)
            ttl = min([rr.ttl for rr in resp.rr] or [60])
            if resp.header.rcode == 0 and ttl > 0:
                self.cache[key] = (time.time() + min(ttl, 600), raw)
                if len(self.cache) > 20000:
                    self.cache.clear()
            for rr in resp.rr:
                if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                    self.ip_names[str(rr.rdata)] = name
            if len(self.ip_names) > 50000:
                self.ip_names.clear()
        except Exception:
            pass
        return raw

    def serve_udp(self, family, addr):
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.bind((addr, 53))
        self.servers.append(s)

        def loop():
            while True:
                try:
                    data, client = s.recvfrom(4096)
                except OSError:
                    if s.fileno() == -1:
                        return
                    continue
                threading.Thread(target=self._answer_udp, args=(s, data, client), daemon=True).start()
        threading.Thread(target=loop, daemon=True, name=f"dns-udp-{addr}").start()

    def _answer_udp(self, s, data, client):
        try:
            resp = self.handle(data)
            if resp:
                s.sendto(resp, client)
        except OSError:
            pass

    def serve_tcp(self, family, addr):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        s.bind((addr, 53))
        s.listen(32)
        self.servers.append(s)

        def loop():
            while True:
                try:
                    c, _ = s.accept()
                except OSError:
                    return
                threading.Thread(target=self._answer_tcp, args=(c,), daemon=True).start()
        threading.Thread(target=loop, daemon=True, name=f"dns-tcp-{addr}").start()

    def _answer_tcp(self, c):
        with c:
            try:
                c.settimeout(5)
                ln = c.recv(2)
                if len(ln) < 2:
                    return
                n = int.from_bytes(ln, "big")
                data = b""
                while len(data) < n:
                    b = c.recv(n - len(data))
                    if not b:
                        return
                    data += b
                resp = self.handle(data)
                if resp:
                    c.sendall(len(resp).to_bytes(2, "big") + resp)
            except OSError:
                pass

    def start_server(self):
        if self.servers:
            return True
        self.upstreams = self.detect_upstreams()
        BLOCK.load()
        try:
            self.serve_udp(socket.AF_INET, "127.0.0.1")
            self.serve_tcp(socket.AF_INET, "127.0.0.1")
        except OSError as e:
            self.stop_server()
            self.error = ("53 numaralı kapı başka bir program tarafından kullanılıyor (ör. Internet Bağlantı Paylaşımı "
                          f"ya da başka bir DNS aracı): {e}")
            return False
        try:
            self.serve_udp(socket.AF_INET6, "::1")
            self.serve_tcp(socket.AF_INET6, "::1")
        except OSError:
            pass
        self.error = ""
        return True

    def stop_server(self):
        for s in self.servers:
            try:
                s.close()
            except OSError:
                pass
        self.servers = []

    # -- bağdaştırıcıların DNS ayarı
    def adapters(self):
        data = core.ps_json("Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name,InterfaceDescription,ifIndex", timeout=60)
        return [a for a in core.as_list(data) if not SKIP_ADAPTERS.search(f"{a.get('Name')} {a.get('InterfaceDescription')}")]

    def apply(self):
        if not core.is_admin():
            raise UserError("DNS filtresi için Kalkan'ın yönetici olarak çalışması gerekiyor.")
        if not self.start_server():
            raise UserError(self.error)
        # Sunucu gerçekten cevap veriyor mu?
        from dnslib import DNSRecord
        try:
            DNSRecord.question("example.com").send("127.0.0.1", 53, timeout=4)
        except Exception:
            self.stop_server()
            raise UserError("Yerel DNS filtresi cevap vermedi; ayar değiştirilmedi.")
        state = core.read_json(STATE_FILE, {}) or {}
        orig = state.get("original", {})
        for a in self.adapters():
            idx = a["ifIndex"]
            if str(idx) not in orig:
                cur = core.ps_json(f"Get-DnsClientServerAddress -InterfaceIndex {idx} | Select-Object AddressFamily,ServerAddresses", timeout=30)
                static = self._static_dns(idx)
                orig[str(idx)] = {"name": a["Name"], "static": static, "current": core.as_list(cur)}
            core.ps(f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses ('127.0.0.1','::1')", timeout=60)
        core.write_json(STATE_FILE, {"applied": True, "original": orig, "time": time.time()})
        core.run(["ipconfig", "/flushdns"], timeout=20)
        self.applied = True
        core.event("dns", "iyi", "DNS filtresi açıldı")

    def _static_dns(self, idx):
        """Bağdaştırıcıda elle yazılmış DNS var mıydı (yoksa DHCP)."""
        guid = core.ps_json(f"(Get-NetAdapter -InterfaceIndex {idx}).InterfaceGuid", timeout=30)
        if not guid:
            return None
        for fam in ("Tcpip", "Tcpip6"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{fam}\Parameters\Interfaces\{guid}") as k:
                    v = winreg.QueryValueEx(k, "NameServer")[0]
                    if v and "127.0.0.1" not in v:
                        return v
            except OSError:
                continue
        return None

    def restore(self, stop=True):
        state = core.read_json(STATE_FILE, {}) or {}
        for idx, info in (state.get("original") or {}).items():
            if info.get("static"):
                servers = [s for s in re.split(r"[ ,]+", info["static"]) if s]
                core.ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(idx)} -ServerAddresses ({','.join(repr(s) for s in servers)})", timeout=60)
            else:
                core.ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(idx)} -ResetServerAddresses", timeout=60)
        # Ayar dosyası olmasa bile 127.0.0.1'de kalmış bağdaştırıcıları düzelt.
        core.ps("Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses -contains '127.0.0.1' -or $_.ServerAddresses -contains '::1' } | "
                "ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }", timeout=60)
        core.write_json(STATE_FILE, {"applied": False, "original": {}})
        core.run(["ipconfig", "/flushdns"], timeout=20)
        self.applied = False
        if stop:
            self.stop_server()

    def watch_networks(self):
        """Yeni bir ağa bağlanınca (ör. farklı Wi-Fi) yeni bağdaştırıcıyı da filtreye al."""
        seen = set()
        while True:
            time.sleep(20)
            if not self.applied:
                continue
            try:
                self.upstreams = self.detect_upstreams()
                ids = {a["ifIndex"] for a in self.adapters()}
                if ids - seen:
                    cur = core.as_list(core.ps_json("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,ServerAddresses", timeout=30))
                    for c in cur:
                        if c.get("InterfaceIndex") in ids and "127.0.0.1" not in core.as_list(c.get("ServerAddresses")):
                            self.apply()
                            break
                seen = ids
            except Exception as e:
                core.log_error("dns watch", e)

    def status(self):
        BLOCK.load()
        return {"on": self.applied, "error": self.error, "stats": self.stats, "recent": list(self.recent)[:40],
                "lists": BLOCK.counts(), "lists_time": BLOCK.loaded, "upstreams": self.upstreams[:3]}


DNS = DnsFilter()


def set_dns_filter(on):
    core.save_settings({"web": {"dns": bool(on)}})
    if on:
        if not os.path.isdir(LIST_DIR) or not os.listdir(LIST_DIR):
            update_lists()
        DNS.apply()
    else:
        DNS.restore()
        core.event("dns", "bilgi", "DNS filtresi kapatıldı")


# ---------------------------------------------------------------- bağlantı izleyici

GEO_FILE = os.path.join(ENGINE_DIR, "dbip-country-lite.mmdb")
_geo = [None]
COUNTRY_TR = {"US": "ABD", "DE": "Almanya", "NL": "Hollanda", "IE": "İrlanda", "GB": "Birleşik Krallık", "FR": "Fransa",
              "TR": "Türkiye", "RU": "Rusya", "CN": "Çin", "JP": "Japonya", "SG": "Singapur", "SE": "İsveç", "FI": "Finlandiya",
              "CA": "Kanada", "IN": "Hindistan", "BR": "Brezilya", "UA": "Ukrayna", "KR": "Güney Kore", "HK": "Hong Kong",
              "IR": "İran", "KP": "Kuzey Kore", "IT": "İtalya", "ES": "İspanya", "PL": "Polonya", "RO": "Romanya",
              "BG": "Bulgaristan", "CH": "İsviçre", "AT": "Avusturya", "BE": "Belçika", "AU": "Avustralya", "AZ": "Azerbaycan"}


def update_geoip(job=None):
    url = f"https://download.db-ip.com/free/dbip-country-lite-{time.strftime('%Y-%m')}.mmdb.gz"
    tmp = GEO_FILE + ".gz"
    try:
        core.download(url, tmp, timeout=120)
    except Exception:
        prev = time.localtime(time.time() - 32 * 86400)
        core.download(f"https://download.db-ip.com/free/dbip-country-lite-{time.strftime('%Y-%m', prev)}.mmdb.gz", tmp, timeout=120)
    with gzip.open(tmp, "rb") as src, open(GEO_FILE + ".new", "wb") as out:
        shutil.copyfileobj(src, out)
    os.remove(tmp)
    if _geo[0]:
        _geo[0].close()
        _geo[0] = None
    os.replace(GEO_FILE + ".new", GEO_FILE)


def country(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "Yerel ağ"
    except ValueError:
        return ""
    if _geo[0] is None and os.path.isfile(GEO_FILE):
        import maxminddb
        _geo[0] = maxminddb.open_database(GEO_FILE)
    if not _geo[0]:
        return ""
    try:
        r = _geo[0].get(ip) or {}
        code = (r.get("country") or {}).get("iso_code", "")
        return COUNTRY_TR.get(code) or (r.get("country") or {}).get("names", {}).get("en", code)
    except Exception:
        return ""


def connections():
    import psutil
    import deep
    import engines
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        raise UserError("Bağlantıları görmek için yönetici yetkisi gerekiyor.")
    snap = core.process_snapshot()
    rows, per_app = [], {}
    for c in conns:
        if not c.raddr or c.status not in ("ESTABLISHED", "SYN_SENT"):
            continue
        ip = c.raddr.ip
        if ip.startswith(("127.", "::1")) or ip == "::ffff:127.0.0.1":
            continue
        pid = c.pid or 0
        name = snap.get(pid, (0, "?"))[1] or "?"
        path = core.process_path(pid) if pid else ""
        host = DNS.ip_names.get(ip, "")
        key = (name.lower(), ip)
        if key in per_app:
            continue
        per_app[key] = True
        state, why = "guvenli", ""
        if host:
            h = check_host(host)
            if h.get("blocked") and not h.get("warn_only"):
                state, why = "tehdit", h["reason"]
        if state == "guvenli" and path and "\\windowsapps\\" not in path.lower():
            sig = engines.SIG.check(path)
            if not sig.get("valid") and deep.in_user_writable(path):
                state, why = "supheli", "İmzasız ve kullanıcı klasöründen çalışan bir program internete bağlanıyor"
            elif DNS.applied and not host and not sig.get("valid"):
                state, why = "supheli", "İmzasız program, adres sormadan doğrudan bir IP adresine bağlanıyor"
        elif not path and pid > 4:
            state = "bilinmiyor"
        rows.append({"pid": pid, "app": name, "path": path, "ip": ip, "port": c.raddr.port, "host": host,
                     "country": country(ip), "state": state, "why": why})
    order = {"tehdit": 0, "supheli": 1, "bilinmiyor": 2, "guvenli": 3}
    rows.sort(key=lambda r: (order.get(r["state"], 9), r["app"].lower()))
    return rows


RULE_PREFIX = "Kalkan engel: "


def block_app(path):
    if not path or not os.path.isfile(path):
        raise UserError("Programın dosyası bulunamadı.")
    name = RULE_PREFIX + os.path.basename(path)
    for d in ("out", "in"):
        code, out = core.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={d}", "action=block",
                              f"program={path}", "enable=yes", "profile=any"], timeout=30)
        if code:
            raise UserError("Güvenlik duvarı kuralı eklenemedi: " + out.strip()[:200])
    core.event("ag", "bilgi", f"İnternet erişimi kesildi: {os.path.basename(path)}", {"path": path})
    return name


def unblock_app(name):
    core.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], timeout=30)
    core.event("ag", "bilgi", f"İnternet erişimi geri verildi: {name[len(RULE_PREFIX):]}")


def blocked_apps():
    data = core.ps_json(f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue | "
                        "Where-Object Direction -eq 'Outbound' | ForEach-Object { [pscustomobject]@{Name=$_.DisplayName;"
                        "Program=($_ | Get-NetFirewallApplicationFilter).Program} }", timeout=60)
    return core.as_list(data)


# ---------------------------------------------------------------- Wi-Fi ve modem

def wifi_info():
    code, out = core.run(["netsh", "wlan", "show", "interfaces"], timeout=20)
    info = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        kl = k.lower()
        if kl in ("ssid",):
            info["ssid"] = v
        elif kl in ("authentication", "kimlik doğrulama", "kimlik doğrulaması"):
            info["auth"] = v
        elif kl in ("cipher", "şifre"):
            info["cipher"] = v
        elif kl in ("state", "durum"):
            info["state"] = v
        elif kl in ("signal", "sinyal"):
            info["signal"] = v
    return info


def default_gateway():
    data = core.ps_json("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | "
                        "Select-Object -First 1 NextHop,InterfaceIndex", timeout=30) or {}
    return data.get("NextHop"), data.get("InterfaceIndex")


ROUTER_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "Web paneli (HTTP)", 443: "Web paneli (HTTPS)",
                445: "Dosya paylaşımı (SMB)", 1900: "UPnP", 7547: "TR-069 uzaktan yönetim", 8080: "Web paneli (8080)",
                8443: "Web paneli (8443)", 8291: "MikroTik Winbox", 5000: "UPnP / NAS"}


def port_open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def router_check(job=None):
    findings = []
    w = wifi_info()
    if w.get("ssid"):
        auth = (w.get("auth") or "").upper()
        if "OPEN" in auth or "AÇIK" in auth or auth in ("", "NONE"):
            findings.append({"level": "tehdit", "title": "Wi-Fi şifresiz", "why": "Bu ağdaki herkes trafiğini görebilir. Modemde WPA2 ya da WPA3 aç."})
        elif "WEP" in auth or ("WPA-" in auth and "WPA2" not in auth and "WPA3" not in auth):
            findings.append({"level": "tehdit", "title": f"Eski Wi-Fi şifrelemesi ({w.get('auth')})", "why": "Dakikalar içinde kırılabilir. Modemden WPA2-AES ya da WPA3 seç."})
        elif "TKIP" in (w.get("cipher") or "").upper():
            findings.append({"level": "supheli", "title": "Wi-Fi TKIP şifrelemesi", "why": "Zayıf. Modemde AES (CCMP) seç."})
    gw, _ = default_gateway()
    open_ports = []
    if gw:
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(16) as ex:
            res = dict(zip(ROUTER_PORTS, ex.map(lambda p: port_open(gw, p), ROUTER_PORTS)))
        open_ports = [p for p, ok in res.items() if ok]
        if 23 in open_ports:
            findings.append({"level": "tehdit", "title": "Modemde Telnet açık", "why": "Şifreler düz metin gider; Mirai gibi botlar bu kapıdan girer. Modem panelinden kapat."})
        if 21 in open_ports:
            findings.append({"level": "supheli", "title": "Modemde FTP açık", "why": "Kullanmıyorsan modem panelinden kapat."})
        if 80 in open_ports and 443 not in open_ports:
            findings.append({"level": "supheli", "title": "Modem paneli şifresiz (HTTP)", "why": "Panel şifren ağda düz metin gider. Mümkünse HTTPS'i aç ve varsayılan panel şifresini değiştir."})
        if 8291 in open_ports:
            findings.append({"level": "supheli", "title": "MikroTik Winbox açık", "why": "Güncel değilse uzaktan ele geçirilebilir."})
    # DNS ele geçirilmesi: modemin verdiği DNS bilinmeyen bir genel adresse uyar.
    import deep
    for ip in DNS.detect_upstreams()[:-2]:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not (a.is_private or ip in deep.KNOWN_DNS):
            findings.append({"level": "supheli", "title": f"Modem bilinmeyen bir DNS veriyor: {ip}",
                             "why": "İnternet sağlayıcının DNS'i değilse modemin DNS ayarı değiştirilmiş olabilir (DNS ele geçirme)."})
    return {"wifi": w, "gateway": gw, "open_ports": [{"port": p, "name": ROUTER_PORTS[p]} for p in open_ports],
            "findings": findings}


def lan_devices(job=None):
    """Aynı ağdaki cihazlar: /24 ağına ping atılır, sonra ARP tablosu okunur."""
    gw, idx = default_gateway()
    if not gw or ":" in gw:
        return []
    prefix = gw.rsplit(".", 1)[0]
    icmp = ctypes.WinDLL("iphlpapi")
    icmp.IcmpCreateFile.restype = ctypes.c_void_p
    icmp.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    icmp.IcmpCloseHandle.argtypes = [ctypes.c_void_p]

    def ping(ip):
        h = icmp.IcmpCreateFile()
        try:
            buf = ctypes.create_string_buffer(64)
            reply = ctypes.create_string_buffer(128)
            addr = int.from_bytes(socket.inet_aton(ip), "little")
            return icmp.IcmpSendEcho(h, addr, buf, 8, None, reply, 128, 400) > 0
        finally:
            icmp.IcmpCloseHandle(h)

    import concurrent.futures as cf
    ips = [f"{prefix}.{i}" for i in range(1, 255)]
    with cf.ThreadPoolExecutor(64) as ex:
        alive = {ip for ip, ok in zip(ips, ex.map(ping, ips)) if ok}
    code, out = core.run(["arp", "-a"], timeout=20)
    macs = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})\s+(\S+)", line, re.I)
        if m and m.group(1).startswith(prefix + "."):
            macs[m.group(1)] = m.group(2).upper()
    my_ips = {a.address for addrs in __import__("psutil").net_if_addrs().values() for a in addrs if a.family == socket.AF_INET}
    devices = []
    for ip in sorted(alive | set(macs), key=lambda x: int(x.rsplit(".", 1)[1])):
        if ip.endswith(".255"):
            continue
        try:
            socket.setdefaulttimeout(0.5)
            name = socket.gethostbyaddr(ip)[0]
        except OSError:
            name = ""
        finally:
            socket.setdefaulttimeout(None)
        devices.append({"ip": ip, "mac": macs.get(ip, ""), "name": name, "gateway": ip == gw, "me": ip in my_ips,
                        "random_mac": bool(macs.get(ip)) and macs[ip][1] in "26AE"})
    return devices
