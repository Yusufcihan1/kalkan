import sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import core
core.ensure_dirs()
import engines, deep, netguard, harden, defender, scanner

def t(label, fn):
    t0 = time.time()
    try:
        r = fn()
        print(f"OK   {label} ({time.time()-t0:.1f}s):", str(r)[:500])
        return r
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"FAIL {label}: {e}")

t("lists", lambda: netguard.update_lists())
t("counts", lambda: netguard.BLOCK.counts())
for h in ["google.com", "ptt-kargotakip-tr.com", "edevlet-iade.net", "www.turkiye.gov.tr", "ziraatbank.com.tr", "ziraat-giris.com", "doubleclick.net", "pttavm.com", "aptt.com", "secure-garanti-bbva.online"]:
    print("  ", h, netguard.check_host(h))
t("geoip", lambda: netguard.update_geoip())
t("country", lambda: [netguard.country(i) for i in ("8.8.8.8", "195.175.39.39", "192.168.1.1")])
t("age", lambda: netguard.domain_age_days("www.google.com"))
t("connections", lambda: netguard.connections()[:5])
t("wifi", lambda: netguard.wifi_info())
t("router", lambda: netguard.router_check())
t("upstreams", lambda: netguard.DNS.detect_upstreams())
t("defender", lambda: {k: v for k, v in defender.status().items() if k != "rules"})
t("security", lambda: [(i["key"], i["ok"]) for i in harden.security_checks()["items"]])
t("score", lambda: harden.cached_score())
t("privacy", lambda: harden.privacy_status())
t("pwned", lambda: harden.pwned_count("password123"))
t("defender engine", lambda: engines.defender_status())
