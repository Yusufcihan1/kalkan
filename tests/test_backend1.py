import sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import core
core.ensure_dirs()
import engines, deep, netguard, harden, defender, scanner

def t(label, fn):
    t0 = time.time()
    try:
        r = fn()
        print(f"OK   {label} ({time.time()-t0:.1f}s):", str(r)[:300])
        return r
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"FAIL {label}: {e}")

t("sig notepad", lambda: engines.SIG.check(r"C:\Windows\System32\notepad.exe"))
t("sig python", lambda: engines.SIG.check(sys.executable))
t("features", lambda: {k: v for k, v in engines.file_features(r"C:\Windows\System32\notepad.exe").items() if k in ("sha256","entropy","pe")})
t("yara update", lambda: engines.YARA.update())
t("yara info", lambda: engines.YARA.info())
t("scan notepad", lambda: engines.scan_file(r"C:\Windows\System32\notepad.exe"))
t("loldrivers", lambda: deep.update_loldrivers())
items = t("autoruns", lambda: deep.autoruns())
print("  types:", {k: sum(1 for i in items if i["type"]==k) for k in set(i["type"] for i in items)})
fs = t("autorun findings", lambda: deep.autorun_findings()[0])
for f in fs or []: print("   ", f["level"], f["title"], "|", f["why"][:120], "|", f["path"][:100])
t("drivers loaded", lambda: len(deep.loaded_drivers()))
fs = t("driver findings", lambda: deep.driver_findings(items))
for f in fs or []: print("   ", f["level"], f["title"], f["why"][:100])
fs = t("process findings", lambda: deep.process_findings())
for f in fs or []: print("   ", f["level"], f["title"], f["why"][:120])
fs = t("net settings", lambda: deep.network_settings_findings())
for f in fs or []: print("   ", f["level"], f["title"], f["why"][:120])
t("extensions", lambda: [(e["browser"], e["name"], e["store"]) for e in deep.browser_extensions()][:30])
fs = t("ext findings", lambda: deep.extension_findings())
for f in fs or []: print("   ", f["level"], f["title"], f["why"][:120])
