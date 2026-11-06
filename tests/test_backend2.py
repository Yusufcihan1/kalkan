import sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import core
core.ensure_dirs()
import engines, deep, netguard, harden, defender, scanner

def t(label, fn):
    t0 = time.time()
    try:
        r = fn()
        print(f"OK   {label} ({time.time()-t0:.1f}s):", str(r)[:400])
        return r
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"FAIL {label}: {e}")

fs, items = deep.autorun_findings()
print("autorun findings", len(fs))
for f in fs: print("   ", f["level"], f["title"], "|", f["why"][:160], "|", f["path"][:90], f["actions"])
fs = t("driver findings", lambda: deep.driver_findings(items))
for f in fs or []: print("   ", f["level"], f["title"], f["why"][:100])
fs = t("process findings", lambda: deep.process_findings())
for f in fs or []: print("   ", f["level"], f["title"], f["why"][:120])
fs = t("net settings", lambda: deep.network_settings_findings())
for f in fs or []: print("   ", f["level"], f["title"], f["why"][:120])
t("extensions", lambda: [(e["browser"], e["name"], e["store"]) for e in deep.browser_extensions()][:40])
fs = t("ext findings", lambda: deep.extension_findings())
for f in fs or []: print("   ", f["level"], f["title"], f["why"][:120])
