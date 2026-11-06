import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import core, quarantine
p = os.path.join(os.environ["TEMP"], "kalkan_q_test.bin")
open(p, "wb").write(b"MZ" + os.urandom(5000))
h = core.sha256_file(p)
m = quarantine.quarantine_file(p, "test", "Test: dosya")
print("q", m["id"], os.path.exists(p), [x["name"] for x in quarantine.list_quarantine()])
dest = quarantine.restore(m["id"], trust=False)
print("restored", dest, core.sha256_file(dest) == h)
os.remove(dest)
# undo log: kayıt defteri girdisi ekle, sil, geri al
import winreg
k = r"Software\KalkanTest"
with winreg.CreateKey(winreg.HKEY_CURRENT_USER, k) as kk:
    winreg.SetValueEx(kk, "deneme", 0, winreg.REG_SZ, "abc")
print(quarantine.remove_autorun({"hive": "HKCU", "key": k, "value": "deneme"}))
print(quarantine.undo(0))
with winreg.OpenKey(winreg.HKEY_CURRENT_USER, k) as kk:
    print("value back:", winreg.QueryValueEx(kk, "deneme")[0])
winreg.DeleteKey(winreg.HKEY_CURRENT_USER, k)
