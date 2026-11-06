import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import core
core.ensure_dirs()
import engines
class J:
    def update(self, p=None, m=None):
        if m: print("  ..", m, flush=True)
t0 = time.time()
engines.CLAM.update(J())
print("clam updated", time.time() - t0, engines.CLAM.has_db, flush=True)
t0 = time.time()
print("ensure", engines.CLAM.ensure(), time.time() - t0, flush=True)
print(engines.CLAM.scan(r"C:\Windows\System32\notepad.exe"))
# EICAR'ı diske yazmadan bellekten akıt: INSTREAM testi
import socket, struct
eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
with socket.create_connection(("127.0.0.1", engines.CLAM_PORT), timeout=30) as s:
    s.sendall(b"zINSTREAM\0" + struct.pack(">I", len(eicar)) + eicar + struct.pack(">I", 0))
    print("eicar:", s.recv(4096))
engines.CLAM.stop()
print("stopped")
