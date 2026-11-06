import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import core
import netguard
from dnslib import DNSRecord
ok = netguard.DNS.start_server()
print("server", ok, netguard.DNS.error)
some_bad = next(iter(netguard.BLOCK.sets["tehdit"]))
for name in ("www.google.com", some_bad, "ads.doubleclick.net"):
    t0 = time.time()
    r = DNSRecord.parse(DNSRecord.question(name).send("127.0.0.1", 53, timeout=4))
    print(name, [str(x.rdata) for x in r.rr][:3], r.header.rcode, f"{time.time()-t0:.2f}s")
r = DNSRecord.parse(DNSRecord.question("www.google.com").send("127.0.0.1", 53, tcp=True, timeout=4))
print("tcp", [str(x.rdata) for x in r.rr][:2])
print(netguard.DNS.status()["stats"], list(netguard.DNS.ip_names.items())[:2])
netguard.DNS.stop_server()
