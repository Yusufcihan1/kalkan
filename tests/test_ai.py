"""Claude işleri, sahte bir istemciyle: istek biçimi, JSON şeması, araç döngüsü ve öneri akışı."""
import json
import os
import sys
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import core  # noqa: E402

core.ensure_dirs()
import ai  # noqa: E402

SEEN = []


def usage():
    return NS(input_tokens=100, output_tokens=50, cache_read_input_tokens=0, cache_creation_input_tokens=0)


class Stream:
    def __init__(self, text):
        self.text = text

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        yield NS(type="content_block_delta", delta=NS(type="text_delta", text=self.text))

    def get_final_message(self):
        return NS(stop_reason="end_turn", content=[NS(type="text", text=self.text)], usage=usage())


def answer_for(kw):
    schema = kw.get("output_config", {}).get("format", {}).get("schema", {})
    props = schema.get("properties", {})
    if "verdict" in props and "confidence" in props:
        return {"verdict": "temiz", "headline": "Windows'un Not Defteri", "reasons": ["Microsoft imzalı"], "what_to_do": ["Bir şey yapma"], "confidence": "yuksek"}
    if "verdict" in props:
        return {"verdict": "dolandirici", "headline": "Sahte PTT mesajı", "reasons": ["Yeni alan adı"], "what_to_do": "Linke tıklama."}
    return {"summary": "Özet", "items": [], "steps": ["Tarama yap"]}


class Beta:
    def stream(self, **kw):
        SEEN.append(("stream", kw))
        assert kw["model"] == ai.MODEL
        for block in kw["messages"][0]["content"]:
            assert block["type"] in ("text", "image")
        return Stream(json.dumps(answer_for(kw), ensure_ascii=False))


class Messages:
    def __init__(self):
        self.n = 0

    def create(self, **kw):
        SEEN.append(("create", kw))
        self.n += 1
        # Mesajlar user/assistant sırasını korumalı, araç sonuçları doğru id'yi göstermeli.
        msgs = kw["messages"]
        assert msgs[0]["role"] == "user"
        if self.n == 1:
            return NS(stop_reason="tool_use", usage=usage(), content=[
                NS(type="text", text="Bakıyorum."),
                NS(type="tool_use", id="tu_1", name="recent_events", input={"hours": 24}),
                NS(type="tool_use", id="tu_2", name="propose_action", input={"action": "quick_scan", "target": "", "label": "Hızlı tara", "reason": "Emin olmak için"})])
        last = msgs[-1]
        assert last["role"] == "user" and {b["tool_use_id"] for b in last["content"]} == {"tu_1", "tu_2"}
        return NS(stop_reason="end_turn", usage=usage(), content=[NS(type="text", text="Son 24 saatte tehdit yok. İstersen hızlı tara.")])

    def stream(self, **kw):
        return Beta().stream(**kw)


FAKE = NS(beta=NS(messages=Beta()), messages=Messages())
ai.client = lambda: FAKE


class J:
    def update(self, p=None, m=None):
        pass


r = ai.explain_file(J(), r"C:\Windows\System32\notepad.exe")
print("explain:", r["verdict"], r["headline"], r["file"]["signer"])
kw = SEEN[-1][1]
summary = kw["messages"][0]["content"][0]["text"]
assert "<file_summary>" in summary and "notepad.exe" in summary and len(summary) < 70000
print("  özet uzunluğu:", len(summary))

r = ai.scam_check(J(), "PTT Kargo: adresiniz eksik, 24 saat içinde güncelleyin: ptt-kargotakip-tr.com/g/8Kx2")
print("scam:", r["verdict"], r["links"])

import scanner  # noqa: E402
if scanner.load_last():
    r = ai.scan_report(J())
    print("report:", r["summary"], r["steps"])

st = ai.chat(J(), "Bugün bir şey oldu mu?")
print("chat:", [(m["role"], m.get("text") or m.get("label")) for m in st["messages"]])
assert any(m["role"] == "proposal" for m in st["messages"])
print("usage:", ai.usage_summary())
print("TAMAM")
