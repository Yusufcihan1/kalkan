"""Microsoft Defender'ın varsayılan olarak kapalı koruma katmanları: ASR kuralları, klasör koruması, ağ koruması, PUA."""
import re
import time

import core
from core import UserError

# (kimlik, Türkçe ad, açıklama, önerilen)
ASR_RULES = [
    ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Zafiyetli imzalı sürücüleri engelle", "Saldırganların korumaları kapatmak için yüklediği bilinen zafiyetli sürücüler.", True),
    ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Adobe Reader alt süreç başlatamasın", "PDF açıklarından program çalıştırmayı engeller.", True),
    ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Office uygulamaları alt süreç başlatamasın", "Makrolu belgelerin komut satırı açmasını engeller.", True),
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "LSASS'tan şifre çalmayı engelle", "Bellekteki Windows şifrelerinin okunmasını engeller.", True),
    ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "E-postadan gelen programları engelle", "Outlook ve web postasından gelen çalıştırılabilir içerik.", True),
    ("01443614-cd74-433a-b99e-2ecdc07bfc25", "Yeni ve az bilinen programları engelle", "Yaygın olmayan, yeni ya da güvenilmeyen exe'ler çalışmaz. Kendi derlediğin programları da engelleyebilir.", False),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Gizlenmiş betikleri engelle", "Karartılmış PowerShell, JavaScript ve VBScript.", True),
    ("d3e037e1-3eb8-44c8-a917-57927947596d", "Betiklerin indirdiği programları engelle", "JavaScript/VBScript'in indirdiği exe'yi başlatmasını engeller.", True),
    ("3b576869-a4ec-4529-8536-b80a7769e899", "Office çalıştırılabilir dosya yazamasın", "Makroların diske program bırakmasını engeller.", True),
    ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Office başka süreçlere kod enjekte edemesin", "Makroların diğer programların içine sızmasını engeller.", True),
    ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Outlook alt süreç başlatamasın", "E-posta istemcisinden program başlatılmasını engeller.", True),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "WMI ile kalıcılığı engelle", "Zararlıların gizli WMI aboneliğiyle her açılışta çalışmasını engeller.", True),
    ("d1e49aac-8f56-4280-b9ba-993a6d77406c", "PSExec ve WMI'den süreç başlatmayı engelle", "Uzaktan yönetim araçlarını bozabilir.", False),
    ("33ddedf1-c6e0-47cb-833e-de6133960387", "Güvenli Mod'da yeniden başlatmayı engelle", "Fidye yazılımlarının korumayı atlatmak için Güvenli Mod'a geçmesini engeller.", True),
    ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "USB'den imzasız programları engelle", "Takılan bellekten imzasız ve güvenilmeyen program çalışmaz.", True),
    ("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Kopyalanmış sistem araçlarını engelle", "Windows araçlarının adını taşıyan sahte kopyalar.", True),
    ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Office makrolarından Win32 çağrılarını engelle", "Makroların doğrudan Windows işlevlerini çağırmasını engeller.", True),
    ("c1db55ab-c21a-4637-bb3f-a12568109d35", "Gelişmiş fidye yazılımı koruması", "Fidye yazılımına benzeyen dosyalar çalışmadan engellenir.", True),
]
MODES = {0: "kapali", 1: "engelle", 2: "denetle", 6: "uyar"}
MODE_IDS = {v: k for k, v in MODES.items()}


def status():
    p = core.ps_json("Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions,"
                     "EnableControlledFolderAccess,ControlledFolderAccessAllowedApplications,ControlledFolderAccessProtectedFolders,"
                     "EnableNetworkProtection,PUAProtection,DisableRealtimeMonitoring", timeout=60) or {}
    ids = [i.lower() for i in core.as_list(p.get("AttackSurfaceReductionRules_Ids"))]
    acts = core.as_list(p.get("AttackSurfaceReductionRules_Actions"))
    current = {i: int(a) for i, a in zip(ids, acts)}
    rules = [{"id": rid, "name": name, "desc": desc, "recommended": rec, "mode": MODES.get(current.get(rid, 0), "kapali")}
             for rid, name, desc, rec in ASR_RULES]
    return {
        "available": bool(p),
        "rules": rules,
        "asr_on": sum(1 for r in rules if r["mode"] in ("engelle", "uyar")),
        "asr_total": len(rules),
        "cfa": {0: "kapali", 1: "engelle", 2: "denetle", 3: "engelle", 4: "denetle"}.get(int(p.get("EnableControlledFolderAccess") or 0), "kapali"),
        "cfa_apps": [x for x in core.as_list(p.get("ControlledFolderAccessAllowedApplications")) if not str(x).startswith("N/A")],
        "cfa_folders": [x for x in core.as_list(p.get("ControlledFolderAccessProtectedFolders")) if not str(x).startswith("N/A")],
        "network": {0: "kapali", 1: "engelle", 2: "denetle"}.get(int(p.get("EnableNetworkProtection") or 0), "kapali"),
        "pua": {0: "kapali", 1: "engelle", 2: "denetle"}.get(int(p.get("PUAProtection") or 0), "kapali"),
        "realtime": not p.get("DisableRealtimeMonitoring", False),
    }


def _mp(cmd):
    if not core.is_admin():
        raise UserError("Bu ayar için Kalkan'ın yönetici olarak çalışması gerekiyor.")
    code, out = core.ps(cmd, timeout=120)
    if code:
        if "0x800106ba" in out or "0x80070422" in out:
            raise UserError("Microsoft Defender kapalı ya da başka bir antivirüs etkin olduğu için bu ayar uygulanamadı.")
        if "Tamper" in out or "0x800704ec" in out:
            raise UserError("Kurcalama koruması ya da bir grup ilkesi bu ayarı engelliyor.")
        raise UserError("Defender ayarı uygulanamadı: " + out.strip()[:250])
    return out


def set_rule(rule_id, mode):
    if mode not in MODE_IDS:
        raise UserError("Geçersiz mod")
    _mp(f"Add-MpPreference -AttackSurfaceReductionRules_Ids {rule_id} -AttackSurfaceReductionRules_Actions {MODE_IDS[mode]}")
    core.event("defender", "bilgi", f"ASR kuralı: {next((n for i, n, _, _ in ASR_RULES if i == rule_id), rule_id)} → {mode}")


def set_recommended(on=True):
    ids = [rid for rid, _, _, rec in ASR_RULES if rec]
    acts = [1 if on else 0] * len(ids)
    _mp(f"Add-MpPreference -AttackSurfaceReductionRules_Ids {','.join(ids)} -AttackSurfaceReductionRules_Actions {','.join(map(str, acts))}")
    core.event("defender", "bilgi", "Önerilen saldırı yüzeyi kuralları " + ("açıldı" if on else "kapatıldı"))


def set_cfa(mode):
    _mp(f"Set-MpPreference -EnableControlledFolderAccess {({'kapali': 'Disabled', 'engelle': 'Enabled', 'denetle': 'AuditMode'})[mode]}")
    core.event("defender", "bilgi", f"Klasör koruması → {mode}")


def cfa_allow(path):
    _mp(f"Add-MpPreference -ControlledFolderAccessAllowedApplications '{path.replace(chr(39), chr(39) * 2)}'")


def cfa_remove(path):
    _mp(f"Remove-MpPreference -ControlledFolderAccessAllowedApplications '{path.replace(chr(39), chr(39) * 2)}'")


def cfa_add_folder(path):
    _mp(f"Add-MpPreference -ControlledFolderAccessProtectedFolders '{path.replace(chr(39), chr(39) * 2)}'")


def set_network(mode):
    _mp(f"Set-MpPreference -EnableNetworkProtection {({'kapali': 'Disabled', 'engelle': 'Enabled', 'denetle': 'AuditMode'})[mode]}")
    core.event("defender", "bilgi", f"Ağ koruması → {mode}")


def set_pua(mode):
    _mp(f"Set-MpPreference -PUAProtection {({'kapali': 'Disabled', 'engelle': 'Enabled', 'denetle': 'AuditMode'})[mode]}")
    core.event("defender", "bilgi", f"İstenmeyen yazılım engeli → {mode}")


def enable_all_recommended():
    """Ana ekrandaki tek anahtar: önerilen kurallar + ağ koruması + PUA. Klasör koruması geliştirici araçlarını
    bozabildiği için ayrıca açılır."""
    set_recommended(True)
    set_network("engelle")
    set_pua("engelle")


def disable_all():
    set_recommended(False)
    set_network("kapali")
    set_pua("denetle")


EVENT_IDS = {1121: ("asr", "engelledi"), 1122: ("asr", "denetledi"), 1123: ("cfa", "engelledi"), 1124: ("cfa", "denetledi"),
             1125: ("network", "denetledi"), 1126: ("network", "engelledi"), 1116: ("threat", "algıladı"), 1117: ("threat", "temizledi")}


def recent_blocks(hours=72, limit=60):
    """Defender'ın son engelledikleri (olay günlüğü)."""
    ids = ",".join(str(i) for i in EVENT_IDS)
    data = core.ps_json(
        "$s=(Get-Date).AddHours(-%d); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';"
        "Id=%s; StartTime=$s} -MaxEvents %d -ErrorAction SilentlyContinue | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{};"
        "foreach($n in $x.Event.EventData.Data){ $d[$n.Name]=$n.'#text' }; [pscustomobject]@{Id=$_.Id; Time=$_.TimeCreated.ToString('o');"
        "Path=$d['Path']; Process=$d['Process Name']; Rule=$d['ID']; Threat=$d['Threat Name']; Target=$d['Remote IP Address']}}" % (hours, ids, limit),
        timeout=90) or []
    out = []
    for e in core.as_list(data):
        kind, verb = EVENT_IDS.get(e.get("Id"), ("?", "?"))
        rule = next((n for i, n, _, _ in ASR_RULES if i == (e.get("Rule") or "").lower()), "")
        out.append({"kind": kind, "verb": verb, "time": e.get("Time"), "path": e.get("Path") or "",
                    "process": e.get("Process") or "", "rule": rule, "threat": e.get("Threat") or "", "id": e.get("Id")})
    return out
