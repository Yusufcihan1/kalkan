"""Kalkan giriş noktası.

  Kalkan.exe            Ajan çalışıyorsa penceresini açar; çalışmıyorsa (yönetici görevini başlatıp) ajanı açar.
  Kalkan.exe --arka     Ajanı penceresiz başlatır (oturum açılınca zamanlanmış görevden).
  Kalkan.exe --kur      Oturum açılışı görevini kaydeder (kurulum sırasında, yönetici olarak).
  Kalkan.exe --kaldir   DNS ayarını geri alır, görevi ve tuzak dosyaları siler (kaldırma sırasında).
"""
import ctypes
import os
import subprocess
import sys
import time
import urllib.request

import core

TASK = "Kalkan"


def agent_alive():
    s = core.read_json(os.path.join(core.DATA_DIR, "oturum.json"))
    if not s:
        return None
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{s['port']}/api/ping", headers={"X-Token": s["token"]})
        os.environ.setdefault("NO_PROXY", "127.0.0.1")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=2) as r:
            if r.status == 200:
                return s
    except Exception:
        return None
    return None


def open_window(s):
    url = f"http://127.0.0.1:{s['port']}/?t={s['token']}"
    core.open_app_window(url)


def exe_command(args=""):
    if core.FROZEN:
        return f'"{sys.executable}" {args}'.strip()
    return f'"{sys.executable}" "{os.path.abspath(__file__)}" {args}'.strip()


def register_task():
    """Oturum açılınca en yüksek yetkiyle çalışan görev (her açılışta UAC sorusu olmadan)."""
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()
    svc = win32com.client.Dispatch("Schedule.Service")
    svc.Connect()
    root = svc.GetFolder("\\")
    td = svc.NewTask(0)
    td.RegistrationInfo.Description = "Kalkan koruması: oturum açılınca arka planda başlar."
    td.RegistrationInfo.Author = "Kalkan"
    user = os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")
    td.Principal.UserId = user
    td.Principal.LogonType = 3          # etkileşimli
    td.Principal.RunLevel = 1           # en yüksek
    st = td.Settings
    st.Enabled = True
    st.StartWhenAvailable = True
    st.DisallowStartIfOnBatteries = False
    st.StopIfGoingOnBatteries = False
    st.ExecutionTimeLimit = "PT0S"
    st.MultipleInstances = 2            # IgnoreNew
    st.Priority = 6
    st.RestartCount = 3
    st.RestartInterval = "PT1M"
    trig = td.Triggers.Create(9)        # oturum açılışı
    trig.UserId = user
    trig.Delay = "PT10S"
    act = td.Actions.Create(0)
    if core.FROZEN:
        act.Path = sys.executable
        act.Arguments = "--arka"
    else:
        act.Path = sys.executable
        act.Arguments = f'"{os.path.abspath(__file__)}" --arka'
    act.WorkingDirectory = core.APP_DIR
    root.RegisterTaskDefinition(TASK, td, 6, user, None, 3)   # 6 = oluştur ya da güncelle


def run_task():
    code, out = core.run(["schtasks", "/run", "/tn", TASK], timeout=20)
    return code == 0


def uninstall_cleanup():
    import netguard
    import realtime
    try:
        s = core.read_json(os.path.join(core.DATA_DIR, "oturum.json"))
        if s:
            core.run(["taskkill", "/F", "/PID", str(s.get("pid"))], timeout=20)
    except Exception:
        pass
    try:
        netguard.DNS.restore(stop=False)
    except Exception as e:
        core.log_error("uninstall dns", e)
    try:
        for folder in [core.known_folder(n) for n in ("Documents", "Desktop", "Pictures")]:
            for name in realtime.CANARY_NAMES:
                p = os.path.join(folder, name)
                if os.path.exists(p):
                    ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
                    os.remove(p)
    except Exception as e:
        core.log_error("uninstall canaries", e)
    core.run(["schtasks", "/delete", "/tn", TASK, "/f"], timeout=20)
    for rule in netguard.blocked_apps():
        netguard.unblock_app(rule.get("Name", ""))


def stop_agent():
    """Güncelleme öncesi: ajanı kapatır, DNS ayarını geri alır, ClamAV'ı durdurur."""
    import netguard
    s = core.read_json(os.path.join(core.DATA_DIR, "oturum.json"))
    if s and s.get("pid"):
        core.run(["taskkill", "/F", "/PID", str(s["pid"])], timeout=20)
    core.run(["taskkill", "/F", "/IM", "clamd.exe"], timeout=20)
    try:
        if (core.read_json(netguard.STATE_FILE, {}) or {}).get("applied"):
            netguard.DNS.restore(stop=False)
    except Exception as e:
        core.log_error("stop dns", e)
    try:
        os.remove(os.path.join(core.DATA_DIR, "oturum.json"))
    except OSError:
        pass


def relaunch_elevated(args):
    params = args if core.FROZEN else f'"{os.path.abspath(__file__)}" {args}'
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, core.APP_DIR, 0) > 32


def single_instance():
    import win32event
    import winerror
    import win32api
    h = win32event.CreateMutex(None, False, "Global\\KalkanAjan")
    return h, win32api.GetLastError() != winerror.ERROR_ALREADY_EXISTS


def main():
    args = sys.argv[1:]
    core.ensure_dirs() if core.is_admin() else os.makedirs(core.USER_DIR, exist_ok=True)
    if "--kur" in args:
        register_task()
        return
    if "--kaldir" in args:
        uninstall_cleanup()
        return
    if "--durdur" in args:
        stop_agent()
        return
    want_window = "--arka" not in args
    s = agent_alive()
    if s:
        if want_window:
            open_window(s)
        return
    if core.is_admin() or "--gelistirme" in args:
        h, first = single_instance()
        if not first:
            for _ in range(30):
                s = agent_alive()
                if s:
                    if want_window:
                        open_window(s)
                    return
                time.sleep(0.5)
            return
        import agent
        agent.run_agent(open_window=want_window)
        return
    # Yönetici değiliz: önce kurulumun kaydettiği görevi dene (UAC sorusu çıkmaz), olmazsa yönetici olarak yeniden başlat.
    if run_task():
        for _ in range(40):
            time.sleep(0.5)
            s = agent_alive()
            if s:
                if want_window:
                    open_window(s)
                return
    relaunch_elevated("" if want_window else "--arka")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        core.log_error("main", e)
        raise
