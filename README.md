# Kalkan

Windows için Türkçe güvenlik uygulaması. Microsoft Defender'ı kapatmaz, onun üstüne katman ekler: birden çok
tarama motoru, derin tarama, fidye yazılımı kalkanı, internet koruması, sistem sıkılaştırma ve istendiğinde
Claude ile açıklama.

## Neler yapar

- **Tarama motorları:** Microsoft Defender, ClamAV (ilk kullanımda indirilir), YARA-X ile YARA Forge kuralları,
  MalwareBazaar ve VirusTotal parmak izi sorgusu (kendi ücretsiz anahtarınla).
- **Derin tarama:** başlangıç kayıtları, zamanlanmış görevler, servisler, WMI abonelikleri, IFEO yönlendirmeleri,
  zafiyetli sürücüler (LOLDrivers), çalışan süreçler, hosts/DNS/proxy, tarayıcı politikaları ve eklentileri.
  Her işlem geri alınabilir.
- **Anlık koruma:** yeni başlayan programlar, indirilenler ve USB bellekler anında taranır.
- **Fidye kalkanı:** tuzak dosyalar, toplu belge şifreleme izleme (yalnız imzasız ve yeni başlamış programlar
  dondurulur), günlük gölge kopya, yalnız Kalkan'ın yazabildiği sürümlü yedek kasası ve tek tıkla geri yükleme.
- **Defender katmanları:** saldırı yüzeyi azaltma (ASR) kuralları, klasör koruması, ağ koruması, istenmeyen
  yazılım engeli.
- **İnternet:** bilgisayarda çalışan DNS filtresi (HaGeZi, malware-filter listeleri), taklit Türk kurum ve banka
  adresi algılama, bağlantı izleyici ve program başına internet engeli, Wi-Fi/modem kontrolü, ağdaki cihazlar,
  tarayıcı eklentisi (`eklenti/`).
- **Sıkılaştırma:** güvenlik puanı ve düzeltmeler, winget ile program güncelleme, şifre sızıntı kontrolü
  (k-anonimlik), gizlilik ayarları, kamera/mikrofon kullanım geçmişi.
- **Claude (Sonnet 5.5, kendi API anahtarınla):** "Bu dosya ne?", dolandırıcılık kontrolü (SMS, link, ekran
  görüntüsü), salt okunur araçlarla güvenlik asistanı, tarama raporu. Dosyanın kendisi gönderilmez, yalnız özeti.

## Mimari

`app/main.py` başlatıcı; `app/agent.py` yönetici yetkisiyle arka planda çalışan ajan (oturum açılınca zamanlanmış
görevden başlar). Arayüz `app/static` altında; ajanın 127.0.0.1'deki API'si rastgele jeton ister ve yalnız Kalkan
penceresinin Edge sürecinden gelen istekleri kabul eder. Tarayıcı eklentisi yalnız `127.0.0.1:47615/check` ile
site durumunu sorar.

## Derleme

```powershell
py -3.14 -m venv .venv
.venv\Scripts\pip install yara-x dnslib pefile pystray watchdog maxminddb keyring anthropic psutil pywin32 pillow pyinstaller
.\build.ps1
```

Kurulum dosyası `Output\Kalkan Kurulum.exe`.

## Sınırlar

Çekirdek sürücüsü yoktur (Microsoft yalnız MVI üyelerinin sürücülerini imzalar); bu yüzden Kalkan Defender'ın
yerine geçmez, yanında çalışır. Yönetici yetkisi ele geçiren bir zararlı Kalkan'ı kapatabilir.

Lisans: MIT. Üçüncü taraf bileşenler kendi lisanslarıyla (LICENSE dosyasına bak).
