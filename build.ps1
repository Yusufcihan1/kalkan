# Kalkan: exe'yi PyInstaller ile derler, Inno Setup ile kurulum dosyası üretir.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = ".\.venv\Scripts\python.exe"

if (-not (Test-Path icon.ico)) { & $py make_icon.py }

& $py -m PyInstaller --noconfirm --clean --windowed --name "Kalkan" --icon icon.ico `
    --paths app --add-data "app\static;static" `
    --hidden-import keyring.backends.Windows --hidden-import win32timezone `
    --hidden-import pystray._win32 --collect-submodules dnslib --collect-submodules watchdog `
    --collect-binaries yara_x `
    app\main.py
if ($LASTEXITCODE) { throw "PyInstaller başarısız" }

$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup bulunamadı: winget install JRSoftware.InnoSetup" }
# Antivirüs yeni exe'yi kısa süre kilitleyebiliyor ("Resource update error"): birkaç kez dene.
for ($i = 1; $i -le 3; $i++) {
    & $iscc /Q installer.iss
    if (-not $LASTEXITCODE) { break }
    if ($i -eq 3) { throw "Inno Setup başarısız" }
    Start-Sleep 10
}
Write-Host "Hazır: $(Resolve-Path 'Output\Kalkan Kurulum.exe')"
