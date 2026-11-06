; Kalkan kurulumu. Program Files'a kurulur (koruma ajanı yönetici yetkisiyle çalışır).
#define AppName "Kalkan"
#define AppVersion "1.0.1"

[Setup]
AppId={{6E2A1D4B-4C1E-4B9B-9C64-8C4A1A0B7E21}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Yusuf Cihan
AppPublisherURL=https://github.com/Yusufcihan1/kalkan
DefaultDirName={autopf}\Kalkan
DefaultGroupName=Kalkan
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=Kalkan Kurulum
OutputDir=Output
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\Kalkan.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
LicenseFile=LICENSE
CloseApplications=no

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[Tasks]
Name: "desktopicon"; Description: "Masaüstüne kısayol oluştur"; GroupDescription: "Kısayollar:"

[Files]
Source: "dist\Kalkan\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "eklenti\*"; DestDir: "{app}\eklenti"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Kalkan"; Filename: "{app}\Kalkan.exe"
Name: "{group}\Kalkan'ı kaldır"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Kalkan"; Filename: "{app}\Kalkan.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Kalkan.exe"; Parameters: "--kur"; StatusMsg: "Oturum açılışı görevi kaydediliyor..."; Flags: runhidden waituntilterminated
Filename: "{app}\Kalkan.exe"; Description: "Kalkan'ı başlat"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\Kalkan.exe"; Parameters: "--kaldir"; Flags: runhidden waituntilterminated; RunOnceId: "KalkanKaldir"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\Kalkan\motorlar"
Type: files; Name: "{commonappdata}\Kalkan\oturum.json"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { Güncellemede çalışan ajanı düzgün kapat (DNS ayarını geri alır). }
  if FileExists(ExpandConstant('{app}\Kalkan.exe')) then
    Exec(ExpandConstant('{app}\Kalkan.exe'), '--durdur', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec('taskkill.exe', '/F /IM Kalkan.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;
