; Instalador do ExpressChat Proteção (Inno Setup 6)
; Programa VISÍVEL em "Aplicativos" e removível pelo administrador.

#define AppName "ExpressChat Proteção"
#define AppVersion "1.0.0"
#define Publisher "Expresschat Tecnologia LTDA"
#define ExeName "ExpressChatProtecao.exe"
#define ServerUrl "https://painel-remoto.link-br.site/ec-protecao"

[Setup]
AppId={{D7FE3F05-048F-4FF0-A7C4-7563F73173BB}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
DefaultDirName={autopf}\ExpressChat Protecao
DefaultGroupName=ExpressChat
DisableProgramGroupPage=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#ExeName}
OutputBaseFilename=ExpressChatProtecao-Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern

[Files]
Source: "{#ExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{app}\{#ExeName}"; \
  Parameters: "install --server=""{#ServerUrl}"" --enroll=""{code:GetEnroll}"" --senha=""{code:GetEnroll}"""; \
  Flags: runhidden waituntilterminated; StatusMsg: "Ativando a proteção..."

[UninstallRun]
Filename: "{app}\{#ExeName}"; Parameters: "uninstall --from-installer"; Flags: runhidden waituntilterminated; RunOnceId: "ecprotecao-uninstall"

[Code]
var
  CodePage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  CodePage := CreateInputQueryPage(wpWelcome,
    'Código de ativação',
    'Cole o código que aparece no painel ExpressChat',
    'No painel, em Proteção, copie o Código de ativação da sua empresa e cole abaixo. ' +
    'Ele liga este computador ao seu painel. Guarde o código: ele também é a senha para remover a proteção.');
  CodePage.Add('Código de ativação:', False);
end;

function GetEnroll(Param: String): String;
begin
  Result := Trim(CodePage.Values[0]);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = CodePage.ID then
    if Trim(CodePage.Values[0]) = '' then
    begin
      MsgBox('Cole o código de ativação que aparece no painel, em Proteção.', mbError, MB_OK);
      Result := False;
    end;
end;
