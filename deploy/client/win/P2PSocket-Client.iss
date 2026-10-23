; M4-02 Windows 客户端安装包脚本（NFR-32、设计 08 §3.1、FR-C-901/902）
; 2026-10-21 命名口径修订（用户指令）：显示名/产物名统一 P2PSocket 品牌——AppName=P2PSocket 客户端、
;   Setup 产物 P2PSocket-Client-Setup-{ver}-x64.exe、安装目录 {autopf}\P2PSocketClient、开始菜单组
;   「P2PSocket 客户端」、服务显示名 P2PSocket 客户端。**服务名 P2PClient 与数据目录
;   %ProgramData%\P2PClient 刻意不动**——已装机覆盖升级与数据保留依赖二者（AppId 不变=同应用）。
; 目录选择（2026-10-24 用户裁定）：**升级也显示目录选择页**，默认=上次安装位置（读卸载键
;   InstallLocation；无旧安装= {autopf}\P2PSocketClient）——实现=UsePreviousAppDir=no（关掉
;   「静默复用旧目录+跳页」默认行为）+ DefaultDirName={code:GetDefaultDir}。注意：升级时若
;   改选新目录，旧目录文件 Inno 不迁移不清理（数据目录 %ProgramData% 不受影响，服务重指新路径）。
; 编译：ISCC /DPkgVersion=1.0.0 deploy\client\win\P2PSocket-Client.iss（package.sh win-setup 目标自动传版本）
;   —— 版本单一事实源=src/Directory.Build.props（package.sh 提取经 /D 传入；直跑 ISCC 用下方 #ifndef 兜底）
; 产物：out/P2PSocket-Client-Setup-{ver}-x64.exe
; 安装：复制 out/client-win 产物 → %ProgramFiles%\P2PSocketClient；创建 P2PClient 服务（LocalSystem/自启/
;   崩溃 5s×3 档恢复，参数对齐 deploy/client/install-windows-service.ps1 已验证口径）并启动；
;   数据目录 %ProgramData%\P2PClient ACL=SYSTEM+Administrators；开始菜单 Web 入口（127.0.0.1:7100）。
; 升级：覆盖安装——检测既有服务先停（等退出释放句柄）→ 覆盖文件 → 重启服务；%ProgramData% 数据保留。
; 卸载：停服务 → 调 p2p-client --uninstall（0x12 解绑+Wintun 适配器清理，M2-25）→ sc delete →
;   数据目录询问保留（交互 MsgBox；静默 /VERYSILENT 默认保留）；/PURGE 参数（静默/交互均可）强制删数据。
; 静默：setup /VERYSILENT /SUPPRESSMSGBOXES（服务照装照启）；unins000.exe /VERYSILENT /PURGE=删数据。
; 注意：本机 D:\P2PClient 已有手工部署同名服务——安装包不在本机实装（实机轮归 M4-10 清单 §8.2）。

#ifndef PkgVersion
#define PkgVersion "1.0.0"
#endif

; 产物源=package.sh client-win 目标输出（Wintun.dll 已拷入）；相对本 .iss 文件目录
#define ClientDir "..\..\..\out\client-win"

[Setup]
AppId={{D2762F4B-9E8A-4C71-9A05-7B3E1D4F5A68}
AppName=P2PSocket 客户端
AppVersion={#PkgVersion}
AppPublisher=P2PSocket_AI
; UsePreviousAppDir=no + 代码默认值：升级仍显示目录选择页且默认上次位置（见头部注记）
UsePreviousAppDir=no
DefaultDirName={code:GetDefaultDir}
DisableProgramGroupPage=yes
OutputDir=..\..\..\out
OutputBaseFilename=P2PSocket-Client-Setup-{#PkgVersion}-x64
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=P2PSocket 客户端 {#PkgVersion}

[Files]
; 全量镜像 publish 产物（wwwroot 递归；pdb 调试符号不分发）
Source: "{#ClientDir}\p2p-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ClientDir}\Wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ClientDir}\*"; Excludes: "*.pdb"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; 数据目录（03 §5）：SYSTEM+Administrators 完全控制（服务 LocalSystem 读写；普通用户不可读——
; 内含设备凭据密文 peers.json 等 07 §4）；uninsneveruninstall=数据去留由卸载逻辑自行控制
Name: "{commonappdata}\P2PClient"; Permissions: system-full admins-full; Flags: uninsneveruninstall

[Icons]
; Web 管理入口（04 §0：仅回环监听，浏览器本机可达）
Name: "{autoprograms}\P2PSocket 客户端\Web 管理页"; Filename: "http://127.0.0.1:7100"

[Code]
const
  ServiceName = 'P2PClient';
  UninstKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D2762F4B-9E8A-4C71-9A05-7B3E1D4F5A68}_is1';

/// 目录选择页默认值（2026-10-24）：上次安装位置（卸载键 InstallLocation），无旧安装=程序文件默认。
/// 配合 UsePreviousAppDir=no——升级仍可改目录（Inno 默认行为是静默复用旧目录并跳过选择页）。
function GetDefaultDir(Param: String): String;
var
  Prev: String;
begin
  Result := ExpandConstant('{autopf}\P2PSocketClient');
  if RegQueryStringValue(HKLM, UninstKey, 'InstallLocation', Prev) and (Prev <> '') then
  begin
    // InstallLocation 带尾反斜杠（如 C:\Program Files\P2PSocketClient\）——去掉避免目录页显示双斜杠
    while (Length(Prev) > 3) and (Copy(Prev, Length(Prev), 1) = '\') do
      Delete(Prev, Length(Prev), 1);
    if DirExists(Prev) then
      Result := Prev;
  end;
end;

// ── 服务操作（sc.exe 命令行，与 install-windows-service.ps1 同参数源）──────────────

function ScPath(): String;
begin
  Result := GetEnv('SystemRoot') + '\System32\sc.exe';
end;

function ScRun(Args: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ScPath(), Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function ServiceExists(): Boolean;
var
  ResultCode: Integer;
begin
  // sc query 退出码 1060=服务不存在（ERROR_SERVICE_DOES_NOT_EXIST）
  Result := Exec(ScPath(), 'query ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode <> 1060);
end;

/// 服务是否已 STOPPED（Exec 无 stdout 回读：经 cmd 重定向临时文件再读；sc query 状态行含 STOPPED）
function IsServiceStopped(): Boolean;
var
  ResultCode: Integer;
  TmpFile: String;
  Content: AnsiString;
begin
  Result := False;
  TmpFile := GetTempDir() + '\p2p_scq.txt';
  Exec(ExpandConstant('{cmd}'), '/C ""' + ScPath() + '" query ' + ServiceName + ' > "' + TmpFile + '""',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if (ResultCode = 0) and LoadStringFromFile(TmpFile, Content) then
    Result := Pos('STOPPED', Content) > 0;
  DeleteFile(TmpFile);
end;

/// 停服务并等待退出（覆盖/卸载前置——运行中 exe/Wintun.dll 句柄锁定不可覆盖删除；
/// 服务进程退出有窗口：2s 轮询 ×10 上限 20s，超时继续后续步骤由文件复制/删除重试兜底）
procedure StopServiceAndWait();
var
  i: Integer;
begin
  if not ServiceExists() then Exit;
  ScRun('stop ' + ServiceName); // 已停时失败无害，等待窗兜底
  for i := 1 to 10 do
  begin
    Sleep(2000);
    if IsServiceStopped() then Exit;
  end;
  Log('等待服务退出超时（20s），继续执行——文件占用时复制/删除失败请重试');
end;

/// 创建服务（不存在时）+ 崩溃恢复参数（FR-C-902）+ 启动；失败仅告警不回滚（可手工 sc 恢复）
function InstallAndStartService(): Boolean;
var
  ExePath: String;
begin
  Result := False;
  if ServiceExists() then
    Log('服务 ' + ServiceName + ' 已存在（升级路径），跳过创建')
  else
  begin
    ExePath := ExpandConstant('{app}\p2p-client.exe');
    if not ScRun(Format('create %s binPath= "%s" start= auto DisplayName= "P2PSocket 客户端"', [ServiceName, ExePath])) then
    begin
      Log('sc create 失败——请手工执行 install-windows-service.ps1');
      Exit;
    end;
  end;
  // 失败即重启（5s×3 档），24h 无失败重置（与 install-windows-service.ps1 逐参一致）
  if not ScRun(Format('failure %s reset= 86400 actions= restart/5000/restart/5000/restart/5000', [ServiceName])) then
    Log('sc failure 设置失败（服务仍可用，崩溃自愈未启用）');
  Result := ScRun('start ' + ServiceName);
  if not Result then
    Log('sc start 失败——请检查 {app} 日志后手工 sc start ' + ServiceName);
end;

// ── 安装期挂点 ─────────────────────────────────────────────────────────────────

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    // 覆盖安装前置：停既有服务（升级路径；文件复制前执行——运行中 exe 锁定不可覆盖）
    if ServiceExists() then
    begin
      Log('检测到既有服务，停服务后升级（数据目录不受影响）');
      StopServiceAndWait();
    end;
  end
  else if CurStep = ssPostInstall then
  begin
    if not InstallAndStartService() then
      MsgBox('服务安装/启动未完全成功：请查看 {app} 下日志，或手工执行 install-windows-service.ps1。',
        mbError, MB_OK);
  end;
end;

// ── 卸载 ─────────────────────────────────────────────────────────────────────

// 自定义参数读取（Inno Pascal 无 ParamStr：GetCommandLineW 外部声明后子串匹配；卸载器同样生效）
function GetCommandLineW(): WideString; external 'GetCommandLineW@kernel32.dll stdcall';

function PurgeRequested(): Boolean;
begin
  Result := Pos('/PURGE', Uppercase(GetCommandLineW())) > 0;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  DataDir: String;
  RemoveData: Boolean;
begin
  if CurUninstallStep = usUninstall then
  begin
    // ① 停服务并等待退出（--uninstall 与文件删除都需要进程不在运行）
    StopServiceAndWait();
    // ② Wintun 适配器清理+0x12 服务端解绑（M2-25 既有 CLI；短命控制台进程，等它退出）
    Exec(ExpandConstant('{app}\p2p-client.exe'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    // ③ 删服务
    if ServiceExists() then
      ScRun('delete ' + ServiceName);
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    // ④ 数据目录去留：/PURGE 参数强制删；静默卸载默认保留；交互询问
    DataDir := ExpandConstant('{commonappdata}\P2PClient');
    RemoveData := False;
    if PurgeRequested() then
      RemoveData := True
    else if not UninstallSilent() then
      RemoveData := MsgBox('是否同时删除数据目录（设备注册状态/凭据/日志）？' + #13#10 +
        '删除后本机需重新向导注册；保留则下次安装可直接恢复使用。',
        mbConfirmation, MB_YESNO) = IDYES;
    if RemoveData and DirExists(DataDir) then
      DelTree(DataDir, True, True, True);
  end;
end;
