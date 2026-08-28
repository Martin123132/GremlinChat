param(
  [switch]$StartWithWindows,
  [string]$InstallRoot,
  [string]$StateRoot
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
  $InstallRoot = Join-Path $env:LOCALAPPDATA "GremlinChat"
}
$GremlinRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallRoot)
if ([string]::IsNullOrWhiteSpace($StateRoot)) {
  $StateRoot = $GremlinRoot
}
$StateRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($StateRoot)
$VenvPath = Join-Path $GremlinRoot ".venv"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"
$GremlinExe = Join-Path $VenvPath "Scripts\gremlinchat.exe"
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\GremlinChat"

New-Item -ItemType Directory -Force -Path $GremlinRoot | Out-Null
New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null

if (-not (Test-Path $PythonExe)) {
  py -3 -m venv $VenvPath
}

& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -e $RepoRoot
$env:GREMLINCHAT_HOME = $StateRoot
$env:GREMLINCHAT_INSTALL_ROOT = $GremlinRoot
& $GremlinExe --home $StateRoot setup

New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null

$Shell = New-Object -ComObject WScript.Shell
$StateRootForPs = $StateRoot.Replace("'", "''")
$GremlinExeForPs = $GremlinExe.Replace("'", "''")

$DashboardShortcut = $Shell.CreateShortcut((Join-Path $StartMenu "GremlinChat Dashboard.lnk"))
$DashboardShortcut.TargetPath = "powershell.exe"
$DashboardShortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -Command `"`$env:GREMLINCHAT_HOME='$StateRootForPs'; & '$GremlinExeForPs' --home '$StateRootForPs' daemon serve`""
$DashboardShortcut.WorkingDirectory = $RepoRoot
$DashboardShortcut.Save()

$ListenerShortcut = $Shell.CreateShortcut((Join-Path $StartMenu "GremlinChat Trial Listener.lnk"))
$ListenerShortcut.TargetPath = "powershell.exe"
$ListenerShortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -Command `"`$env:GREMLINCHAT_HOME='$StateRootForPs'; & '$GremlinExeForPs' --home '$StateRootForPs' trial listen`""
$ListenerShortcut.WorkingDirectory = $RepoRoot
$ListenerShortcut.Save()

$PreflightShortcut = $Shell.CreateShortcut((Join-Path $StartMenu "GremlinChat Preflight.lnk"))
$PreflightShortcut.TargetPath = "powershell.exe"
$PreflightShortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -Command `"`$env:GREMLINCHAT_HOME='$StateRootForPs'; & '$GremlinExeForPs' --home '$StateRootForPs' trial preflight --write-report`""
$PreflightShortcut.WorkingDirectory = $RepoRoot
$PreflightShortcut.Save()

$DoctorShortcut = $Shell.CreateShortcut((Join-Path $StartMenu "GremlinChat Install Doctor.lnk"))
$DoctorShortcut.TargetPath = "powershell.exe"
$DoctorShortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -Command `"`$env:GREMLINCHAT_HOME='$StateRootForPs'; & '$GremlinExeForPs' --home '$StateRootForPs' install doctor --write-report`""
$DoctorShortcut.WorkingDirectory = $RepoRoot
$DoctorShortcut.Save()

$StopShortcut = $Shell.CreateShortcut((Join-Path $StartMenu "GremlinChat Emergency Stop.lnk"))
$StopShortcut.TargetPath = $GremlinExe
$StopShortcut.Arguments = "--home `"$StateRoot`" emergency-stop"
$StopShortcut.WorkingDirectory = $RepoRoot
$StopShortcut.Save()

if ($StartWithWindows) {
  $Startup = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
  New-Item -ItemType Directory -Force -Path $Startup | Out-Null
  $StartupShortcut = $Shell.CreateShortcut((Join-Path $Startup "GremlinChat Dashboard.lnk"))
  $StartupShortcut.TargetPath = "powershell.exe"
  $StartupShortcut.Arguments = "-WindowStyle Minimized -ExecutionPolicy Bypass -Command `"`$env:GREMLINCHAT_HOME='$StateRootForPs'; & '$GremlinExeForPs' --home '$StateRootForPs' daemon serve`""
  $StartupShortcut.WorkingDirectory = $RepoRoot
  $StartupShortcut.Save()
}

Write-Host "Running GremlinChat install doctor..."
& $GremlinExe --home $StateRoot install doctor --write-report

Write-Host "GremlinChat installed."
Write-Host "Install root: $GremlinRoot"
Write-Host "State root: $StateRoot"
Write-Host "Dashboard launcher: $StartMenu"
Write-Host "Dashboard URL: http://127.0.0.1:8777/dashboard"
