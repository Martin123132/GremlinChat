param(
  [switch]$StartWithWindows
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$GremlinRoot = Join-Path $env:LOCALAPPDATA "GremlinChat"
$VenvPath = Join-Path $GremlinRoot ".venv"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"
$GremlinExe = Join-Path $VenvPath "Scripts\gremlinchat.exe"
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\GremlinChat"

New-Item -ItemType Directory -Force -Path $GremlinRoot | Out-Null

if (-not (Test-Path $PythonExe)) {
  py -3 -m venv $VenvPath
}

& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -e $RepoRoot
& $GremlinExe setup

New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null

$Shell = New-Object -ComObject WScript.Shell

$DashboardShortcut = $Shell.CreateShortcut((Join-Path $StartMenu "GremlinChat Dashboard.lnk"))
$DashboardShortcut.TargetPath = "powershell.exe"
$DashboardShortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -Command `"& '$GremlinExe' daemon serve`""
$DashboardShortcut.WorkingDirectory = $RepoRoot
$DashboardShortcut.Save()

$StopShortcut = $Shell.CreateShortcut((Join-Path $StartMenu "GremlinChat Emergency Stop.lnk"))
$StopShortcut.TargetPath = $GremlinExe
$StopShortcut.Arguments = "emergency-stop"
$StopShortcut.WorkingDirectory = $RepoRoot
$StopShortcut.Save()

if ($StartWithWindows) {
  $Startup = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
  New-Item -ItemType Directory -Force -Path $Startup | Out-Null
  $StartupShortcut = $Shell.CreateShortcut((Join-Path $Startup "GremlinChat Dashboard.lnk"))
  $StartupShortcut.TargetPath = "powershell.exe"
  $StartupShortcut.Arguments = "-WindowStyle Minimized -ExecutionPolicy Bypass -Command `"& '$GremlinExe' daemon serve`""
  $StartupShortcut.WorkingDirectory = $RepoRoot
  $StartupShortcut.Save()
}

Write-Host "GremlinChat installed."
Write-Host "Dashboard launcher: $StartMenu"
Write-Host "Dashboard URL: http://127.0.0.1:8777/dashboard"

