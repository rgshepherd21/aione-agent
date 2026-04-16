#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AI One Agent installer for Windows.
.DESCRIPTION
    Downloads the agent binary, writes config, and registers it as a
    Windows Service using the built-in service control commands.
.PARAMETER InstallToken
    One-time installation token (required).
.PARAMETER ApiUrl
    Base URL of the AI One API (required).
.PARAMETER Version
    Agent version to install (default: latest).
.PARAMETER InstallDir
    Directory for the agent binary (default: C:\Program Files\AIOne\Agent).
.PARAMETER DataDir
    Directory for certs and state (default: C:\ProgramData\AIOne\Agent).
.EXAMPLE
    .\install.ps1 -InstallToken "tok_xxx" -ApiUrl "https://api.aione.example.com"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InstallToken,

    [Parameter(Mandatory)]
    [string]$ApiUrl,

    [string]$Version    = "latest",
    [string]$InstallDir = "C:\Program Files\AIOne\Agent",
    [string]$DataDir    = "C:\ProgramData\AIOne\Agent",
    [string]$ConfigDir  = "C:\ProgramData\AIOne\Agent"
)

$ErrorActionPreference = "Stop"
$ServiceName    = "AIONEAgent"
$ServiceDisplay = "AI One Agent"
$BinaryName     = "aione-agent.exe"
$BinaryPath     = Join-Path $InstallDir $BinaryName
$ConfigPath     = Join-Path $ConfigDir  "agent.yaml"
$Arch           = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$DownloadBase   = "https://releases.aione.example.com/agent/$Version"
$DownloadUrl    = "$DownloadBase/aione-agent_windows_$Arch.exe"
$ChecksumUrl    = "$DownloadBase/aione-agent_windows_$Arch.exe.sha256"

Write-Host "==> AI One Agent Installer"
Write-Host "    Version:  $Version"
Write-Host "    Arch:     $Arch"
Write-Host "    API URL:  $ApiUrl"

# --- Download binary -------------------------------------------------------
Write-Host "==> Downloading from $DownloadUrl"
$TmpBin  = [System.IO.Path]::GetTempFileName() + ".exe"
$TmpHash = [System.IO.Path]::GetTempFileName()
try {
    Invoke-WebRequest -Uri $DownloadUrl  -OutFile $TmpBin  -UseBasicParsing
    Invoke-WebRequest -Uri $ChecksumUrl  -OutFile $TmpHash -UseBasicParsing

    $Expected = (Get-Content $TmpHash -Raw).Trim().Split(" ")[0].ToLower()
    $Actual   = (Get-FileHash $TmpBin -Algorithm SHA256).Hash.ToLower()
    if ($Expected -ne $Actual) {
        throw "Checksum mismatch: expected $Expected, got $Actual"
    }
    Write-Host "    Checksum verified."
} catch {
    Remove-Item $TmpBin,$TmpHash -Force -ErrorAction SilentlyContinue
    throw
}

# --- Stop existing service if running --------------------------------------
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "==> Stopping existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# --- Install binary --------------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir    | Out-Null
Copy-Item $TmpBin $BinaryPath -Force
Remove-Item $TmpBin,$TmpHash -Force -ErrorAction SilentlyContinue
Write-Host "==> Binary installed to $BinaryPath"

# --- Write config ----------------------------------------------------------
if (-not (Test-Path $ConfigPath)) {
    $Hostname = $env:COMPUTERNAME
    $Config = @"
agent:
  name: "$Hostname"
  install_token: "$InstallToken"
  data_dir: "$($DataDir -replace '\\','\\')"
  heartbeat: 30s

api:
  base_url: "$ApiUrl"
  timeout: 30s
  retry_max: 5
  retry_delay: 5s

transport:
  insecure_skip_verify: false

telemetry:
  wmi:
    enabled: true
    interval: 30s
    queries:
      - name: cpu_load
        namespace: "root\\cimv2"
        query: "SELECT LoadPercentage FROM Win32_Processor"
      - name: disk_space
        namespace: "root\\cimv2"
        query: "SELECT FreeSpace, Size, DeviceID FROM Win32_LogicalDisk WHERE DriveType=3"
      - name: memory
        namespace: "root\\cimv2"
        query: "SELECT FreePhysicalMemory, TotalVisibleMemorySize FROM Win32_OperatingSystem"
  syslog:
    enabled: false
  snmp:
    enabled: false
  api_collector:
    enabled: false

actions:
  enabled: true
  max_concurrent: 5
  timeout: 5m
  allowed_actions:
    - run_command
    - restart_service
    - collect_diagnostics
    - apply_config

buffer:
  enabled: true
  max_size: 10000

updater:
  enabled: true
  channel: stable
  interval: 6h

log:
  level: info
  file: "C:\\ProgramData\\AIOne\\Agent\\agent.log"
"@
    $Config | Set-Content -Path $ConfigPath -Encoding UTF8
    Write-Host "==> Config written to $ConfigPath"
}

# Restrict config permissions to SYSTEM + Administrators only.
$Acl = Get-Acl $ConfigPath
$Acl.SetAccessRuleProtection($true, $false)
foreach ($Identity in @("SYSTEM","Administrators")) {
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Identity, "FullControl", "Allow")
    $Acl.AddAccessRule($Rule)
}
Set-Acl -Path $ConfigPath -AclObject $Acl

# --- Register Windows Service ---------------------------------------------
$ExistingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($ExistingSvc) {
    Write-Host "==> Updating existing service..."
    sc.exe config $ServiceName binPath= "`"$BinaryPath`" -config `"$ConfigPath`"" | Out-Null
} else {
    Write-Host "==> Registering Windows service..."
    New-Service `
        -Name        $ServiceName `
        -DisplayName $ServiceDisplay `
        -Description "AI One telemetry collection and management agent" `
        -BinaryPathName "`"$BinaryPath`" -config `"$ConfigPath`"" `
        -StartupType Automatic | Out-Null
}

# Set recovery actions: restart after 10s, 30s, 60s.
sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

Start-Service -Name $ServiceName
Write-Host "==> Service '$ServiceName' started."
Write-Host ""
Write-Host "==> AI One Agent installation complete."
Write-Host "    View status: Get-Service $ServiceName"
Write-Host "    View logs:   Get-Content `"$DataDir\agent.log`" -Wait"
