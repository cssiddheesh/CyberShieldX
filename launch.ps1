$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $projectRoot "config.yml"
$cloudflaredPath = Join-Path $projectRoot "cloudflared.exe"
$envPath = Join-Path $projectRoot ".env"

Set-Location $projectRoot

foreach ($requiredPath in @($configPath, $cloudflaredPath, (Join-Path $projectRoot "run.bat"))) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required project file not found: $requiredPath"
    }
}

if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    $examplePath = Join-Path $projectRoot ".env.example"
    if (-not (Test-Path -LiteralPath $examplePath -PathType Leaf)) {
        throw "Neither .env nor .env.example exists in the project folder."
    }
    Copy-Item -LiteralPath $examplePath -Destination $envPath
    Write-Host "Created .env from .env.example."
}

$portLines = @(Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^\s*CYBERSHIELD_PORT\s*=' })
if ($portLines.Count -gt 1) {
    throw "The .env file contains more than one CYBERSHIELD_PORT setting."
}

$serverPort = 8000
if ($portLines.Count -eq 1) {
    if ($portLines[0] -notmatch '^\s*CYBERSHIELD_PORT\s*=\s*(\d+)\s*$') {
        throw "CYBERSHIELD_PORT in .env must be a port number."
    }
    $serverPort = [int]$Matches[1]
}
if ($serverPort -lt 1 -or $serverPort -gt 65535) {
    throw "CYBERSHIELD_PORT must be between 1 and 65535."
}

$configText = Get-Content -LiteralPath $configPath -Raw
if ($configText -notmatch '(?m)^\s*service:\s*http://127\.0\.0\.1:(\d+)\s*$') {
    throw "config.yml must route an ingress to http://127.0.0.1:<port>."
}
$tunnelPort = [int]$Matches[1]
if ($serverPort -ne $tunnelPort) {
    throw "Port mismatch: .env uses $serverPort but config.yml routes to $tunnelPort. Set both to the same port."
}

if ($configText -notmatch '(?m)^\s*-\s*hostname:\s*(\S+)\s*$') {
    throw "No tunnel hostname was found in config.yml."
}
$publicHostname = $Matches[1]

if ($configText -notmatch '(?m)^\s*credentials-file:\s*(.+?)\s*$') {
    throw "No credentials-file setting was found in config.yml."
}
$credentialsPath = $Matches[1].Trim().Trim('"').Trim("'").Replace('/', '\')
if (-not [IO.Path]::IsPathRooted($credentialsPath)) {
    $credentialsPath = Join-Path $projectRoot $credentialsPath
}
if (-not (Test-Path -LiteralPath $credentialsPath -PathType Leaf)) {
    throw "Cloudflare tunnel credentials were not found at $credentialsPath."
}

$healthUrl = "http://127.0.0.1:$serverPort/api/health"
function Test-CyberShieldHealth {
    try {
        $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 3
        if ($response.StatusCode -ne 200) {
            return $false
        }
        $health = $response.Content | ConvertFrom-Json
        return $health.status -eq "ok" -and $health.app -eq "CyberShield X"
    }
    catch {
        return $false
    }
}

if (Test-CyberShieldHealth) {
    Write-Host "CyberShield X is already healthy on port $serverPort."
}
else {
    $listener = Get-NetTCPConnection -State Listen -LocalPort $serverPort -ErrorAction SilentlyContinue
    if ($listener) {
        throw "Port $serverPort is already in use by a service that did not pass the CyberShield X health check."
    }

    Write-Host "Starting CyberShield X. Its console will show server logs."
    $serverCommand = "cd /d `"$projectRoot`" && call run.bat"
    Start-Process -FilePath $env:ComSpec -ArgumentList @("/k", $serverCommand) -WorkingDirectory $projectRoot

    $ready = $false
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        Start-Sleep -Seconds 2
        if (Test-CyberShieldHealth) {
            $ready = $true
            break
        }
    }
    if (-not $ready) {
        throw "CyberShield X did not become healthy on port $serverPort within 180 seconds. Check the server console."
    }
    Write-Host "CyberShield X is healthy on port $serverPort."
}

$cloudflaredProcesses = @(Get-CimInstance Win32_Process -Filter "Name = 'cloudflared.exe'" |
    Where-Object {
        $_.ExecutablePath -eq $cloudflaredPath -and
        $_.CommandLine -match '(?i)tunnel.*--config.*config\.yml.*run'
    })

if ($cloudflaredProcesses.Count -gt 0) {
    Write-Host "The project Cloudflare tunnel is already running."
}
else {
    Write-Host "Starting the Cloudflare tunnel. Its console will show tunnel status."
    Start-Process -FilePath $cloudflaredPath `
        -ArgumentList @("tunnel", "--config", "config.yml", "run") `
        -WorkingDirectory $projectRoot

    Start-Sleep -Seconds 3
    $cloudflaredProcesses = @(Get-CimInstance Win32_Process -Filter "Name = 'cloudflared.exe'" |
        Where-Object {
            $_.ExecutablePath -eq $cloudflaredPath -and
            $_.CommandLine -match '(?i)tunnel.*--config.*config\.yml.*run'
        })
    if ($cloudflaredProcesses.Count -eq 0) {
        throw "The Cloudflare tunnel process did not stay running. Check your tunnel console and config.yml."
    }
}

Write-Host ""
Write-Host "CyberShield X: http://localhost:$serverPort"
Write-Host "Public tunnel:  https://$publicHostname"
