@echo off
setlocal
cd /d "%~dp0"

if not exist "cloudflared.exe" (
  echo cloudflared.exe was not found in "%~dp0".
  pause
  exit /b 1
)

if not exist "config.yml" (
  echo config.yml was not found in "%~dp0".
  pause
  exit /b 1
)

echo Starting the Cloudflare tunnel. Press Ctrl+C to stop it.
.\cloudflared.exe tunnel --config config.yml run

echo.
echo The Cloudflare tunnel has stopped.
pause
