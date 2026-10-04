@echo off
rem Optional. The built interface is already included in frontend\dist.
rem Only run this if you change files in frontend\src. It needs Node.js 18 or newer.
cd /d "%~dp0frontend"
call npm install || goto :fail
call npm run build || goto :fail
echo.
echo Frontend built into frontend\dist
goto :eof

:fail
echo.
echo Build failed. Install Node.js 18 or newer from https://nodejs.org and try again.
pause
