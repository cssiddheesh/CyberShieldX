@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")

if not exist ".venv\Scripts\python.exe" (
  echo Creating a Python virtual environment...
  %PY% -m venv .venv || goto :fail
)
call ".venv\Scripts\activate.bat"

echo Checking Python packages...
python -m pip install --disable-pip-version-check -q -r requirements.txt || goto :fail

if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo Created .env from .env.example. API keys are optional.
)

python -m app.main
goto :eof

:fail
echo.
echo Setup failed. Install Python 3.10 or newer from https://www.python.org/downloads/
echo (tick "Add python.exe to PATH") and make sure you are online for the first run.
pause
