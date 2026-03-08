@echo off
cd /d "%~dp0"

REM Activate venv if exists
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

echo Starting VPN Server...
python run_server.py
pause
