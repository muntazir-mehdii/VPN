@echo off
REM Production VPN Launcher - WinTun/WireGuard
REM Right-click this file and select "Run as administrator"

cd /d "%~dp0"
echo.
echo ================================================================
echo  Starting Production VPN (WinTun + WireGuard)
echo ================================================================
echo.

REM Activate virtual environment if it exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo WARNING: Virtual environment not found!
    echo Installing scapy to system Python...
    python -m pip install scapy
)

echo.
python launch_vpn.py
pause
