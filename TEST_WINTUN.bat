@echo off
REM WinTun Test Script - Must run as Administrator
cd /d "%~dp0"

echo.
echo ================================================================
echo  WinTun Driver Test
echo ================================================================
echo.
echo This will test if WinTun can create a TUN interface.
echo.

REM Activate venv
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

python test_wintun.py
pause
