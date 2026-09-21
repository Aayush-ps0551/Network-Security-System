@echo off
TITLE Network Security Dashboard Server
COLOR 0B

:: 1. Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo =====================================================
    echo Requesting Administrator privileges for Network Scan...
    echo =====================================================
    :: Safely launch cmd as admin and run this script
    powershell -Command "Start-Process cmd -ArgumentList '/c """%~dpnx0"""' -Verb RunAs"
    exit /b
)

:: 2. Set working directory to the folder where the bat file is
cd /d "%~dp0"
if exist dashboard (
    cd dashboard
) else (
    echo ERROR: Dashboard folder not found. 
    pause
    exit /b
)

echo =======================================================
echo       Network Recon Dashboard - Startup Sequence       
echo =======================================================
echo.

:: 3. Check if Python is accessible in Admin mode
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not recognized as a command!
    echo This usually happens if Python was installed without checking the "Add to PATH" box,
    echo or if it's only in your user's path, not the Administrator path.
    echo.
    echo Please reinstall Python and check "Add Python to system PATH".
    echo.
    pause
    exit /b
)

echo [1/3] Checking required Python packages...
python -m pip install -r requirements.txt -q

echo.
echo [2/3] Opening Dashboard in your web browser...
start http://127.0.0.1:5000

echo.
echo [3/3] Starting Backend Server...
echo.
echo *** KEEP THIS WINDOW OPEN TO KEEP THE APP RUNNING ***
echo =======================================================
python app.py

:: If the server crashes or closes, this keeps the window open so you can read the error!
echo.
echo [!] The server has stopped or crashed.
pause
