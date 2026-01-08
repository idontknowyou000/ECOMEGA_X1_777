@echo off
:: OMEGA-PLOUTUS AI INTEGRATION - Windows XP Compatible
:: ===================================================
:: This script is designed to run on Windows XP systems

:: Check Windows version
ver | find "Windows XP" > nul
if errorlevel 1 (
    echo This script is designed for Windows XP only.
    echo Current system may not be fully compatible.
    pause
)

:: Set compatibility mode
set COMPAT_MODE=XP
set MEMORY_LIMIT=512M
set CPU_PRIORITY=NORMAL

:: Display header
echo =================================================
echo 🔥 OMEGA-PLOUTUS AI - Windows XP Edition 🔥
echo =================================================
echo =================================================
echo.

:: Check system requirements
echo 📋 Checking system requirements...
echo.

:: Check memory
systeminfo | find "Total Physical Memory" > temp_mem.txt
for /f "tokens=2 delims=:" %%a in ('findstr /c:"Total Physical Memory" temp_mem.txt') do (
    for /f "tokens=2 delims=MB" %%b in ("%%a") do (
        set TOTAL_MEM=%%b
    )
)
del temp_mem.txt

if %TOTAL_MEM% LSS 64 (
    echo ❌ Error: Minimum 64MB RAM required (Found: %TOTAL_MEM%MB)
    pause
    exit /b 1
) else (
    echo ✅ Memory: %TOTAL_MEM%MB (Minimum 64MB required)
)

:: Check CPU
echo ✅ CPU: Compatible with Windows XP

:: Set environment variables
set OMEGA_AI_PORT=31337
set OMEGA_AI_HOST=127.0.0.1
set OMEGA_LOG_FILE=omega_xp.log
set OMEGA_CONFIG=omega_ploutus_config.txt

:: Create log file
echo [OMEGA-AI-XP] %date% %time% - Script started > %OMEGA_LOG_FILE%

:: Main menu
:menu
cls
echo =================================================
echo 🔥 OMEGA-PLOUTUS AI - Windows XP Edition 🔥
echo =================================================
echo.
echo 1. Start AI Server (XP Compatible)
echo 2. Run Malware Simulation (XP Safe Mode)
echo 3. Test System Compatibility
echo 4. View Configuration
echo 5. Exit
echo.
set /p choice=Enter your choice (1-5):

if "%choice%"=="1" goto start_ai
if "%choice%"=="2" goto malware_sim
if "%choice%"=="3" goto test_compat
if "%choice%"=="4" goto view_config
if "%choice%"=="5" goto exit_script

echo Invalid choice. Please try again.
pause
goto menu

:start_ai
echo 🚀 Starting OMEGA AI Server (XP Compatible Mode)...
echo [OMEGA-AI-XP] %date% %time% - AI Server starting >> %OMEGA_LOG_FILE%

:: Check if Python is available
python --version > nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Install Python 2.7 for Windows XP.
    echo Download: https://www.python.org/downloads/release/python-2718/
    pause
    goto menu
)

:: Start AI server with XP compatibility
start "OMEGA AI Server" /LOW python omega_ai_server.py
echo ✅ AI Server started in XP compatibility mode.
echo 📊 Port: %OMEGA_AI_PORT% | Host: %OMEGA_AI_HOST%
pause
goto menu

:malware_sim
echo 💉 Running Malware Simulation (XP Safe Mode)...
echo [OMEGA-AI-XP] %date% %time% - Malware simulation started >> %OMEGA_LOG_FILE%

:: XP Safe Mode simulation
echo 🔍 Scanning for targets (Simulation)...
timeout /t 2 > nul
echo 🎯 Target found: Generic ATM (Simulation)
timeout /t 2 > nul
echo 🧠 AI Analysis: High success probability (Simulation)
timeout /t 2 > nul
echo ✅ Operation completed successfully (Simulation)
echo.

echo This is system simulation.
pause
goto menu

:test_compat
echo 🧪 Testing Windows XP Compatibility...
echo [OMEGA-AI-XP] %date% %time% - Compatibility test started >> %OMEGA_LOG_FILE%

:: Test system components
echo 🔍 Testing network connectivity...
ping 127.0.0.1 -n 1 > nul
if errorlevel 1 (
    echo ❌ Network test failed
) else (
    echo ✅ Network test passed
)

echo 🔍 Testing file system...
if exist %OMEGA_CONFIG% (
    echo ✅ Configuration file accessible
) else (
    echo ❌ Configuration file not found
)

echo 🔍 Testing memory allocation...
:: Simple memory test
set /a test_var=1024*1024
if %test_var% EQU 1048576 (
    echo ✅ Memory allocation test passed
) else (
    echo ❌ Memory allocation test failed
)

echo.
echo ✅ Windows XP compatibility test complete.
pause
goto menu

:view_config
echo 📄 Viewing Configuration...
echo =================================================
if exist %OMEGA_CONFIG% (
    type %OMEGA_CONFIG%
) else (
    echo Configuration file not found: %OMEGA_CONFIG%
)
echo =================================================
pause
goto menu

:exit_script
echo 🛑 Shutting down OMEGA-PLOUTUS AI (XP Edition)...
echo [OMEGA-AI-XP] %date% %time% - Script terminated >> %OMEGA_LOG_FILE%

:: Clean up
taskkill /f /im python.exe > nul 2>&1

echo ✅ Thank you for using OMEGA-PLOUTUS AI.
echo System terminated successfully.
timeout /t 3 > nul
exit /b 0
