@echo off
title ClamAV Windows 11 Scanner (Final Fixed)

set CLAMAV_DIR=C:\Program Files\ClamAV
set DB_DIR=%CLAMAV_DIR%\database
set CONF=%CLAMAV_DIR%\freshclam.conf
set SCAN_TARGET=C:\Users
set REPORT=%~dp0clamav_report.txt

echo =====================================
echo   ClamAV Manual Scanner (Windows 11)
echo =====================================
echo.

REM ---- Check ClamAV ----
if not exist "%CLAMAV_DIR%\freshclam.exe" (
    echo ❌ ClamAV not found!
    pause
    exit /b
)

REM ---- Ensure database directory ----
if not exist "%DB_DIR%" mkdir "%DB_DIR%"

REM ---- Build freshclam.conf from scratch ----
echo 🔧 Rebuilding freshclam.conf ...

(
echo DatabaseDirectory "%DB_DIR%"
echo UpdateLogFile "%CLAMAV_DIR%\freshclam.log"
echo LogTime yes
echo DatabaseMirror database.clamav.net
echo DatabaseMirror db.local.clamav.net
echo CompressLocalDatabase no
) > "%CONF%"

echo 🔄 Updating virus database...
"%CLAMAV_DIR%\freshclam.exe"
if errorlevel 1 (
    echo ❌ Database update failed
    echo Check firewall / Defender exclusions
    pause
    exit /b
)

echo.
echo 🔍 Scanning %SCAN_TARGET% ...
echo.

"%CLAMAV_DIR%\clamscan.exe" -r --infected --log="%REPORT%" "%SCAN_TARGET%"

echo.
echo =====================================
echo ✅ Scan completed
echo 📄 Report saved to:
echo %REPORT%
echo =====================================
pause
