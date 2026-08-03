@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "RUNTIME_DIR=%CD%\.runtime"
set "PYTHON_EXE=%RUNTIME_DIR%\python\python.exe"
set "BROWSER_PATH_FILE=%RUNTIME_DIR%\browser.path"
set "CHROMIUM_PATH="
if exist "%BROWSER_PATH_FILE%" set /p "CHROMIUM_PATH="<"%BROWSER_PATH_FILE%"
set "LOCAL_TEMP=%RUNTIME_DIR%\temp"
set "TEMP=%LOCAL_TEMP%"
set "TMP=%LOCAL_TEMP%"
set "PIP_CACHE_DIR=%RUNTIME_DIR%\pip-cache"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

set "NEED_SETUP=0"
if not exist "%PYTHON_EXE%" set "NEED_SETUP=1"
if not defined CHROMIUM_PATH set "NEED_SETUP=1"
if defined CHROMIUM_PATH if not exist "%CHROMIUM_PATH%" set "NEED_SETUP=1"
if not exist "%RUNTIME_DIR%\requirements.sha256" set "NEED_SETUP=1"

if "%NEED_SETUP%"=="0" (
    for /f "usebackq delims=" %%H in (`powershell.exe -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%CD%\requirements.txt').Hash"`) do set "CURRENT_HASH=%%H"
    set /p "INSTALLED_HASH="<"%RUNTIME_DIR%\requirements.sha256"
    if /i not "!CURRENT_HASH!"=="!INSTALLED_HASH!" set "NEED_SETUP=1"
)

if "%NEED_SETUP%"=="1" (
    echo The project-local Python environment is missing or outdated.
    call "%CD%\setup.cmd"
    if errorlevel 1 goto :failed
    set /p "CHROMIUM_PATH="<"%BROWSER_PATH_FILE%"
)

if "%~1"=="" goto :menu
if "%~1"=="1" goto :menu_dashboard
if "%~1"=="2" goto :menu_status
if "%~1"=="3" goto :menu_sanitize
if "%~1"=="4" goto :menu_sanitize_single
if "%~1"=="5" goto :menu_export
if "%~1"=="6" goto :menu_retry
if /i "%~1"=="0" goto :menu_exit

"%PYTHON_EXE%" -m src.main %*
exit /b %errorlevel%

:menu
echo.
echo  RIYU Quick Start
echo  ==================
echo   1. Dashboard panel      start.cmd dashboard
echo   2. Account status       start.cmd status
echo   3. Batch sanitize TXT   start.cmd sanitize --input accounts.txt
echo   4. Single sanitize      start.cmd sanitize-single
echo   5. Export accounts      start.cmd export
echo   6. Retry failed         start.cmd retry-failed
echo   0. Exit
echo.
set /p "CHOICE=Enter number: "
if /i "!CHOICE!"=="1" goto :menu_dashboard
if /i "!CHOICE!"=="2" goto :menu_status
if /i "!CHOICE!"=="3" goto :menu_sanitize
if /i "!CHOICE!"=="4" goto :menu_sanitize_single
if /i "!CHOICE!"=="5" goto :menu_export
if /i "!CHOICE!"=="6" goto :menu_retry
if /i "!CHOICE!"=="0" goto :menu_exit
echo Invalid number: !CHOICE!
pause
exit /b 0

:menu_dashboard
"%PYTHON_EXE%" -m src.main dashboard
pause
exit /b %errorlevel%

:menu_status
"%PYTHON_EXE%" -m src.main status
pause
exit /b %errorlevel%

:menu_sanitize
set "INPUT_FILE="
set /p "INPUT_FILE=Enter account file path (default accounts.txt): "
if not defined INPUT_FILE set "INPUT_FILE=accounts.txt"
"%PYTHON_EXE%" -m src.main sanitize --input "%INPUT_FILE%"
pause
exit /b %errorlevel%

:menu_sanitize_single
set "GMAIL="
set "PASSWORD="
set "TOTP="
set /p "GMAIL=Enter Gmail: "
set /p "PASSWORD=Enter current password: "
set /p "TOTP=Enter 2FA secret (leave empty if none): "
"%PYTHON_EXE%" -m src.main sanitize-single --gmail "%GMAIL%" --password "%PASSWORD%" --2fa "%TOTP%"
pause
exit /b %errorlevel%

:menu_export
set "OUTPUT="
set /p "OUTPUT=Enter export path (default clean_accounts.json): "
if not defined OUTPUT set "OUTPUT=clean_accounts.json"
"%PYTHON_EXE%" -m src.main export --output "%OUTPUT%"
pause
exit /b %errorlevel%

:menu_retry
"%PYTHON_EXE%" -m src.main retry-failed
pause
exit /b %errorlevel%

:menu_exit
echo Exited.
exit /b 0

:failed
echo.
echo Startup failed.
pause
exit /b 1
