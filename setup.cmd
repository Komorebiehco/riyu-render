@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "RUNTIME_DIR=%CD%\.runtime"
set "DOWNLOAD_DIR=%RUNTIME_DIR%\downloads"
set "PYTHON_DIR=%RUNTIME_DIR%\python"
set "PYTHON_EXE=%PYTHON_DIR%\python.exe"
set "PYTHON_VERSION=3.12.10"
set "PYTHON_ZIP=%DOWNLOAD_DIR%\python-%PYTHON_VERSION%-embed-amd64.zip"
set "PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-embed-amd64.zip"
set "GET_PIP=%DOWNLOAD_DIR%\get-pip.py"
set "BROWSER_PATH_FILE=%RUNTIME_DIR%\browser.path"
set "LOCAL_TEMP=%RUNTIME_DIR%\temp"
set "TEMP=%LOCAL_TEMP%"
set "TMP=%LOCAL_TEMP%"
set "PIP_CACHE_DIR=%RUNTIME_DIR%\pip-cache"
set "PYTHONUTF8=1"
set "PIP_DISABLE_PIP_VERSION_CHECK=1"

echo [1/5] Preparing local runtime directory...
if not exist "%DOWNLOAD_DIR%" mkdir "%DOWNLOAD_DIR%"
if not exist "%LOCAL_TEMP%" mkdir "%LOCAL_TEMP%"
if not exist "%PIP_CACHE_DIR%" mkdir "%PIP_CACHE_DIR%"
if errorlevel 1 goto :failed

if not exist "%PYTHON_EXE%" (
    echo [2/5] Downloading portable Python %PYTHON_VERSION%...
    where curl.exe >nul 2>&1
    if errorlevel 1 (
        echo ERROR: curl.exe is unavailable on this Windows installation.
        goto :failed
    )

    curl.exe --fail --location --retry 3 --output "%PYTHON_ZIP%" "%PYTHON_URL%"
    if errorlevel 1 goto :failed

    if not exist "%PYTHON_DIR%" mkdir "%PYTHON_DIR%"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%PYTHON_ZIP%' -DestinationPath '%PYTHON_DIR%' -Force"
    if errorlevel 1 goto :failed

    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p = Join-Path '%PYTHON_DIR%' 'python312._pth'; (Get-Content -LiteralPath $p) -replace '^#import site$', 'import site' | Set-Content -LiteralPath $p -Encoding ascii"
    if errorlevel 1 goto :failed
) else (
    echo [2/5] Portable Python is already installed.
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p = Join-Path '%PYTHON_DIR%' 'python312._pth'; $lines = @(Get-Content -LiteralPath $p); $lines = $lines -replace '^#import site$', 'import site'; if ($lines -notcontains '..\..') { $lines += '..\..' }; $lines | Set-Content -LiteralPath $p -Encoding ascii"
if errorlevel 1 goto :failed

echo [3/5] Preparing local pip...
"%PYTHON_EXE%" -m pip --version >nul 2>&1
if errorlevel 1 (
    if not exist "%GET_PIP%" (
        curl.exe --fail --location --retry 3 --output "%GET_PIP%" "https://bootstrap.pypa.io/get-pip.py"
        if errorlevel 1 goto :failed
    )
    "%PYTHON_EXE%" "%GET_PIP%" --no-warn-script-location
    if errorlevel 1 goto :failed
)

echo [4/5] Installing Python dependencies into the project...
"%PYTHON_EXE%" -m pip install --no-warn-script-location --upgrade pip setuptools wheel
if errorlevel 1 goto :failed
"%PYTHON_EXE%" -m pip install --no-warn-script-location -r "%CD%\requirements.txt"
if errorlevel 1 goto :failed

echo [5/5] Detecting a Chromium-based browser...
set "BROWSER_EXE="
if exist "%RUNTIME_DIR%\chromium\chrome-win64\chrome.exe" set "BROWSER_EXE=%RUNTIME_DIR%\chromium\chrome-win64\chrome.exe"
if not defined BROWSER_EXE if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" set "BROWSER_EXE=C:\Program Files\Google\Chrome\Application\chrome.exe"
if not defined BROWSER_EXE if exist "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" set "BROWSER_EXE=C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
if not defined BROWSER_EXE if exist "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe" set "BROWSER_EXE=%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"
if not defined BROWSER_EXE if exist "C:\Program Files\Microsoft\Edge\Application\msedge.exe" set "BROWSER_EXE=C:\Program Files\Microsoft\Edge\Application\msedge.exe"
if not defined BROWSER_EXE if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" set "BROWSER_EXE=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not defined BROWSER_EXE (
    echo ERROR: Chrome or Microsoft Edge was not found.
    goto :failed
)

>"%BROWSER_PATH_FILE%" echo %BROWSER_EXE%
for /f "usebackq delims=" %%V in (`powershell.exe -NoProfile -Command "(Get-Item -LiteralPath '%BROWSER_EXE%').VersionInfo.FileVersion"`) do set "BROWSER_VERSION=%%V"

for /f "usebackq delims=" %%H in (`powershell.exe -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%CD%\requirements.txt').Hash"`) do set "REQUIREMENTS_HASH=%%H"
>"%RUNTIME_DIR%\requirements.sha256" echo %REQUIREMENTS_HASH%

echo.
echo Local environment is ready:
echo   Python: %PYTHON_EXE%
echo   Browser: %BROWSER_EXE% ^(%BROWSER_VERSION%^)
exit /b 0

:failed
echo.
echo ERROR: Local environment setup failed. Check the message above and try again.
exit /b 1
