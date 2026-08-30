@echo off
setlocal

:: ── Check if already running as admin ──────────────────────────────────────
net session >nul 2>&1
if %errorlevel% == 0 goto :run

:: ── Re-launch this .bat elevated via PowerShell ────────────────────────────
powershell -NoProfile -Command ^
  "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs -Wait"
exit /b

:run
:: ── Locate Python ──────────────────────────────────────────────────────────
:: 1. Try 'py' launcher (standard Windows Python installer)
where py >nul 2>&1
if %errorlevel% == 0 (
    set PYTHON=py -3
    goto :check_dep
)
:: 2. Try 'python' on PATH
where python >nul 2>&1
if %errorlevel% == 0 (
    set PYTHON=python
    goto :check_dep
)
:: 3. Common user-install fallback (update version if needed)
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%D\python.exe" set PYTHON="%%D\python.exe"
)
if defined PYTHON goto :check_dep

echo Python not found. Install Python 3.10+ from https://python.org
pause
exit /b

:check_dep
:: ── Ensure customtkinter is installed ──────────────────────────────────────
%PYTHON% -c "import customtkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing customtkinter...
    %PYTHON% -m pip install customtkinter --quiet
)

:: ── Launch ─────────────────────────────────────────────────────────────────
%PYTHON% "%~dp0ASR-ControlCenter.py"
if %errorlevel% neq 0 (
    echo.
    echo ERROR: App exited with code %errorlevel%
    pause
)
