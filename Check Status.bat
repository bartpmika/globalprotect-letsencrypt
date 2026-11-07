@echo off
rem Windows: double-click to run. Keeps the window open to show the result.
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 gpcert.py status
  goto done
)
where python >nul 2>nul
if not errorlevel 1 (
  python gpcert.py status
  goto done
)
echo Python 3 is needed: install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
:done
echo.
pause
