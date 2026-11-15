@echo off
setlocal
if not exist build mkdir build
xcopy /E /I /Y src build\src >nul
echo Build finished.
