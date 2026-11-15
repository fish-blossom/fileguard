Option Explicit
Dim fso, f, n
Set fso = CreateObject("Scripting.FileSystemObject")
n = 0
For Each f In fso.GetFolder(".").Files
  n = n + 1
Next
WScript.Echo "Files: " & n
