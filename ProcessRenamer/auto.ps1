$csc = Get-ChildItem -Path 'C:\Windows\Microsoft.NET\Framework\v4.0.30319' -Recurse -Filter csc.exe | Sort-Object LastWriteTime -Descending | Select-Object -First 1

$psdll = $null
$searchPaths = @(
    'C:\Program Files (x86)\Reference Assemblies\Microsoft\WindowsPowerShell\',
    'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation',
    'C:\Windows\System32\WindowsPowerShell\v1.0'
)
foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        $found = Get-ChildItem -Path $path -Recurse -Filter System.Management.Automation.dll -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($found) { $psdll = $found; break }
    }
}

if ($csc -and $psdll) {
    & $csc.FullName  /out:ProcessRenamer.exe /reference:"$($psdll.FullName)" ProcessRenamer.cs
} elseif (-not $psdll) {
    Write-Host "System.Management.Automation.dll not found. Checked paths:`n$($searchPaths -join "`n")`nInstall Windows Management Framework or Windows PowerShell SDK."
} else {
    Write-Host "csc.exe not found. Install .NET Framework Developer Pack or use dotnet CLI."
}