<#
  Builds the Windows release files from target\release (after `cargo build --release`):
    dist\PIALite-<version>-windows-x64.msi            installer (choose features)
    dist\PIALite-<version>-windows-x64-portable.zip   the tray alone, nothing installed
  Needs the WiX Toolset v5 command-line tool:
    dotnet tool install --global wix --version 5.0.2
    wix extension add -g WixToolset.UI.wixext/5.0.2
    wix extension add -g WixToolset.Util.wixext/5.0.2
#>
param([Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')
New-Item -ItemType Directory -Force -Path dist | Out-Null
foreach ($f in 'pialite-tray.exe', 'pialite-guard.exe') {
    if (-not (Test-Path "target\release\$f")) { throw "target\release\$f missing - run cargo build --release first" }
}

$msi = "dist\PIALite-$Version-windows-x64.msi"
wix build packaging\windows\PIALite.wxs -arch x64 -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext `
    -d "Version=$Version" -d "Bin=target\release" -d "Assets=assets" -d "Pkg=packaging\windows" -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
Remove-Item -Force -ErrorAction SilentlyContinue "dist\*.wixpdb"   # WiX debug data, not for release
Write-Host "built $msi"

$p = 'dist\portable'
if (Test-Path $p) { Remove-Item -Recurse -Force $p }
New-Item -ItemType Directory -Path $p | Out-Null
Copy-Item target\release\pialite-tray.exe, target\release\pialite-guard.exe, LICENSE -Destination $p
[IO.File]::WriteAllText((Join-Path (Resolve-Path $p) 'install-kind'), "portable`n")
$readme = @"
PIA Lite $Version - portable

Double-click pialite-tray.exe. Nothing is installed; delete the folder to remove it.
Needs Private Internet Access (PIA) to be installed.

The portable version is the tray only. For the kill switch, encrypted DNS and the
hotel Wi-Fi login (a background service), use PIALite-$Version-windows-x64.msi.

https://github.com/NicholasBly/PIALite
"@
[IO.File]::WriteAllText((Join-Path (Resolve-Path $p) 'README.txt'), $readme.Replace("`n", "`r`n"))
$zip = "dist\PIALite-$Version-windows-x64-portable.zip"
Compress-Archive -Path "$p\*" -DestinationPath $zip -Force
Remove-Item -Recurse -Force $p
Write-Host "built $zip"
