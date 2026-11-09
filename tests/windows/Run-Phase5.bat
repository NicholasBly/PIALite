@echo off
title PIA Lite - Phase 5 tests
cd /d "%~dp0"
rem needs admin (firewall audit, packet capture, reading firewall rules)
net session >nul 2>&1
if errorlevel 1 (
    rem Not elevated yet: first check the guard's control pipe AS A NORMAL USER
    rem - a normal program must not be able to weaken the block or take over the pipe.
    if exist "%ProgramFiles%\PiaLite\pialite-guard.exe" (
        echo Checking the guard's control pipe as a normal user - a few seconds...
        "%ProgramFiles%\PiaLite\pialite-guard.exe" pipe-selftest > "%PUBLIC%\PiaLite-pipe-selftest.txt" 2>&1
    )
    powershell.exe -NoProfile -Command "Start-Process -FilePath \"%~f0\" -Verb RunAs"
    exit /b
)
rem check the scripts for typos before running them
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$bad = 0; foreach ($f in @('Phase5-Tests.ps1', 'PiaLite-Common.ps1')) { $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('%~dp0scripts\' + $f, [ref]$null, [ref]$e); if ($e) { $bad = 1; $e | ForEach-Object { Write-Host ($f + ': ' + $_) -ForegroundColor Red } } }; exit $bad"
if errorlevel 1 (
    echo.
    echo The test script has an error - copy the red text above into a bug report.
    pause
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Phase5-Tests.ps1"
