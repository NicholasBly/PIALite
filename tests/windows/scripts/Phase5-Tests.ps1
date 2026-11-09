<#
    Phase5-Tests.ps1  -  PIA Lite test kit. Start it with Run-Phase5.bat (it asks for admin).

      1  Quick checks (2-5 minutes, no restart)
           guard health, control pipe protections (tested as a normal user),
           NextDNS end-to-end (Windows' own resolver, NextDNS's test page, your
           profile: confirmed / wrong / not confirmed), the route the DoH traffic
           really takes, DNS settings per adapter, the rules as Windows' firewall
           engine reports them (one condition per field), block test, hotel test,
           memory/CPU use
      2  Start the STARTUP LEAK TEST (turns on recording, then you restart)
      3  Finish the startup leak test (after restarting + VPN connected)
           Evidence from two independent sources, analysed here on this PC:
           - Windows firewall audit log: every allowed (5156) and blocked (5157)
             connection with the program that made it
           - packet capture that starts before Windows' firewall engine (netsh trace)
           Recording settings are put back afterwards.
      4  Undo leak test recording (if something went wrong)
      5  Packet-capture self-check (about a minute, no restart): sends known
           packets and checks the capture analysis finds them - proof the
           startup leak test's packet capture can see this PC's traffic

    Writes a report to your Desktop with your user name, PC name, NextDNS ID and
    MAC addresses removed. Nothing is uploaded anywhere.
#>
$ErrorActionPreference = 'Stop'
$piaDir      = Join-Path $env:ProgramFiles 'Private Internet Access'
$piactl      = Join-Path $piaDir 'piactl.exe'
$piaSettings = Join-Path $piaDir 'data\settings.json'
$guardExe    = Join-Path $env:ProgramFiles 'PiaLite\pialite-guard.exe'
$dataDir     = Join-Path $env:ProgramData 'PiaLite'
$workDir     = Join-Path $dataDir 'phase5'
$marker      = Join-Path $workDir 'leaktest.json'
$etl         = Join-Path $workDir 'boot.etl'
$auditBak    = Join-Path $workDir 'audit-before.csv'
$logSizeBak  = Join-Path $workDir 'seclog-size-before.txt'
$guardLog    = Join-Path $dataDir 'guard.log'
$wfpConnGuid = '{0CCE9226-69AE-11D9-BED3-505054503030}'   # audit subcategory "Filtering Platform Connection"
$svcName     = 'PiaLiteGuard'
$fixtures    = Join-Path $PSScriptRoot 'recovery-fixtures.json'

$script:lines  = New-Object System.Collections.Generic.List[string]
$script:counts = @{ PASS = 0; FAIL = 0; WARN = 0; INFO = 0 }

# ------------------------------------------------------------------ helpers

function Say([string]$Text) {
    $script:lines.Add($Text)
    Write-Host $Text
}

function Result([string]$Status, [string]$Name, [string]$Detail) {
    $script:counts[$Status]++
    $colors = @{ PASS = 'Green'; FAIL = 'Red'; WARN = 'Yellow'; INFO = 'Gray' }
    $line = '[' + $Status + '] ' + $Name
    if ($Detail) { $line += ' - ' + $Detail }
    $script:lines.Add($line)
    Write-Host $line -ForegroundColor $colors[$Status]
}

# ConvertTo-Arg, Invoke-Native (one overall time limit for the program AND its
# output), Get-Msg and the hotel recovery reader are shared with the installer.
. (Join-Path $PSScriptRoot 'PiaLite-Common.ps1')
$PSDefaultParameterValues['Invoke-Native:TimeoutSec'] = 180

function Invoke-Piactl([string]$ArgLine) {
    $p = Start-Process -FilePath $piactl -ArgumentList $ArgLine -PassThru -WindowStyle Hidden
    [void]$p.Handle
    if (-not $p.WaitForExit(30000)) { try { $p.Kill() } catch { }; return -1 }
    return $p.ExitCode
}

function Get-PiaSettings { return (Get-Content -LiteralPath $piaSettings -Raw | ConvertFrom-Json) }
function Get-PiaState { return (Invoke-Native $piactl @('get', 'connectionstate') -AllowFail).Output }

function Wait-PiaState([string]$Want, [int]$Seconds) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        if ((Get-PiaState) -eq $Want) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Set-PiaKillSwitch([string]$Value) {
    $code = Invoke-Piactl ('-u applysettings "{\"killswitch\":\"' + $Value + '\"}"')
    if ($code -ne 0) { throw "piactl could not change the kill switch (exit $code)" }
    for ($i = 0; $i -lt 10; $i++) {
        if ((Get-PiaSettings).killswitch -eq $Value) { return }
        Start-Sleep -Milliseconds 500
    }
    throw "PIA did not keep kill switch = $Value"
}

function Get-GuardStatus {
    if (-not (Test-Path -LiteralPath $guardExe)) { return $null }
    $r = Invoke-Native $guardExe @('status', '--json') -AllowFail
    try { return ($r.Output | ConvertFrom-Json) } catch { return $null }
}

# TCP connect with a time limit. $true = connected.
function Test-Tcp([string]$Ip, [int]$Port, [int]$Ms) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $c.ConnectAsync($Ip, $Port)
        if ($t.Wait($Ms)) { return $c.Connected }
        return $false
    } catch {
        return $false
    } finally {
        $c.Close()
    }
}

# The VPN tunnel adapter's IPv4 address: WireGuard (wgpia0) or OpenVPN
# (PIA's TAP / Wintun adapter). $null when the VPN isn't up.
function Get-Tunnel {
    $c = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'wgpia0' })
    if ($c.Count -eq 0) {
        $idx = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'Private Internet Access|TAP-Windows|Wintun|WireGuard' } |
            ForEach-Object { $_.ifIndex })
        $c = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $idx -contains $_.InterfaceIndex })
    }
    if ($c.Count -eq 0) { return $null }
    return [pscustomobject]@{ Alias = $c[0].InterfaceAlias; Index = $c[0].InterfaceIndex; Ip = $c[0].IPAddress }
}

function Protect-Text([string]$Text) {
    $nd = ''
    try { $nd = [string](Get-Content -LiteralPath (Join-Path $dataDir 'guard.json') -Raw | ConvertFrom-Json).profile_id } catch { }
    foreach ($s in @($env:USERNAME, $env:COMPUTERNAME, $nd)) {
        if ($s -and $s.Length -ge 3) { $Text = $Text -replace [regex]::Escape($s), '<redacted>' }
    }
    $Text = $Text -replace '(?i)\\users\\[^\\]+\\', '\users\<user>\'
    $Text = $Text -replace '(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b', '<mac>'
    return $Text
}

function Save-Report([string]$Kind) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path = Join-Path ([Environment]::GetFolderPath('Desktop')) "PiaLite-Phase5-$Kind-$stamp.txt"
    $head = @(
        "PIA Lite Phase 5 - $Kind - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        ('Summary: {0} PASS, {1} FAIL, {2} WARN, {3} INFO' -f $script:counts.PASS, $script:counts.FAIL, $script:counts.WARN, $script:counts.INFO),
        ''
    )
    $text = Protect-Text ((@($head) + @($script:lines)) -join "`r`n")
    [System.IO.File]::WriteAllText($path, $text, [System.Text.Encoding]::ASCII)
    Write-Host ''
    Write-Host "Report saved: $path" -ForegroundColor Cyan
    Write-Host 'Attach that file to your bug report (names, IDs and MAC addresses are already removed).' -ForegroundColor Cyan
}

function Get-IpClass([string]$Ip, [int]$Proto, [int]$Port) {
    if ($Proto -eq 17 -and ($Port -eq 67 -or $Port -eq 547)) { return 'dhcp' }
    if ($Ip -match '^(127\.|::1$|0\.0\.0\.0$|::$)') { return 'loopback' }
    if ($Ip -match '^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|22[4-9]\.|23\d\.|255\.255\.255\.255$)') { return 'local' }
    if ($Ip -match '^(?i)(fe[89ab]|ff|fc|fd)') { return 'local' }
    return 'internet'
}

function Write-Header {
    $os = Get-CimInstance Win32_OperatingSystem
    Say ('Windows: {0} build {1}' -f $os.Caption, $os.BuildNumber)
    $v = Invoke-Native $piactl @('--version') -AllowFail
    Say ('PIA: ' + ($v.Output -split "`n")[0])
    $fs = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue).HiberbootEnabled
    if ($fs -eq 1) { Say 'Fast Startup: ON (power-on after "Shut down" is a wake-up, not a fresh boot)' } else { Say 'Fast Startup: off' }
    # which build was tested (RELEASE-CHECKLIST.txt): the first 16 hex digits of each program's SHA-256
    # 0.9 installs the tray next to the guard (MSI); older builds put it in your profile
    $tray = Join-Path (Split-Path $guardExe) 'pialite-tray.exe'
    if (-not (Test-Path -LiteralPath $tray)) { $tray = Join-Path $env:LOCALAPPDATA 'PiaLite\pialite-tray.exe' }
    $ids = foreach ($f in @($guardExe, $tray)) {
        if (Test-Path -LiteralPath $f) { '{0} {1}' -f (Split-Path $f -Leaf), (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.Substring(0, 16) }
        else { '{0} not installed' -f (Split-Path $f -Leaf) }
    }
    Say ('Build: ' + ($ids -join ', '))
}

# ------------------------------------------------------------- quick checks

function Test-GuardHealth {
    Say ''
    Say '== Guard service'
    $s = Get-GuardStatus
    if (-not $s -or $s.error) {
        $why = 'no answer'
        if ($s -and $s.error) { $why = $s.error }
        Result 'FAIL' 'Guard service answers' $why
        return $null
    }
    Result 'PASS' 'Guard service answers' ('version ' + $s.version)
    Say ('Block mode: {0} ({1}); blocking now: {2}' -f $s.mode, $s.reason, $s.blocking)
    if ($s.mode -ne 'off') {
        if ($s.armed) { Result 'PASS' 'Block rules in place' 'confirmed in Windows by the guard' }
        else { Result 'FAIL' 'Block rules in place' $s.fw_error }
        if ($s.boot_rules) { Result 'PASS' 'Boot-time rules accepted by Windows' 'active before the firewall engine starts' }
        else { Result 'WARN' 'Boot-time rules accepted by Windows' $s.boot_rules_error }
    }
    Say ('PIA kill switch: {0}; PIA Allow LAN: {1}' -f $s.pia_killswitch, $s.pia_allow_lan)
    # the guard's own check of PIA's network adapter (review V4-12, F51-07)
    if ($s.pia_state -eq 'Connected') {
        $va = [string]$s.vpn_adapter
        switch ([string]$s.tunnel_watch) {
            'up' { Result 'PASS' 'PIA adapter observed up' "$va - what Windows reports, not a test of the encrypted tunnel itself. Always mode opens only while it is up; if it goes down while PIA still says Connected, the guard blocks" }
            'down' { Result 'WARN' 'PIA adapter observed up' "$va is DOWN while PIA says Connected - the guard blocks until it is back" }
            'not-found' { Result 'WARN' 'PIA adapter observed up' "none of PIA's adapters is up although PIA says Connected - Always mode keeps blocking" }
            'checking' { Result 'INFO' 'PIA adapter observed up' 'still looking (PIA just connected) - run again in a few seconds' }
            'query-failed' { Result 'WARN' 'PIA adapter observed up' "the last look at the network adapters failed ($va kept)" }
            default { Result 'INFO' 'PIA adapter observed up' 'this guard version does not report it' }
        }
        # information only (review V60-08): does Windows route internet traffic through it?
        if ($s.PSObject.Properties['route_via_vpn']) {
            if ($s.route_via_vpn -eq $true) { Result 'INFO' 'Internet route goes through the PIA adapter' "Windows' best route to NextDNS uses $va" }
            elseif ($s.route_via_vpn -eq $false) { Result 'WARN' 'Internet route goes through the PIA adapter' "Windows' best route to NextDNS does NOT use $va - PIA may be using a different adapter, or a route bypasses the VPN (please send this report)" }
            else { Result 'INFO' 'Internet route goes through the PIA adapter' 'not known yet' }
        }
    }
    if ($null -ne $s.network_ready) { Say ('Network (an adapter with an address and a gateway): {0}' -f $(if ($s.network_ready) { 'up' } else { 'none' })) }
    # left over from a "guard held back" leak test that wasn't finished
    $svc = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.DelayedAutoStart) { Result 'WARN' 'Guard service starts at boot' "it is set to DELAYED start (from a leak test hold) - finish the leak test (option 3) or undo it (option 4)" }
    if ($s.mode -eq 'startup' -and $s.pia_killswitch -ne 'on') {
        Result 'WARN' "PIA's kill switch is not 'Always'" "in 'startup' mode a later VPN drop is not blocked - use 'always' mode or set PIA's kill switch to Always"
    }
    if ($s.config_error) { Result 'FAIL' 'Guard settings file' $s.config_error }
    if ($s.restore_pending) { Result 'FAIL' 'Kill switch after hotel login' 'restore still pending' }
    $d = $s.dns
    if (-not $d.listening) { Result 'FAIL' 'DNS proxy listening on 127.0.0.1:53' $d.bind_error }
    else { Result 'PASS' 'DNS proxy listening on 127.0.0.1:53' '' }
    Say ('DNS health: {0}; answered {1}, failed {2}, refused (overload) {3}, malformed {4}; last lookup {5} ms' -f $d.health, $d.answered, $d.failed, $d.overloaded, $d.malformed, $d.last_ms)
    if ($d.health -eq 'down') { Result 'FAIL' 'NextDNS reachable' $d.last_error }
    if ($d.health -eq 'degraded') { Result 'WARN' 'NextDNS reachable' 'some recent lookups failed' }
    return $s
}

function Test-NextDnsPath {
    Say ''
    Say '== NextDNS end-to-end (Windows resolver -> guard -> NextDNS, checked on NextDNS test page)'
    $t = Invoke-Native $guardExe @('test-dns', '--json') -AllowFail
    $r = $null
    try { $r = $t.Output | ConvertFrom-Json } catch { }
    if (-not $r) { Result 'FAIL' 'NextDNS end-to-end test' (Get-Msg $t); return }
    if ($r.proxy_ok) { Result 'PASS' 'Lookups answered by the guard' '' }
    else { Result 'FAIL' 'Lookups answered by the guard' $r.proxy_error; return }
    if ($r.encrypted_ok) { Result 'PASS' 'NextDNS sees the lookups, encrypted (DoH)' ('NextDNS test page: status={0} protocol={1}' -f $r.nextdns_status, $r.protocol) }
    elseif ($r.page_checked) { Result 'FAIL' 'NextDNS sees the lookups, encrypted (DoH)' ('NextDNS test page: status={0} protocol={1}' -f $r.nextdns_status, $r.protocol) }
    else { Result 'FAIL' "NextDNS's test page" $r.page_error }
    switch ([string]$r.os_resolver) {
        'proxy'     { Result 'PASS' "Windows' own resolver sends lookups to the guard" $r.os_resolver_note }
        'elsewhere' { Result 'FAIL' "Windows' own resolver sends lookups to the guard" $r.os_resolver_note }
        default     { Result 'WARN' "Windows' own resolver sends lookups to the guard" ('not checked: ' + $r.os_resolver_note) }
    }
    switch ([string]$r.profile_check) {
        'match'    { Result 'PASS' 'YOUR NextDNS profile is used' $r.profile_note }
        'mismatch' { Result 'FAIL' 'YOUR NextDNS profile is used' $r.profile_note }
        default    { Result 'WARN' 'YOUR NextDNS profile is used' ('NOT confirmed: ' + $r.profile_note + ' - optional proof: put a test domain on your Denylist and run "pialite-guard test-dns --canary <domain>"') }
    }
}

function Test-DohRoute {
    Say ''
    Say '== Route of the encrypted DNS traffic'
    $svc = Get-CimInstance Win32_Service -Filter "Name='PiaLiteGuard'"
    if (-not $svc -or -not $svc.ProcessId) { Result 'FAIL' 'Guard process found' ''; return }
    $tun = Get-Tunnel
    $conns = @(Get-NetTCPConnection -OwningProcess $svc.ProcessId -RemotePort 443 -State Established -ErrorAction SilentlyContinue)
    if ($conns.Count -eq 0) { Result 'INFO' 'DoH route' 'no open DoH connection right now (run again right after browsing)'; return }
    if (-not $tun) { Result 'WARN' 'DoH route' 'VPN tunnel adapter not found (WireGuard wgpia0 or OpenVPN TAP/Wintun) - cannot compare'; return }
    Say ('  VPN tunnel adapter: {0}' -f $tun.Alias)
    $outside = @($conns | Where-Object { $_.LocalAddress -ne $tun.Ip })
    if ($outside.Count -eq 0) {
        Result 'PASS' 'DoH traffic leaves through the VPN tunnel' ('{0} connection(s), all from the tunnel address' -f $conns.Count)
    } else {
        Result 'FAIL' 'DoH traffic leaves through the VPN tunnel' ('{0} connection(s) from a non-tunnel address' -f $outside.Count)
    }
}

function Test-DnsSettings {
    Say ''
    Say '== DNS servers per adapter (connected adapters)'
    $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.ifIndex })
    $tunOk = $false
    $tun = Get-Tunnel
    $rows = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -and (($up -contains $_.InterfaceIndex) -or ($tun -and $_.InterfaceIndex -eq $tun.Index)) }
    foreach ($r in $rows) {
        Say ('  {0}: {1}' -f $r.InterfaceAlias, ($r.ServerAddresses -join ', '))
        if ($tun -and $r.InterfaceIndex -eq $tun.Index -and ($r.ServerAddresses -contains '127.0.0.1')) { $tunOk = $true }
    }
    if ($tunOk) { Result 'PASS' 'VPN adapter uses the guard (127.0.0.1) for DNS' $tun.Alias }
    elseif ((Get-PiaState) -eq 'Connected') { Result 'FAIL' 'VPN adapter uses the guard (127.0.0.1) for DNS' 'the tunnel adapter does not list 127.0.0.1' }
    else { Result 'INFO' 'VPN adapter DNS' 'VPN not connected' }
    try {
        $null = Resolve-DnsName -Name 'example.com' -Server '1.1.1.1' -DnsOnly -QuickTimeout -ErrorAction Stop
        Result 'INFO' 'Plain DNS straight to 1.1.1.1' 'answered (sent inside the VPN, but it skips NextDNS - only apps that pick their own DNS server do this)'
    } catch {
        Result 'PASS' 'Plain DNS straight to 1.1.1.1' 'blocked (PIA DNS leak protection)'
    }
}

function Show-WfpRules {
    Say ''
    Say '== Rules as Windows firewall engine reports them (netsh wfp)'
    $xmlPath = Join-Path $workDir 'wfp-filters.xml'
    try {
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null
        [void](Invoke-Native 'netsh.exe' @('wfp', 'show', 'filters', "file=$xmlPath"))
        $x = New-Object System.Xml.XmlDocument
        $x.Load($xmlPath)
        # our persistent + boot-time rules have fixed IDs starting with this; the
        # temporary allow-all has a random ID, so it's found by its name
        $keyPrefix = '{5a1f7e2c-3b4d-4c8a-9e61-2f0b6d1d0'
        $items = @($x.SelectNodes("//item[filterKey and (starts-with(translate(filterKey, 'ABCDEF', 'abcdef'), '$keyPrefix') or displayData/name[starts-with(., 'PIA Lite: allow all')])]"))
        $persist = 0; $boot = 0; $dyn = 0; $multi = 0; $withConds = 0
        foreach ($i in $items) {
            $flags = ($i.SelectNodes('flags/item') | ForEach-Object { $_.InnerText }) -join ','
            if ($flags -match 'BOOTTIME') { $boot++ } elseif ($flags -match 'PERSISTENT') { $persist++ } else { $dyn++ }
            $w = $i.SelectSingleNode('weight/uint8')
            $wt = ''
            if ($w) { $wt = $w.InnerText }
            # each allowed program / network range must be its own rule: never two
            # conditions on the same field in one filter (they would ALL have to match)
            $fields = @($i.SelectNodes('filterCondition/item/fieldKey') | ForEach-Object { $_.InnerText })
            $dup = @($fields | Group-Object | Where-Object { $_.Count -gt 1 })
            if ($dup.Count -gt 0) { $multi++ }
            if ($fields.Count -gt 0) { $withConds++ }
            Say ('  {0,-62} {1,-17} w={2,-3} conds={3} {4}' -f $i.SelectSingleNode('displayData/name').InnerText, $i.SelectSingleNode('action/type').InnerText, $wt, $fields.Count, $flags)
        }
        if ($items.Count -gt 0 -and $withConds -eq 0) {
            # no conditions read at all = the netsh format wasn't understood: no verdict
            Result 'WARN' 'Every rule has at most one condition per field' 'could not read the conditions from the netsh output'
        } elseif ($items.Count -gt 0) {
            if ($multi -eq 0) { Result 'PASS' 'Every rule has at most one condition per field' 'each PIA program and each LAN range is its own rule' }
            else { Result 'FAIL' 'Every rule has at most one condition per field' "$multi rule(s) combine several values of one field" }
        }
        Say ('Counts: {0} persistent, {1} boot-time (usually not listed once the engine runs), {2} temporary allow-all' -f $persist, $boot, $dyn)
        $s = Get-GuardStatus
        if ($s -and $s.mode -ne 'off') {
            if ($persist -ge 6) { Result 'PASS' 'Persistent block rules present in Windows' "$persist rules" }
            elseif ($persist -gt 0) { Result 'INFO' 'netsh lists only some PIA Lite rules' "$persist shown - a netsh display quirk; the guard checks all rules by ID, and the block test proves them" }
            else { Result 'FAIL' 'Persistent block rules present in Windows' 'none found' }
        } elseif ($s -and $persist -eq 0) {
            Result 'PASS' 'No leftover block rules (block is off)' ''
        }
    } catch {
        Result 'WARN' 'Read rules from Windows' $_.Exception.Message
    } finally {
        Remove-Item -LiteralPath $xmlPath -ErrorAction SilentlyContinue
    }
}

# Every PIA Lite firewall rule as Windows holds it - field, match type and
# value of each condition - and the guard's own check of them against its plan
# (review V3-05: native evidence, not just "the keys exist").
function Show-GuardRules {
    Say ''
    Say '== PIA Lite firewall rules, read back from Windows (pialite-guard show-rules)'
    $r = Invoke-Native $guardExe @('show-rules') -AllowFail
    # exit 1 means "something differs" - the CHECK lines say what (review V4-05)
    $n = 0; $checks = 0
    foreach ($l in @($r.Output -split "`r?`n")) {
        if ($l -match '^CHECK-OK: (.*)$') { Result 'PASS' 'Rules in Windows match what should be there' $Matches[1]; $checks++ }
        elseif ($l -match '^CHECK-DIFF: (.*)$') { Result 'FAIL' 'Rules in Windows match what should be there' $Matches[1]; $checks++ }
        elseif ($l.Trim()) { Say "  $l"; $n++ }
    }
    Say ('({0} lines)' -f $n)
    if ($checks -eq 0) { Result 'WARN' 'Read PIA Lite rules from Windows' (Get-Msg $r) }
}

# PIA's adapter goes down while PIA may still say Connected (review V4-12,
# F51-07). Run inside the block test, in 'always' mode.
function Test-AdapterDown {
    $st = Get-GuardStatus
    $name = ([string]$st.vpn_adapter) -replace '\s*\((up|DOWN)\)$', ''
    if (-not $name -or [string]$st.tunnel_watch -ne 'up') { Result 'INFO' 'VPN adapter down test' "skipped - the guard doesn't observe PIA's adapter up right now"; return }
    $a = Read-Host "Also test PIA's network adapter going down while PIA may still say Connected? '$name' is turned off for a few seconds. (y/N)"
    if ($a -notmatch '^\s*[Yy]') { Result 'INFO' 'VPN adapter down test' 'skipped'; return }
    $t0 = Get-Date
    try {
        Disable-NetAdapter -Name $name -Confirm:$false -ErrorAction Stop
        $seen = $null
        $piaThen = ''
        for ($i = 0; $i -lt 30 -and -not $seen; $i++) {
            Start-Sleep -Milliseconds 200
            $g = Get-GuardStatus
            if ($g -and $g.blocking) { $seen = Get-Date; $piaThen = [string]$g.pia_state }
        }
        $reach = Test-Tcp '1.1.1.1' 443 2000
        if ($seen -and -not $reach) {
            $how = "PIA noticed too (it said '$piaThen')"
            if ($piaThen -eq 'Connected') { $how = "the guard's own adapter check caught it while PIA still said Connected" }
            Result 'PASS' 'VPN adapter down -> internet blocked' ('within {0:N1} s - {1}' -f ($seen - $t0).TotalSeconds, $how)
        } elseif (-not $reach) {
            Result 'WARN' 'VPN adapter down -> internet blocked' 'not reachable, but the guard did not report blocking within 6 s'
        } else {
            Result 'FAIL' 'VPN adapter down -> internet blocked' 'a test site was reachable with the VPN adapter off'
        }
    } catch {
        Result 'WARN' 'VPN adapter down test' ("could not turn the adapter off: " + $_.Exception.Message)
    } finally {
        # WireGuard's adapter (wgpia0) is removed when PIA drops the tunnel and
        # made new when it reconnects - then there is nothing to turn back on
        $still = @(Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue)
        if ($still.Count -eq 0) {
            Result 'INFO' 'VPN adapter turned back on' "not needed - PIA removed '$name' when the tunnel dropped (WireGuard does that) and makes a new one when it reconnects"
        } else {
            try { Enable-NetAdapter -Name $name -Confirm:$false -ErrorAction Stop }
            catch {
                if (@(Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue).Count -eq 0) {
                    Result 'INFO' 'VPN adapter turned back on' "not needed - PIA removed '$name' meanwhile and makes a new one when it reconnects"
                } else {
                    Result 'FAIL' 'VPN adapter turned back on' ($_.Exception.Message + " - turn '$name' back on in Settings > Network")
                }
            }
        }
    }
    if (-not (Wait-PiaState 'Connected' 45)) {
        [void](Invoke-Native $piactl @('connect') -AllowFail)
        [void](Wait-PiaState 'Connected' 60)
    }
}

function Test-Block($Status) {
    Say ''
    Say '== Block test: VPN off, then reconnect WHILE blocked (like after a restart)'
    if (-not $Status -or $Status.mode -eq 'off') { Result 'INFO' 'Block test' 'skipped - block mode is off'; return }
    if ((Get-PiaState) -ne 'Connected') { Result 'INFO' 'Block test' 'skipped - connect the VPN first'; return }
    $a = Read-Host 'Run the block test now? The VPN is off for up to 2 minutes. (y/N)'
    if ($a -notmatch '^\s*[Yy]') { Result 'INFO' 'Block test' 'skipped'; return }
    $origMode = [string]$Status.mode
    if ($origMode -eq 'startup') {
        # only "always" blocks after the first connect - borrow it for the test
        [void](Invoke-Native $guardExe @('mode', 'always'))
        Say "  (block mode switched to 'always' for this test, put back to 'startup' after)"
    }
    $ks = (Get-PiaSettings).killswitch
    $alone = $false
    if ($ks -eq 'on') {
        $b = Read-Host "Also prove the guard blocks ON ITS OWN? PIA's kill switch goes to Off during the test and is put back after. (y/N)"
        $alone = ($b -match '^\s*[Yy]')
    }
    $auditBk = Join-Path $workDir 'audit-quick.csv'
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    [void](Invoke-Native 'auditpol.exe' @('/backup', "/file:$auditBk"))
    [void](Invoke-Native 'auditpol.exe' @('/set', "/subcategory:$wfpConnGuid", '/success:enable', '/failure:enable'))
    $t0 = Get-Date
    $connectedAt = $null
    try {
        if ($alone) { Set-PiaKillSwitch 'off' }
        [void](Invoke-Native $piactl @('disconnect') -AllowFail)
        if (-not (Wait-PiaState 'Disconnected' 20)) { Result 'WARN' 'Block test' 'VPN did not disconnect' }
        Start-Sleep -Seconds 2
        $st = Get-GuardStatus
        $reach = (Test-Tcp '1.1.1.1' 443 3000) -or (Test-Tcp '9.9.9.9' 443 3000)
        $who = "PIA's kill switch + guard"
        if ($alone) { $who = "the guard ALONE (PIA's kill switch was off)" }
        if (-not $reach -and $st.blocking) { Result 'PASS' 'VPN off -> internet blocked' "by $who" }
        elseif (-not $reach) { Result 'WARN' 'VPN off -> internet blocked' 'blocked, but the guard did not report blocking' }
        else { Result 'FAIL' 'VPN off -> internet blocked' 'a test site was reachable while the VPN was off' }

        # now connect while still blocked - this is what happens after a restart
        $c0 = Get-Date
        [void](Invoke-Native $piactl @('connect') -AllowFail)
        if (Wait-PiaState 'Connected' 120) {
            $connectedAt = Get-Date
            Result 'PASS' 'PIA connects while the internet is blocked' ('took {0:N0} s' -f ($connectedAt - $c0).TotalSeconds)
        } else {
            Result 'FAIL' 'PIA connects while the internet is blocked' ('still "' + (Get-PiaState) + '" after 120 s')
        }
        if ($connectedAt) {
            Start-Sleep -Seconds 2   # the guard looks at the new connection's adapter first
            Test-AdapterDown
        }
    } finally {
        if ($alone) {
            try { Set-PiaKillSwitch 'on'; Result 'PASS' "PIA's kill switch put back to On" 'confirmed in PIA settings' }
            catch { Result 'FAIL' "PIA's kill switch put back to On" ($_.Exception.Message + ' - SET IT BACK IN PIA SETTINGS') }
        }
        if ($origMode -eq 'startup') { [void](Invoke-Native $guardExe @('mode', 'startup') -AllowFail) }
        # what was blocked while PIA was trying to connect (helps find what PIA needs)
        Start-Sleep -Seconds 2   # let Windows finish writing the audit events
        $until = Get-Date
        if ($connectedAt) { $until = $connectedAt }
        $blocked = @(Get-WfpEvents $t0 $until | Where-Object { $_.Out -and -not $_.Allowed })
        $piaOut = @(Get-WfpEvents $t0 $until | Where-Object { $_.Out -and $_.Allowed -and $_.Pia })
        Say ('  while blocked: {0} connection(s) by PIA allowed, {1} blocked' -f $piaOut.Count, $blocked.Count)
        foreach ($g in ($blocked | Group-Object App | Sort-Object Count -Descending | Select-Object -First 8)) {
            $top = ($g.Group | Group-Object Dst, Port | Sort-Object Count -Descending | Select-Object -First 4 | ForEach-Object { '{0}:{1}' -f $_.Group[0].Dst, $_.Group[0].Port }) -join ', '
            Say ('    blocked {0,4} x {1,-22} e.g. {2}' -f $g.Count, $g.Name, $top)
        }
        [void](Invoke-Native 'auditpol.exe' @('/restore', "/file:$auditBk") -AllowFail)
        Remove-Item -LiteralPath $auditBk -ErrorAction SilentlyContinue
        if (-not $connectedAt) { [void](Invoke-Native $piactl @('connect') -AllowFail) }
    }
    if ((Get-PiaState) -eq 'Connected' -or (Wait-PiaState 'Connected' 45)) {
        Start-Sleep -Seconds 3
        if (Test-Tcp '1.1.1.1' 443 4000) { Result 'PASS' 'VPN back on -> internet works' '' }
        else { Result 'FAIL' 'VPN back on -> internet works' 'test site not reachable after reconnecting' }
    } else {
        Result 'FAIL' 'VPN reconnects after the test' 'not connected - open PIA and connect'
    }
}

function Test-Hotel($Status) {
    Say ''
    Say '== Hotel login test (VPN off for about 15 seconds)'
    if (-not $Status) { return }
    $a = Read-Host 'Run the hotel login test now? (y/N)'
    if ($a -notmatch '^\s*[Yy]') { Result 'INFO' 'Hotel test' 'skipped'; return }
    $ksBefore = (Get-PiaSettings).killswitch
    $r = Invoke-Native $guardExe @('hotel', 'start') -AllowFail
    if ($r.Code -ne 0) { Result 'FAIL' 'Hotel login starts' (Get-Msg $r); return }
    Start-Sleep -Seconds 4
    $st = Get-GuardStatus
    if ($st.hotel) { Result 'PASS' 'Hotel login starts' ('{0} s left' -f $st.hotel_left) } else { Result 'FAIL' 'Hotel login starts' 'guard does not report hotel mode' }
    if (Test-Tcp '1.1.1.1' 443 4000) { Result 'PASS' 'Internet reachable without the VPN (for the login page)' '' }
    else { Result 'FAIL' 'Internet reachable without the VPN' 'still blocked' }
    $r = Invoke-Native $guardExe @('hotel', 'stop') -AllowFail
    if ($r.Code -eq 0) { Result 'PASS' 'Hotel login ends' $r.Output } else { Result 'FAIL' 'Hotel login ends' (Get-Msg $r) }
    $ksAfter = (Get-PiaSettings).killswitch
    if ($ksAfter -eq $ksBefore) { Result 'PASS' "PIA's kill switch back to '$ksBefore'" 'confirmed in PIA settings' }
    else { Result 'FAIL' "PIA's kill switch back to '$ksBefore'" "it is '$ksAfter' - SET IT BACK IN PIA SETTINGS" }
    $st = Get-GuardStatus
    if ($st -and -not $st.restore_pending -and -not $st.hotel) { Result 'PASS' 'Guard left hotel mode cleanly' '' }
    else { Result 'FAIL' 'Guard left hotel mode cleanly' 'hotel still on or restore pending' }
    if (Wait-PiaState 'Connected' 45) { Result 'PASS' 'VPN reconnected after hotel login' '' }
    else { Result 'FAIL' 'VPN reconnected after hotel login' 'not connected after 45 s' }
}

function Show-SleepLog {
    Say ''
    Say '== Recent guard events (startup / sleep / wake)'
    if (-not (Test-Path -LiteralPath $guardLog)) { Say '  (no guard log)'; return }
    $l = @(Get-Content -LiteralPath $guardLog -Tail 600 | Where-Object { $_ -match 'starting|going to sleep|woke up|block lifted|blocking until|not responding|lost track' } | Select-Object -Last 14)
    foreach ($x in $l) { Say "  $x" }
    $wake = -1; $lift = -1
    for ($i = 0; $i -lt $l.Count; $i++) {
        if ($l[$i] -match 'woke up') { $wake = $i }
        if ($l[$i] -match 'block lifted') { $lift = $i }
    }
    if ($wake -ge 0 -and $lift -gt $wake) { Result 'PASS' 'After the last wake-up: blocked, then lifted once PIA connected' '' }
    elseif ($wake -ge 0) { Result 'WARN' 'After the last wake-up' 'no "block lifted" line yet' }
    else { Result 'INFO' 'Sleep/wake' 'no wake-up in the recent log (put the PC to sleep and wake it, then run this again to check)' }
}

function Show-Resources {
    Say ''
    Say '== Memory and CPU (all PIA + PIA Lite processes)'
    $names = @('pialite-tray', 'pialite-guard', 'piactl', 'pia-service', 'pia-wgservice', 'pia-client', 'pia-openvpn', 'pia-ss-local', 'pia-unbound')
    $procs = @(Get-Process -Name $names -ErrorAction SilentlyContinue | Sort-Object Name)
    foreach ($p in $procs) {
        Say ('  {0,-15} working set {1,6:N1} MB  private {2,6:N1} MB  handles {3,5}  threads {4,3}  cpu {5,7:N1} s' -f $p.Name, ($p.WorkingSet64 / 1MB), ($p.PrivateMemorySize64 / 1MB), $p.HandleCount, $p.Threads.Count, $p.TotalProcessorTime.TotalSeconds)
    }
    $orph = @(Get-CimInstance Win32_Process -Filter "Name='piactl.exe'" -ErrorAction SilentlyContinue | Where-Object { -not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue) })
    if ($orph.Count -gt 0) { Result 'WARN' 'Leftover piactl helpers (owner already closed)' ('{0} - reinstalling or restarting clears them' -f $orph.Count) }
    else { Result 'PASS' 'No leftover piactl helpers' '' }
    $lite = @($procs | Where-Object { $_.Name -like 'pialite-*' -or $_.Name -eq 'piactl' })
    $win  = @($procs | Where-Object { $_.Name -eq 'pia-client' })
    $sumLite = ($lite | Measure-Object -Property PrivateMemorySize64 -Sum).Sum / 1MB
    Say ('PIA Lite total (tray + guard + {0} piactl helpers): {1:N1} MB private memory' -f @($procs | Where-Object { $_.Name -eq 'piactl' }).Count, $sumLite)
    if ($win.Count -gt 0) { Say ('PIA window (pia-client) is running too: {0:N1} MB' -f (($win | Measure-Object -Property PrivateMemorySize64 -Sum).Sum / 1MB)) }
    else { Say 'PIA window (pia-client): not running' }
}

# The control pipe's protections must be tested as a NORMAL user, so
# Run-Phase5.bat runs `pialite-guard pipe-selftest` before it asks for admin.
function Test-PipeSelftest {
    Say ''
    Say '== Control pipe protections (tested as a normal user before this window asked for admin)'
    $f = Join-Path $env:PUBLIC 'PiaLite-pipe-selftest.txt'
    if (-not (Test-Path -LiteralPath $f) -or ((Get-Date) - (Get-Item -LiteralPath $f).LastWriteTime).TotalMinutes -gt 15) {
        Result 'INFO' 'Control pipe self-test' 'no recent result - start Run-Phase5.bat with a double-click (not "Run as administrator") to include it'
        return
    }
    foreach ($l in @(Get-Content -LiteralPath $f)) {
        if ($l -match '^(PASS|FAIL|WARN): (.*)$') { Result $Matches[1] $Matches[2] '' }
        elseif ($l.Trim()) { Say "  $l" }
    }
    Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
}

# The installer's PowerShell readers and helpers, checked on this PC.
function Test-ScriptContracts {
    Say ''
    Say '== Installer checks (the PowerShell parts, run here on Windows)'
    # 1. the uninstaller reads the hotel recovery record exactly like the guard (review F51-01)
    if (Test-Path -LiteralPath $fixtures) {
        $t = Test-RecoveryFixtures $fixtures
        if ($t.Wrong.Count -eq 0) { Result 'PASS' 'Uninstaller reads the hotel recovery record like the guard' ("all {0} cases (valid, damaged, odd values, disagreeing files) give the same answer" -f $t.Count) }
        else {
            Result 'FAIL' 'Uninstaller reads the hotel recovery record like the guard' ("{0} of {1} cases differ" -f $t.Wrong.Count, $t.Count)
            foreach ($w in ($t.Wrong | Select-Object -First 10)) { Say "    $w" }
        }
    } else { Result 'WARN' 'Uninstaller reads the hotel recovery record like the guard' "$fixtures is missing" }
    # 2. a time limit holds even when a program leaves a child holding its
    #    output, and that child is stopped too (review F51-06, V60-07, V60-10):
    #    at most the limit + 8 s to clean up
    $t0 = Get-Date
    $r = Invoke-Native 'cmd.exe' @('/c', 'start', '/b', 'ping', '-n', '30', '127.0.0.1') -AllowFail -TimeoutSec 4
    $took = ((Get-Date) - $t0).TotalSeconds
    Start-Sleep -Milliseconds 500
    $left = @(Get-Process -Name 'PING' -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -ge $t0.AddSeconds(-1) })
    if ($r.Code -eq -1 -and $took -le 12 -and $r.Error -match 'kept its output open' -and $left.Count -eq 0) {
        Result 'PASS' 'Program time limits hold' ("a program whose child kept its output open was given up after {0:N1} s (limit 4 s + up to 8 s to clean up) and the child was stopped: {1}" -f $took, $r.Error)
    } elseif ($took -gt 12) {
        Result 'FAIL' 'Program time limits hold' ("took {0:N1} s with a 4 s limit (+8 s clean-up)" -f $took)
    } elseif ($left.Count -gt 0) {
        Result 'FAIL' 'Program time limits hold' ("given up after {0:N1} s, but the child program it started is still running" -f $took)
        $left | Stop-Process -Force -ErrorAction SilentlyContinue
    } elseif ($r.Code -ne -1) {
        Result 'WARN' 'Program time limits hold' ("the test program ended on its own in {0:N1} s (exit {1}) - inconclusive" -f $took, $r.Code)
    } else {
        Result 'WARN' 'Program time limits hold' ("given up after {0:N1} s, but with an unexpected reason: {1}" -f $took, $r.Error)
    }
    # 3. lots of output: kept up to the cap, the rest read and dropped, and said so
    $r = Invoke-Native 'cmd.exe' @('/c', 'for /l %i in (1,1,5000) do @echo 0123456789012345678901234567890123456789') -AllowFail -TimeoutSec 60 -MaxOutputBytes 65536
    if ($r.Code -eq 0 -and $r.Truncated -and $r.Output.Length -le 65536 -and $r.Output.Length -ge 60000) { Result 'PASS' 'Program output is capped and the cut is reported' ('kept {0} of about 210000 bytes, marked as cut' -f $r.Output.Length) }
    else { Result 'FAIL' 'Program output is capped and the cut is reported' ('exit {0}, cut reported: {1}, kept {2} bytes, {3}' -f $r.Code, $r.Truncated, $r.Output.Length, $r.Error) }
    # 4. capture attribution (review FINAL-03): UDP port 1337 alone is not PIA
    $flows = @{ '192.0.2.10|1337|17' = $true; '192.0.2.20|443|6' = $true }
    $pk = @(
        [pscustomobject]@{ Dst = '192.0.2.10'; Port = 1337; Proto = 17 },  # PIA's audited WireGuard endpoint
        [pscustomobject]@{ Dst = '203.0.113.9'; Port = 1337; Proto = 17 },    # UDP/1337 somewhere else
        [pscustomobject]@{ Dst = '192.0.2.20'; Port = 8443; Proto = 6 },   # PIA's address, another port
        [pscustomobject]@{ Dst = '198.51.100.7'; Port = 443; Proto = 6 })     # anything else
    $sp = Split-CapturedInternet $pk $flows
    if (@($sp.Pia).Count -eq 1 -and @($sp.Ambiguous).Count -eq 2 -and @($sp.Other).Count -eq 1 -and @($sp.Ambiguous)[0].Dst -eq '203.0.113.9') {
        Result 'PASS' 'Capture analysis: UDP port 1337 alone does not count as PIA' '1 PIA, 2 unsure (other address on 1337; PIA address on another port), 1 other - as expected'
    } else {
        Result 'FAIL' 'Capture analysis: UDP port 1337 alone does not count as PIA' ('PIA {0}, unsure {1}, other {2} (expected 1, 2, 1)' -f @($sp.Pia).Count, @($sp.Ambiguous).Count, @($sp.Other).Count)
    }
    # 5. a program that can't be started: an explicit failure, never empty success
    $r = Invoke-Native (Join-Path $env:TEMP 'pialite-no-such-program.exe') @() -AllowFail -TimeoutSec 10
    if ($r.Code -eq -1 -and $r.Error -match 'could not be started') { Result 'PASS' 'A program that cannot start is reported as a failure' $r.Error }
    else { Result 'FAIL' 'A program that cannot start is reported as a failure' ('exit {0}: {1}' -f $r.Code, $r.Error) }
}

function Invoke-QuickChecks {
    Write-Header
    if (Test-Path -LiteralPath $marker) { Result 'WARN' 'Startup leak test recording is still active' 'finish it (option 3) or undo it (option 4)' }
    $s = Test-GuardHealth
    Test-ScriptContracts
    if ($s) {
        Test-PipeSelftest
        Test-NextDnsPath
        Test-DohRoute
    }
    Test-DnsSettings
    Show-WfpRules
    Show-GuardRules
    Show-SleepLog
    Show-Resources
    if ($s) {
        Test-Block $s
        Test-Hotel (Get-GuardStatus)
    }
    Save-Report 'quick'
}

# --------------------------------------------------------- startup leak test

function Start-LeakTest {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    if (Test-Path -LiteralPath $marker) { throw 'A leak test is already recording - restart, then use option 3 (or option 4 to cancel).' }
    $s = Get-GuardStatus
    if (-not $s -or $s.mode -eq 'off') {
        Write-Host 'The internet block is OFF, so this would only show what leaks WITHOUT it.' -ForegroundColor Yellow
        $a = Read-Host 'Continue anyway? (y/N)'
        if ($a -notmatch '^\s*[Yy]') { return }
    }
    # 1. firewall audit: back up the whole audit policy, then log allowed + blocked connections
    [void](Invoke-Native 'auditpol.exe' @('/backup', "/file:$auditBak"))
    [void](Invoke-Native 'auditpol.exe' @('/set', "/subcategory:$wfpConnGuid", '/success:enable', '/failure:enable'))
    # bigger Security log so boot events are not overwritten
    $size = ((Invoke-Native 'wevtutil.exe' @('gl', 'Security')).Output -split "`n" | Where-Object { $_ -match '^\s*maxSize:' }) -replace '[^0-9]', ''
    Set-Content -LiteralPath $logSizeBak -Value $size -Encoding ASCII
    [void](Invoke-Native 'wevtutil.exe' @('sl', 'Security', '/ms:268435456'))
    # 2. packet capture that survives the restart and starts very early in boot
    $cap = Invoke-Native 'netsh.exe' @('trace', 'start', 'capture=yes', 'persistent=yes', 'report=disabled', 'maxsize=512', 'filemode=single', 'packettruncatebytes=256', 'overwrite=yes', "tracefile=$etl") -AllowFail
    $capOk = ($cap.Code -eq 0)
    if (-not $capOk) { Write-Host "Packet capture could not start (the firewall audit still works): $(Get-Msg $cap)" -ForegroundColor Yellow }
    # 3. optional: hold the guard back after the restart, so for about two
    #    minutes only the rules stored in Windows protect (review F51-08)
    $hold = $false
    Write-Host ''
    Write-Host "Optional: hold the guard back after the restart (Windows starts it about 2 minutes late)." -ForegroundColor Cyan
    Write-Host "That shows whether the rules stored in Windows block ON THEIR OWN while the guard isn't running." -ForegroundColor Cyan
    Write-Host "The VPN only connects after the guard starts, so the internet stays blocked a bit longer." -ForegroundColor Cyan
    $h = Read-Host 'Hold the guard back? (y/N)'
    if ($h -match '^\s*[Yy]') {
        $r = Invoke-Native 'sc.exe' @('config', $svcName, 'start=', 'delayed-auto') -AllowFail
        if ($r.Code -eq 0) { $hold = $true; Write-Host '  ok  the guard starts late after the next restart (put back by option 3 or 4)' -ForegroundColor Green }
        else { Write-Host "  !!  could not set that ($(Get-Msg $r)) - testing without the hold" -ForegroundColor Yellow }
    }
    $info = [pscustomobject]@{ started = (Get-Date).ToString('o'); capture = $capOk; mode = [string]$s.mode; hold = $hold }
    Set-Content -LiteralPath $marker -Value ($info | ConvertTo-Json) -Encoding ASCII
    Write-Host ''
    Write-Host 'Recording is ON.' -ForegroundColor Green
    Write-Host 'Now: Start > Power > Restart (or Shut down and turn back on).' -ForegroundColor Cyan
    Write-Host 'After you log in, wait until the tray shows CONNECTED, then run Run-Phase5.bat again and pick 3.' -ForegroundColor Cyan
    Write-Host 'Tip: do not open apps before running step 3 - they are not needed for the test.' -ForegroundColor Cyan
}

# A "hold the guard back" leak test: normal start again, and running.
function Restore-GuardStart {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    if ($svc.DelayedAutoStart) { [void](Invoke-Native 'sc.exe' @('config', $svcName, 'start=', 'auto') -AllowFail -TimeoutSec 30) }
    if ($svc.State -ne 'Running') {
        [void](Invoke-Native 'sc.exe' @('start', $svcName) -AllowFail -TimeoutSec 30)
        Start-Sleep -Seconds 3
    }
}

function Undo-Recording {
    Restore-GuardStart
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & netsh.exe trace stop 2>&1 | Out-Null
    if (Test-Path -LiteralPath $auditBak) { & auditpol.exe /restore "/file:$auditBak" 2>&1 | Out-Null }
    else { & auditpol.exe /set "/subcategory:$wfpConnGuid" /success:disable /failure:disable 2>&1 | Out-Null }
    if (Test-Path -LiteralPath $logSizeBak) {
        $size = (Get-Content -LiteralPath $logSizeBak -Raw).Trim()
        if ($size -match '^\d+$') { & wevtutil.exe sl Security "/ms:$size" 2>&1 | Out-Null }
    }
    $ErrorActionPreference = $old
    Remove-Item -LiteralPath $marker, $auditBak, $logSizeBak -ErrorAction SilentlyContinue
}

# Guard log lines since $Since: times (millisecond precision from v0.2.2 on)
# of service start and block lift, plus the lines themselves for the report.
function Get-GuardLogTimes([datetime]$Since) {
    $res = @{ start = $null; lifted = $null; precise = $false; found = $null; lines = (New-Object System.Collections.Generic.List[string]) }
    if (-not (Test-Path -LiteralPath $guardLog)) { return $res }
    foreach ($l in (Get-Content -LiteralPath $guardLog -Tail 3000)) {
        if ($l -match '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\.\d{3})?Z (.*)$') {
            $ms = 0
            if ($Matches[2]) { $ms = [int]$Matches[2].Substring(1) }
            $msg = $Matches[3]
            $t = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).ToLocalTime().AddMilliseconds($ms)
            if ($t -lt $Since) { continue }
            $res.lines.Add(('+{0,6:N1}s {1}' -f ($t - $Since).TotalSeconds, $msg))
            if (-not $res.start -and $msg -match 'starting') { $res.start = $t }
            if (-not $res.found -and $msg -match '^found at start') { $res.found = $msg }
            if (-not $res.lifted -and $msg -match 'block lifted') { $res.lifted = $t; $res.precise = [bool]$Matches[2] }
        }
    }
    return $res
}

function Get-WfpEvents([datetime]$From, [datetime]$To) {
    $list = New-Object System.Collections.Generic.List[object]
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5156, 5157; StartTime = $From; EndTime = $To } -ErrorAction SilentlyContinue)
    foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $app = [string]$d['Application']
        $leaf = 'unknown'
        if ($app) { $leaf = ($app -split '\\')[-1] }
        $port = 0
        [void][int]::TryParse([string]$d['DestPort'], [ref]$port)
        $proto = 0
        [void][int]::TryParse([string]$d['Protocol'], [ref]$proto)
        $list.Add([pscustomobject]@{
            Time = $e.TimeCreated; Allowed = ($e.Id -eq 5156); App = $leaf
            Pia = ($app -match '(?i)private internet access'); Out = ($d['Direction'] -eq '%%14593')
            Dst = [string]$d['DestAddress']; Port = $port; Proto = $proto; Src = [string]$d['SourceAddress']
            Filter = [string]$d['FilterRTID']
        })
    }
    return $list
}

function Get-U16([byte[]]$B, [int]$O) { return ([int]$B[$O] -shl 8) -bor [int]$B[$O + 1] }

# Outgoing packets from this PC's own network adapters, from the netsh capture.
# How a packet is recorded (Microsoft-Windows-NDIS-PacketCapture keywords, as
# Microsoft's etl2pcapng reads them): 0x100000000 = sent by this PC,
# 0x200000000 = received, 0x10000 = a raw Wi-Fi (802.11) frame instead of an
# Ethernet frame, 0x200 = a bare IP packet (mobile broadband), 0x40000000 /
# 0x80000000 = first / last piece of a packet split over several events.
# Wi-Fi frames were read as Ethernet before, so a Wi-Fi capture never showed
# any packet "from this PC" (v0.5.0 test run).
# (written as [long] decimals: Windows PowerShell reads 0x80000000 as -2147483648)
$KwSend  = [long]4294967296   # 0x100000000
$KwRecv  = [long]8589934592   # 0x200000000
$KwWifi  = [long]65536        # 0x10000
$KwRawIp = [long]512          # 0x200
$KwStart = [long]1073741824   # 0x40000000
$KwEnd   = [long]2147483648   # 0x80000000

# Where the IP header starts in a captured frame, and its EtherType; $null if
# it isn't an IP packet sent by this PC.
function Get-IpStart([byte[]]$B, [long]$Kw, [hashtable]$Own) {
    $dirKnown = ($Kw -band ($KwSend -bor $KwRecv)) -ne 0
    $sent = ($Kw -band $KwSend) -ne 0
    if ($dirKnown -and -not $sent) { return $null }
    if (($Kw -band $KwWifi) -ne 0) {
        # 802.11 data frame going to the access point (ToDS); our own frames,
        # whatever MAC address Windows uses for this network
        if (-not $sent -or $B.Length -lt 32) { return $null }
        $fc0 = [int]$B[0]; $fc1 = [int]$B[1]
        if (($fc0 -band 0x0C) -ne 0x08 -or ($fc1 -band 0x01) -eq 0) { return $null }
        $h = 24
        if (($fc1 -band 0x03) -eq 0x03) { $h += 6 }
        if (($fc0 -band 0x80) -ne 0) { $h += 2; if (($fc1 -band 0x80) -ne 0) { $h += 4 } }
        foreach ($o in @($h, ($h + 8))) {
            # LLC/SNAP header AA AA 03 00 00 00, then the EtherType
            if ($B.Length -ge $o + 8 -and $B[$o] -eq 0xAA -and $B[$o + 1] -eq 0xAA -and $B[$o + 2] -eq 0x03 -and
                $B[$o + 3] -eq 0 -and $B[$o + 4] -eq 0 -and $B[$o + 5] -eq 0) {
                return @(($o + 8), (Get-U16 $B ($o + 6)))
            }
        }
        return $null
    }
    if (($Kw -band $KwRawIp) -ne 0) {
        if (-not $sent -or $B.Length -lt 20) { return $null }
        $ver = [int]$B[0] -shr 4
        if ($ver -eq 4) { return @(0, 0x0800) }
        if ($ver -eq 6) { return @(0, 0x86DD) }
        return $null
    }
    # Ethernet: marked "sent", or (older captures without that mark) sent
    # from the MAC address of one of this PC's adapters
    if ($B.Length -lt 34) { return $null }
    if (-not $dirKnown -and -not $Own.ContainsKey([System.BitConverter]::ToString($B, 6, 6))) { return $null }
    $o = 12
    $et = Get-U16 $B $o
    if ($et -eq 0x8100) { $o += 4; $et = Get-U16 $B $o }
    return @(($o + 2), $et)
}

# Internet-bound captured packets split by who they can be tied to (review
# FINAL-03): .Pia = to an address+port+protocol the firewall audit saw a PIA
# program connect to; .Ambiguous = PIA's address but another port, or UDP
# port 1337 (WireGuard's usual port) to an address no PIA program was seen
# using - never counted as PIA; .Other = everything else.
function Split-CapturedInternet($Packets, [hashtable]$PiaFlows) {
    $piaIp = @{}
    foreach ($k in $PiaFlows.Keys) { $piaIp[($k -split '\|')[0]] = $true }
    $r = [pscustomobject]@{ Pia = @(); Ambiguous = @(); Other = @() }
    foreach ($p in @($Packets)) {
        if ($PiaFlows.ContainsKey(('{0}|{1}|{2}' -f $p.Dst, $p.Port, $p.Proto))) { $r.Pia += $p }
        elseif ($piaIp.ContainsKey([string]$p.Dst) -or ($p.Proto -eq 17 -and $p.Port -eq 1337)) { $r.Ambiguous += $p }
        else { $r.Other += $p }
    }
    return $r
}

# What the capture saw up to $Until. .Truncated: the read limit was reached
# before $Until (what came after it was never looked at); .First / .Last: the
# first and last event read; .MaxGap: the longest stretch without any event
# (review V60-06).
function Get-CapturedPackets([string]$Path, [datetime]$Until, [int]$MaxEvents = 400000) {
    $own = @{}
    $byIdx = @{}
    $vpnIdx = @{}
    foreach ($a in (Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) {
        if ($a.MacAddress) { $own[$a.MacAddress.ToUpper()] = $a.Name }
        $byIdx[[int64]$a.ifIndex] = $a.Name
        if ($a.Name -eq 'wgpia0' -or $a.InterfaceDescription -match 'Private Internet Access|TAP-Windows|Wintun|WireGuard') { $vpnIdx[[int64]$a.ifIndex] = $true }
    }
    $q = [string[]]@("Event/EventData/Data[@Name='Fragment']", "Event/EventData/Data[@Name='MiniportIfIndex']")
    $sel = New-Object System.Diagnostics.Eventing.Reader.EventLogPropertySelector -ArgumentList (, $q)
    $utc = $Until.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $xpath = "*[System[EventID=1001 and TimeCreated[@SystemTime<='$utc']]]"
    $list = New-Object System.Collections.Generic.List[object]
    $n = @{ seen = 0; wifi = 0; eth = 0; raw = 0; sent = 0; recv = 0; nodir = 0; vpn = 0; piece = 0; first = $null; last = $null; gap = 0.0; gapAt = $null }
    $events = $null
    try {
        $events = Get-WinEvent -Path $Path -Oldest -FilterXPath $xpath -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        # some Windows versions refuse time filters on capture files: filter here instead
        $events = Get-WinEvent -Path $Path -Oldest -FilterXPath '*[System[EventID=1001]]' -MaxEvents $MaxEvents -ErrorAction Stop
    }
    $events = @($events)
    $lastRead = $null
    if ($events.Count -gt 0) { $lastRead = $events[$events.Count - 1].TimeCreated }
    $truncated = ($events.Count -ge $MaxEvents) -and (-not $lastRead -or $lastRead -lt $Until)
    $events | Where-Object { $_.TimeCreated -le $Until } | ForEach-Object {
        $n.seen++
        $tc = $_.TimeCreated
        if (-not $n.first) { $n.first = $tc }
        elseif (($tc - $n.last).TotalSeconds -gt $n.gap) { $n.gap = ($tc - $n.last).TotalSeconds; $n.gapAt = $n.last }
        $n.last = $tc
        $kw = [long]0
        if ($null -ne $_.Keywords) { $kw = [long]$_.Keywords }
        if (($kw -band $KwWifi) -ne 0) { $n.wifi++ } elseif (($kw -band $KwRawIp) -ne 0) { $n.raw++ } else { $n.eth++ }
        if (($kw -band $KwSend) -ne 0) { $n.sent++ } elseif (($kw -band $KwRecv) -ne 0) { $n.recv++ } else { $n.nodir++ }
        $v = $_.GetPropertyValues($sel)
        $idx = [int64]0
        try { $idx = [int64]$v[1] } catch { }
        if ($vpnIdx.ContainsKey($idx)) { $n.vpn++; return } # the VPN tunnel itself, not the real adapter
        # only the first piece of a packet has its headers
        if (($kw -band ($KwStart -bor $KwEnd)) -ne 0 -and ($kw -band $KwStart) -eq 0) { $n.piece++; return }
        $b = [byte[]]$v[0]
        if (-not $b) { return }
        $ip = Get-IpStart $b $kw $own
        if (-not $ip) { return }
        $o = $ip[0]; $et = $ip[1]
        $proto = -1; $dst = ''; $l4 = 0
        if ($et -eq 0x0800 -and $b.Length -ge $o + 20 -and ([int]$b[$o] -shr 4) -eq 4) {
            $proto = [int]$b[$o + 9]
            $dst = '{0}.{1}.{2}.{3}' -f $b[$o + 16], $b[$o + 17], $b[$o + 18], $b[$o + 19]
            $l4 = $o + (([int]$b[$o] -band 0x0F) * 4)
        } elseif ($et -eq 0x86DD -and $b.Length -ge $o + 40 -and ([int]$b[$o] -shr 4) -eq 6) {
            $proto = [int]$b[$o + 6]
            $dst = ([System.Net.IPAddress]::new([byte[]]$b[($o + 24)..($o + 39)])).ToString()
            $l4 = $o + 40
        }
        if ($proto -ge 0) {
            $port = 0
            if (($proto -eq 6 -or $proto -eq 17) -and $b.Length -ge $l4 + 4) { $port = Get-U16 $b ($l4 + 2) }
            $name = $byIdx[$idx]
            if (-not $name) { $name = '?' }
            $media = 'ethernet'
            if (($kw -band $KwWifi) -ne 0) { $media = 'wifi-802.11' } elseif (($kw -band $KwRawIp) -ne 0) { $media = 'ip' }
            $raw = $b[0..([Math]::Min($b.Length, $l4 + 8) - 1)]
            $list.Add([pscustomobject]@{ Time = $_.TimeCreated; Adapter = $name; Proto = $proto; Dst = $dst; Port = $port; Media = $media; Ip = $o; Raw = $raw; Kw = $kw })
        }
    }
    $what = 'frames: {0} Ethernet, {1} Wi-Fi (802.11), {2} bare IP; marked sent {3}, received {4}, unmarked {5}; on the VPN adapter {6}; follow-on pieces {7}' -f $n.eth, $n.wifi, $n.raw, $n.sent, $n.recv, $n.nodir, $n.vpn, $n.piece
    $byAd = (@($list | Group-Object Adapter | Sort-Object Count -Descending | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })) -join ', '
    if ($byAd) { $what += "; sent IP packets by adapter: $byAd" }
    return [pscustomobject]@{ Packets = $list; Events = $n.seen; What = $what; Truncated = $truncated; Read = $events.Count
        First = $n.first; Last = $n.last; MaxGap = $n.gap; MaxGapAt = $n.gapAt }
}

# When a service's program started ($null if it isn't running). For the
# timeline only: a shared or restarted host process gives a later time.
function Get-ServiceProcStart([string]$Name) {
    try {
        $sv = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if ($sv -and $sv.ProcessId) { return (Get-Process -Id $sv.ProcessId -ErrorAction Stop).StartTime }
    } catch { }
    return $null
}

# When the earliest running copy of a program started ($null if none runs).
function Get-ProcStart([string]$Name) {
    $t = @(Get-Process -Name $Name -ErrorAction SilentlyContinue | ForEach-Object { try { $_.StartTime } catch { } } | Where-Object { $_ } | Sort-Object)
    if ($t.Count -gt 0) { return $t[0] }
    return $null
}

function Complete-LeakTest {
    if (-not (Test-Path -LiteralPath $marker)) { throw 'No leak test is recording. Use option 2 first.' }
    $info = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($info.started -is [datetime]) { $started = $info.started }
    else { $started = [datetime]::Parse([string]$info.started, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    Write-Header
    Say ''
    Say '== Startup leak test'
    if ($boot -lt $started) {
        Result 'FAIL' 'PC was restarted after recording started' 'no restart detected (with Fast Startup on, use Restart, not Shut down)'
        Say 'Recording is still on: restart now, then run option 3 again (or option 4 to cancel).'
        Save-Report 'leaktest'
        return
    }
    Write-Host 'Stopping the packet capture (can take a minute)...' -ForegroundColor Cyan
    try {
        $times = Get-GuardLogTimes $boot
        $s = Get-GuardStatus
        $until = $times.lifted
        if (-not $until) {
            $until = Get-Date
            Result 'WARN' 'VPN connected after the restart' 'no "block lifted" in the guard log - analysing everything up to now'
        }
        Say ('Boot: {0:HH:mm:ss}   guard started: {1}   block lifted (VPN connected): {2:HH:mm:ss}' -f $boot, $(if ($times.start) { $times.start.ToString('HH:mm:ss') } else { '?' }), $until)
        Say ('Block mode during the test: {0}; PIA kill switch: {1}; PIA Allow LAN: {2}' -f $info.mode, $(if ($s) { $s.pia_killswitch } else { '?' }), $(if ($s) { $s.pia_allow_lan } else { '?' }))
        $rel = { param($t) if ($t) { '+{0:N1}s' -f ($t - $boot).TotalSeconds } else { 'not seen' } }

        # --- firewall audit evidence (has program names)
        # A connection whose source is the VPN tunnel address went THROUGH the VPN,
        # so it is never a leak (matters for events right around the hand-off).
        $tunIp = $null
        $tun = Get-Tunnel
        if ($tun) { $tunIp = $tun.Ip }
        $slack = 0
        if (-not $times.precise) { $slack = 1 }   # older guard logs only have whole seconds
        $ev = Get-WfpEvents $boot $until.AddSeconds($slack)
        $outEv = @($ev | Where-Object { $_.Out -and (Get-IpClass $_.Dst $_.Proto $_.Port) -ne 'loopback' })
        Say ''
        if ($ev.Count -eq 0) {
            Result 'WARN' 'Firewall audit events found' 'none - the audit log may not have been running early enough'
        } else {
            $first = ($ev | Sort-Object Time | Select-Object -First 1).Time
            Say ('Firewall audit: {0} events, first one {1:N0} s after boot' -f $ev.Count, ($first - $boot).TotalSeconds)
        }
        $piaDst = @{}
        $piaFlows = @{}   # address|port|protocol PIA's own programs were allowed to connect to
        foreach ($e in $outEv) { if ($e.Pia -and $e.Allowed) { $piaDst[$e.Dst] = $true; $piaFlows[('{0}|{1}|{2}' -f $e.Dst, $e.Port, $e.Proto)] = $true } }
        $allowed = @($outEv | Where-Object { $_.Allowed })
        $inet = @($allowed | Where-Object { -not $_.Pia -and (Get-IpClass $_.Dst $_.Proto $_.Port) -eq 'internet' })
        $viaVpn = @($inet | Where-Object { $tunIp -and $_.Src -eq $tunIp })
        $leaks = @($inet | Where-Object { -not ($tunIp -and $_.Src -eq $tunIp) })
        if ($viaVpn.Count -gt 0) { Say ('({0} connection(s) right at the hand-off came from the VPN tunnel address - through the VPN, not leaks)' -f $viaVpn.Count) }
        $lan = @($allowed | Where-Object { -not $_.Pia -and (Get-IpClass $_.Dst $_.Proto $_.Port) -eq 'local' })
        $dhcp = @($allowed | Where-Object { (Get-IpClass $_.Dst $_.Proto $_.Port) -eq 'dhcp' })
        $pia = @($allowed | Where-Object { $_.Pia })
        Say ('Allowed outgoing before the VPN connected: {0} by PIA itself, {1} DHCP, {2} local network, {3} to the internet by other programs' -f $pia.Count, $dhcp.Count, $lan.Count, $leaks.Count)
        if ($leaks.Count -eq 0) { Result 'PASS' 'Firewall audit: no program other than PIA reached the internet before the VPN connected' '' }
        else {
            Result 'FAIL' 'Firewall audit: other programs reached the internet before the VPN connected' ('{0} connection(s)' -f $leaks.Count)
            foreach ($l in ($leaks | Select-Object -First 25)) { Say ('    +{0,6:N1}s {1,-24} -> {2}:{3} (proto {4}) from {5}' -f ($l.Time - $boot).TotalSeconds, $l.App, $l.Dst, $l.Port, $l.Proto, $l.Src) }
        }
        # --- what the guard found stored in Windows when it started (review
        # F51-08, V60-03). It looked AFTER Windows' filtering engine was
        # running: this shows the rules were there, not that anything was
        # blocked before - that is the separate verdict at the end.
        Say ''
        $ourIds = @{}
        $storedIds = @{}
        if ($times.found) {
            $short = $times.found -replace '; rule ids.*$', ''
            if ($times.found -match 'provider ok' -and $times.found -match 'sublayer ok' -and $times.found -match '\d+ persistent rules \(matching the plan\)') {
                Result 'INFO' 'Stored PIA Lite rules were present and matched the plan when the guard service started' "$short (an observation: on its own it doesn't show anything was blocked before the guard started)"
            } elseif ($info.mode -eq 'off') {
                Result 'INFO' 'Stored PIA Lite rules when the guard service started' "$short (block mode off: none expected)"
            } else {
                Result 'WARN' 'Stored PIA Lite rules were present and matched the plan when the guard service started' "no: $short"
            }
            foreach ($k in @('rule ids', 'boot ids')) {
                if ($times.found -match ($k + ' ([0-9,]*)')) { foreach ($i in ($Matches[1] -split ',')) { if ($i) { $ourIds[$i] = $true; $storedIds[$i] = $true } } }
            }
        } else {
            Result 'INFO' 'Stored PIA Lite rules when the guard service started' 'not in the guard log (older guard version)'
        }
        # the rules the guard put in place after it started (their ids)
        $sr = Invoke-Native $guardExe @('show-rules') -AllowFail -TimeoutSec 60
        foreach ($m in [regex]::Matches([string]$sr.Output, '\[id (\d+)\]')) { $ourIds[$m.Groups[1].Value] = $true }
        $blockedAll = @($outEv | Where-Object { -not $_.Allowed })
        $byUs = @($blockedAll | Where-Object { $ourIds.ContainsKey($_.Filter) })
        if ($blockedAll.Count -gt 0) {
            Say ('Who blocked: {0} of {1} blocked attempts were decided by a PIA Lite rule; the rest by other rules (PIA''s own kill switch, Windows Firewall)' -f $byUs.Count, $blockedAll.Count)
        }
        # was there a network before the guard started? Only then is the early-boot window tested.
        $wifi = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; Id = 8001; StartTime = $boot; EndTime = $until.AddSeconds(5) } -ErrorAction SilentlyContinue | Sort-Object TimeCreated)
        $netUp = $null
        $firstDhcp = $dhcp | Sort-Object Time | Select-Object -First 1
        if ($wifi.Count -gt 0) { $netUp = $wifi[0].TimeCreated }
        if ($firstDhcp -and (-not $netUp -or $firstDhcp.Time -lt $netUp)) { $netUp = $firstDhcp.Time }
        $pre = @(); $preBlocked = @(); $preByStored = @(); $preTries = @(); $preLeaks = @()
        if ($times.start) {
            $gs = ($times.start - $boot).TotalSeconds
            if ($netUp -and $netUp -lt $times.start) {
                Result 'INFO' 'This run covered the time before the guard started' ('yes - the network was up at +{0:N1} s, the guard started at +{1:N1} s' -f ($netUp - $boot).TotalSeconds, $gs)
            } elseif ($netUp) {
                Result 'WARN' 'This run covered the time before the guard started' ('no - the network only came up at +{0:N1} s, after the guard started (+{1:N1} s). To cover it: Ethernet plugged in, Wi-Fi that connects before you sign in, or the "hold the guard back" option' -f ($netUp - $boot).TotalSeconds, $gs)
            } else {
                Result 'INFO' 'This run covered the time before the guard started' 'no network start seen in the logs (wired and already up, or no DHCP)'
            }
            # firewall audit before the guard started: only the rules stored in Windows were there
            $pre = @($outEv | Where-Object { $_.Time -lt $times.start })
            $preBlocked = @($pre | Where-Object { -not $_.Allowed })
            $preByStored = @($preBlocked | Where-Object { $storedIds.ContainsKey($_.Filter) })
            $preTries = @($pre | Where-Object { -not $_.Pia -and (Get-IpClass $_.Dst $_.Proto $_.Port) -eq 'internet' })
            $preLeaks = @($preTries | Where-Object { $_.Allowed -and -not ($tunIp -and $_.Src -eq $tunIp) })
            Say ('Before the guard started (+{0:N1} s{1}): {2} attempts by other programs to reach the internet; {3} outgoing attempts blocked ({4} decided by a stored PIA Lite rule); {5} reached the internet' -f $gs, $(if ($info.hold) { ', held back' } else { '' }), $preTries.Count, $preBlocked.Count, $preByStored.Count, $preLeaks.Count)
            foreach ($l in ($preLeaks | Select-Object -First 10)) { Say ('    +{0,6:N1}s {1,-24} -> {2}:{3} (proto {4})' -f ($l.Time - $boot).TotalSeconds, $l.App, $l.Dst, $l.Port, $l.Proto) }
        }

        # --- startup timeline: was the network itself late, or was PIA idle?
        $firstOf = {
            param($list)
            $f = $list | Sort-Object Time | Select-Object -First 1
            if ($f) { return ('+{0:N1}s' -f ($f.Time - $boot).TotalSeconds) }
            return 'none'
        }
        $wifiAt = 'no Wi-Fi connect event (wired, or already connected)'
        if ($wifi.Count -gt 0) { $wifiAt = '+{0:N1}s' -f ($wifi[0].TimeCreated - $boot).TotalSeconds }
        Say ''
        Say 'Startup timeline (seconds after boot):'
        Say '    Windows networking (TCP/IP) starts with Windows itself; PIA Lite''s boot-time rules apply from then'
        $bfeAt = Get-ServiceProcStart 'BFE'
        Say ('    filtering engine (BFE) .... {0} (its program started; the stored rules take over from the boot-time rules here)' -f (& $rel $bfeAt))
        $first5 = $ev | Sort-Object Time | Select-Object -First 1
        if ($first5) { Say ('    first firewall audit event  {0}' -f (& $rel $first5.Time)) }
        Say ('    PIA service ............... {0} (its program started; PIA''s own kill switch can only act after this)' -f (& $rel (Get-ProcStart 'pia-service')))
        if ($times.start) { Say ('    guard started ............. +{0:N1}s{1}' -f ($times.start - $boot).TotalSeconds, $(if ($info.hold) { ' (held back)' } else { '' })) }
        Say ('    Wi-Fi connected ........... {0}' -f $wifiAt)
        Say ('    first DHCP (got address) .. {0}' -f (& $firstOf $dhcp))
        Say ('    first local-network traffic {0}' -f (& $firstOf $lan))
        Say ('    first PIA connection ...... {0}' -f (& $firstOf $pia))
        foreach ($l in $times.lines) { if ($l -match '^\+\s*([0-9.,]+)s PIA: Connecting') { Say ('    PIA started connecting .... +{0}s' -f $Matches[1]); break } }
        Say ('    VPN connected ............. +{0:N1}s' -f ($until - $boot).TotalSeconds)
        Say ''
        Say 'Where PIA itself connected before the VPN was up:'
        foreach ($g in ($pia | Group-Object App, Dst, Port | Sort-Object Count -Descending | Select-Object -First 15)) {
            $f = $g.Group[0]
            Say ('    {0,4} x {1,-20} -> {2}:{3} (proto {4}) first +{5:N1}s' -f $g.Count, $f.App, $f.Dst, $f.Port, $f.Proto, ($f.Time - $boot).TotalSeconds)
        }
        $blocked = $blockedAll
        Say ('Blocked outgoing attempts before the VPN connected: {0}' -f $blocked.Count)
        foreach ($g in ($blocked | Group-Object App | Sort-Object Count -Descending | Select-Object -First 12)) {
            $top = ($g.Group | Group-Object Dst, Port | Sort-Object Count -Descending | Select-Object -First 4 | ForEach-Object { '{0}:{1}' -f $_.Group[0].Dst, $_.Group[0].Port }) -join ', '
            Say ('    {0,5} x {1,-22} e.g. {2}' -f $g.Count, $g.Name, $top)
        }
        if ($lan.Count -gt 0) {
            Say 'Local network (allowed because PIA Allow LAN is on):'
            foreach ($g in ($lan | Group-Object App | Sort-Object Count -Descending | Select-Object -First 8)) { Say ('    {0,5} x {1}' -f $g.Count, $g.Name) }
        }

        # --- packet capture evidence (includes the time before the firewall engine started)
        Say ''
        $capInfo = $null
        if ($info.capture) {
            $old = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            $stopSaid = (& netsh.exe trace stop 2>&1 | Out-String).Trim()
            $stopCode = $LASTEXITCODE
            $ErrorActionPreference = $old
            if ($stopCode -ne 0) { Say ('Stopping the capture reported a problem (exit {0}): {1}' -f $stopCode, (($stopSaid -split "`r?`n" | Select-Object -Last 3) -join ' ')) }
            if (Test-Path -LiteralPath $etl) {
                try {
                    $cap = Get-CapturedPackets $etl $until
                    $pk = $cap.Packets
                    Say ('Packet capture: {0} packets read, {1} sent by this PC before the VPN connected' -f $cap.Events, $pk.Count)
                    Say ('  ' + $cap.What)
                    # coverage: the whole time up to the VPN connecting must have been read (review V60-06)
                    $covWhy = @()
                    if ($cap.Truncated) { $covWhy += ('only the first {0} capture events could be read (up to {1})' -f $cap.Read, (& $rel $cap.Last)) }
                    if (-not $cap.Last -or $cap.Last -lt $until.AddSeconds(-3)) { $covWhy += 'its events end before the VPN connected (capture file full, or the capture stopped?)' }
                    if ($netUp -and (-not $cap.First -or $cap.First -gt $netUp.AddSeconds(5))) { $covWhy += ('its first event ({0}) is later than the network start ({1})' -f (& $rel $cap.First), (& $rel $netUp)) }
                    $covered = ($covWhy.Count -eq 0)
                    Say ('Capture coverage: events from {0} to {1} (VPN connected {2}); longest stretch without any event {3:N1} s (from {4}); {5}' -f (& $rel $cap.First), (& $rel $cap.Last), (& $rel $until), $cap.MaxGap, (& $rel $cap.MaxGapAt), $(if ($covered) { 'complete' } else { 'INCOMPLETE: ' + ($covWhy -join '; ') }))
                    if ($pk.Count -gt 0) { Say ('First outgoing packet: {0:N1} s after boot' -f (($pk[0].Time) - $boot).TotalSeconds) }
                    $firstAudit = $null
                    if ($ev.Count -gt 0) { $firstAudit = ($ev | Sort-Object Time | Select-Object -First 1).Time }
                    $inet = @($pk | Where-Object { (Get-IpClass $_.Dst $_.Proto $_.Port) -eq 'internet' })
                    $split = Split-CapturedInternet $inet $piaFlows
                    $toPia = @($split.Pia); $amb = @($split.Ambiguous); $other = @($split.Other)
                    Say ('Internet-bound packets on the real adapter: {0} to connections the firewall audit tied to PIA (address, port and protocol), {1} that can''t be tied to PIA for sure, {2} to anything else' -f $toPia.Count, $amb.Count, $other.Count)
                    foreach ($g in ($amb | Group-Object Dst, Port, Proto | Sort-Object Count -Descending | Select-Object -First 10)) {
                        $f = $g.Group[0]
                        Say ('    unsure: {0,4} pkts  first +{1,6:N1}s  -> {2}:{3} (proto {4})' -f $g.Count, ($f.Time - $boot).TotalSeconds, $f.Dst, $f.Port, $f.Proto)
                    }
                    # for the verdict on the time before the guard started
                    $preWhy = @()
                    if ($times.start) {
                        if (-not $cap.Last -or $cap.Last -lt $times.start) { $preWhy += 'its events end before the guard started' }
                        if (@($pk | Where-Object { $_.Time -lt $times.start }).Count -eq 0) { $preWhy += 'it saw no packet from this PC before the guard started' }
                        if ($netUp -and (-not $cap.First -or $cap.First -gt $netUp.AddSeconds(5))) { $preWhy += 'it started seeing packets later than the network start' }
                    } else { $preWhy += 'the guard start time is not known' }
                    $capInfo = [pscustomobject]@{ Control = ($toPia.Count -gt 0); PreCovered = ($preWhy.Count -eq 0); PreWhy = ($preWhy -join ', ')
                        PreOther = @($other | Where-Object { $times.start -and $_.Time -lt $times.start }).Count
                        PreAmbiguous = @($amb | Where-Object { $times.start -and $_.Time -lt $times.start }).Count }
                    if ($pk.Count -eq 0) {
                        # an empty capture proves nothing: it may simply not see this adapter (the line above says what it did see)
                        Result 'WARN' 'Packet capture: INCONCLUSIVE' "it saw no outgoing packets at all, so it can't show anything either way - the firewall audit above is the evidence"
                    } elseif ($other.Count -eq 0 -and $toPia.Count -eq 0) {
                        # nothing to the internet at all - not even PIA: no positive control
                        Result 'WARN' 'Packet capture: INCONCLUSIVE' ("it saw {0} local packets but none of PIA's own traffic, so it may have missed internet traffic too" -f $pk.Count)
                    } elseif ($other.Count -eq 0 -and $amb.Count -gt 0) {
                        Result 'WARN' 'Packet capture: INCONCLUSIVE' ("{0} packet(s) went to addresses/ports the firewall audit doesn't tie to PIA (listed above as 'unsure') - not counted as PIA's" -f $amb.Count)
                    } elseif ($other.Count -eq 0 -and -not $covered) {
                        Result 'WARN' 'Packet capture: INCONCLUSIVE' ('nothing but PIA seen, but the capture did not cover the whole time: ' + ($covWhy -join '; '))
                    } elseif ($other.Count -eq 0) {
                        # positive control: PIA's own packets were seen on the real adapter, and the whole time was read
                        Result 'PASS' 'Packet capture: nothing but PIA left this PC for the internet before the VPN connected' ("it did see PIA's own {0} packets, so it was watching the right adapter, and it covered the time from the network start to the VPN connecting" -f $toPia.Count)
                    } else {
                        $early = @()
                        if ($firstAudit) { $early = @($other | Where-Object { $_.Time -lt $firstAudit }) }
                        Result 'FAIL' 'Packet capture: other internet traffic before the VPN connected' ('{0} packets ({1} before the firewall audit log started)' -f $other.Count, $early.Count)
                        foreach ($g in ($other | Group-Object Dst, Port, Proto | Sort-Object Count -Descending | Select-Object -First 25)) {
                            $f = $g.Group[0]
                            Say ('    {0,4} pkts  first +{1,6:N1}s  -> {2}:{3} (proto {4}) on {5}' -f $g.Count, ($f.Time - $boot).TotalSeconds, $f.Dst, $f.Port, $f.Proto, $f.Adapter)
                        }
                    }
                } catch {
                    Result 'WARN' 'Packet capture analysis' ("could not read the capture: " + $_.Exception.Message + " (file kept at $etl)")
                }
            } else {
                Result 'WARN' 'Packet capture' 'no capture file was produced'
            }
        } else {
            Result 'INFO' 'Packet capture' 'was not running for this test'
        }

        # --- the time before the guard started: PASS only with every piece of
        #     evidence, otherwise INCONCLUSIVE with what is missing (review V60-03)
        Say ''
        Say '== Protection before the guard service started'
        if ($info.mode -eq 'off') {
            Result 'INFO' 'Protection before the guard started' 'block mode was off - nothing to test'
        } elseif (-not $times.start) {
            Result 'WARN' 'Protection before the guard started: INCONCLUSIVE' 'the guard start time is not in its log'
        } else {
            $need = @()
            $bad = @()
            if (-not ($netUp -and $netUp -lt $times.start)) { $need += 'a network that was up before the guard started (Ethernet plugged in, or the "hold the guard back" option)' }
            if ($preTries.Count -eq 0 -and $preBlocked.Count -eq 0) { $need += 'outgoing attempts before the guard started' }
            if ($preByStored.Count -eq 0) { $need += "a blocked attempt decided by a stored PIA Lite rule (PIA's own kill switch often decides first - only an attempt PIA Lite's rule blocked shows PIA Lite protecting)" }
            if ($preLeaks.Count -gt 0) { $bad += ('firewall audit: {0} connection(s) reached the internet' -f $preLeaks.Count) }
            if (-not $capInfo) { $need += 'a packet capture that could be read (it also sees the time before the firewall audit starts)' }
            else {
                if ($capInfo.PreOther -gt 0) { $bad += ('packet capture: {0} internet packet(s) not to PIA' -f $capInfo.PreOther) }
                if (-not $capInfo.Control) { $need += "the capture seeing PIA's own packets (its proof it watched the right adapter)" }
                if ($capInfo.PreAmbiguous -gt 0) { $need += ('{0} captured packet(s) in that time that could not be tied to PIA for sure' -f $capInfo.PreAmbiguous) }
                if (-not $capInfo.PreCovered) { $need += ('the capture covering that time (' + $capInfo.PreWhy + ')') }
            }
            if ($bad.Count -gt 0) { Result 'FAIL' 'Protection before the guard started' ('traffic got out before the guard started - ' + ($bad -join '; ')) }
            elseif ($need.Count -eq 0) { Result 'PASS' 'Protection before the guard started' ('the network was up from {0}, the guard started at {1}; {2} attempts were blocked by stored PIA Lite rules, none got out (firewall audit), and the capture - which saw PIA''s own packets - saw nothing else leave' -f (& $rel $netUp), (& $rel $times.start), $preByStored.Count) }
            else { Result 'WARN' 'Protection before the guard started: INCONCLUSIVE' ('nothing got out that the tests saw, but this run lacks: ' + ($need -join '; ')) }
            Say "  (the switch from the boot-time rules to the stored rules when the filtering engine starts can only be seen by the capture - Windows' firewall audit isn't running yet then)"
        }
        Say ''
        Say '== Guard log since boot'
        # Run-Phase5.bat's pipe self-test holds all 4 control-pipe slots on purpose
        $st = $null
        $stFile = Join-Path $env:PUBLIC 'PiaLite-pipe-selftest.txt'
        if (Test-Path -LiteralPath $stFile) { $st = (Get-Item -LiteralPath $stFile).LastWriteTime }
        foreach ($l in $times.lines) {
            if ($l -match 'all 4 slots busy' -and $st -and $st -gt $boot) { $l += ' (expected: the pipe self-test Run-Phase5.bat runs first fills them on purpose)' }
            Say "  $l"
        }
    } finally {
        Undo-Recording
        Say ''
        Say 'Recording settings put back (firewall audit policy, Security log size, capture stopped).'
    }
    if (Test-Path -LiteralPath $etl) {
        $mb = (Get-Item -LiteralPath $etl).Length / 1MB
        $a = Read-Host ('Delete the capture file ({0:N0} MB)? Keep it only if a developer asks for it. (Y/n)' -f $mb)
        if ($a -notmatch '^\s*[Nn]') { Remove-Item -LiteralPath $etl -Force -ErrorAction SilentlyContinue }
    }
    Save-Report 'leaktest'
}

# ------------------------------------------------- packet-capture self-check

# A captured frame up to the end of its UDP/TCP header, as hex, with every
# hardware (MAC) address and this PC's own IP address zeroed: safe to share,
# and usable as a test case for the capture analysis (review F51-09).
function Get-AnonymizedHex($Pk) {
    $b = [byte[]]@($Pk.Raw)
    if ($Pk.Media -eq 'wifi-802.11') {
        $end = 22
        if ($b.Length -gt 1 -and ($b[1] -band 0x03) -eq 0x03) { $end = 30 }   # 4-address frame
        for ($i = 4; $i -lt [Math]::Min($end, $b.Length); $i++) { if ($i -lt 22 -or $i -ge 24) { $b[$i] = 0 } }
    } elseif ($Pk.Media -eq 'ethernet') {
        for ($i = 0; $i -lt [Math]::Min(12, $b.Length); $i++) { $b[$i] = 0 }
    }
    $o = [int]$Pk.Ip
    if ($b.Length -ge $o + 20 -and ($b[$o] -shr 4) -eq 4) { for ($i = $o + 12; $i -lt $o + 16; $i++) { $b[$i] = 0 } }
    elseif ($b.Length -ge $o + 40 -and ($b[$o] -shr 4) -eq 6) { for ($i = $o + 8; $i -lt $o + 24; $i++) { $b[$i] = 0 } }
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

# Known packets, sent on purpose while a capture runs, must be found by the
# same analysis the startup leak test uses: the positive control that shows
# the capture can see this PC's packets at all (review F51-09).
function Test-CaptureSelfCheck {
    Write-Header
    Say ''
    Say '== Packet-capture self-check (known packets sent on purpose, then looked for in the capture)'
    if (Test-Path -LiteralPath $marker) { Result 'WARN' 'Packet-capture self-check' 'a startup leak test is recording - finish it (3) or undo it (4) first'; Save-Report 'capture'; return }
    $cfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object {
        $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' -and $_.InterfaceAlias -ne 'wgpia0' -and
        $_.NetAdapter.InterfaceDescription -notmatch 'Private Internet Access|WireGuard|Wintun|TAP-Windows'
    } | Select-Object -First 1
    if (-not $cfg) { Result 'WARN' 'Packet-capture self-check' 'no network adapter with a gateway found'; Save-Report 'capture'; return }
    $gw = [string]@($cfg.IPv4DefaultGateway)[0].NextHop
    $ifIndex = [int]$cfg.InterfaceIndex
    Say ("Adapter: {0} ({1}). Test packets: 5 to its gateway {2} and 5 to ff02::1 (everyone on this network), UDP port 9 ('discard', ignored)" -f $cfg.InterfaceAlias, $cfg.NetAdapter.InterfaceDescription, $gw)
    $s = Get-GuardStatus
    if ($s -and -not $s.pia_allow_lan -and (Get-PiaState) -eq 'Connected') { Say "  note: PIA's Allow LAN is off - PIA may block these local packets before they leave, then they can't be seen" }
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    $etl2 = Join-Path $workDir 'selfcheck.etl'
    $st = Invoke-Native 'netsh.exe' @('trace', 'start', 'capture=yes', 'persistent=no', 'report=disabled', 'maxsize=64', 'filemode=single', 'packettruncatebytes=256', 'overwrite=yes', "tracefile=$etl2") -AllowFail
    if ($st.Code -ne 0) { Result 'FAIL' 'Packet capture starts' (Get-Msg $st); Save-Report 'capture'; return }
    $sent6 = $false
    try {
        Start-Sleep -Seconds 2
        $payload = [Text.Encoding]::ASCII.GetBytes('PIALITE-SELFCHECK')
        $u4 = New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetwork)
        try { for ($i = 0; $i -lt 5; $i++) { [void]$u4.Send($payload, $payload.Length, $gw, 9); Start-Sleep -Milliseconds 200 } } finally { $u4.Close() }
        try {
            $u6 = New-Object System.Net.Sockets.UdpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
            try {
                $u6.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IPv6, [System.Net.Sockets.SocketOptionName]::MulticastInterface, $ifIndex)
                $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("ff02::1%$ifIndex"), 9)
                for ($i = 0; $i -lt 5; $i++) { [void]$u6.Send($payload, $payload.Length, $ep); Start-Sleep -Milliseconds 200 }
                $sent6 = $true
            } finally { $u6.Close() }
        } catch { Say "  (IPv6 test packets could not be sent: $($_.Exception.Message))" }
        Start-Sleep -Seconds 2
    } finally {
        Write-Host 'Stopping the capture (can take a minute)...' -ForegroundColor Cyan
        [void](Invoke-Native 'netsh.exe' @('trace', 'stop') -AllowFail -TimeoutSec 300)
    }
    try {
        $cap = Get-CapturedPackets $etl2 (Get-Date)
        Say ('Capture: {0} frames read - {1}' -f $cap.Events, $cap.What)
        $mine = @($cap.Packets | Where-Object { $_.Proto -eq 17 -and $_.Port -eq 9 })
        $v4 = @($mine | Where-Object { $_.Dst -eq $gw })
        $v6 = @($mine | Where-Object { $_.Dst -eq 'ff02::1' })
        if ($v4.Count -gt 0) { Result 'PASS' 'Capture analysis finds known IPv4 packets sent by this PC' ('{0} of 5 found on {1}, read as {2} frames' -f [Math]::Min(5, $v4.Count), $v4[0].Adapter, $v4[0].Media) }
        else { Result 'FAIL' 'Capture analysis finds known IPv4 packets sent by this PC' "none of the 5 packets to $gw was found - the startup leak test's packet capture would be INCONCLUSIVE on this PC (please send this report)" }
        if ($sent6) {
            if ($v6.Count -gt 0) { Result 'PASS' 'Capture analysis finds known IPv6 packets sent by this PC' ('{0} of 5 found, read as {1} frames' -f [Math]::Min(5, $v6.Count), $v6[0].Media) }
            else { Result 'WARN' 'Capture analysis finds known IPv6 packets sent by this PC' 'none found (IPv6 may be off on this network)' }
        }
        # one frame of each, anonymized: future test cases for the analysis
        foreach ($k in (@($v4 | Select-Object -First 1) + @($v6 | Select-Object -First 1))) {
            Say ('  frame ({0}, keywords 0x{1:x}): {2}' -f $k.Media, $k.Kw, (Get-AnonymizedHex $k))
        }
        # the read limit is noticed, never a silent "nothing found" (review V60-06):
        # the same file read with a tiny limit must say it was cut short
        if ($cap.Events -gt 10) {
            $small = Get-CapturedPackets $etl2 (Get-Date) 5
            if ($small.Truncated -and -not $cap.Truncated) { Result 'PASS' 'Capture analysis notices when it could not read everything' ('read with a limit of 5 events it reported itself incomplete (up to {0:HH:mm:ss.fff})' -f $small.Last) }
            else { Result 'FAIL' 'Capture analysis notices when it could not read everything' ('limit 5: cut reported {0}; full read: cut reported {1}' -f $small.Truncated, $cap.Truncated) }
        }
    } catch {
        Result 'WARN' 'Packet-capture self-check' ('could not read the capture: ' + $_.Exception.Message)
    } finally {
        Remove-Item -LiteralPath $etl2, ($etl2 -replace '\.etl$', '.cab') -Force -ErrorAction SilentlyContinue
    }
    Save-Report 'capture'
}

# --------------------------------------------------------------------- menu

try {
    if (-not (Test-Path -LiteralPath $piactl)) { throw "PIA not found in $piaDir" }
    Write-Host 'PIA Lite - Phase 5 tests' -ForegroundColor Cyan
    Write-Host '  1  Quick checks (2-5 minutes, no restart)'
    Write-Host '  2  Start the startup leak test (then you restart)'
    Write-Host '  3  Finish the startup leak test (after restarting + VPN connected)'
    Write-Host '  4  Undo leak test recording'
    Write-Host '  5  Packet-capture self-check (about a minute, no restart)'
    if (Test-Path -LiteralPath $marker) { Write-Host '  (a leak test is recording right now - pick 3 after restarting)' -ForegroundColor Yellow }
    $c = (Read-Host 'Pick 1-5').Trim()
    switch ($c) {
        '1' { Invoke-QuickChecks }
        '2' { Start-LeakTest }
        '3' { Complete-LeakTest }
        '4' { Undo-Recording; Write-Host 'Recording turned off and settings put back (guard back to its normal start).' -ForegroundColor Green }
        '5' { Test-CaptureSelfCheck }
        default { Write-Host 'Nothing picked.' }
    }
} catch {
    Write-Host ''
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    if ($script:lines.Count -gt 0) { Result 'FAIL' 'Test run stopped early' $_.Exception.Message; Save-Report 'partial' }
} finally {
    Write-Host ''
    [void](Read-Host 'Press Enter to close')
}
