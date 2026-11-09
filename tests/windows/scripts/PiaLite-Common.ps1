<#
    PiaLite-Common.ps1  -  helpers for Phase5-Tests.ps1 (the Windows release test kit)
    (dot-sourced; not meant to be run on its own).

      Invoke-Native          run a program with a time limit (+ a short grace to stop it)
      Get-RecoveryVerdict    the strict reader for the hotel recovery record
#>

# Quote one argument for the Windows command line (CommandLineToArgvW rules).
function ConvertTo-Arg([string]$A) {
    if ($A -ne '' -and $A -notmatch '[\s"]') { return $A }
    $q = $A -replace '(\\*)"', '$1$1\"'
    $q = $q -replace '(\\+)$', '$1$1'
    return '"' + $q + '"'
}

# Everything a program said (output + error text), for messages.
function Get-Msg($Res) {
    if (-not $Res) { return 'no result' }
    return (($Res.Output + ' ' + $Res.Error).Trim() -replace '^ERROR:\s*', '')
}

# Stop what a program started (and the program itself if -KillRoot), within
# -GraceMs (review V60-10). Found through Windows' parent-process links; a
# process is only counted if it started after $Since (and, when the program
# itself already ended, before $UpTo) - a reused process number belongs to
# someone else and is left alone. No outside tool that could hang.
function Stop-ProcessTree([int]$Id, [datetime]$Since, $UpTo, [bool]$KillRoot, [int]$GraceMs = 5000) {
    $until = [DateTime]::UtcNow.AddMilliseconds($GraceMs)
    $found = New-Object System.Collections.Generic.List[int]
    $todo = New-Object System.Collections.Generic.Queue[int]
    $todo.Enqueue($Id)
    while ($todo.Count -gt 0 -and $found.Count -lt 64 -and [DateTime]::UtcNow -lt $until) {
        $cur = $todo.Dequeue()
        $kids = @()
        try { $kids = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId=$cur" -OperationTimeoutSec 3 -ErrorAction Stop) } catch { }
        foreach ($k in $kids) {
            $made = $k.CreationDate
            if ($made -and $made -lt $Since) { continue }
            if ($cur -eq $Id -and $UpTo -and $made -and $made -gt $UpTo) { continue }
            $found.Add([int]$k.ProcessId)
            $todo.Enqueue([int]$k.ProcessId)
        }
    }
    foreach ($c in $found) { try { Stop-Process -Id $c -Force -ErrorAction Stop } catch { } }
    if ($KillRoot) { try { Stop-Process -Id $Id -Force -ErrorAction Stop } catch { } }
}

# Run a program with a time limit for everything: its output being read to
# the end AND the program ending (review V4-10, F51-06). The limit is
# -TimeoutSec, plus up to ~8 s to stop what is still running after it
# (review V60-10). Output is read in pieces and kept up to -MaxOutputBytes per
# stream - more is drained and dropped, and the result says so (Truncated)
# (review V60-07). Outcomes that are errors unless -AllowFail (then Code = -1):
#   - the program can't be started
#   - not finished in time: it and everything it started are stopped
#   - it ended, but something it started kept its output open: that is stopped
#   - its output could not be read (never a silent "empty output")
#   - a non-zero exit code (then Code is that code)
# Its normal output and its error messages are kept apart (so JSON answers
# stay readable).
function Invoke-Native([string]$Exe, [string[]]$Arguments, [switch]$AllowFail, [int]$TimeoutSec = 90, [int]$MaxOutputBytes = 4MB) {
    $what = (Split-Path $Exe -Leaf) + ' ' + ($Arguments -join ' ')
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = (@($Arguments) | ForEach-Object { ConvertTo-Arg $_ }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    $left = { [int][Math]::Max(0, [Math]::Min([double][int]::MaxValue, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)) }
    $since = (Get-Date).AddSeconds(-1)
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
    } catch {
        $why = "could not be started ($($_.Exception.Message))"
        if (-not $AllowFail) { throw "$what $why" }
        return [pscustomobject]@{ Code = -1; Output = ''; Error = $why; Truncated = $false }
    }
    $res = $null
    try {
        $streams = @(
            @{ Name = 'output'; Reader = $p.StandardOutput },
            @{ Name = 'error output'; Reader = $p.StandardError }
        )
        foreach ($st in $streams) {
            $st.Stream = $st.Reader.BaseStream
            $st.Buf = New-Object byte[] 65536
            $st.Data = New-Object System.IO.MemoryStream
            $st.Done = $false
            $st.Cut = $false
            $st.Fault = ''
            $st.Task = $st.Stream.ReadAsync($st.Buf, 0, $st.Buf.Length)
        }
        # 1. read both outputs to their end, in pieces, within the time limit
        $timedOut = $false
        while ($true) {
            $open = @($streams | Where-Object { -not $_.Done })
            if ($open.Count -eq 0) { break }
            $i = [System.Threading.Tasks.Task]::WaitAny([System.Threading.Tasks.Task[]]@($open | ForEach-Object { $_.Task }), (& $left))
            if ($i -lt 0) { $timedOut = $true; break }
            $st = $open[$i]
            $t = $st.Task
            if ($t.IsFaulted -or $t.IsCanceled) {
                $st.Fault = 'canceled'
                if ($t.Exception) { $st.Fault = $t.Exception.GetBaseException().Message }
                $st.Done = $true
                continue
            }
            $n = [int]$t.Result
            if ($n -le 0) { $st.Done = $true; continue }
            $room = $MaxOutputBytes - [int]$st.Data.Length
            if ($room -gt 0) { $st.Data.Write($st.Buf, 0, [Math]::Min($n, $room)) }
            if ($n -gt $room) { $st.Cut = $true }
            $st.Task = $st.Stream.ReadAsync($st.Buf, 0, $st.Buf.Length)
        }
        # 2. the program itself, in the time that is left
        $exited = (-not $timedOut) -and $p.WaitForExit((& $left))
        $why = $null
        if (-not $exited) {
            $gone = $p.HasExited
            $upTo = $null
            if ($gone) { try { $upTo = $p.ExitTime.AddSeconds(1) } catch { } }
            Stop-ProcessTree $p.Id $since $upTo (-not $gone)
            if ($gone) { $why = "ended, but a program it started kept its output open past $TimeoutSec s (that program was stopped)" }
            else { $why = "did not finish within $TimeoutSec s (stopped, with what it started)" }
        } else {
            $faults = @($streams | Where-Object { $_.Fault } | ForEach-Object { $_.Name + ': ' + $_.Fault })
            if ($faults.Count -gt 0) { $why = 'ran, but its output could not be read (' + ($faults -join '; ') + ')' }
        }
        if ($why) {
            if (-not $AllowFail) { throw "$what $why" }
            return [pscustomobject]@{ Code = -1; Output = ''; Error = $why; Truncated = $false }
        }
        $out = $streams[0].Reader.CurrentEncoding.GetString($streams[0].Data.ToArray())
        $err = $streams[1].Reader.CurrentEncoding.GetString($streams[1].Data.ToArray())
        $cut = $streams[0].Cut -or $streams[1].Cut
        if ($cut) { $err = ($err.Trim() + " [output cut at $MaxOutputBytes bytes]").Trim() }
        $res = [pscustomobject]@{ Code = $p.ExitCode; Output = $out.Trim(); Error = $err.Trim(); Truncated = $cut }
    } finally {
        $p.Dispose()
    }
    if ($res.Code -ne 0 -and -not $AllowFail) {
        throw ("$what failed (exit $($res.Code)): " + (Get-Msg $res))
    }
    return $res
}

# ------------------------------------------------- hotel recovery record
# The same rules as pialite-guard (config.rs: parse_recovery / decide), checked
# against the same cases (scripts\recovery-fixtures.json) by the Phase 5 quick
# checks (review F51-01). hotel-recovery.json, version 1:
#   {"version": 1, "hotel": <whole number 1..2^53-1>, "saved_killswitch": "on"|"auto"|"off"}
# no other fields, names case-sensitive, "version" may be missing (v0.5.x).

function Test-WholeNumber($V) { return ($V -is [int] -or $V -is [long]) }

# Field names must be unambiguous (review V60-11) - the same simple scan as
# the guard's json_keys_ok: a name is a string followed by ':'; no name twice,
# also not in different capitals (ConvertFrom-Json in PowerShell 5.1 merges
# those), and no escape codes in a name. '' = fine, else why not.
function Test-JsonKeys([string]$Text) {
    $keys = New-Object System.Collections.Generic.List[string]
    $n = $Text.Length
    $i = 0
    while ($i -lt $n) {
        if ($Text[$i] -ne '"') { $i++; continue }
        $j = $i + 1
        $esc = $false
        while ($j -lt $n) {
            $c = $Text[$j]
            if ($esc) { $esc = $false }
            elseif ($c -eq '\') { $esc = $true }
            elseif ($c -eq '"') { break }
            $j++
        }
        $tok = $Text.Substring($i + 1, [Math]::Min($j, $n) - $i - 1)
        $k = $j + 1
        while ($k -lt $n -and (" `t`r`n".IndexOf($Text[$k]) -ge 0)) { $k++ }
        if ($k -lt $n -and $Text[$k] -eq ':') { $keys.Add($tok) }
        $i = $j + 1
    }
    foreach ($k in $keys) { if ($k.Contains('\')) { return "a field name uses escape codes ($k)" } }
    $seen = @{}   # PowerShell hashtables ignore capitals: exactly the rule
    foreach ($k in $keys) {
        if ($seen.ContainsKey($k)) { return "field '$k' appears twice" }
        $seen[$k] = $true
    }
    return ''
}

function Read-RecoveryRecord([string]$Text) {
    $bad = { param($w) return @{ Ok = $false; Saved = ''; Why = $w } }
    if ($Text.Length -gt 4096) { return (& $bad "$($Text.Length) characters - too big to be a recovery record") }
    $why = Test-JsonKeys $Text
    if ($why) { return (& $bad $why) }
    $o = $null
    try { $o = $Text | ConvertFrom-Json -ErrorAction Stop } catch { return (& $bad 'not valid JSON') }
    if (-not ($o -is [System.Management.Automation.PSCustomObject])) { return (& $bad 'not a JSON object') }
    $names = @($o.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($n in $names) {
        if (-not (@('version', 'hotel', 'saved_killswitch') -ccontains $n)) { return (& $bad "unexpected field '$n'") }
    }
    if ($names -ccontains 'version') {
        $v = $o.version
        if (-not (Test-WholeNumber $v) -or $v -ne 1) { return (& $bad "unknown version '$v'") }
    }
    if (-not ($names -ccontains 'hotel')) { return (& $bad "'hotel' is missing") }
    $h = $o.hotel
    if (-not (Test-WholeNumber $h)) { return (& $bad "'hotel' must be a whole number") }
    if ($h -lt 1 -or $h -gt 9007199254740991) { return (& $bad "'hotel' $h is out of range") }
    if (-not ($names -ccontains 'saved_killswitch')) { return (& $bad "'saved_killswitch' is missing") }
    $s = $o.saved_killswitch
    if (-not ($s -is [string]) -or -not (@('on', 'auto', 'off') -ccontains $s)) { return (& $bad "unknown kill switch value '$s'") }
    return @{ Ok = $true; Saved = $s; Why = '' }
}

# guard.json's own hotel marker: only the two hotel fields matter, and they
# must have the right types.
function Read-GuardMarker([string]$Text) {
    $bad = { param($w) return @{ Readable = $false; Active = $false; Saved = ''; Why = $w } }
    $why = Test-JsonKeys $Text
    if ($why) { return (& $bad "guard.json: $why") }
    $o = $null
    try { $o = $Text | ConvertFrom-Json -ErrorAction Stop } catch { return (& $bad "guard.json can't be read") }
    if (-not ($o -is [System.Management.Automation.PSCustomObject])) { return (& $bad 'guard.json is not a JSON object') }
    $names = @($o.PSObject.Properties | ForEach-Object { $_.Name })
    $active = $false
    if ($names -ccontains 'hotel_active') {
        if (-not ($o.hotel_active -is [bool])) { return (& $bad 'guard.json: hotel_active is not true/false') }
        $active = $o.hotel_active
    }
    $saved = ''
    if ($names -ccontains 'hotel_saved_killswitch') {
        if (-not ($o.hotel_saved_killswitch -is [string])) { return (& $bad 'guard.json: hotel_saved_killswitch is not text') }
        $saved = $o.hotel_saved_killswitch
    }
    return @{ Readable = $true; Active = $active; Saved = $saved; Why = '' }
}

# What the records say about an unfinished hotel login. $RecordText /
# $GuardText: the files' text, $null = the file doesn't exist.
#   State 'none' | 'restore' (+ Saved = the kill switch to put back) |
#   'unknown' (+ Why) - the records are damaged or disagree: you check PIA
#   yourself (the guard, which can't ask, assumes 'on').
# The recovery record decides; guard.json's marker counts only without one;
# a disagreement between the two is never settled by guessing.
function Get-RecoveryVerdict($RecordText, $GuardText) {
    $v = { param($st, $sv, $w) return [pscustomobject]@{ State = $st; Saved = $sv; Why = $w } }
    if ($null -ne $RecordText) {
        $r = Read-RecoveryRecord ([string]$RecordText)
        if (-not $r.Ok) { return (& $v 'unknown' '' "the hotel recovery record is damaged: $($r.Why)") }
        if ($null -ne $GuardText) {
            $m = Read-GuardMarker ([string]$GuardText)
            if ($m.Readable -and $m.Active -and ($m.Saved -cne $r.Saved)) {
                return (& $v 'unknown' '' "the hotel recovery record ('$($r.Saved)') and guard.json ('$($m.Saved)') disagree")
            }
        }
        return (& $v 'restore' $r.Saved '')
    }
    if ($null -eq $GuardText) { return (& $v 'unknown' '' 'guard.json is missing') }
    $m = Read-GuardMarker ([string]$GuardText)
    if (-not $m.Readable) { return (& $v 'unknown' '' $m.Why) }
    if ($m.Active) {
        if (@('on', 'auto', 'off') -ccontains $m.Saved) { return (& $v 'restore' $m.Saved '') }
        return (& $v 'unknown' '' "guard.json records a hotel login with an unknown kill switch value '$($m.Saved)'")
    }
    return (& $v 'none' '' '')
}

# A file's text, or $null if it doesn't exist. Throws if it exists but can't be read.
function Get-TextOrNull([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return [System.IO.File]::ReadAllText($Path)
}

# Every fixture case through Get-RecoveryVerdict: the cases that disagree
# with the expected answer (empty = the reader matches the guard's).
function Test-RecoveryFixtures([string]$FixturePath) {
    $doc = Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json
    $wrong = @()
    foreach ($c in $doc.cases) {
        $r = Get-RecoveryVerdict $c.record $c.guard
        $got = $r.State
        if ($got -eq 'restore') { $got = 'restore:' + $r.Saved }
        if ($got -cne [string]$c.expect) { $wrong += "'$($c.name)': got $got, expected $($c.expect)" }
    }
    return [pscustomobject]@{ Count = @($doc.cases).Count; Wrong = $wrong }
}
