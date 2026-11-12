<#
  PIA Lite - DNS report for a Windows PC (reads only, changes nothing).

  Shows how this PC's DNS is set up today, so PIA Lite's encrypted DNS can be
  set up to match: network adapters (automatic or typed-in DNS, Windows' own
  DNS over HTTPS), DNS programs (YogaDNS, NextDNS app, ...), what holds port
  53, PIA's DNS settings, and - with -Server - whether your home DNS server
  (e.g. a Pi-hole) answers plain DNS, DNS over TLS (853) or HTTPS (443),
  with its certificate.

  Run in PowerShell (no admin needed; some details need admin):
    powershell -ExecutionPolicy Bypass -File dns-report.ps1 -Server 192.168.1.2 -Name pi.hole
    (or the same with pwsh, PowerShell 7)

  The report is saved on your Desktop as PIALite-DNS-report.txt. It contains
  your local network addresses and program names - no passwords, and your
  public IP address is not looked up. Read it before you share it.
#>
param(
    [string]$Server = '',
    [string]$Name = ''
)
$ErrorActionPreference = 'SilentlyContinue'
$out = New-Object System.Collections.Generic.List[string]
function W([string]$s = '') { $out.Add($s); Write-Host $s }
# not 'H': that is PowerShell's alias for Get-History, which wins over a function
function Section([string]$s) { W ''; W ('== ' + $s) }

W ('PIA Lite DNS report - ' + (Get-Date -Format 'yyyy-MM-dd HH:mm'))
$os = Get-CimInstance Win32_OperatingSystem
W ('Windows: ' + $os.Caption + ' ' + $os.Version)

Section 'Network adapters (connected)'
foreach ($a in (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })) {
    $g = $a.InterfaceGuid
    $n4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g").NameServer
    $n6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g").NameServer
    $used = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex | ForEach-Object { $_.ServerAddresses }) -join ', '
    $ip = Get-NetIPInterface -InterfaceIndex $a.ifIndex
    W ("- " + $a.Name + '  [' + $a.InterfaceDescription + ']  metric ' + ($ip | Where-Object { $_.AddressFamily -eq 'IPv4' }).InterfaceMetric)
    if (-not $ip) { W '    (no IP of its own - bound to a virtual switch, so Windows does not use the DNS below)' }
    W ('    DNS in use     : ' + $used)
    W ('    typed in (v4)  : ' + $(if ($n4) { $n4 } else { '(none - automatic)' }))
    W ('    typed in (v6)  : ' + $(if ($n6) { $n6 } else { '(none - automatic)' }))
    $dohKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$g\DohInterfaceSettings"
    if (Test-Path $dohKey) {
        foreach ($k in (Get-ChildItem $dohKey -Recurse)) {
            $p = Get-ItemProperty $k.PSPath
            W ('    DNS over HTTPS : ' + $k.PSChildName + '  flags=' + $p.DohFlags + $(if ($p.DohTemplate) { '  template=' + $p.DohTemplate } else { '' }))
        }
    }
}

Section "Windows' list of DNS-over-HTTPS servers"
Get-DnsClientDohServerAddress | ForEach-Object { W ('- ' + $_.ServerAddress + '  ' + $_.DohTemplate + '  fallback-to-plain=' + $_.AllowFallbackToUdp + '  auto=' + $_.AutoUpgrade) }

Section 'Name resolution policy (NRPT)'
$nrpt = Get-DnsClientNrptPolicy
if ($nrpt) { $nrpt | ForEach-Object { W ('- ' + ($_.Namespace -join ',') + ' -> ' + ($_.NameServers -join ',')) } } else { W '(none)' }

Section 'What holds DNS ports (53 = DNS, 853 = DNS over TLS)'
foreach ($port in 53, 853) {
    $eps = @(Get-NetUDPEndpoint -LocalPort $port | ForEach-Object { ,@('UDP', $_.LocalAddress, $_.OwningProcess) })
    $eps += @(Get-NetTCPConnection -LocalPort $port -State Listen | ForEach-Object { ,@('TCP', $_.LocalAddress, $_.OwningProcess) })
    foreach ($e in $eps) {
        $pn = (Get-Process -Id $e[2]).ProcessName
        # svchost hosts many Windows services - name the ones in that process
        $svc = if ($pn -eq 'svchost') { '  services: ' + ((Get-CimInstance Win32_Service -Filter "ProcessId=$($e[2])" | ForEach-Object { $_.Name + ' (' + $_.DisplayName + ')' }) -join ', ') } else { '' }
        W ($e[0] + ' ' + $e[1] + ':' + $port + '  ' + $pn + $svc)
    }
}

Section 'DNS programs (services and running programs)'
$pat = 'yogadns|nextdns|dnscrypt|acrylic|adguard|portmaster|technitium|dnsproxy|simplednscrypt|unbound|stubby|cloudflared|pialite'
Get-Service | Where-Object { $_.Name -match $pat -or $_.DisplayName -match $pat } | ForEach-Object { W ('service: ' + $_.Name + ' / ' + $_.DisplayName + ' / ' + $_.Status + ' / ' + $_.StartType) }
Get-Process | Where-Object { $_.ProcessName -match $pat } | ForEach-Object { W ('program: ' + $_.ProcessName + '  ' + $_.Path) }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' |
    ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -match $pat } |
    ForEach-Object { W ('installed: ' + $_.DisplayName + ' ' + $_.DisplayVersion + '  in ' + $_.InstallLocation) }

Section 'YogaDNS settings (server lines only)'
$yoga = @("$env:ProgramData\YogaDNS", "$env:APPDATA\YogaDNS", "$env:LOCALAPPDATA\YogaDNS", "${env:ProgramFiles}\YogaDNS", "${env:ProgramFiles(x86)}\YogaDNS")
$found = $false
foreach ($d in $yoga) {
    if (Test-Path $d) {
        $found = $true
        W ('folder: ' + $d)
        Get-ChildItem $d -Recurse -Include *.xml, *.ini, *.json, *.conf, *.cfg | Select-Object -First 10 | ForEach-Object {
            W ('  file: ' + $_.Name)
            Select-String -Path $_.FullName -Pattern 'address|server|protocol|url|port|doh|dot|tls|https|plain' -SimpleMatch:$false |
                Where-Object { $_.Line -notmatch 'pass|key|licen|token|serial' } | Select-Object -First 40 |
                ForEach-Object { W ('    ' + $_.Line.Trim()) }
        }
    }
}
if (-not $found) { W '(no YogaDNS folder found)' }

Section 'Private Internet Access'
$pia = Join-Path $env:ProgramFiles 'Private Internet Access'
$ctl = Join-Path $pia 'piactl.exe'
if (Test-Path $ctl) {
    W ('connection : ' + (& $ctl get connectionstate))
    W ('protocol   : ' + (& $ctl get protocol))
    $sf = Join-Path $pia 'data\settings.json'
    if (Test-Path $sf) {
        $j = Get-Content $sf -Raw | ConvertFrom-Json
        W ('overrideDNS: ' + ($j.overrideDNS | ConvertTo-Json -Compress))
        W ('allowLAN   : ' + $j.allowLAN + '   killswitch: ' + $j.killswitch + '   splitTunnel: ' + $j.splitTunnelEnabled)
    } else { W '(PIA settings file not readable - run as administrator for these)' }
} else { W 'PIA not found' }

Section 'PIA Lite'
$g = Join-Path $env:ProgramFiles 'PiaLite\pialite-guard.exe'
if (Test-Path $g) { & $g version | ForEach-Object { W $_ }; & $g features | ForEach-Object { W $_ } } else { W 'not installed' }

Section 'Name lookups'
foreach ($n in @('example.com', $Name) | Where-Object { $_ }) {
    $r = Resolve-DnsName $n -Type A -DnsOnly -ErrorAction SilentlyContinue
    W ($n + ' (system) -> ' + (($r | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) -join ', '))
}

# The TLS check is C#: a PowerShell script block as the certificate callback fails
# in PowerShell 7 (it runs on a thread that has no PowerShell to run it).
if ($Server -and -not ('PiaLiteTls' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
public class PiaLiteTls {
    public X509Certificate2 Cert;
    public string Errors = "";
    public string Protocol = "";
    public static PiaLiteTls Probe(string host, int port, string sni) {
        PiaLiteTls r = new PiaLiteTls();
        using (TcpClient c = new TcpClient()) {
            if (!c.ConnectAsync(host, port).Wait(3000)) throw new Exception("no connection");
            c.ReceiveTimeout = 5000;
            c.SendTimeout = 5000;
            using (SslStream s = new SslStream(c.GetStream(), false, delegate (object o, X509Certificate ce, X509Chain ch, SslPolicyErrors e) {
                if (ce != null) r.Cert = new X509Certificate2(ce);
                r.Errors = e.ToString();
                return true;
            })) {
                s.AuthenticateAsClient(sni);
                r.Protocol = s.SslProtocol.ToString();
            }
        }
        return r;
    }
}
'@
}

if ($Server) {
    Section ("Your DNS server " + $Server + $(if ($Name) { " ($Name)" } else { '' }))
    $r = Resolve-DnsName example.com -Server $Server -Type A -DnsOnly -ErrorAction SilentlyContinue
    W ('plain DNS (53)        : ' + $(if ($r) { 'answers' } else { 'NO answer' }))
    foreach ($port in 853, 443, 8443) {
        $c = New-Object Net.Sockets.TcpClient
        $open = $c.ConnectAsync($Server, $port).Wait(2000) -and $c.Connected
        W ('TCP port ' + $port + '          : ' + $(if ($open) { 'open' } else { 'closed' }))
        $c.Close()
        if ($open) {
            $sni = if ($Name) { $Name } else { $Server }
            try {
                $t = [PiaLiteTls]::Probe($Server, $port, $sni)
                $x = $t.Cert
                $san = ($x.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | ForEach-Object { $_.Format($false) })
                W ('  TLS certificate     : ' + $x.Subject)
                W ('  issued by           : ' + $x.Issuer)
                W ('  names (SAN)         : ' + $san)
                W ('  valid until         : ' + $x.NotAfter.ToString('yyyy-MM-dd'))
                W ('  trusted by Windows  : ' + $(if ($t.Errors -eq 'None') { 'yes' } else { 'NO (' + $t.Errors + ')' }))
                W ('  TLS version         : ' + $t.Protocol)
            } catch {
                $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }
                W ('  TLS: no handshake (' + $ex.Message + ')')
            }
        }
    }
    if ($Name) {
        # a DNS-over-HTTPS endpoint answers a GET with a DNS message (example.com, type A)
        foreach ($u in @("https://$Name/dns-query", "https://${Name}:8443/dns-query")) {
            try {
                $resp = Invoke-WebRequest -Uri ($u + '?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE') -Headers @{ Accept = 'application/dns-message' } -UseBasicParsing -TimeoutSec 5
                W ($u + ' : HTTP ' + $resp.StatusCode + ' ' + $resp.Headers['Content-Type'])
            } catch { W ($u + ' : ' + $_.Exception.Message) }
        }
    }
    Section 'Certificate authorities installed for it'
    Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'pi-hole|pihole|pi\.hole' -or ($Name -and $_.Subject -match [regex]::Escape($Name)) } |
        ForEach-Object { W ('- ' + $_.PSParentPath.Split(':')[-1] + '  ' + $_.Subject + '  thumbprint ' + $_.Thumbprint) }
}

$file = Join-Path ([Environment]::GetFolderPath('Desktop')) 'PIALite-DNS-report.txt'
$out | Set-Content -Path $file -Encoding UTF8
Write-Host ''
Write-Host ('Saved: ' + $file)
