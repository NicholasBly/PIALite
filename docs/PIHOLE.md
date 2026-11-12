# Encrypted DNS to your own Pi-hole

Pi-hole answers DNS on port 53 in plain text. That's fine inside your own network, but anyone who can see your
Wi-Fi or LAN traffic can read every name you look up. PIA Lite can encrypt the hop from your PC to the Pi-hole
with DNS over TLS. Pi-hole can't do that by itself, so a small program on the Pi, **dnsdist** (PowerDNS's DNS load
balancer), takes the encrypted lookups on port 853 and hands them to Pi-hole.

```
PC: PIA Lite guard ──DNS over TLS (853)──> Pi: dnsdist ──> Pi-hole (53) ──> its upstream (e.g. cloudflared, DoH)
```

Pi-hole still sees which PC asked (dnsdist passes the client's address on with EDNS Client Subnet), so its
per-client statistics and group rules keep working.

> **Before you start:** run the two report scripts in [`tools/`](../tools) and keep the output. They show your
> Pi-hole version, its certificate and what already listens on which port. Nothing here changes Pi-hole itself.

## 1. On the Pi: dnsdist on port 853

```sh
sudo apt install dnsdist
# dnsdist needs Pi-hole's certificate and key as two files it can read
sudo openssl x509 -in /etc/pihole/tls.pem -out /etc/dnsdist/pihole.crt
sudo openssl pkey -in /etc/pihole/tls.pem -out /etc/dnsdist/pihole.key
sudo chown _dnsdist:_dnsdist /etc/dnsdist/pihole.*
sudo chmod 600 /etc/dnsdist/pihole.key
```

`/etc/dnsdist/dnsdist.conf` (replace `192.168.1.2` with your Pi's address):

```lua
-- encrypted DNS from the home network, handed to Pi-hole
setLocal('127.0.0.1:5399')          -- dnsdist's own plain listener, moved off port 53 (Pi-hole's)
addTLSLocal('0.0.0.0:853', '/etc/dnsdist/pihole.crt', '/etc/dnsdist/pihole.key', { minTLSVersion = 'tls1.2' })
setACL({ '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fe80::/10' })
-- Pi-hole, with the asking PC's address passed on (Pi-hole: dns.EDNS0ECS = true, the default)
-- the only backend: always used. setUp() turns dnsdist's health checks off - otherwise it asks Pi-hole for
-- a.root-servers.net every second (86,400 lines a day in Pi-hole's query log, from 127.0.0.1), and a missed
-- answer (Pi-hole restarting) would stop all lookups until the next check succeeds
local pihole = newServer({ address = '192.168.1.2:53', useClientSubnet = true })
pihole:setUp()
setECSSourcePrefixV4(32)
setECSSourcePrefixV6(128)
setECSOverride(true)
```

> dnsdist would otherwise listen on 127.0.0.1:53 by default, which Pi-hole already uses - the `setLocal` line
> moves it out of the way. Port 5399 is just an unused one; pick another if the report shows it in use.

```sh
sudo dnsdist --check-config && sudo systemctl restart dnsdist
sudo ufw allow 853/tcp     # only if you use ufw
```

Pi-hole renews its certificate now and then; run the two `openssl` lines again afterwards (or make a small cron
job / systemd path unit for it).

## 2. On the PC: point PIA Lite at it

Copy Pi-hole's certificate authority to the PC: `/etc/pihole/tls_ca.crt` (it is public - no secrets in it, but
only Pi-hole may read the file, so copy it to your home folder first):

```sh
# on the Pi
sudo cp /etc/pihole/tls_ca.crt ~/ && sudo chown "$USER" ~/tls_ca.crt
# on the PC (PowerShell or a terminal) - your Pi user and address
scp you@192.168.1.2:~/tls_ca.crt .
```

Check from the PC that port 853 can be reached: `Test-NetConnection 192.168.1.2 -Port 853` (Windows) or
`nc -zv 192.168.1.2 853` (Linux). If not, the Pi's firewall needs to let TCP 853 in. Then, in an administrator
window (Windows) or with sudo (Linux):

```text
pialite-guard set-dns custom tls://pi.hole 192.168.1.2 C:\Users\you\Downloads\tls_ca.crt
pialite-guard test-dns
```

- `tls://pi.hole` - the name must be one the certificate lists (the report script shows it, usually `pi.hole`).
- `192.168.1.2` - the Pi's address. PIA Lite never looks the server up by name.
- the last part - Pi-hole's own certificate authority. Only it is trusted for this server; leave it out if your
  Pi-hole has a certificate from a public authority (e.g. Let's Encrypt).

At install time the same works with `pialite-guard setup --dns custom --doh-url tls://pi.hole --doh-ips 192.168.1.2 --doh-ca tls_ca.crt`.

## Things to know

- **PIA's "Allow LAN" must be on.** While the VPN is connected, PIA otherwise blocks your home network - and the
  Pi-hole with it. PIA Lite's setup warns about this.
- **Your lookups leave home without the VPN.** Pi-hole's upstream (cloudflared, unbound...) runs on the Pi and
  reaches the internet through your router, not through PIA. That's how Pi-hole always works; the encryption
  above protects the PC-to-Pi hop. Away from home the Pi-hole can't be reached; switch PIA Lite to a public
  provider then (`pialite-guard set-dns quad9`).
- **One DNS program at a time.** If YogaDNS, the NextDNS app or another DNS program is running, turn it off while
  PIA Lite does encrypted DNS - or keep that program and install PIA Lite *without* "Encrypted DNS". `setup` and
  `pialite-guard adapter-dns` tell you what they find.
- **Nothing goes around the Pi-hole while the VPN is connected (Windows).** PIA Lite blocks DNS to every other
  server then (ports 53 and 853), so a program or VM that asks 8.8.8.8 itself gets no answer. Browsers' own
  "secure DNS" (DNS over HTTPS to Google / Cloudflare) can't be told apart from web traffic - turn it off in the
  browser's settings. Pi-hole already switches Firefox's off for you.
- **Your YogaDNS block lists** belong in Pi-hole now (Domains page, or `sudo pihole deny NAME ...`): they then
  apply to every device, and you see them in the Query Log.
- **YogaDNS instead?** YogaDNS can also speak DNS over TLS to the dnsdist above. Then install PIA Lite without
  "Encrypted DNS" and let YogaDNS do it; the kill switch works the same either way.
