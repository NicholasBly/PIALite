#!/bin/bash
# PIA Lite - report for a Pi-hole (reads only, changes nothing).
#
# Shows what PIA Lite needs to know to send this PC's DNS to your Pi-hole
# encrypted: Pi-hole version and DNS/web settings, its certificate, what
# listens on the DNS ports, cloudflared / dnsdist / unbound, the firewall.
#
#   sudo bash pihole-report.sh            (prints and saves ~/pihole-report.txt)
#
# No passwords or keys are printed (the password hash, API keys and the
# certificate's private key are never read). Read it before you share it.
OUT="${SUDO_USER:+/home/$SUDO_USER}"; OUT="${OUT:-$HOME}/pihole-report.txt"
exec > >(tee "$OUT") 2>&1
h() { echo; echo "== $*"; }
echo "Pi-hole report - $(date '+%Y-%m-%d %H:%M')"
. /etc/os-release 2>/dev/null; echo "System: ${PRETTY_NAME:-?} $(uname -m), kernel $(uname -r)"

h "Addresses"
ip -br addr 2>/dev/null | grep -v '^lo '

h "Pi-hole"
pihole -v 2>/dev/null || pihole version 2>/dev/null || echo "pihole command not found"
if command -v pihole-FTL >/dev/null; then
  for k in dns.upstreams dns.listeningMode dns.interface dns.port dns.EDNS0ECS dns.domain dns.revServers \
           webserver.port webserver.domain webserver.tls.cert webserver.tls.validity; do
    printf '%-24s %s\n' "$k" "$(pihole-FTL --config "$k" 2>/dev/null | tr '\n' ' ')"
  done
fi

h "Pi-hole's certificate (no private key)"
for f in /etc/pihole/tls.crt /etc/pihole/tls.pem /etc/pihole/tls_ca.crt; do
  [ -f "$f" ] || continue
  echo "-- $f ($(stat -c '%U:%G %a' "$f"))"
  openssl x509 -in "$f" -noout -subject -issuer -enddate -fingerprint -sha256 2>/dev/null
  openssl x509 -in "$f" -noout -ext subjectAltName,basicConstraints 2>/dev/null | sed 's/^/   /'
done

h "Listening on DNS / web ports (53, 853, 443, 80, 5053, 5335, 8443)"
ss -tulpnH 2>/dev/null | awk '$5 ~ /:(53|853|443|80|5053|5335|8443)$/ {print $1, $5, $7}'

h "cloudflared"
if command -v cloudflared >/dev/null; then
  cloudflared --version 2>/dev/null
  for u in cloudflared cloudflared-proxy-dns; do
    systemctl is-active "$u" >/dev/null 2>&1 && { echo "service $u: active"; systemctl cat "$u" 2>/dev/null | grep -E '^(ExecStart|Environment)'; }
  done
  for f in /etc/default/cloudflared /etc/cloudflared/config.yml /etc/cloudflared/config.yaml; do
    [ -f "$f" ] && { echo "-- $f"; grep -viE 'token|secret|credentials|cert' "$f"; }
  done
else echo "not installed"; fi

h "dnsdist / unbound / stunnel / nginx / lighttpd"
for p in dnsdist unbound stunnel4 stunnel nginx lighttpd caddy; do
  command -v "$p" >/dev/null && echo "$p: $("$p" -V 2>&1 | head -1 || true) ($(systemctl is-active "$p" 2>/dev/null))"
done
[ -f /etc/dnsdist/dnsdist.conf ] && { echo "-- /etc/dnsdist/dnsdist.conf"; grep -viE 'key|secret|password' /etc/dnsdist/dnsdist.conf; }

h "Firewall"
command -v ufw >/dev/null && ufw status 2>/dev/null | head -20
nft list ruleset 2>/dev/null | grep -cE 'dport' | sed 's/^/nftables port rules: /'

h "Lookups"
if command -v dig >/dev/null; then
  for s in 127.0.0.1 $(hostname -I 2>/dev/null | awk '{print $1}'); do echo "@$s example.com -> $(dig +short +time=2 @"$s" example.com A | head -2 | tr '\n' ' ')"; done
  dig +short +time=2 @127.0.0.1 -p 5053 example.com A >/dev/null 2>&1 && echo "cloudflared on 5053 answers"
  command -v kdig >/dev/null && kdig +tls +short @127.0.0.1 example.com A 2>/dev/null | head -1 | sed 's/^/DNS over TLS on 853: /'
else echo "(dig not installed: sudo apt install dnsutils)"; fi

echo; echo "Saved: $OUT"
