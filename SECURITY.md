# Security policy

PIA Lite contains a firewall component (the kill switch) and a DNS proxy that run with full system rights,
so security reports are very welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**[Report a vulnerability](https://github.com/NicholasBly/PIALite/security/advisories/new)**
(the *Security* tab of this repository).

Include what you found, how to reproduce it, the PIA Lite version (`pialite-guard version`), your operating
system and, if possible, the guard log with personal details removed. You should get an answer within a week.

## Supported versions

Only the latest release gets fixes.

## Scope

In scope, for example: a way for a normal user or program to weaken or switch off the block, to talk to the
guard without being approved, to make DNS leave unencrypted while encrypted DNS is on, to get traffic out while
the kill switch should block it, or to make the updater install something that isn't a signed release.

Out of scope: problems in Private Internet Access itself (report those to PIA), and attacks that already need
administrator / root rights.

## How releases are protected

Release files are built by GitHub Actions from a tagged commit. `SHA256SUMS` lists every file and is signed with
an ed25519 key (`SHA256SUMS.sig`); the matching public key is in `keys/release-signing.pub` and built into
`pialite-guard`, which refuses to install an update whose signature or checksum doesn't match.
