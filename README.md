# PortScope

***
This is not a substitute for Nmap; it does not replace its significant role in host discovery and port diagnosis. It is a lightweight complement based on Python3. Feel free to clone, modify, duplicate, and share any changes to this code. It is my honor to contribute. This program is still being developed and not completely tested. 
***
**Protocol-aware post-Nmap port diagnostics, with careful pacing for fragile or rate-limited services.**

PortScope takes the ports Nmap already found and asks a second, more specific set of
questions: what application is really there, what protection is in front of it, and
whether the observed state matches Nmap's result. It also suggests likely vulnerability
areas and relevant Nmap NSE scripts, while marking them as candidates rather than
confirmed findings. It performs read-only protocol exchanges. It does not exploit
services, guess passwords, write application data, or implement IDS evasion.

Use PortScope only on systems you own or have explicit permission to test.


---

## Why this exists

Nmap's service/version detection is broad, but a short TCP or HTTP probe can leave
important questions unanswered:

- Is an SSH server offering legacy key-exchange or host-key algorithms?
- Does SMB require signing? Is SMB1 still enabled?
- Does RDP require NLA, or does it fall back to Standard RDP Security?
- Is PostgreSQL using trust authentication or a cleartext password prompt?
- Does Redis answer PING without authentication?
- Is Docker's Engine API reachable without an authentication challenge?
- Is a TLS certificate expired, self-signed, for the wrong host, or using a weak key?
- Does an HTTPS service support TLS 1.0/1.1?
- Is a WAF/CDN in front of the application? Are HSTS, CSP, and cookie flags present?
- Did the port state change between the Nmap scan and a real TCP handshake?

PortScope answers these with protocol-specific probes and produces a text, Markdown,
or JSON report. Nmap remains the discovery engine; PortScope is the follow-up
diagnosis layer.

---

## Requirements

- Python 3.9 or newer. The script is standard-library only.
- Optional: the **cryptography** package. If installed, certificate subject, key size,
  SANs, and signature hash are richer. Without it, PortScope falls back to CPython's
  built-in certificate decoder.
- Nmap is optional for the normal probes (only its XML output is consumed), but the
  **--nse** / **--nse-scripts** feature requires an Nmap executable on PATH or
  specified with **--nmap-bin**.

Check the version:

    python3 portscope.py --version

---

## Quick start

### 1. Discover ports with Nmap

    nmap -sV -oX scan.xml 192.168.56.101

For a UDP pass as well:

    nmap -sU -p 53,123,161 -oX udp.xml 192.168.56.101
    python3 portscope.py --nmap udp.xml --protocol udp --snmp-community public

### 2. Diagnose the discovered ports

    python3 portscope.py --nmap scan.xml --profile polite --json report.json --markdown report.md

Read the report on stdout as well. Add **--verbose** for full evidence and progress.
Add **--nse** to run a curated low-impact Nmap NSE set; the report also includes
candidate vulnerability areas even without it.

    python3 portscope.py --nmap scan.xml --profile polite --nse --json report.json --markdown report.md

### 3. Direct target mode

Useful when you already know the ports and do not need an Nmap XML file:

    python3 portscope.py --target 192.168.56.101 --ports 21,22,80,445,3306 --profile fast

For a custom port whose service Nmap could not identify:

    python3 portscope.py --target 10.0.0.5 --ports 8080 --service-map 8080=http

---

## Timing profiles

| Profile | Connect timeout | Read timeout | Attempts | Spacing | Workers | Intended use |
|---|---:|---:|---:|---:|---:|---|
| fast | 1.0 s | 1.5 s | 1 | none | 16 | Isolated Metasploitable-style lab targets |
| polite | 2.5 s | 3.0 s | 2 | 0.35-0.9 s | 6 | Default; ordinary authorized testing |
| slow | 5.0 s | 6.0 s | 3 | 2.5-5.0 s | 2 | Fragile services and rate-limit-based filters |

All profiles are overridable:

    python3 portscope.py --target 10.0.0.5 --ports 443 --profile slow --timeout 8 --attempts 4 --delay 4 9

**What the slow profile does:** every connection attempt, including retries, is spaced
by a global jittered delay. This is useful when a firewall or service drops clients
that connect too quickly. It is deliberately not stealth technology: PortScope does
not use decoys, spoofed sources, fragmentation, or crafted evasion. A port that is
silently dropped by a default-deny firewall will still look filtered. The slow
profile cannot make a closed or unreachable service answer.

**What the fast profile does:** short timeouts, no pacing, and a larger worker pool.
Use it only on an isolated lab network where incidental load is acceptable.

---

## What gets checked

### TCP reachability and state

Each selected TCP port receives repeated full TCP handshakes. PortScope records:

- connect latency and each attempt outcome;
- open, refused, timeout, unreachable, or local error;
- differences between the Nmap state and the live result; and
- a note when an Nmap-open port has gone silent or a filtered port now accepts.

A full TCP connect can succeed where an Nmap SYN result was filtered because of scan
timing or a stateful firewall. PortScope reports that difference rather than assuming
which result is "correct".

### Service-specific probes

| Service | Probe | Protection / service signals |
|---|---|---|
| HTTP / HTTPS | GET and OPTIONS | Status, title, Server/X-Powered-By, WAF/CDN fingerprints, security headers, cookies, CORS, HSTS, redirects, rate limiting, Docker/Elasticsearch/Kubernetes exposure |
| TLS | Handshake plus 1.0/1.1/1.2/1.3 matrix | Negotiated version/cipher, ALPN, certificate validity, SAN/CN match, self-signature, key size, signature hash, legacy protocols |
| SSH | Banner and KEXINIT | Protocol version, software, KEX/host-key/encryption/MAC algorithm lists, legacy algorithm names |
| FTP | Banner, FEAT, SYST | Server software, explicit FTPS (AUTH TLS), cleartext control channel |
| SMTP | Banner, EHLO/HELO, STARTTLS | Extensions, AUTH mechanisms, STARTTLS availability, certificate when STARTTLS succeeds |
| IMAP | Greeting, CAPABILITY, STARTTLS | Capabilities, PREAUTH, LOGINDISABLED, auth mechanisms, TLS certificate |
| POP3 | Greeting, CAPA, STLS | Capabilities, SASL, STLS upgrade, cleartext channel |
| DNS | CHAOS TXT version.bind / hostname.bind | Version/hostname disclosure, recursion flag, rcode, DoT when TLS is indicated |
| RDP | X.224 connection request with RDP negotiation | Standard RDP Security, TLS, CredSSP/NLA, negotiation failure codes |
| MySQL | Initial handshake | Server version, auth plugin, capability flags, CLIENT_SSL capability |
| PostgreSQL | SSLRequest and StartupMessage | TLS support, AuthenticationOk/trust, cleartext password, MD5, SCRAM |
| Redis | PING | Unauthenticated PONG, NOAUTH, protected mode, TLS if configured |
| Memcached | version | Unauthenticated version response, TLS if configured |
| MongoDB | OP_MSG hello/isMaster | Handshake result, maxWireVersion, authentication-required errors |
| VNC | RFB version and security-type list | None, VNC password, TLS/VeNCrypt security types |
| Telnet | Banner and IAC negotiation | Cleartext exposure, option negotiation |
| SMB | SMB2 NEGOTIATE, SMB1 fallback | Dialect, signing enabled/required, SMB1 enabled |
| LDAP | Anonymous bind and unbind | Anonymous bind accepted or authentication required, LDAPS TLS |
| NTP | Single client-mode packet | Version, stratum, reference ID, kiss-o'-death/unsynchronized status |
| SNMP | Read-only GET sysDescr.0, only with --snmp-community | Readable community string, default community warning |
| Docker | HTTP GET /version | Engine API metadata, unauthenticated exposure |
| Elasticsearch | HTTP GET / | Cluster metadata, unauthenticated exposure |
| Kubernetes | HTTP GET /version | API server version metadata |

Unknown services receive a passive banner read. If a TLS record is seen, PortScope
performs a TLS handshake and reports certificate and protocol details. No generic
exploit payload is sent. If Nmap could not name the service and you want one cautious
application-layer attempt, add **--http-fallback**; PortScope will then send a single
GET and OPTIONS to see whether the endpoint is HTTP.

### Vulnerability hints

Every open service receives a list of **candidate vulnerability areas**, not a claim
that the target is vulnerable. Hints include a likelihood label:

- **likely**: direct evidence, such as an unauthenticated Redis PING or an exact
  known-backdoor version banner.
- **possible**: the service type creates a credible test area, such as SSH brute force,
  SMB1 legacy checks, or an exposed SQL listener.
- **test**: a broad application-layer candidate, such as SQL injection on an HTTP
  service, where no evidence has been gathered yet.

Example hints include:

- HTTP: SQL/command injection and login brute-force candidates.
- SSH: password brute force, weak algorithms, and protocol 1.
- FTP: anonymous access, weak credentials, and exact backdoor signatures for
  vsftpd 2.3.4 and ProFTPD 1.3.3c.
- SMB/Samba: null sessions, share/user enumeration, SMB1 legacy checks, MS17-010
  candidates on Windows SMB, and SambaCry checks on Samba.
- SQL services: weak/default/blank credentials and unauthenticated access.
- Redis/Memcached/MongoDB: unauthenticated data exposure and weak credentials.
- RDP/VNC/Telnet: interactive-access, weak-credential, and cleartext concerns.
- LDAP/mail/SNMP/NTP: anonymous or weak authentication and information exposure.

Hints list **suggested NSE scripts**, but intrusive scripts are not run automatically.
This is intentional: scripts containing brute-force, exploit, flood, backdoor, or
dump/query behavior can lock accounts, crash services, or alter state. Review and run
them yourself only after authorization.

Disable hints with **--no-hints** if you only want the passive/protocol findings.

### Safe Nmap NSE execution

The optional NSE integration runs only a curated low-impact allowlist:

- HTTP: http-title, http-headers, http-methods, http-security-headers,
  http-cookie-flags, http-cors, ssl-cert
- SSH: ssh2-enum-algos, ssh-auth-methods
- FTP: ftp-anon, ftp-syst
- SMB: smb-security-mode, smb2-security-mode, smb-os-discovery, smb-protocols
- RDP: rdp-enum-encryption, rdp-ntlm-info
- MySQL/MSSQL: mysql-info, ms-sql-info
- Redis/Memcached/MongoDB: redis-info, memcached-info, mongodb-info
- VNC: vnc-info
- LDAP: ldap-rootdse
- DNS: dns-nsid
- Mail: smtp-commands, imap-capabilities, pop3-capabilities
- NTP: ntp-info

Run the automatic set:

    python3 portscope.py --nmap scan.xml --nse --json report.json

Run a specific safe subset:

    python3 portscope.py --nmap scan.xml --nse-scripts http-title,ssh-auth-methods

Nmap remains the executor, so the target must be reachable by Nmap as well. NSE port
rules depend on Nmap's own service identification; on unusual ports, Nmap may not run
a service-specific script even when PortScope has inferred the service. The generated
command is recorded in the report for auditability. PortScope refuses to auto-run a
script outside the low-impact allowlist, including **ssh-brute**, **mysql-brute**,
**ftp-vsftpd-backdoor**, and similar credential or exploit scripts.

### TLS certificate checks

When a TLS handshake succeeds, the report can include:

- subject, issuer, common names, DNS/IP SANs, serial number;
- not-before/not-after and expired/not-yet-valid status;
- self-signed heuristic;
- expected-hostname match;
- RSA/EC key type and key size when cryptography is available;
- SHA-256 fingerprint and signature hash; and
- the TLS protocol matrix with per-version support/error details.

A TLS version marked unsupported by the client is distinguished from one explicitly
refused by the server where the error text permits.

---

## Reading the report

By default PortScope prints a human-readable report. It can also write:

- **--json PATH**: full machine-readable schema, including evidence and attempts.
- **--markdown PATH**: shareable summary and per-port details.
- **--text PATH**: save the human-readable report instead of printing it.

Example:

    python3 portscope.py --nmap scan.xml --profile polite --text report.txt --json report.json --markdown report.md

The text summary shows port, Nmap state, live state, connect latency, inferred service,
and a one-line probe observation. The detail block lists Nmap service information,
attempt outcomes, probe output, protection signals, findings, notes, NSE results, and
vulnerability hints. JSON includes a top-level hints array and per-port hints/NSE data.
The Markdown report has a dedicated vulnerability-hints table.

### Severity

Findings are ranked **info**, **low**, **medium**, **high**, or **critical**. Examples:

- **high**: Redis answers unauthenticated PING; SMB1 is enabled; VNC offers None auth;
  SNMP default community is accepted; Docker API is exposed.
- **medium**: SMB signing is not required; PostgreSQL trust auth; legacy TLS accepted;
  expired certificate; TLS hostname mismatch; RDP falls back to Standard Security.
- **low**: cleartext HTTP/FTP/SMTP/IMAP/POP3; missing HTTP hardening headers; HSTS absent;
  self-signed certificate; cookie flags missing.
- **info**: server version disclosure, WAF/CDN fingerprint, authentication required,
  SSH algorithms modern, DNS recursion available.

The report is evidence, not a vulnerability verdict. A self-signed certificate on an
internal lab host is not the same risk as one on a public endpoint, and an open Redis
instance may be protected by a network ACL that PortScope cannot see. Vulnerability
hints are deliberately separate from findings: a service can be exposed and still be
fully patched, authenticated, and network-restricted. Treat a hint as a scoped test
idea, not proof.

---

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Scan completed |
| 2 | Invalid arguments or input file |
| 3 | No ports were diagnosed |
| 10 | **--fail-on** threshold reached |
| 130 | Interrupted |

For CI or a lab gate:

    python3 portscope.py --nmap scan.xml --fail-on high --quiet --json report.json

---

## Useful options

    --protocol tcp|udp|both     Transport to diagnose (default: tcp)
    --states LIST               Nmap states to include; default open,open|filtered,filtered,unfiltered
    --include-closed            Also probe Nmap-closed ports
    --include-down              Probe hosts marked down by Nmap
    --max-ports N               Safety cap; default 512, 0 means unlimited
    --service-map PORT=SERVICE  Override inference, optionally PROTO/PORT=SERVICE
    --sni HOSTNAME              SNI and expected certificate hostname
    --http-path PATH            Path for the HTTP GET (default: /)
    --snmp-community STRING     Required to send the read-only SNMP GET
    --http-fallback             Try one GET/OPTIONS on an unidentified service
    --nse                       Run the curated low-impact NSE script set
    --nse-scripts LIST          Run specific allowed low-impact scripts
    --nmap-bin PATH             Nmap executable for NSE (default: nmap)
    --nse-timeout SECONDS       Overall NSE timeout per host (default: 180)
    --script-timeout SECONDS    Per-script timeout (default: 30)
    --no-hints                  Disable candidate vulnerability hints
    --no-tls-version-probe      Skip the four-version TLS matrix
    --quiet                     No stdout report; files are still written
    --verbose                   Progress plus full evidence

Examples:

    # Check a protected high port carefully
    python3 portscope.py --target 10.0.0.5 --ports 8443 --profile slow --verbose --json slow.json

    # Lab scan with an explicit service hint
    python3 portscope.py --target 192.168.56.101 --ports 21,22,80,139,445,3306,5432,6379 --profile fast

    # Nmap XML plus UDP and SNMP
    python3 portscope.py --nmap scan.xml --protocol both --snmp-community public --json all.json

    # Filter a large Nmap scan to a few ports
    python3 portscope.py --nmap scan.xml --ports 22,443,445 --markdown focused.md

    # Add safe NSE evidence and candidate vulnerability hints
    python3 portscope.py --nmap scan.xml --nse --json report.json

    # Run only selected low-impact scripts
    python3 portscope.py --nmap scan.xml --nse-scripts smb-security-mode,ssh-auth-methods

---

## Safety and limitations

PortScope is intentionally read-only:

- HTTP: GET and OPTIONS only. No path brute force, upload, or exploit request.
- SSH: identification and KEXINIT only. No authentication or command execution.
- FTP: banner, FEAT, SYST, QUIT. No login or file access.
- Mail: EHLO/CAPABILITY and STARTTLS/STLS. No login, relay test, or message.
- Databases: handshake, SSLRequest, StartupMessage, PING, hello. No credentials,
  queries, or writes.
- SMB: NEGOTIATE only. No session setup, share access, or authentication.
- LDAP: anonymous bind only. No search or credential attempt.
- SNMP: one GET for sysDescr.0, and only when you provide a community string.
- VNC: version and security-type negotiation only. No password attempt.
- RDP: X.224 negotiation only. No login.
- NSE: only the curated low-impact allowlist. Brute-force, exploit, flood, backdoor,
  query, and dump scripts are never auto-run.

Limitations to keep in mind:

- Protocol inference is heuristic. A surprising result should be confirmed with the
  service owner and Nmap -sV/NSE.
- PortScope does not exploit CVEs and does not prove that a service is vulnerable.
- Vulnerability hints are candidates, not verdicts. An exposed SSH, SMB, or SQL port
  is not necessarily weak or unpatched.
- NSE results inherit Nmap's script behavior and false-positive rate. Confirm anything
  important independently.
- It does not implement IDS evasion, source spoofing, decoys, or fragmentation.
- A silent drop firewall cannot be "bypassed" by being polite; slow retries only help
  with rate-limit or burst-sensitive filters.
- TLS checks use the local OpenSSL policy. A client-side "no protocols available"
  error does not necessarily mean the server refused that version.
- Authentication is reported only where a harmless exchange reveals it. Many services
  are marked "not-tested" because testing would require credentials.
- Reports can contain internal hostnames, certificates, banners, and infrastructure
  details. Review before sharing.
- The **--max-ports** cap is a safety default, not a substitute for scoping.

---

## Development and tests

Run the standard-library test suite:

    python3 -m unittest discover -s tests -v

The tests bind only to 127.0.0.1 and cover the Nmap XML parser, HTTP/TLS diagnosis,
Redis, SSH KEXINIT parsing, SMB2 parsing, DNS parsing, vulnerability hints, the NSE
allowlist, and NSE result merging.

Compile check:

    python3 -m py_compile portscope.py

---

## Nmap references and attribution

PortScope is an independent implementation. Nmap and its NSE libraries were used as
protocol-layout references, especially:

- the Nmap XML output format / **nmap.dtd** for the input parser;
- **nmap-service-probes** concepts for service-aware follow-up;
- Nmap's **nselib/smb2.lua** and **nselib/smb.lua** for SMB2 NEGOTIATE and SMB1
  dialect negotiation field layouts;
- public protocol specifications and RFCs for HTTP, TLS, SSH, SMTP, IMAP, POP3, DNS,
  RDP, MySQL, PostgreSQL, Redis, MongoDB, VNC, Telnet, LDAP, NTP, and SNMP.

No Nmap source code is copied into PortScope. Nmap is distributed under the Nmap
Public Source License; consult the Nmap distribution for its exact terms.

---

## Legal and ethical use

Port scanning and service interrogation can be restricted by law, policy, or contract
even when the packets are harmless. Obtain written authorization, define the target
scope, choose a timing profile appropriate to the environment, and stop if you see
signs of instability. The authors are not responsible for unauthorized use.
