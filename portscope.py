#!/usr/bin/env python3
"""
PortScope -- protocol-aware post-Nmap port diagnostics.

PortScope is a read-only, defensive diagnostic helper for ports that Nmap has
already discovered.  It complements (rather than replaces) Nmap:

  * validates the TCP/UDP reachability of each selected port;
  * applies service-specific, low-impact protocol probes;
  * inspects transport protection (TLS versions, certificates, STARTTLS);
  * reports authentication posture, WAF/CDN hints, HTTP hardening, SMB signing,
    RDP NLA, SSH algorithm choices, and similar protection signals;
  * suggests likely vulnerability areas and relevant NSE scripts, without treating
    those suggestions as confirmed vulnerabilities;
  * optionally runs a curated low-impact Nmap NSE script set and merges the results;
    and
  * supports a deliberately slow, jittered profile for fragile services and
    rate-limit-based filters, plus a fast profile for isolated lab targets.

It never exploits a service, guesses passwords, writes application data, or
attempts to evade an IDS.  Intrusive NSE scripts are only suggested, never run
automatically.  Use it only on systems you own or are explicitly authorized to
test.

Requires Python 3.9+.  Optional: the "cryptography" package gives richer X.509
details; without it, PortScope falls back to CPython's built-in certificate
decoder.

Nmap's NSE SMB libraries and the Nmap XML DTD were used as protocol-layout
references during development.  No Nmap code is copied into this file.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as _dt
import hashlib
import ipaddress
import json
import os
import random
import re
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import warnings
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

try:  # optional, only used to enrich certificate output
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.asymmetric import (
        dsa as _dsa,
        ec as _ec,
        ed25519 as _ed25519,
        ed448 as _ed448,
        rsa as _rsa,
    )

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_CRYPTO = False

VERSION = "1.1.0"
SCHEMA_VERSION = "1.1"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

AUTHORIZATION_NOTICE = (
    "Use PortScope only against systems you own or have explicit permission to "
    "test. Probes are read-only and intentionally low impact."
)

LIMITATIONS = [
    "PortScope does not exploit vulnerabilities, guess credentials, or write data.",
    "It does not implement IDS evasion: no decoys, spoofing, fragmentation, or "
    "packet-timing manipulation beyond polite jitter and retries.",
    "Slow-profile retries can pass some rate-limit-based filters, but a silent "
    "drop firewall will still look filtered.",
    "Protocol inference is heuristic. Confirm surprising results with the service "
    "owner and with Nmap -sV/NSE.",
    "TLS version checks use the local OpenSSL policy; a version marked "
    "unsupported-by-client does not prove the server rejects it.",
    "Authentication is reported only where a harmless protocol exchange reveals "
    "it; no login or credential attempt is made.",
    "Vulnerability hints are candidate test areas, not confirmed vulnerabilities.",
    "NSE execution is restricted to a curated low-impact allowlist; brute-force, "
    "exploit, flood, and backdoor scripts are only recommended, never auto-run.",
]

DEFAULT_STATES = "open,open|filtered,filtered,unfiltered"
TLS_PORTS = {
    443,
    465,
    636,
    853,
    990,
    992,
    993,
    994,
    995,
    2376,
    5986,
    6443,
    8443,
    9443,
}

PORT_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    139: "smb",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtp",
    514: "syslog",
    587: "smtp",
    636: "ldap",
    853: "dns",
    990: "ftp",
    993: "imap",
    995: "pop3",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    6443: "kubernetes",
    8000: "http",
    8080: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9200: "elasticsearch",
    9443: "https",
    11211: "memcached",
    27017: "mongodb",
}

SERVICE_ALIASES = {
    "http-alt": "http",
    "http-proxy": "http",
    "https-alt": "https",
    "ssl/http": "https",
    "http/ssl": "https",
    "ms-wbt-server": "rdp",
    "rdp": "rdp",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "smb": "smb",
    "postgresql": "postgres",
    "ms-sql-s": "mssql",
    "ms-sql": "mssql",
    "oracle-tns": "oracle",
    "domain": "dns",
    "dns": "dns",
    "submission": "smtp",
    "smtps": "smtp",
    "imaps": "imap",
    "pop3s": "pop3",
    "ldaps": "ldap",
    "ftps": "ftp",
    "docker": "docker",
    "docker-tls": "docker",
    "elasticsearch": "elasticsearch",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "mongodb": "mongodb",
    "memcached": "memcached",
    "vnc": "vnc",
    "telnet": "telnet",
    "mysql": "mysql",
    "redis": "redis",
    "ntp": "ntp",
    "snmp": "snmp",
    "ssh": "ssh",
    "ftp": "ftp",
    "smtp": "smtp",
    "imap": "imap",
    "pop3": "pop3",
    "ldap": "ldap",
    "http": "http",
    "https": "https",
}

TLS_SERVICES = {"https", "imaps", "pop3s", "smtps", "ldaps", "ftps"}

# Only deliberately low-impact scripts are eligible for automatic execution.
# Brute-force, exploit, flood/DoS, and backdoor scripts are recommendations only;
# users must review and run those deliberately outside PortScope.
NSE_SAFE_BY_SERVICE: dict[str, list[str]] = {
    "http": [
        "http-title",
        "http-headers",
        "http-methods",
        "http-security-headers",
        "http-cookie-flags",
        "http-cors",
    ],
    "https": [
        "http-title",
        "http-headers",
        "http-methods",
        "http-security-headers",
        "http-cookie-flags",
        "http-cors",
        "ssl-cert",
    ],
    "docker": ["http-title", "http-headers"],
    "elasticsearch": ["http-title", "http-headers"],
    "kubernetes": ["http-title", "http-headers"],
    "ssh": ["ssh2-enum-algos", "ssh-auth-methods"],
    "ftp": ["ftp-anon", "ftp-syst"],
    "smtp": ["smtp-commands"],
    "imap": ["imap-capabilities"],
    "pop3": ["pop3-capabilities"],
    "dns": ["dns-nsid"],
    "rdp": ["rdp-enum-encryption", "rdp-ntlm-info"],
    "mysql": ["mysql-info"],
    "mssql": ["ms-sql-info"],
    "redis": ["redis-info"],
    "memcached": ["memcached-info"],
    "mongodb": ["mongodb-info"],
    "vnc": ["vnc-info"],
    "smb": [
        "smb-security-mode",
        "smb2-security-mode",
        "smb-os-discovery",
        "smb-protocols",
    ],
    "ldap": ["ldap-rootdse"],
    "ntp": ["ntp-info"],
}

SAFE_NSE_SCRIPTS: tuple[str, ...] = tuple(
    sorted({script for scripts in NSE_SAFE_BY_SERVICE.values() for script in scripts})
)

HINT_LIKELIHOOD_ORDER = {"likely": 0, "possible": 1, "test": 2}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"invalid severity: {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class VulnerabilityHint:
    category: str
    likelihood: str
    title: str
    rationale: str
    suggested_scripts: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.likelihood not in {"likely", "possible", "test"}:
            raise ValueError(f"invalid hint likelihood: {self.likelihood!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "likelihood": self.likelihood,
            "title": self.title,
            "rationale": self.rationale,
            "suggested_scripts": self.suggested_scripts,
            "references": self.references,
            "evidence": self.evidence,
        }


@dataclass
class ProbeResult:
    protocol: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    protections: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "summary": self.summary,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
            "protections": self.protections,
            "error": self.error,
        }


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    ostype: str = ""
    devicetype: str = ""
    scripts: dict[str, str] = field(default_factory=dict)
    cpes: list[str] = field(default_factory=list)

    @property
    def display_service(self) -> str:
        bits = [self.product, self.version, self.extrainfo]
        text = " ".join(b for b in bits if b)
        if text:
            return f"{self.service} ({text})" if self.service else text
        return self.service or "unknown"


@dataclass
class PortRecord:
    address: str
    port: int
    protocol: str
    nmap: Optional[NmapPort] = None
    hostname: Optional[str] = None
    live_state: str = "unknown"
    service_guess: str = "unknown"
    tls_initial: bool = False
    connect_ms: Optional[float] = None
    attempts: list[dict[str, Any]] = field(default_factory=list)
    probe: Optional[ProbeResult] = None
    findings: list[Finding] = field(default_factory=list)
    hints: list[VulnerabilityHint] = field(default_factory=list)
    nse: dict[str, str] = field(default_factory=dict)
    nse_error: Optional[str] = None
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_ms: Optional[float] = None

    @property
    def nmap_state(self) -> str:
        return self.nmap.state if self.nmap else "unknown"

    @property
    def nmap_reason(self) -> str:
        return self.nmap.reason if self.nmap else ""

    @property
    def label(self) -> str:
        return f"{self.port}/{self.protocol}"

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "label": self.label,
            "nmap": dataclasses.asdict(self.nmap) if self.nmap else None,
            "nmap_state": self.nmap_state,
            "nmap_reason": self.nmap_reason,
            "live_state": self.live_state,
            "service_guess": self.service_guess,
            "tls_initial": self.tls_initial,
            "connect_ms": round(self.connect_ms, 2) if self.connect_ms is not None else None,
            "attempts": self.attempts,
            "probe": self.probe.to_dict() if self.probe else None,
            "findings": [f.to_dict() for f in self.findings],
            "hints": [h.to_dict() for h in self.hints],
            "nse": self.nse,
            "nse_error": self.nse_error,
            "notes": self.notes,
            "error": self.error,
            "elapsed_ms": round(self.elapsed_ms, 2) if self.elapsed_ms is not None else None,
        }


@dataclass
class HostRecord:
    address: str
    hostname: Optional[str] = None
    status: str = "up"
    os_matches: list[dict[str, Any]] = field(default_factory=list)
    extraports: list[dict[str, Any]] = field(default_factory=list)
    ports: list[PortRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    nse_command: str = ""
    nse_error: Optional[str] = None
    nse_elapsed_ms: Optional[float] = None
    nse_host: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "hostname": self.hostname,
            "status": self.status,
            "os_matches": self.os_matches,
            "extraports": self.extraports,
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
            "nse_command": self.nse_command,
            "nse_error": self.nse_error,
            "nse_elapsed_ms": (
                round(self.nse_elapsed_ms, 2) if self.nse_elapsed_ms is not None else None
            ),
            "nse_host": self.nse_host,
            "ports": [p.to_dict() for p in self.ports],
        }


@dataclass(frozen=True)
class Profile:
    name: str
    connect_timeout: float
    read_timeout: float
    attempts: int
    delay_min: float
    delay_max: float
    workers: int
    description: str


PROFILES = {
    "fast": Profile(
        "fast",
        1.0,
        1.5,
        1,
        0.0,
        0.0,
        16,
        "Lab speed: short timeouts, no spacing, 16 workers.",
    ),
    "polite": Profile(
        "polite",
        2.5,
        3.0,
        2,
        0.35,
        0.9,
        6,
        "Default: modest spacing and one retry.",
    ),
    "slow": Profile(
        "slow",
        5.0,
        6.0,
        3,
        2.5,
        5.0,
        2,
        "Fragile/rate-limited targets: long timeouts, 2.5-5s spacing, 3 tries.",
    ),
}


@dataclass
class Config:
    profile: Profile
    connect_timeout: float
    read_timeout: float
    attempts: int
    delay_min: float
    delay_max: float
    workers: int
    max_ports: int
    states: set[str]
    states_explicit: bool
    include_down: bool
    protocol: str
    service_overrides: dict[tuple[str, int], str]
    sni: Optional[str]
    http_path: str
    user_agent: str
    max_body: int
    tls_matrix: bool
    snmp_community: Optional[str]
    http_fallback: bool
    run_nse: bool
    nse_scripts: list[str]
    nmap_bin: str
    nse_timeout: float
    script_timeout: float
    show_hints: bool
    verbose: bool
    quiet: bool
    fail_on: str


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def short_exc(exc: BaseException) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    return text[:500]


def human_ms(value: Optional[float]) -> str:
    if value is None:
        return "-"
    if value < 1:
        return f"{value * 1000:.0f} us"
    if value < 1000:
        return f"{value:.1f} ms"
    return f"{value / 1000:.2f} s"


def truncate(value: Any, limit: int = 200) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def safe_decode(data: bytes, limit: int = 4096) -> str:
    if not data:
        return ""
    chunk = data[:limit]
    for encoding in ("utf-8", "latin-1"):
        try:
            return chunk.decode(encoding)
        except UnicodeDecodeError:
            continue
    return chunk.decode("utf-8", "replace")


def printable_preview(data: bytes, limit: int = 300) -> str:
    text = safe_decode(data, limit * 2)
    cleaned = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "." for ch in text)
    return truncate(cleaned.replace("\r", ""), limit)


def hex_preview(data: bytes, limit: int = 128) -> str:
    return data[:limit].hex(" ")


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    if not spec:
        raise ValueError("empty port list")
    for raw in spec.split(","):
        part = raw.strip()
        if not part:
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            start = int(left.strip(), 10)
            end = int(right.strip(), 10)
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise ValueError(f"port out of range: {part}")
            # Keep deliberate ranges bounded; a typo such as 1-65535 is still legal.
            ports.update(range(start, end + 1))
        else:
            value = int(part, 10)
            if value < 1 or value > 65535:
                raise ValueError(f"port out of range: {part}")
            ports.add(value)
    if not ports:
        raise ValueError("no ports parsed")
    return sorted(ports)


def parse_states(spec: str) -> set[str]:
    allowed = {
        "open",
        "closed",
        "filtered",
        "unfiltered",
        "open|filtered",
        "closed|filtered",
        "unknown",
        "all",
    }
    result: set[str] = set()
    for item in spec.split(","):
        value = item.strip().lower()
        if not value:
            continue
        if value not in allowed:
            raise ValueError(f"unknown Nmap state: {value}")
        if value == "all":
            result.update(allowed - {"all"})
        else:
            result.add(value)
    return result


def parse_service_overrides(items: Iterable[str]) -> dict[tuple[str, int], str]:
    overrides: dict[tuple[str, int], str] = {}
    for item in items:
        text = item.strip()
        if not text:
            continue
        left, sep, value = text.partition("=")
        if not sep or not value.strip():
            raise ValueError(f"service override must be PORT=SERVICE or PROTO/PORT=SERVICE: {item}")
        proto = "tcp"
        port_text = left.strip()
        if "/" in port_text:
            proto, port_text = port_text.split("/", 1)
            proto = proto.strip().lower()
        if proto not in {"tcp", "udp"}:
            raise ValueError(f"invalid protocol in service override: {item}")
        try:
            port = int(port_text.strip(), 10)
        except ValueError as exc:
            raise ValueError(f"invalid port in service override: {item}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range in service override: {item}")
        overrides[(proto, port)] = value.strip().lower()
    return overrides


def normalize_service_name(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return "unknown"
    if text.startswith("ssl/"):
        text = text[4:]
    if text.startswith("https"):
        return "https"
    return SERVICE_ALIASES.get(text, text)


def infer_service(nmap_port: Optional[NmapPort], override: Optional[str] = None) -> str:
    if override:
        return normalize_service_name(override)
    if nmap_port:
        if nmap_port.tunnel == "ssl" and nmap_port.service in {"http", "http-alt"}:
            return "https"
        service = normalize_service_name(nmap_port.service)
        if service and service != "unknown":
            return service
        haystack = " ".join(
            [nmap_port.product or "", nmap_port.version or "", nmap_port.extrainfo or ""]
        ).lower()
        for needle, guess in (
            ("openssh", "ssh"),
            ("dropbear", "ssh"),
            ("apache", "http"),
            ("nginx", "http"),
            ("lighttpd", "http"),
            ("microsoft-iis", "http"),
            ("samba", "smb"),
            ("microsoft windows", "smb"),
            ("terminal services", "rdp"),
            ("mariadb", "mysql"),
            ("mysql", "mysql"),
            ("postgres", "postgres"),
            ("redis", "redis"),
            ("memcached", "memcached"),
            ("mongodb", "mongodb"),
            ("vsftpd", "ftp"),
            ("proftpd", "ftp"),
            ("pure-ftpd", "ftp"),
            ("exim", "smtp"),
            ("postfix", "smtp"),
            ("sendmail", "smtp"),
            ("dovecot", "imap"),
            ("docker", "docker"),
            ("vnc", "vnc"),
            ("openldap", "ldap"),
        ):
            if needle in haystack:
                return guess
        hint = PORT_HINTS.get(nmap_port.port)
        if hint:
            return hint
    return "unknown"


def infer_tls_initial(nmap_port: Optional[NmapPort], service: str, port: int) -> bool:
    if nmap_port and nmap_port.tunnel == "ssl":
        return True
    raw_service = (nmap_port.service or "").lower() if nmap_port else ""
    if raw_service in {"https", "imaps", "pop3s", "smtps", "ldaps", "ftps", "docker-tls"}:
        return True
    if raw_service.startswith("ssl/"):
        return True
    if service in TLS_SERVICES:
        return True
    if "ssl" in raw_service:
        return True
    return port in TLS_PORTS


def merge_findings(existing: list[Finding], incoming: Iterable[Finding]) -> list[Finding]:
    seen = {(f.code, f.title, f.detail) for f in existing}
    for finding in incoming:
        key = (finding.code, finding.title, finding.detail)
        if key not in seen:
            existing.append(finding)
            seen.add(key)
    return existing


def sev_at_least(value: str, threshold: str) -> bool:
    if threshold == "none":
        return False
    return SEVERITY_ORDER.get(value, -1) >= SEVERITY_ORDER.get(threshold, 99)


# ---------------------------------------------------------------------------
# Nmap XML input
# ---------------------------------------------------------------------------


def _text(element: Optional[ET.Element], default: str = "") -> str:
    return (element.text or default) if element is not None else default


def parse_nmap_xml(path: str) -> list[HostRecord]:
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"cannot read Nmap XML {path!r}: {short_exc(exc)}") from exc

    root = tree.getroot()
    if root.tag != "nmaprun":
        raise ValueError(f"{path!r} does not look like Nmap XML (root tag {root.tag!r})")

    hosts: list[HostRecord] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = (status_el.get("state") if status_el is not None else "unknown") or "unknown"

        address = ""
        addresses: list[tuple[str, str]] = []
        for addr in host_el.findall("address"):
            value = addr.get("addr") or ""
            kind = (addr.get("addrtype") or "").lower()
            if value:
                addresses.append((kind, value))
        for kind in ("ipv4", "ipv6", "ipv4-mapped", "mac"):
            for k, value in addresses:
                if k == kind:
                    address = value
                    break
            if address:
                break
        if not address and addresses:
            address = addresses[0][1]
        if not address:
            continue

        hostnames = []
        for hostname_el in host_el.findall("./hostnames/hostname"):
            name = (hostname_el.get("name") or "").strip()
            if name:
                hostnames.append(name)
        hostname = hostnames[0] if hostnames else None

        os_matches = []
        for osmatch in host_el.findall("./os/osmatch"):
            os_matches.append(
                {
                    "name": osmatch.get("name") or "",
                    "accuracy": int(osmatch.get("accuracy") or 0),
                    "line": _text(osmatch.find("osclass")),
                }
            )

        ports: list[NmapPort] = []
        for port_el in host_el.findall("./ports/port"):
            try:
                port_num = int(port_el.get("portid") or 0)
            except ValueError:
                continue
            if not 1 <= port_num <= 65535:
                continue
            proto = (port_el.get("protocol") or "tcp").lower()
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            scripts: dict[str, str] = {}
            for script_el in port_el.findall("script"):
                sid = script_el.get("id") or ""
                output = script_el.get("output") or _text(script_el)
                if sid:
                    scripts[sid] = output[:4096]
            cpes = []
            if service_el is not None:
                for cpe in service_el.findall("cpe"):
                    if cpe.text:
                        cpes.append(cpe.text.strip())
            service = service_el.get("name") if service_el is not None else ""
            ports.append(
                NmapPort(
                    port=port_num,
                    protocol=proto,
                    state=(state_el.get("state") if state_el is not None else "unknown") or "unknown",
                    reason=(state_el.get("reason") if state_el is not None else "") or "",
                    service=service or "",
                    product=(service_el.get("product") if service_el is not None else "") or "",
                    version=(service_el.get("version") if service_el is not None else "") or "",
                    extrainfo=(service_el.get("extrainfo") if service_el is not None else "") or "",
                    tunnel=(service_el.get("tunnel") if service_el is not None else "") or "",
                    ostype=(service_el.get("ostype") if service_el is not None else "") or "",
                    devicetype=(service_el.get("devicetype") if service_el is not None else "") or "",
                    scripts=scripts,
                    cpes=cpes,
                )
            )

        host_scripts: dict[str, str] = {}
        for script_el in host_el.findall("./hostscript/script"):
            sid = script_el.get("id") or ""
            output = script_el.get("output") or _text(script_el)
            if sid:
                host_scripts[sid] = output[:4096]

        extraports = []
        for extra in host_el.findall("./ports/extraports"):
            extraports.append(
                {
                    "state": extra.get("state") or "",
                    "count": int(extra.get("count") or 0),
                    "reason": _text(extra.find("extrareasons")),
                }
            )

        hosts.append(
            HostRecord(
                address=address,
                hostname=hostname,
                status=status,
                os_matches=os_matches,
                extraports=extraports,
                ports=ports,
                nse_host=host_scripts,
            )
        )

    if not hosts:
        raise ValueError(f"no hosts found in Nmap XML {path!r}")
    return hosts


# ---------------------------------------------------------------------------
# Networking primitives and pacing
# ---------------------------------------------------------------------------


class Pacer:
    """Global minimum spacing between connection attempts.

    The lock intentionally covers the sleep: the slow profile is meant to be
    genuinely gentle, even when the worker pool has several tasks.
    """

    def __init__(self, delay_min: float, delay_max: float) -> None:
        self.delay_min = max(0.0, float(delay_min))
        self.delay_max = max(self.delay_min, float(delay_max))
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.delay_max <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if self._next > now:
                time.sleep(self._next - now)
            delay = random.uniform(self.delay_min, self.delay_max)
            self._next = time.monotonic() + delay


def is_ip_literal(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def open_tcp(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    return sock


def _tls_sni(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None
    if is_ip_literal(hostname):
        return None
    return hostname.rstrip(".")


def wrap_tls(
    raw: socket.socket,
    server_hostname: Optional[str],
    timeout: float,
    version: Optional[ssl.TLSVersion] = None,
    alpn: Optional[list[str]] = None,
) -> tuple[ssl.SSLSocket, ssl.SSLContext]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.options |= ssl.OP_NO_COMPRESSION
    except AttributeError:
        pass
    if alpn:
        try:
            context.set_alpn_protocols(alpn)
        except NotImplementedError:
            pass
    if version is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            try:
                context.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
    else:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = ssl.TLSVersion.TLSv1
        except (AttributeError, ValueError):
            pass
    raw.settimeout(timeout)
    sni = _tls_sni(server_hostname)
    ssock = context.wrap_socket(raw, server_hostname=sni)
    ssock.settimeout(timeout)
    return ssock, context


def tls_metadata(ssock: ssl.SSLSocket, expected_host: Optional[str]) -> dict[str, Any]:
    info: dict[str, Any] = {
        "version": ssock.version(),
        "cipher": ssock.cipher()[0] if ssock.cipher() else None,
        "cipher_bits": ssock.cipher()[2] if ssock.cipher() and len(ssock.cipher()) > 2 else None,
        "alpn": ssock.selected_alpn_protocol(),
        "server_hostname": expected_host,
        "session_reused": ssock.session_reused,
    }
    der = ssock.getpeercert(binary_form=True)
    if der:
        info["certificate"] = parse_certificate(der, expected_host)
        info["certificate_sha256"] = hashlib.sha256(der).hexdigest()
    else:
        info["certificate"] = None
    return info


def _name_to_str(name: Any) -> str:
    if not name:
        return ""
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _cert_dt(value: Any) -> Optional[_dt.datetime]:
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=_dt.timezone.utc)
        return value.astimezone(_dt.timezone.utc)
    return None


def _idna(value: str) -> str:
    try:
        return value.rstrip(".").encode("idna").decode("ascii").lower()
    except Exception:
        return value.rstrip(".").lower()


def hostname_matches(pattern: str, hostname: str) -> bool:
    host = _idna(hostname)
    pat = _idna(pattern)
    if not pat or not host:
        return False
    if pat == host:
        return True
    if pat.startswith("*."):
        suffix = pat[2:]
        if not suffix:
            return False
        head, sep, tail = host.partition(".")
        return bool(sep and tail == suffix and head)
    return False


def cert_hostname_match(cert: dict[str, Any], expected_host: Optional[str]) -> Optional[bool]:
    if not expected_host:
        return None
    sans_dns = [x for x in cert.get("san_dns", []) if x]
    sans_ip = [x for x in cert.get("san_ip", []) if x]
    try:
        ip = ipaddress.ip_address(expected_host)
    except ValueError:
        ip = None
    if ip is not None:
        for candidate in sans_ip:
            try:
                if ipaddress.ip_address(candidate) == ip:
                    return True
            except ValueError:
                continue
        return False if (sans_ip or sans_dns) else None
    for candidate in sans_dns:
        if hostname_matches(candidate, expected_host):
            return True
    for candidate in cert.get("cn", []):
        if hostname_matches(candidate, expected_host):
            return True
    return False if (sans_dns or cert.get("cn")) else None


def parse_certificate(der: bytes, expected_host: Optional[str]) -> dict[str, Any]:
    cert: dict[str, Any] = {
        "sha256": hashlib.sha256(der).hexdigest(),
        "subject": "",
        "issuer": "",
        "cn": [],
        "san_dns": [],
        "san_ip": [],
        "not_before": None,
        "not_after": None,
        "expired": None,
        "not_yet_valid": None,
        "self_signed": None,
        "key_type": None,
        "key_size": None,
        "signature_hash": None,
        "serial": None,
        "decode": "cryptography" if _HAVE_CRYPTO else "stdlib",
    }

    if _HAVE_CRYPTO:
        try:
            xcert = _x509.load_der_x509_certificate(der)
            cert["subject"] = _name_to_str(xcert.subject)
            cert["issuer"] = _name_to_str(xcert.issuer)
            cert["serial"] = format(xcert.serial_number, "x")
            for attr in xcert.subject.get_attributes_for_oid(_x509.oid.NameOID.COMMON_NAME):
                if attr.value:
                    cert["cn"].append(str(attr.value))
            try:
                san = xcert.extensions.get_extension_for_class(_x509.SubjectAlternativeName).value
                cert["san_dns"] = list(san.get_values_for_type(_x509.DNSName))
                cert["san_ip"] = [str(x) for x in san.get_values_for_type(_x509.IPAddress)]
            except _x509.ExtensionNotFound:
                pass
            not_before = getattr(xcert, "not_valid_before_utc", None)
            not_after = getattr(xcert, "not_valid_after_utc", None)
            if not_before is None:
                not_before = xcert.not_valid_before.replace(tzinfo=_dt.timezone.utc)
            if not_after is None:
                not_after = xcert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
            cert["not_before"] = not_before.isoformat()
            cert["not_after"] = not_after.isoformat()
            now = _dt.datetime.now(_dt.timezone.utc)
            cert["expired"] = not_after < now
            cert["not_yet_valid"] = not_before > now
            cert["self_signed"] = xcert.issuer == xcert.subject
            try:
                cert["signature_hash"] = xcert.signature_hash_algorithm.name.lower()
            except Exception:
                pass
            public_key = xcert.public_key()
            if isinstance(public_key, _rsa.RSAPublicKey):
                cert["key_type"] = "RSA"
                cert["key_size"] = public_key.key_size
            elif isinstance(public_key, _ec.EllipticCurvePublicKey):
                cert["key_type"] = "EC"
                cert["key_size"] = public_key.key_size
                cert["curve"] = public_key.curve.name
            elif isinstance(public_key, _dsa.DSAPublicKey):
                cert["key_type"] = "DSA"
                cert["key_size"] = public_key.key_size
            elif isinstance(public_key, _ed25519.Ed25519PublicKey):
                cert["key_type"] = "Ed25519"
            elif isinstance(public_key, _ed448.Ed448PublicKey):
                cert["key_type"] = "Ed448"
        except Exception as exc:
            cert["decode_error"] = short_exc(exc)
    else:
        # CPython's private-but-stable decoder is adequate for the common fields.
        try:
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as handle:
                handle.write(pem)
                handle.flush()
                decoded = ssl._ssl._test_decode_cert(handle.name)  # type: ignore[attr-defined]
            subject = decoded.get("subject", ())
            issuer = decoded.get("issuer", ())
            cert["subject"] = ", ".join(f"{k}={v}" for group in subject for k, v in group)
            cert["issuer"] = ", ".join(f"{k}={v}" for group in issuer for k, v in group)
            for group in subject:
                for key, value in group:
                    if key == "commonName":
                        cert["cn"].append(value)
            san = decoded.get("subjectAltName", ())
            for kind, value in san:
                if kind == "DNS":
                    cert["san_dns"].append(value)
                elif kind == "IP Address":
                    cert["san_ip"].append(value)
            cert["serial"] = decoded.get("serialNumber")
            not_before = _dt.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(decoded["notBefore"]), _dt.timezone.utc
            )
            not_after = _dt.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(decoded["notAfter"]), _dt.timezone.utc
            )
            cert["not_before"] = not_before.isoformat()
            cert["not_after"] = not_after.isoformat()
            now = _dt.datetime.now(_dt.timezone.utc)
            cert["expired"] = not_after < now
            cert["not_yet_valid"] = not_before > now
            cert["self_signed"] = subject == issuer
        except Exception as exc:
            cert["decode_error"] = short_exc(exc)

    match = cert_hostname_match(cert, expected_host)
    cert["hostname_match"] = match
    return cert


def tls_findings(info: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    cert = info.get("certificate") or {}
    if cert.get("expired"):
        findings.append(
            Finding(
                "medium",
                "TLS_CERT_EXPIRED",
                "TLS certificate has expired",
                f"Certificate expired at {cert.get('not_after')}.",
                {"not_after": cert.get("not_after")},
            )
        )
    if cert.get("not_yet_valid"):
        findings.append(
            Finding(
                "medium",
                "TLS_CERT_NOT_YET_VALID",
                "TLS certificate is not yet valid",
                f"Certificate becomes valid at {cert.get('not_before')}.",
                {"not_before": cert.get("not_before")},
            )
        )
    if cert.get("self_signed"):
        findings.append(
            Finding(
                "low",
                "TLS_SELF_SIGNED",
                "TLS certificate is self-signed",
                "The leaf certificate issuer and subject are identical.",
                {"subject": cert.get("subject")},
            )
        )
    if cert.get("hostname_match") is False:
        findings.append(
            Finding(
                "medium",
                "TLS_HOSTNAME_MISMATCH",
                "TLS certificate does not match the expected host",
                "No subjectAltName/CN entry matched the target hostname.",
                {
                    "expected": info.get("server_hostname"),
                    "san_dns": cert.get("san_dns"),
                    "san_ip": cert.get("san_ip"),
                },
            )
        )
    if cert.get("key_type") == "RSA" and isinstance(cert.get("key_size"), int) and cert["key_size"] < 2048:
        findings.append(
            Finding(
                "medium",
                "TLS_WEAK_KEY",
                "TLS certificate uses a small RSA key",
                f"RSA key is {cert['key_size']} bits; 2048+ is expected.",
                {"key_size": cert["key_size"]},
            )
        )
    if cert.get("signature_hash") in {"md5", "sha1"}:
        findings.append(
            Finding(
                "medium",
                "TLS_LEGACY_SIGNATURE",
                "TLS certificate uses a legacy signature hash",
                f"Certificate signature hash: {cert['signature_hash']}.",
                {"signature_hash": cert["signature_hash"]},
            )
        )

    versions = info.get("versions") or {}
    for label, result in versions.items():
        if not isinstance(result, dict) or not result.get("supported"):
            continue
        if result.get("client_unsupported"):
            continue
        if label in {"TLSv1.0", "TLSv1.1"}:
            findings.append(
                Finding(
                    "medium",
                    "TLS_LEGACY_PROTOCOL",
                    "Legacy TLS protocol is accepted",
                    f"The server completed a {label} handshake.",
                    {"version": label, "cipher": result.get("cipher")},
                )
            )
    cipher = (info.get("cipher") or "").upper()
    if any(token in cipher for token in ("RC4", "3DES", "DES-CBC3", "NULL", "EXPORT", "ANON")):
        findings.append(
            Finding(
                "medium",
                "TLS_WEAK_CIPHER",
                "Weak TLS cipher suite negotiated",
                f"Negotiated cipher: {info.get('cipher')}.",
                {"cipher": info.get("cipher")},
            )
        )
    return findings


def probe_tls_versions(ctx: "ProbeContext") -> dict[str, Any]:
    results: dict[str, Any] = {}
    candidates = [
        ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    for label, version in candidates:
        if version is None:
            continue
        ssock = None
        try:
            ssock, _ = ctx.open_tls(version=version, alpn=["http/1.1"])
            results[label] = {
                "supported": True,
                "negotiated": ssock.version(),
                "cipher": ssock.cipher()[0] if ssock.cipher() else None,
            }
            ssock.close()
        except (ssl.SSLError, OSError, ValueError) as exc:
            message = short_exc(exc)
            client_unsupported = any(
                token in message.upper()
                for token in (
                    "NO PROTOCOLS AVAILABLE",
                    "NO_CIPHERS_AVAILABLE",
                    "UNSUPPORTED_PROTOCOL",
                    "WRONG_SSL_VERSION",
                    "NO CIPHERS AVAILABLE",
                )
            )
            results[label] = {
                "supported": False,
                "error": message,
                "client_unsupported": client_unsupported,
            }
        except Exception as exc:  # defensive: protocol stacks vary
            results[label] = {"supported": False, "error": short_exc(exc)}
        finally:
            if ssock is not None:
                try:
                    ssock.close()
                except OSError:
                    pass
    return results


@dataclass
class ProbeContext:
    host: str
    port: int
    protocol: str
    connect_timeout: float
    read_timeout: float
    pacer: Pacer
    sni: Optional[str]
    max_body: int
    user_agent: str
    http_path: str
    tls_matrix: bool
    snmp_community: Optional[str]
    hostname: Optional[str] = None

    @property
    def tls_hostname(self) -> Optional[str]:
        return self.sni or self.hostname or (None if is_ip_literal(self.host) else self.host)

    def open_tcp(self) -> socket.socket:
        self.pacer.wait()
        return open_tcp(self.host, self.port, self.connect_timeout)

    def open_tls(
        self,
        version: Optional[ssl.TLSVersion] = None,
        alpn: Optional[list[str]] = None,
    ) -> tuple[ssl.SSLSocket, ssl.SSLContext]:
        raw = self.open_tcp()
        try:
            return wrap_tls(
                raw,
                self.tls_hostname,
                self.read_timeout,
                version=version,
                alpn=alpn,
            )
        except Exception:
            try:
                raw.close()
            except OSError:
                pass
            raise

    def udp_exchange(self, payload: bytes, timeout: Optional[float] = None) -> bytes:
        self.pacer.wait()
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout or self.read_timeout)
            sock.connect((self.host, self.port))
            sock.send(payload)
            data, _ = sock.recvfrom(65535)
            return data
        finally:
            sock.close()


class LineReader:
    """Buffered reader with per-call deadlines over a (possibly TLS) socket."""

    def __init__(self, sock: socket.socket, default_timeout: float) -> None:
        self.sock = sock
        self.default_timeout = default_timeout
        self.buf = b""

    def _fill(self, n: int = 4096, timeout: Optional[float] = None) -> bool:
        wait = self.default_timeout if timeout is None else timeout
        if wait <= 0:
            raise socket.timeout("deadline exceeded")
        self.sock.settimeout(wait)
        chunk = self.sock.recv(n)
        if not chunk:
            return False
        self.buf += chunk
        return True

    def readline(self, max_bytes: int = 8192, timeout: Optional[float] = None) -> bytes:
        end = time.monotonic() + (self.default_timeout if timeout is None else timeout)
        while b"\n" not in self.buf:
            if len(self.buf) > max_bytes:
                line = self.buf[:max_bytes]
                self.buf = self.buf[max_bytes:]
                return line
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            try:
                if not self._fill(4096, min(remaining, self.default_timeout)):
                    break
            except socket.timeout:
                break
        if b"\n" in self.buf:
            line, _, self.buf = self.buf.partition(b"\n")
            return line + b"\n"
        line = self.buf
        self.buf = b""
        return line

    def read_exact(self, n: int, timeout: Optional[float] = None) -> bytes:
        end = time.monotonic() + (self.default_timeout if timeout is None else timeout)
        while len(self.buf) < n:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("timed out reading exact bytes")
            if not self._fill(4096, min(remaining, self.default_timeout)):
                raise EOFError("peer closed connection")
        data = self.buf[:n]
        self.buf = self.buf[n:]
        return data

    def read_until(
        self,
        marker: bytes,
        max_bytes: int = 65536,
        timeout: Optional[float] = None,
    ) -> bytes:
        end = time.monotonic() + (self.default_timeout if timeout is None else timeout)
        while marker not in self.buf:
            if len(self.buf) > max_bytes:
                raise ValueError("response exceeded maximum size")
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            try:
                if not self._fill(4096, min(remaining, self.default_timeout)):
                    break
            except socket.timeout:
                break
        if marker in self.buf:
            index = self.buf.index(marker) + len(marker)
            data = self.buf[:index]
            self.buf = self.buf[index:]
            return data
        data = self.buf[:max_bytes]
        self.buf = self.buf[max_bytes:]
        return data

    def read_some(
        self,
        max_bytes: int = 4096,
        timeout: Optional[float] = None,
        idle: float = 0.25,
    ) -> bytes:
        end = time.monotonic() + (self.default_timeout if timeout is None else timeout)
        started = bool(self.buf)
        while len(self.buf) < max_bytes:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            wait = idle if started else min(remaining, self.default_timeout)
            try:
                if not self._fill(min(4096, max_bytes - len(self.buf)), min(wait, remaining)):
                    break
            except socket.timeout:
                break
            started = True
        data = self.buf[:max_bytes]
        self.buf = self.buf[max_bytes:]
        return data

    def drain(self) -> bytes:
        data = self.buf
        self.buf = b""
        return data


# ---------------------------------------------------------------------------
# HTTP helpers and generic probes
# ---------------------------------------------------------------------------


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
}


@dataclass
class HttpResult:
    status_line: str = ""
    status_code: Optional[int] = None
    reason: str = ""
    header_items: list[tuple[str, str]] = field(default_factory=list)
    headers: dict[str, list[str]] = field(default_factory=dict)
    body: bytes = b""
    body_text: str = ""
    title: str = ""
    json_body: Any = None
    truncated: bool = False
    raw_preview: str = ""

    def header(self, name: str, default: str = "") -> str:
        values = self.headers.get(name.lower())
        return values[0] if values else default

    def header_all(self, name: str) -> list[str]:
        return list(self.headers.get(name.lower(), []))


def sanitize_headers(items: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    clean: list[dict[str, str]] = []
    for name, value in items:
        lower = name.lower()
        if lower == "set-cookie":
            cookie_name = value.split("=", 1)[0].strip()
            flags = []
            for flag in ("secure", "httponly", "samesite=lax", "samesite=strict", "samesite=none"):
                if flag in value.lower():
                    flags.append(flag)
            value = f"{cookie_name}=<redacted>" + (f"; {'; '.join(flags)}" if flags else "")
        elif lower in {"authorization", "proxy-authorization", "x-api-key"}:
            value = "<redacted>"
        clean.append({"name": name, "value": truncate(value, 500)})
    return clean[:60]


def parse_set_cookies(items: Iterable[tuple[str, str]]) -> list[dict[str, Any]]:
    cookies = []
    for name, value in items:
        if name.lower() != "set-cookie":
            continue
        first, *attrs = value.split(";")
        cookie_name = first.split("=", 1)[0].strip()
        lower = value.lower()
        samesite = None
        for attr in attrs:
            key, _, val = attr.strip().partition("=")
            if key.lower() == "samesite":
                samesite = val.strip() or None
        cookies.append(
            {
                "name": cookie_name,
                "secure": "secure" in lower,
                "httponly": "httponly" in lower,
                "samesite": samesite,
            }
        )
    return cookies


def detect_waf(
    headers: dict[str, list[str]],
    body_text: str,
    cookie_names: Iterable[str],
) -> list[dict[str, str]]:
    lower_headers = {k.lower(): " ".join(v).lower() for k, v in headers.items()}
    cookies = {c.lower() for c in cookie_names}
    body_lower = body_text[:20000].lower()
    detections: list[dict[str, str]] = []

    def add(vendor: str, evidence: str, category: str = "WAF") -> None:
        if not any(d["vendor"] == vendor for d in detections):
            detections.append({"vendor": vendor, "evidence": evidence, "category": category})

    if "cf-ray" in lower_headers or "cloudflare" in lower_headers.get("server", ""):
        add("Cloudflare", "cf-ray/Server header", "CDN/WAF")
    if any(k in lower_headers for k in ("akamai-grn", "x-akamai-transformed", "akamai-origin-hop")):
        add("Akamai", "Akamai header set", "CDN/WAF")
    if "x-iinfo" in lower_headers or {"visid_incap", "incap_ses"} & cookies:
        add("Imperva", "x-iinfo/Incapsula cookie", "WAF")
    if "x-sucuri-id" in lower_headers or "x-sucuri-cache" in lower_headers:
        add("Sucuri", "Sucuri header", "WAF/CDN")
    if any(k in lower_headers for k in ("x-wa-info", "x-f5-request-id")) or any(
        c.startswith(("ts01", "bigipserver")) for c in cookies
    ):
        add("F5 BIG-IP", "F5 header/cookie", "ADC/WAF")
    if "x-azure-ref" in lower_headers or "x-fd-int-roxy-purgeid" in lower_headers:
        add("Azure Front Door", "Azure Front Door header", "CDN/WAF")
    if "x-amz-cf-id" in lower_headers:
        add("Amazon CloudFront", "x-amz-cf-id", "CDN")
    if "x-amzn-requestid" in lower_headers and "x-amzn-errortype" in lower_headers:
        add("AWS API Gateway", "AWS API Gateway headers", "API gateway")
    if "barra_counter_session" in cookies:
        add("Barracuda", "Barracuda cookie", "WAF")
    if "fortiwafsid" in cookies:
        add("Fortinet FortiWeb", "FortiWeb cookie", "WAF")
    if "mod_security" in body_lower or "modsecurity" in body_lower or "naxsi" in body_lower:
        add("ModSecurity/NAXSI", "block page signature", "WAF")
    if "request rejected" in body_lower and "support id" in body_lower:
        add("F5 BIG-IP", "F5 block page signature", "WAF")
    return detections


def parse_http_response(raw: bytes, body: bytes, truncated: bool = False) -> HttpResult:
    result = HttpResult(body=body, truncated=truncated)
    if not raw:
        return result
    separator = b"\r\n\r\n"
    if separator in raw:
        head, _, inline_body = raw.partition(separator)
    elif b"\n\n" in raw:
        head, _, inline_body = raw.partition(b"\n\n")
        separator = b"\n\n"
    else:
        head, inline_body = raw, b""
    if inline_body and not body:
        body = inline_body
        result.body = body
    text = head.decode("iso-8859-1", "replace")
    lines = text.splitlines()
    if not lines or not lines[0].upper().startswith("HTTP/"):
        result.raw_preview = printable_preview(raw, 500)
        return result
    result.status_line = lines[0].strip()
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)", result.status_line)
    if match:
        result.status_code = int(match.group(1))
        result.reason = match.group(2).strip()
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in (" ", "\t"):
            continue
        name, sep, value = line.partition(":")
        if not sep:
            continue
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        result.header_items.append((name, value))
        result.headers.setdefault(name.lower(), []).append(value)
    result.body = body
    content_type = result.header("content-type")
    charset_match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    charset = charset_match.group(1).strip('"\'') if charset_match else "utf-8"
    try:
        result.body_text = body.decode(charset, "replace")
    except LookupError:
        result.body_text = body.decode("utf-8", "replace")
    if result.body_text:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", result.body_text, re.I | re.S)
        if title_match:
            result.title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:300]
        stripped = result.body_text.lstrip()
        if stripped.startswith(("{", "[")) and len(stripped) < 2_000_000:
            try:
                result.json_body = json.loads(stripped)
            except (ValueError, TypeError):
                pass
    return result


def read_http_response(reader: LineReader, max_body: int, head_only: bool = False) -> HttpResult:
    header_raw = reader.read_until(b"\r\n\r\n", max_bytes=65536)
    if not header_raw:
        return HttpResult()
    if b"\r\n\r\n" not in header_raw and b"\n\n" not in header_raw:
        result = parse_http_response(header_raw, b"")
        return result
    head, _, inline = header_raw.partition(b"\r\n\r\n")
    if not _:
        head, _, inline = header_raw.partition(b"\n\n")
    result = parse_http_response(head + b"\r\n\r\n", b"")
    body = bytearray(inline)
    truncated = False
    if not head_only:
        content_length = None
        raw_length = result.header("content-length")
        if raw_length:
            try:
                content_length = int(raw_length.split(",", 1)[0].strip())
            except ValueError:
                content_length = None
        if content_length is not None and content_length >= 0:
            want = min(content_length, max_body)
            have = len(body)
            if have < want:
                try:
                    body.extend(reader.read_exact(want - have, timeout=reader.default_timeout))
                except (socket.timeout, EOFError):
                    pass
            if len(body) > want:
                body = body[:want]
            truncated = content_length > max_body
        else:
            extra = reader.read_some(
                max_bytes=max(0, max_body - len(body)),
                timeout=min(reader.default_timeout, 2.0),
                idle=0.25,
            )
            body.extend(extra)
            if len(body) >= max_body:
                truncated = True
    result = parse_http_response(head + b"\r\n\r\n", bytes(body), truncated)
    return result


def build_http_request(
    method: str,
    path: str,
    host_header: str,
    user_agent: str,
    extra_headers: Optional[dict[str, str]] = None,
) -> bytes:
    if not path.startswith("/"):
        path = "/" + path
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host_header}",
        f"User-Agent: {user_agent}",
        "Accept: */*",
        "Accept-Encoding: identity",
        "Connection: close",
    ]
    if extra_headers:
        lines.extend(f"{k}: {v}" for k, v in extra_headers.items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")


def host_header_for(ctx: ProbeContext) -> str:
    host = ctx.hostname or ctx.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default = 443 if ctx.port == 443 else 80
    if ctx.port != default:
        return f"{host}:{ctx.port}"
    return host


def http_options(ctx: ProbeContext, tls: bool, path: str) -> dict[str, Any]:
    try:
        if tls:
            sock, _ = ctx.open_tls(alpn=["http/1.1"])
        else:
            sock = ctx.open_tcp()
    except Exception as exc:
        return {"error": short_exc(exc)}
    try:
        sock.sendall(build_http_request("OPTIONS", path, host_header_for(ctx), ctx.user_agent))
        reader = LineReader(sock, ctx.read_timeout)
        result = read_http_response(reader, max_body=4096, head_only=True)
        return {
            "status_code": result.status_code,
            "allow": result.header("allow"),
            "server": result.header("server"),
        }
    except Exception as exc:
        return {"error": short_exc(exc)}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_http(ctx: ProbeContext, tls_initial: bool, service: str) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    used_tls = bool(tls_initial)
    sock: Optional[socket.socket] = None
    tls_info: Optional[dict[str, Any]] = None
    path = ctx.http_path or "/"
    if service == "docker":
        path = "/version"
    elif service == "kubernetes":
        path = "/version"

    try:
        if tls_initial:
            try:
                sock, _ = ctx.open_tls(alpn=["http/1.1"])
            except Exception as exc:
                data["tls_error"] = short_exc(exc)
                findings.append(
                    Finding(
                        "medium",
                        "TLS_HANDSHAKE_FAILED",
                        "TLS handshake failed on an expected TLS port",
                        f"TLS handshake error: {short_exc(exc)}. Falling back to plain HTTP for diagnosis.",
                        {"port": ctx.port},
                    )
                )
                used_tls = False
                sock = ctx.open_tcp()
        else:
            sock = ctx.open_tcp()
    except Exception as exc:
        return ProbeResult("http", f"connection failed: {short_exc(exc)}", data=data, error=short_exc(exc))

    try:
        if used_tls:
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            data["tls"] = tls_info
        sock.sendall(build_http_request("GET", path, host_header_for(ctx), ctx.user_agent))
        reader = LineReader(sock, ctx.read_timeout)
        result = read_http_response(reader, max_body=ctx.max_body)
        # Close before opening additional TLS/OPTIONS connections so a
        # single-threaded server is not blocked behind our first socket.
        sock.close()
        sock = None
        if tls_info is not None:
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            findings.extend(tls_findings(tls_info))
        data.update(
            {
                "status_code": result.status_code,
                "status_line": result.status_line,
                "reason": result.reason,
                "title": result.title,
                "server": result.header("server"),
                "powered_by": result.header("x-powered-by"),
                "content_type": result.header("content-type"),
                "body_bytes": len(result.body),
                "body_sha256": hashlib.sha256(result.body).hexdigest() if result.body else None,
                "body_preview": truncate(
                    "".join(
                        ch if (ch.isprintable() or ch in "\r\n\t") else " "
                        for ch in result.body_text[:1200]
                    ),
                    1200,
                ),
                "headers": sanitize_headers(result.header_items),
                "cookies": parse_set_cookies(result.header_items),
                "truncated": result.truncated,
            }
        )
        if result.raw_preview:
            data["raw_preview"] = result.raw_preview
        if result.json_body is not None:
            if service == "docker" and isinstance(result.json_body, dict):
                data["json"] = {
                    key: result.json_body.get(key)
                    for key in (
                        "Version",
                        "ApiVersion",
                        "MinAPIVersion",
                        "Os",
                        "Arch",
                        "KernelVersion",
                        "GoVersion",
                    )
                    if key in result.json_body
                }
            elif service == "elasticsearch" and isinstance(result.json_body, dict):
                data["json"] = {
                    "name": result.json_body.get("name"),
                    "cluster_name": result.json_body.get("cluster_name"),
                    "version": result.json_body.get("version"),
                    "tagline": result.json_body.get("tagline"),
                }
            elif service == "kubernetes" and isinstance(result.json_body, dict):
                data["json"] = {
                    key: result.json_body.get(key)
                    for key in ("major", "minor", "gitVersion", "platform")
                    if key in result.json_body
                }
            else:
                data["json_preview"] = truncate(json.dumps(result.json_body, default=str), 1500)

        server = result.header("server")
        powered = result.header("x-powered-by")
        if server:
            findings.append(
                Finding(
                    "info",
                    "HTTP_SERVER_DISCLOSURE",
                    "Server software is disclosed",
                    f"Server header: {truncate(server, 200)}",
                    {"server": server},
                )
            )
        if powered:
            findings.append(
                Finding(
                    "info",
                    "HTTP_POWERED_BY_DISCLOSURE",
                    "Application framework is disclosed",
                    f"X-Powered-By: {truncate(powered, 200)}",
                    {"x_powered_by": powered},
                )
            )

        if result.status_code == 401:
            findings.append(
                Finding(
                    "info",
                    "HTTP_AUTHENTICATION_REQUIRED",
                    "HTTP endpoint requires authentication",
                    f"Status 401; WWW-Authenticate: {result.header('www-authenticate') or 'not supplied'}",
                    {"www_authenticate": result.header("www-authenticate")},
                )
            )
        elif result.status_code == 403:
            findings.append(
                Finding(
                    "low",
                    "HTTP_ACCESS_DENIED",
                    "HTTP endpoint denied access",
                    "Status 403 observed; this may be an ACL or a WAF block page.",
                    {"status": 403},
                )
            )
        elif result.status_code == 429:
            findings.append(
                Finding(
                    "info",
                    "HTTP_RATE_LIMITED",
                    "HTTP rate limiting was observed",
                    f"Status 429; Retry-After: {result.header('retry-after') or 'not supplied'}",
                    {"retry_after": result.header("retry-after")},
                )
            )
        elif result.status_code and result.status_code >= 500:
            findings.append(
                Finding(
                    "low",
                    "HTTP_SERVER_ERROR",
                    "HTTP endpoint returned a server error",
                    f"Status {result.status_code} {result.reason}.",
                    {"status": result.status_code},
                )
            )

        if not used_tls:
            findings.append(
                Finding(
                    "low",
                    "HTTP_CLEARTEXT",
                    "HTTP is served without transport encryption",
                    "The request and response were plaintext on the wire.",
                    {"port": ctx.port},
                )
            )
        else:
            data["hsts"] = result.header("strict-transport-security")
            if not result.header("strict-transport-security"):
                findings.append(
                    Finding(
                        "low",
                        "HTTP_HSTS_MISSING",
                        "HTTPS response is missing HSTS",
                        "Strict-Transport-Security was not present.",
                        {"port": ctx.port},
                    )
                )

        content_type = result.header("content-type").lower()
        looks_html = "text/html" in content_type or "<html" in result.body_text[:2000].lower()
        security_headers = {
            name: bool(result.header(name)) for name in SECURITY_HEADERS
        }
        data["security_headers"] = security_headers
        if looks_html and result.status_code and result.status_code < 500:
            missing = [
                label
                for name, label in SECURITY_HEADERS.items()
                if name != "strict-transport-security" and not result.header(name)
            ]
            if missing:
                findings.append(
                    Finding(
                        "low",
                        "HTTP_SECURITY_HEADERS_MISSING",
                        "Common HTTP security headers are missing",
                        "Missing: " + ", ".join(missing),
                        {"missing": missing},
                    )
                )

        cookies = data.get("cookies") or []
        insecure_cookies = []
        for cookie in cookies:
            if used_tls and not cookie.get("secure"):
                insecure_cookies.append(cookie.get("name"))
            if not cookie.get("httponly"):
                insecure_cookies.append(cookie.get("name"))
        if insecure_cookies:
            findings.append(
                Finding(
                    "low",
                    "HTTP_COOKIE_FLAGS",
                    "Cookies lack recommended security flags",
                    "Cookie names with missing Secure/HttpOnly flags: "
                    + ", ".join(sorted({c for c in insecure_cookies if c})),
                    {"cookies": cookies},
                )
            )

        cors_origin = result.header("access-control-allow-origin")
        cors_creds = result.header("access-control-allow-credentials").lower() == "true"
        data["cors"] = {"allow_origin": cors_origin, "allow_credentials": cors_creds}
        if cors_origin == "*" and cors_creds:
            findings.append(
                Finding(
                    "medium",
                    "HTTP_CORS_WILDCARD_CREDENTIALS",
                    "CORS allows any origin with credentials",
                    "Access-Control-Allow-Origin is '*' while credentials are allowed.",
                    {"cors": data["cors"]},
                )
            )

        redirect = result.header("location")
        if redirect and not used_tls:
            data["redirect"] = redirect
            parsed = urlparse(redirect)
            if parsed.scheme.lower() == "https":
                findings.append(
                    Finding(
                        "info",
                        "HTTP_HTTPS_REDIRECT",
                        "HTTP redirects to HTTPS",
                        f"Location: {truncate(redirect, 300)}",
                        {"location": redirect},
                    )
                )
        elif redirect:
            data["redirect"] = redirect

        waf = detect_waf(
            result.headers,
            result.body_text,
            [c.get("name", "") for c in cookies],
        )
        data["waf"] = waf
        for item in waf:
            findings.append(
                Finding(
                    "info",
                    "WAF_CDN_DETECTED",
                    f"{item['category']} fingerprint: {item['vendor']}",
                    f"Evidence: {item['evidence']}.",
                    item,
                )
            )

        if service == "docker" and result.status_code == 200 and isinstance(result.json_body, dict):
            findings.append(
                Finding(
                    "high",
                    "DOCKER_API_EXPOSED",
                    "Docker Engine API is reachable without observed authentication",
                    "The /version endpoint returned engine metadata. Restrict the Docker socket/API to trusted hosts.",
                    {"api_version": result.json_body.get("ApiVersion")},
                )
            )
        if service == "elasticsearch" and result.status_code == 200 and isinstance(result.json_body, dict):
            version = result.json_body.get("version")
            findings.append(
                Finding(
                    "high",
                    "ELASTICSEARCH_UNAUTHENTICATED",
                    "Elasticsearch root endpoint is readable",
                    "The cluster metadata endpoint returned data without an observed authentication challenge.",
                    {"version": version if isinstance(version, dict) else None},
                )
            )

        options = http_options(ctx, used_tls, path)
        if options.get("allow"):
            data["allow"] = options["allow"]
            if "TRACE" in options["allow"].upper():
                findings.append(
                    Finding(
                        "low",
                        "HTTP_TRACE_ADVERTISED",
                        "HTTP TRACE is advertised",
                        f"Allow header: {truncate(options['allow'], 200)}",
                        {"allow": options["allow"]},
                    )
                )
        elif options.get("error"):
            data["options_error"] = options["error"]

        protections = {
            "transport": "TLS" if used_tls else "cleartext",
            "tls_version": tls_info.get("version") if tls_info else None,
            "authentication": "required" if result.status_code == 401 else "not-observed",
            "waf_cdn": [d["vendor"] for d in waf],
            "rate_limiting": result.status_code == 429,
            "security_headers": security_headers,
        }
        summary_bits = [f"HTTP {result.status_code or '?'}"]
        if result.reason:
            summary_bits.append(result.reason)
        if result.title:
            summary_bits.append(f"title={truncate(result.title, 80)}")
        if server:
            summary_bits.append(f"server={truncate(server, 80)}")
        if waf:
            summary_bits.append("waf=" + ",".join(d["vendor"] for d in waf))
        if tls_info:
            summary_bits.append(f"tls={tls_info.get('version')}")
        return ProbeResult(
            "http",
            "; ".join(summary_bits),
            data=data,
            findings=findings,
            protections=protections,
        )
    except Exception as exc:
        return ProbeResult(
            "http",
            f"HTTP probe failed: {short_exc(exc)}",
            data=data,
            findings=findings,
            error=short_exc(exc),
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_tls_generic(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    sock = None
    try:
        sock, _ = ctx.open_tls(alpn=["http/1.1"])
        info = tls_metadata(sock, ctx.tls_hostname)
        data["tls"] = info
        sock.close()
        sock = None
        if ctx.tls_matrix:
            info["versions"] = probe_tls_versions(ctx)
        findings.extend(tls_findings(info))
        summary = f"TLS {info.get('version')}"
        if info.get("alpn"):
            summary += f", ALPN {info['alpn']}"
        cert = info.get("certificate") or {}
        if cert.get("subject"):
            summary += f", cert {truncate(cert['subject'], 100)}"
        protections = {
            "transport": "TLS",
            "tls_version": info.get("version"),
            "cipher": info.get("cipher"),
            "certificate": cert,
        }
        return ProbeResult("tls", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("tls", f"TLS probe failed: {short_exc(exc)}", data=data, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_generic(ctx: ProbeContext, nmap_port: Optional[NmapPort] = None) -> ProbeResult:
    data: dict[str, Any] = {}
    sock = None
    try:
        sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        chunk = reader.read_some(8192, timeout=min(ctx.read_timeout, 1.5), idle=0.2)
        if not chunk:
            notes = "TCP connection accepted, but no banner was sent."
            findings: list[Finding] = []
            if nmap_port and (nmap_port.service or "").lower() == "tcpwrapped":
                findings.append(
                    Finding(
                        "low",
                        "TCPWRAPPED_BEHAVIOR",
                        "Service accepts and closes connections without a banner",
                        "This matches Nmap's tcpwrapped classification and may indicate an ACL, "
                        "port-knocking gate, or a proxy that only speaks after a specific handshake.",
                        {"nmap_service": nmap_port.service},
                    )
                )
            return ProbeResult("generic", notes, data=data, findings=findings)
        if chunk.startswith(b"\x16\x03") or chunk[:2] == b"\x16\x03":
            sock.close()
            sock = None
            return probe_tls_generic(ctx)
        if chunk.startswith(b"SSH-"):
            sock.close()
            sock = None
            try:
                return probe_ssh(ctx)
            except Exception:
                pass
        text = printable_preview(chunk, 500)
        data["banner"] = text
        data["hex_preview"] = hex_preview(chunk, 96)
        if all(32 <= b < 127 or b in (9, 10, 13) for b in chunk[:64]):
            summary = f"Banner: {truncate(text, 180)}"
        else:
            summary = f"Binary response ({len(chunk)} bytes): {hex_preview(chunk, 48)}"
        return ProbeResult("generic", summary, data=data)
    except Exception as exc:
        return ProbeResult("generic", f"Generic probe failed: {short_exc(exc)}", data=data, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# File transfer, mail, and DNS probes
# ---------------------------------------------------------------------------


def _ftp_response(reader: LineReader) -> tuple[str, list[str]]:
    first = reader.readline(max_bytes=8192)
    if not first:
        return "", []
    line = first.decode("utf-8", "replace").rstrip("\r\n")
    code = line[:3]
    lines = [line]
    if len(line) >= 4 and line[3] == "-":
        while True:
            nxt = reader.readline(max_bytes=8192)
            if not nxt:
                break
            text = nxt.decode("utf-8", "replace").rstrip("\r\n")
            lines.append(text)
            if text.startswith(code + " "):
                break
    return code, lines


def _smtp_response(reader: LineReader) -> tuple[str, list[str]]:
    return _ftp_response(reader)


def probe_ftp(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    used_tls = bool(tls_initial)
    try:
        if tls_initial:
            sock, _ = ctx.open_tls()
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            data["tls"] = tls_info
            findings.extend(tls_findings(tls_info))
        else:
            sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        code, banner_lines = _ftp_response(reader)
        data["banner"] = " | ".join(banner_lines)[:1000]
        data["greeting_code"] = code
        if code not in {"220", "120"}:
            data["unexpected_greeting"] = True
        sock.sendall(b"FEAT\r\n")
        feat_code, feat_lines = _ftp_response(reader)
        features: list[str] = []
        if feat_code == "211":
            for line in feat_lines[1:]:
                if line.startswith("211"):
                    continue
                value = line.strip()
                if value:
                    features.append(value)
        sock.sendall(b"SYST\r\n")
        syst_code, syst_lines = _ftp_response(reader)
        system = ""
        if syst_lines:
            system = syst_lines[0][4:].strip() if len(syst_lines[0]) > 4 else syst_lines[0]
        data.update(
            {
                "features": features,
                "feat_code": feat_code,
                "system": system,
                "syst_code": syst_code,
            }
        )
        feat_upper = " ".join(features).upper()
        auth_tls = "AUTH TLS" in feat_upper or "AUTH SSL" in feat_upper
        data["auth_tls"] = auth_tls
        if used_tls:
            findings.append(
                Finding(
                    "info",
                    "FTP_TLS",
                    "FTP is protected with TLS",
                    f"Implicit FTPS/TLS negotiated {tls_info.get('version') if tls_info else ''}.",
                    {"tls_version": tls_info.get("version") if tls_info else None},
                )
            )
        else:
            findings.append(
                Finding(
                    "low",
                    "FTP_CLEARTEXT",
                    "FTP control channel is plaintext",
                    "Credentials and commands traverse the network in cleartext unless a separate tunnel is used.",
                    {"port": ctx.port, "auth_tls_available": auth_tls},
                )
            )
            if auth_tls:
                findings.append(
                    Finding(
                        "info",
                        "FTP_AUTH_TLS_AVAILABLE",
                        "FTP server advertises AUTH TLS",
                        "Explicit FTPS is available; the client must opt in.",
                        {"features": features},
                    )
                )
        try:
            sock.sendall(b"QUIT\r\n")
        except OSError:
            pass
        protections = {
            "transport": "TLS" if used_tls else "cleartext",
            "explicit_ftps": auth_tls,
            "tls_version": tls_info.get("version") if tls_info else None,
            "authentication": "not-tested",
        }
        summary = f"FTP {code or '?'} {truncate(system or (banner_lines[0] if banner_lines else ''), 120)}"
        if auth_tls:
            summary += "; AUTH TLS available"
        return ProbeResult("ftp", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("ftp", f"FTP probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_smtp(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    used_tls = bool(tls_initial)
    try:
        if tls_initial:
            sock, _ = ctx.open_tls()
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            data["tls"] = tls_info
            findings.extend(tls_findings(tls_info))
        else:
            sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        code, greeting = _smtp_response(reader)
        data["greeting"] = " | ".join(greeting)[:1000]
        data["greeting_code"] = code
        sock.sendall(b"EHLO portscope.local\r\n")
        ehlo_code, ehlo_lines = _smtp_response(reader)
        extensions: list[str] = []
        if ehlo_code.startswith("2"):
            for line in ehlo_lines[1:]:
                value = line[4:].strip() if len(line) > 4 else ""
                if value:
                    extensions.append(value)
        else:
            sock.sendall(b"HELO portscope.local\r\n")
            helo_code, helo_lines = _smtp_response(reader)
            data["helo_code"] = helo_code
        ext_upper = " ".join(extensions).upper()
        auth_line = next((e for e in extensions if e.upper().startswith("AUTH")), "")
        auth_mechs = auth_line[4:].strip().split() if auth_line else []
        starttls = "STARTTLS" in ext_upper
        data.update(
            {
                "extensions": extensions,
                "auth_mechanisms": auth_mechs,
                "starttls": starttls,
                "ehlo_code": ehlo_code,
            }
        )
        if starttls and not used_tls:
            try:
                sock.sendall(b"STARTTLS\r\n")
                st_code, st_lines = _smtp_response(reader)
                data["starttls_code"] = st_code
                if st_code == "220":
                    sock, _ = wrap_tls(sock, ctx.tls_hostname, ctx.read_timeout)
                    used_tls = True
                    tls_info = tls_metadata(sock, ctx.tls_hostname)
                    if ctx.tls_matrix:
                        tls_info["versions"] = probe_tls_versions(ctx)
                    data["tls"] = tls_info
                    data["starttls_upgraded"] = True
                    findings.extend(tls_findings(tls_info))
                    reader = LineReader(sock, ctx.read_timeout)
                    try:
                        sock.sendall(b"QUIT\r\n")
                        _smtp_response(reader)
                    except OSError:
                        pass
                else:
                    data["starttls_error"] = " | ".join(st_lines)[:500]
            except Exception as exc:
                data["starttls_error"] = short_exc(exc)
        if used_tls:
            findings.append(
                Finding(
                    "info",
                    "SMTP_TLS",
                    "SMTP session is protected with TLS",
                    f"TLS {tls_info.get('version') if tls_info else ''} negotiated.",
                    {"tls_version": tls_info.get("version") if tls_info else None},
                )
            )
        else:
            findings.append(
                Finding(
                    "low",
                    "SMTP_CLEARTEXT",
                    "SMTP session is plaintext",
                    "The initial SMTP exchange is not encrypted.",
                    {"starttls_offered": starttls},
                )
            )
            if not starttls:
                findings.append(
                    Finding(
                        "low",
                        "SMTP_NO_STARTTLS",
                        "SMTP server does not advertise STARTTLS",
                        "Mail submission/relay traffic may traverse the network in cleartext.",
                        {"extensions": extensions},
                    )
                )
        if auth_mechs and not used_tls:
            if any(m.upper() in {"PLAIN", "LOGIN"} for m in auth_mechs):
                findings.append(
                    Finding(
                        "low",
                        "SMTP_CLEARTEXT_AUTH_ADVERTISED",
                        "SMTP advertises cleartext-capable AUTH mechanisms without TLS",
                        "AUTH PLAIN/LOGIN are only safe inside a TLS tunnel.",
                        {"auth_mechanisms": auth_mechs},
                    )
                )
        if not used_tls:
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
        protections = {
            "transport": "TLS" if used_tls else "cleartext",
            "starttls": starttls,
            "tls_version": tls_info.get("version") if tls_info else None,
            "auth_mechanisms": auth_mechs,
            "authentication": "not-tested",
        }
        server_name = greeting[0][4:].strip() if greeting and len(greeting[0]) > 4 else ""
        summary = f"SMTP {code or '?'} {truncate(server_name, 100)}"
        if starttls:
            summary += "; STARTTLS"
        if auth_mechs:
            summary += "; AUTH=" + ",".join(auth_mechs[:5])
        return ProbeResult("smtp", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("smtp", f"SMTP probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _tagged_response(reader: LineReader, tag: bytes, timeout: Optional[float] = None) -> list[bytes]:
    lines: list[bytes] = []
    tag_upper = tag.upper()
    end = time.monotonic() + (reader.default_timeout if timeout is None else timeout)
    while time.monotonic() < end:
        line = reader.readline(max_bytes=8192)
        if not line:
            break
        lines.append(line)
        upper = line.upper()
        if upper.startswith(tag_upper + b" ") or upper.startswith(tag_upper + b"\t"):
            break
    return lines


def probe_imap(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    used_tls = bool(tls_initial)
    try:
        if tls_initial:
            sock, _ = ctx.open_tls()
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            data["tls"] = tls_info
            findings.extend(tls_findings(tls_info))
        else:
            sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        greeting = reader.readline(max_bytes=8192)
        data["greeting"] = truncate(greeting.decode("utf-8", "replace").strip(), 500)
        preauth = greeting.upper().startswith(b"* PREAUTH")
        if preauth:
            findings.append(
                Finding(
                    "high",
                    "IMAP_PREAUTH",
                    "IMAP server grants a pre-authenticated session",
                    "The greeting was '* PREAUTH', so no login was required.",
                    {},
                )
            )
        sock.sendall(b"a1 CAPABILITY\r\n")
        cap_lines = _tagged_response(reader, b"a1")
        capabilities: list[str] = []
        for line in cap_lines:
            upper = line.upper()
            if upper.startswith(b"* CAPABILITY"):
                capabilities.extend(line.decode("utf-8", "replace").split()[2:])
        data["capabilities"] = capabilities
        cap_upper = " ".join(capabilities).upper()
        starttls = "STARTTLS" in cap_upper
        logindisabled = "LOGINDISABLED" in cap_upper
        auth_mechs = [c[5:] for c in capabilities if c.upper().startswith("AUTH=")]
        data["starttls"] = starttls
        data["logindisabled"] = logindisabled
        data["auth_mechanisms"] = auth_mechs
        if starttls and not used_tls:
            try:
                sock.sendall(b"a2 STARTTLS\r\n")
                st_lines = _tagged_response(reader, b"a2")
                data["starttls_response"] = truncate(b" ".join(st_lines).decode("utf-8", "replace"), 500)
                if st_lines and any(line.upper().startswith(b"A2 OK") for line in st_lines):
                    sock, _ = wrap_tls(sock, ctx.tls_hostname, ctx.read_timeout)
                    used_tls = True
                    tls_info = tls_metadata(sock, ctx.tls_hostname)
                    if ctx.tls_matrix:
                        tls_info["versions"] = probe_tls_versions(ctx)
                    data["tls"] = tls_info
                    data["starttls_upgraded"] = True
                    findings.extend(tls_findings(tls_info))
                    reader = LineReader(sock, ctx.read_timeout)
                    try:
                        sock.sendall(b"a3 LOGOUT\r\n")
                        _tagged_response(reader, b"a3")
                    except OSError:
                        pass
            except Exception as exc:
                data["starttls_error"] = short_exc(exc)
        if used_tls:
            findings.append(
                Finding(
                    "info",
                    "IMAP_TLS",
                    "IMAP session is protected with TLS",
                    f"TLS {tls_info.get('version') if tls_info else ''} negotiated.",
                    {"tls_version": tls_info.get("version") if tls_info else None},
                )
            )
        else:
            findings.append(
                Finding(
                    "low",
                    "IMAP_CLEARTEXT",
                    "IMAP session is plaintext",
                    "The initial IMAP exchange is not encrypted.",
                    {"starttls_offered": starttls},
                )
            )
            if not starttls:
                findings.append(
                    Finding(
                        "low",
                        "IMAP_NO_STARTTLS",
                        "IMAP server does not advertise STARTTLS",
                        "Credentials and mail may traverse the network in cleartext.",
                        {"capabilities": capabilities},
                    )
                )
        if logindisabled:
            findings.append(
                Finding(
                    "info",
                    "IMAP_LOGIN_DISABLED",
                    "IMAP LOGIN command is disabled",
                    "The server expects an AUTH mechanism or TLS before login.",
                    {"capabilities": capabilities},
                )
            )
        if not used_tls:
            try:
                sock.sendall(b"a3 LOGOUT\r\n")
                _tagged_response(reader, b"a3")
            except OSError:
                pass
        protections = {
            "transport": "TLS" if used_tls else "cleartext",
            "starttls": starttls,
            "tls_version": tls_info.get("version") if tls_info else None,
            "logindisabled": logindisabled,
            "auth_mechanisms": auth_mechs,
        }
        summary = "IMAP " + truncate(data.get("greeting", ""), 120)
        if preauth:
            summary += "; PREAUTH"
        if starttls:
            summary += "; STARTTLS"
        return ProbeResult("imap", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("imap", f"IMAP probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_pop3(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    used_tls = bool(tls_initial)
    try:
        if tls_initial:
            sock, _ = ctx.open_tls()
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            data["tls"] = tls_info
            findings.extend(tls_findings(tls_info))
        else:
            sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        greeting = reader.readline(max_bytes=8192)
        data["greeting"] = truncate(greeting.decode("utf-8", "replace").strip(), 500)
        sock.sendall(b"CAPA\r\n")
        cap_lines: list[bytes] = []
        first = reader.readline(max_bytes=8192)
        cap_lines.append(first)
        if first.upper().startswith(b"+OK"):
            while True:
                line = reader.readline(max_bytes=8192)
                if not line or line.strip() == b".":
                    break
                cap_lines.append(line)
        capabilities = [
            line.decode("utf-8", "replace").strip()
            for line in cap_lines[1:]
            if line.strip() and line.strip() != b"."
        ]
        cap_upper = " ".join(capabilities).upper()
        stls = "STLS" in cap_upper
        sasl = [c for c in capabilities if c.upper().startswith("SASL")]
        data.update({"capabilities": capabilities, "stls": stls, "sasl": sasl})
        if stls and not used_tls:
            try:
                sock.sendall(b"STLS\r\n")
                st_line = reader.readline(max_bytes=8192)
                data["stls_response"] = truncate(st_line.decode("utf-8", "replace").strip(), 500)
                if st_line.upper().startswith(b"+OK"):
                    sock, _ = wrap_tls(sock, ctx.tls_hostname, ctx.read_timeout)
                    used_tls = True
                    tls_info = tls_metadata(sock, ctx.tls_hostname)
                    if ctx.tls_matrix:
                        tls_info["versions"] = probe_tls_versions(ctx)
                    data["tls"] = tls_info
                    data["stls_upgraded"] = True
                    findings.extend(tls_findings(tls_info))
                    reader = LineReader(sock, ctx.read_timeout)
                    try:
                        sock.sendall(b"QUIT\r\n")
                        reader.readline(max_bytes=1024)
                    except OSError:
                        pass
            except Exception as exc:
                data["stls_error"] = short_exc(exc)
        if used_tls:
            findings.append(
                Finding(
                    "info",
                    "POP3_TLS",
                    "POP3 session is protected with TLS",
                    f"TLS {tls_info.get('version') if tls_info else ''} negotiated.",
                    {"tls_version": tls_info.get("version") if tls_info else None},
                )
            )
        else:
            findings.append(
                Finding(
                    "low",
                    "POP3_CLEARTEXT",
                    "POP3 session is plaintext",
                    "The initial POP3 exchange is not encrypted.",
                    {"stls_offered": stls},
                )
            )
            if not stls:
                findings.append(
                    Finding(
                        "low",
                        "POP3_NO_STLS",
                        "POP3 server does not advertise STLS",
                        "Credentials and mail may traverse the network in cleartext.",
                        {"capabilities": capabilities},
                    )
                )
        if not used_tls:
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
        protections = {
            "transport": "TLS" if used_tls else "cleartext",
            "stls": stls,
            "tls_version": tls_info.get("version") if tls_info else None,
            "sasl": sasl,
        }
        summary = "POP3 " + truncate(data.get("greeting", ""), 120)
        if stls:
            summary += "; STLS"
        return ProbeResult("pop3", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("pop3", f"POP3 probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def _dns_wire_name(name: str) -> bytes:
    parts = [p for p in name.rstrip(".").split(".") if p]
    return b"".join(bytes([len(p)]) + p.encode("idna") for p in parts) + b"\x00"


def _dns_read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 12:
        raise ValueError("DNS compression pointer loop")
    labels: list[str] = []
    while True:
        if offset >= len(data):
            raise ValueError("DNS name out of range")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            pointed, _ = _dns_read_name(data, pointer, depth + 1)
            if pointed:
                labels.append(pointed)
            offset += 2
            break
        offset += 1
        label = data[offset : offset + length]
        if len(label) != length:
            raise ValueError("truncated DNS label")
        try:
            labels.append(label.decode("idna"))
        except UnicodeError:
            labels.append(label.decode("ascii", "replace"))
        offset += length
    return ".".join(labels), offset


def _dns_query(name: str, qtype: int = 16, qclass: int = 3) -> bytes:
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _dns_wire_name(name) + struct.pack(">HH", qtype, qclass)
    return header + question


def _dns_parse(data: bytes) -> dict[str, Any]:
    if len(data) < 12:
        raise ValueError("DNS response too short")
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = _dns_read_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("truncated DNS question")
        qtype, qclass = struct.unpack(">HH", data[offset : offset + 4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    answers = []
    for _ in range(an + ns + ar):
        name, offset = _dns_read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        value: Any = None
        if rtype == 16:  # TXT
            chunks = []
            pos = 0
            while pos < len(rdata):
                length = rdata[pos]
                pos += 1
                chunks.append(rdata[pos : pos + length].decode("utf-8", "replace"))
                pos += length
            value = "".join(chunks)
        elif rtype == 1 and len(rdata) == 4:
            value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28 and len(rdata) == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            try:
                value, _ = _dns_read_name(data, offset - rdlength)
            except ValueError:
                value = None
        elif rtype == 6:
            try:
                mname, pos = _dns_read_name(data, offset - rdlength)
                rname, pos = _dns_read_name(data, pos)
                serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[pos : pos + 20])
                value = {
                    "mname": mname,
                    "rname": rname,
                    "serial": serial,
                    "refresh": refresh,
                    "retry": retry,
                    "expire": expire,
                    "minimum": minimum,
                }
            except (ValueError, struct.error):
                value = None
        else:
            value = rdata.hex(" ")
        answers.append(
            {
                "name": name,
                "type": rtype,
                "class": rclass,
                "ttl": ttl,
                "value": value,
            }
        )
    return {
        "id": txid,
        "flags": flags,
        "rcode": flags & 0x000F,
        "recursion_available": bool(flags & 0x0080),
        "questions": questions,
        "answers": answers,
    }


DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def _dns_tcp_exchange(sock: socket.socket, query: bytes, timeout: float) -> bytes:
    sock.sendall(struct.pack(">H", len(query)) + query)
    reader = LineReader(sock, timeout)
    length_raw = reader.read_exact(2, timeout=timeout)
    length = struct.unpack(">H", length_raw)[0]
    if length <= 0 or length > 65535:
        raise ValueError(f"invalid DNS/TCP length {length}")
    return reader.read_exact(length, timeout=timeout)


def probe_dns(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    used_tls = bool(tls_initial)
    queries = [("version.bind", 16, 3), ("hostname.bind", 16, 3)]
    results: list[dict[str, Any]] = []
    try:
        is_udp = ctx.protocol == "udp"
        if not is_udp:
            if tls_initial:
                sock, _ = ctx.open_tls()
                tls_info = tls_metadata(sock, ctx.tls_hostname)
                if ctx.tls_matrix:
                    tls_info["versions"] = probe_tls_versions(ctx)
                data["tls"] = tls_info
                findings.extend(tls_findings(tls_info))
            else:
                sock = ctx.open_tcp()
        query_errors: list[str] = []
        for name, qtype, qclass in queries:
            try:
                query = _dns_query(name, qtype, qclass)
                if is_udp:
                    payload = ctx.udp_exchange(query)
                else:
                    payload = _dns_tcp_exchange(sock, query, ctx.read_timeout)
                parsed = _dns_parse(payload)
                parsed["query_name"] = name
                parsed["rcode_name"] = DNS_RCODES.get(parsed["rcode"], str(parsed["rcode"]))
                results.append(parsed)
            except Exception as exc:
                message = f"{name}: {short_exc(exc)}"
                query_errors.append(message)
                results.append({"query_name": name, "error": short_exc(exc)})
        data["queries"] = results
        if query_errors:
            data["query_errors"] = query_errors
        if not any("rcode" in result for result in results):
            raise RuntimeError("; ".join(query_errors) or "no DNS response")
        version_value = None
        hostname_value = None
        for result in results:
            for answer in result.get("answers", []):
                if answer.get("type") == 16 and answer.get("value"):
                    if result.get("query_name") == "version.bind":
                        version_value = answer["value"]
                    elif result.get("query_name") == "hostname.bind":
                        hostname_value = answer["value"]
        data["version_bind"] = version_value
        data["hostname_bind"] = hostname_value
        if version_value:
            findings.append(
                Finding(
                    "low",
                    "DNS_VERSION_DISCLOSURE",
                    "DNS server discloses its version",
                    f"version.bind TXT: {version_value}",
                    {"version": version_value},
                )
            )
        if hostname_value:
            findings.append(
                Finding(
                    "info",
                    "DNS_HOSTNAME_DISCLOSURE",
                    "DNS server discloses its hostname",
                    f"hostname.bind TXT: {hostname_value}",
                    {"hostname": hostname_value},
                )
            )
        if any(r.get("recursion_available") for r in results):
            findings.append(
                Finding(
                    "info",
                    "DNS_RECURSION_AVAILABLE",
                    "DNS server advertises recursion",
                    "Recursive resolvers should be restricted to intended clients to avoid abuse.",
                    {},
                )
            )
        if all(r.get("rcode") in (4, 5) for r in results):
            findings.append(
                Finding(
                    "info",
                    "DNS_CHAOS_REFUSED",
                    "DNS server refuses CHAOS version queries",
                    "This is a common hardening choice; it does not indicate a fault.",
                    {},
                )
            )
        protections = {
            "transport": "TLS" if used_tls else ("UDP" if is_udp else "TCP"),
            "tls_version": tls_info.get("version") if tls_info else None,
            "version_disclosure": bool(version_value),
            "recursion_available": any(r.get("recursion_available") for r in results),
        }
        summary = "DNS"
        if version_value:
            summary += f" version={version_value}"
        if hostname_value:
            summary += f" hostname={hostname_value}"
        if not version_value and not hostname_value:
            summary += " (CHAOS version query returned no TXT answer)"
        return ProbeResult("dns", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("dns", f"DNS probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# RDP, databases, cache services, and MongoDB
# ---------------------------------------------------------------------------


RDP_PROTOCOLS = {
    0x00000000: "Standard RDP Security",
    0x00000001: "TLS",
    0x00000002: "CredSSP/NLA",
    0x00000004: "RDSTLS",
    0x00000008: "CredSSP/HYBRID_EX",
}

RDP_FAILURE_CODES = {
    0x00000001: "SSL_REQUIRED_BY_SERVER",
    0x00000002: "SSL_NOT_ALLOWED_BY_SERVER",
    0x00000003: "SSL_CERT_NOT_ON_SERVER",
    0x00000004: "INCONSISTENT_FLAGS",
    0x00000005: "HYBRID_REQUIRED_BY_SERVER",
    0x00000006: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}


def probe_rdp(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    # X.224 Connection Request with RDP negotiation request (TLS | CredSSP).
    request = bytes.fromhex(
        "030000130ee000000000000100080003000000"
    )
    sock = None
    try:
        sock = ctx.open_tcp()
        sock.sendall(request)
        reader = LineReader(sock, ctx.read_timeout)
        header = reader.read_exact(4)
        if header[0] != 0x03:
            data["raw_preview"] = hex_preview(header, 16)
            return ProbeResult("rdp", "RDP probe received a non-TPKT response", data=data)
        tpkt_length = struct.unpack(">H", header[2:4])[0]
        if not 7 <= tpkt_length <= 65535:
            return ProbeResult("rdp", f"RDP response has invalid TPKT length {tpkt_length}", data=data)
        rest = reader.read_exact(tpkt_length - 4)
        packet = header + rest
        data["packet_hex"] = packet.hex(" ")
        data["tpkt_length"] = tpkt_length
        if len(packet) < 11:
            return ProbeResult("rdp", "RDP response too short", data=data)
        x224_type = packet[5]
        data["x224_type"] = f"0x{x224_type:02x}"
        selected = None
        neg_type = None
        neg_code = None
        if len(packet) >= 19 and x224_type == 0xD0:
            neg_type, flags, neg_length, selected = struct.unpack("<BBHI", packet[11:19])
            data["negotiation"] = {
                "type": neg_type,
                "flags": flags,
                "length": neg_length,
                "selected_protocol": selected,
                "selected_protocol_name": RDP_PROTOCOLS.get(selected, f"unknown(0x{selected:08x})"),
            }
            if neg_type == 0x03 and len(packet) >= 19:
                neg_code = selected
                data["negotiation"]["failure_code"] = RDP_FAILURE_CODES.get(
                    neg_code, f"unknown(0x{neg_code:08x})"
                )
        if neg_type == 0x02 and selected is not None:
            name = RDP_PROTOCOLS.get(selected, f"unknown(0x{selected:08x})")
            if selected == 0:
                findings.append(
                    Finding(
                        "high",
                        "RDP_STANDARD_SECURITY",
                        "RDP does not negotiate TLS or NLA",
                        "The server selected Standard RDP Security, which is legacy and weaker.",
                        {"selected_protocol": selected},
                    )
                )
            elif selected == 1:
                findings.append(
                    Finding(
                        "low",
                        "RDP_TLS_ONLY",
                        "RDP negotiates TLS but not NLA",
                        "TLS protects the session, but CredSSP/NLA adds pre-authentication.",
                        {"selected_protocol": selected},
                    )
                )
            elif selected in (2, 8):
                findings.append(
                    Finding(
                        "info",
                        "RDP_NLA_REQUIRED",
                        "RDP negotiates CredSSP/NLA",
                        f"Selected protocol: {name}.",
                        {"selected_protocol": selected},
                    )
                )
        elif neg_type == 0x03:
            findings.append(
                Finding(
                    "medium",
                    "RDP_NEGOTIATION_FAILED",
                    "RDP protocol negotiation failed",
                    f"Failure code: {RDP_FAILURE_CODES.get(neg_code, neg_code)}",
                    {"failure_code": neg_code},
                )
            )
        elif x224_type == 0xD0 and len(packet) < 19:
            findings.append(
                Finding(
                    "medium",
                    "RDP_LEGACY_SECURITY",
                    "RDP server did not return a negotiation response",
                    "The response did not include RDP_NEG_RSP; legacy Standard RDP Security may be in use.",
                    {"x224_type": x224_type},
                )
            )
        protections = {
            "transport": RDP_PROTOCOLS.get(selected, "unknown") if selected is not None else "unknown",
            "selected_protocol": selected,
            "nla": selected in (2, 8) if selected is not None else None,
            "tls": selected in (1, 2, 8) if selected is not None else None,
        }
        summary = "RDP"
        if selected is not None:
            summary += f" selected={RDP_PROTOCOLS.get(selected, hex(selected))}"
        if neg_code is not None:
            summary += f" failure={RDP_FAILURE_CODES.get(neg_code, hex(neg_code))}"
        return ProbeResult("rdp", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("rdp", f"RDP probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# MySQL
# ---------------------------------------------------------------------------


MYSQL_CAPABILITIES = {
    0x00000001: "CLIENT_LONG_PASSWORD",
    0x00000004: "CLIENT_LONG_FLAG",
    0x00000008: "CLIENT_CONNECT_WITH_DB",
    0x00000020: "CLIENT_COMPRESS",
    0x00000080: "CLIENT_LOCAL_FILES",
    0x00000200: "CLIENT_PROTOCOL_41",
    0x00000800: "CLIENT_SSL",
    0x00008000: "CLIENT_SECURE_CONNECTION",
    0x00080000: "CLIENT_PLUGIN_AUTH",
    0x00100000: "CLIENT_CONNECT_ATTRS",
    0x00200000: "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
    0x00400000: "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS",
    0x00800000: "CLIENT_SESSION_TRACK",
    0x01000000: "CLIENT_DEPRECATE_EOF",
}


def _read_mysql_packet(reader: LineReader) -> tuple[int, bytes]:
    header = reader.read_exact(4)
    length = int.from_bytes(header[:3], "little")
    sequence = header[3]
    if length > 4 * 1024 * 1024:
        raise ValueError(f"MySQL packet too large: {length}")
    payload = reader.read_exact(length) if length else b""
    return sequence, payload


def _mysql_parse_handshake(payload: bytes) -> dict[str, Any]:
    if not payload:
        raise ValueError("empty MySQL handshake")
    if payload[0] == 0xFF:
        code = struct.unpack("<H", payload[1:3])[0] if len(payload) >= 3 else None
        message = payload[3:].decode("utf-8", "replace") if len(payload) > 3 else ""
        raise RuntimeError(f"MySQL error {code}: {message}")
    if payload[0] != 0x0A:
        raise ValueError(f"unexpected MySQL protocol byte 0x{payload[0]:02x}")
    pos = 1
    end = payload.find(b"\x00", pos)
    if end < 0:
        raise ValueError("unterminated MySQL server version")
    version = payload[pos:end].decode("utf-8", "replace")
    pos = end + 1
    if pos + 4 > len(payload):
        raise ValueError("truncated MySQL thread id")
    thread_id = struct.unpack("<I", payload[pos : pos + 4])[0]
    pos += 4
    auth1 = payload[pos : pos + 8]
    pos += 8
    pos += 1  # filler
    if pos + 2 > len(payload):
        raise ValueError("truncated MySQL capability flags")
    cap_low = struct.unpack("<H", payload[pos : pos + 2])[0]
    pos += 2
    charset = None
    status = None
    cap_high = 0
    if pos < len(payload):
        charset = payload[pos]
        pos += 1
    if pos + 2 <= len(payload):
        status = struct.unpack("<H", payload[pos : pos + 2])[0]
        pos += 2
    if pos + 2 <= len(payload):
        cap_high = struct.unpack("<H", payload[pos : pos + 2])[0]
        pos += 2
    capabilities = cap_low | (cap_high << 16)
    auth_len = payload[pos] if pos < len(payload) else 0
    pos += 1
    pos += 10
    auth2 = b""
    if pos < len(payload):
        part2_len = max(13, auth_len - 8) if auth_len else 13
        auth2 = payload[pos : pos + part2_len]
        pos += part2_len
    plugin = ""
    if capabilities & 0x00080000 and pos < len(payload):
        plugin = payload[pos:].split(b"\x00", 1)[0].decode("utf-8", "replace")
    return {
        "server_version": version,
        "thread_id": thread_id,
        "capabilities": capabilities,
        "capability_names": [name for bit, name in MYSQL_CAPABILITIES.items() if capabilities & bit],
        "charset": charset,
        "status": status,
        "auth_plugin": plugin,
        "auth_plugin_data_length": auth_len,
        "auth_plugin_data_part1_bytes": len(auth1),
        "auth_plugin_data_part2_bytes": len(auth2),
    }


def probe_mysql(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    sock = None
    try:
        # MySQL TLS is negotiated with an SSLRequest after the handshake packet,
        # not by wrapping the socket immediately.
        sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        sequence, payload = _read_mysql_packet(reader)
        data["sequence"] = sequence
        handshake = _mysql_parse_handshake(payload)
        data.update(handshake)
        caps = handshake["capabilities"]
        tls_capable = bool(caps & 0x00000800)
        data["tls_capable"] = tls_capable
        if not tls_capable:
            findings.append(
                Finding(
                    "medium",
                    "MYSQL_NO_TLS",
                    "MySQL server does not advertise TLS",
                    "CLIENT_SSL is absent; credentials and queries may traverse the network in cleartext.",
                    {"server_version": handshake["server_version"]},
                )
            )
        elif caps & 0x00000200:
            findings.append(
                Finding(
                    "info",
                    "MYSQL_TLS_AVAILABLE",
                    "MySQL server advertises TLS",
                    "CLIENT_SSL is present. TLS was not forced because that would require client credentials.",
                    {"server_version": handshake["server_version"]},
                )
            )
        plugin = handshake.get("auth_plugin") or ""
        if plugin == "mysql_native_password":
            findings.append(
                Finding(
                    "low",
                    "MYSQL_NATIVE_PASSWORD",
                    "MySQL advertises mysql_native_password",
                    "This legacy challenge-response scheme is weaker than caching_sha2_password and is often disabled in modern deployments.",
                    {"auth_plugin": plugin},
                )
            )
        if handshake["server_version"]:
            findings.append(
                Finding(
                    "info",
                    "MYSQL_VERSION_DISCLOSURE",
                    "MySQL server version is disclosed",
                    f"Server version: {handshake['server_version']}",
                    {"server_version": handshake["server_version"]},
                )
            )
        protections = {
            "transport": "TLS-capable" if tls_capable else "cleartext-only",
            "tls": tls_capable,
            "authentication": "not-tested",
            "auth_plugin": plugin,
        }
        summary = f"MySQL {handshake['server_version']}"
        if plugin:
            summary += f"; auth={plugin}"
        summary += "; TLS-capable" if tls_capable else "; no TLS capability"
        return ProbeResult("mysql", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("mysql", f"MySQL probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------


POSTGRES_AUTH_NAMES = {
    0: "AuthenticationOk (trust)",
    2: "KerberosV5",
    3: "CleartextPassword",
    5: "MD5Password",
    6: "SCMCredential",
    7: "GSS",
    8: "GSSContinue",
    9: "SSPI",
    10: "SASL/SCRAM",
    11: "SASLContinue",
    12: "SASLFinal",
}


def _pg_read_message(reader: LineReader) -> tuple[str, bytes]:
    type_byte = reader.read_exact(1)
    length_raw = reader.read_exact(4)
    length = struct.unpack("!I", length_raw)[0]
    if length < 4 or length > 8 * 1024 * 1024:
        raise ValueError(f"invalid PostgreSQL message length {length}")
    body = reader.read_exact(length - 4) if length > 4 else b""
    return type_byte.decode("latin-1"), body


def _pg_error_fields(body: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    pos = 0
    while pos < len(body):
        code = body[pos]
        pos += 1
        if code == 0:
            break
        end = body.find(b"\x00", pos)
        if end < 0:
            break
        value = body[pos:end].decode("utf-8", "replace")
        fields[chr(code)] = value
        pos = end + 1
    return fields


def probe_postgres(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    used_tls = False
    try:
        sock = ctx.open_tcp()
        sock.sendall(struct.pack("!II", 8, 80877103))
        ssl_reply = sock.recv(1)
        data["ssl_reply"] = ssl_reply.decode("latin-1", "replace") if ssl_reply else ""
        if ssl_reply == b"S":
            sock, _ = wrap_tls(sock, ctx.tls_hostname, ctx.read_timeout)
            used_tls = True
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            data["tls"] = tls_info
            findings.extend(tls_findings(tls_info))
        elif ssl_reply not in {b"N", b""}:
            data["unexpected_ssl_reply"] = hex_preview(ssl_reply or ssl_reply, 8)
        if ssl_reply != b"S":
            findings.append(
                Finding(
                    "medium",
                    "POSTGRES_NO_TLS",
                    "PostgreSQL does not support TLS",
                    "The server rejected SSLRequest, so database traffic may be cleartext.",
                    {"ssl_reply": data["ssl_reply"]},
                )
            )
        # A minimal StartupMessage is harmless and lets the server reveal its
        # authentication method through AuthenticationRequest/ErrorResponse.
        params = b"user\x00portscope\x00database\x00postgres\x00\x00"
        startup = struct.pack("!II", len(params) + 8, 196608) + params
        sock.sendall(startup)
        reader = LineReader(sock, ctx.read_timeout)
        auth_type = None
        error_fields: dict[str, str] = {}
        parameter_status: dict[str, str] = {}
        messages = []
        for _ in range(8):
            msg_type, body = _pg_read_message(reader)
            messages.append(msg_type)
            if msg_type == "R":
                if len(body) >= 4:
                    auth_type = struct.unpack("!I", body[:4])[0]
                break
            if msg_type == "E":
                error_fields = _pg_error_fields(body)
                break
            if msg_type == "S":
                parts = body.split(b"\x00")
                if len(parts) >= 2:
                    parameter_status[parts[0].decode("utf-8", "replace")] = parts[1].decode(
                        "utf-8", "replace"
                    )
                continue
            if msg_type == "N":
                continue
            if msg_type == "Z":
                break
        data.update(
            {
                "authentication_type": auth_type,
                "authentication_name": POSTGRES_AUTH_NAMES.get(auth_type, None) if auth_type is not None else None,
                "error_fields": error_fields,
                "parameter_status": parameter_status,
                "message_types": messages,
            }
        )
        if auth_type == 0:
            findings.append(
                Finding(
                    "high",
                    "POSTGRES_TRUST_AUTH",
                    "PostgreSQL accepts unauthenticated startup",
                    "The server returned AuthenticationOk without a password challenge (trust authentication).",
                    {},
                )
            )
        elif auth_type == 3 and not used_tls:
            findings.append(
                Finding(
                    "medium",
                    "POSTGRES_CLEARTEXT_AUTH",
                    "PostgreSQL requests a cleartext password over a non-TLS channel",
                    "AuthenticationCleartextPassword over plaintext exposes credentials to the network.",
                    {},
                )
            )
        elif auth_type == 5:
            findings.append(
                Finding(
                    "low",
                    "POSTGRES_MD5_AUTH",
                    "PostgreSQL uses MD5 password authentication",
                    "MD5 challenge-response is legacy; SCRAM-SHA-256 is preferred.",
                    {},
                )
            )
        elif auth_type == 10:
            findings.append(
                Finding(
                    "info",
                    "POSTGRES_SCRAM_AUTH",
                    "PostgreSQL uses SCRAM authentication",
                    "The server requested SASL/SCRAM, a modern password-authentication method.",
                    {},
                )
            )
        if error_fields:
            findings.append(
                Finding(
                    "info",
                    "POSTGRES_STARTUP_ERROR",
                    "PostgreSQL returned a startup error",
                    truncate(
                        f"{error_fields.get('S', '')}: {error_fields.get('M', '')}".strip(": "),
                        300,
                    ),
                    error_fields,
                )
            )
        transport = "TLS" if used_tls else "cleartext"
        protections = {
            "transport": transport,
            "tls_version": tls_info.get("version") if tls_info else None,
            "authentication": POSTGRES_AUTH_NAMES.get(auth_type, "unknown") if auth_type is not None else "not-observed",
        }
        summary = f"PostgreSQL SSL={data['ssl_reply'] or 'none'}"
        if auth_type is not None:
            summary += f"; auth={POSTGRES_AUTH_NAMES.get(auth_type, auth_type)}"
        if error_fields.get("M"):
            summary += f"; {truncate(error_fields['M'], 100)}"
        return ProbeResult("postgres", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("postgres", f"PostgreSQL probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Redis / Memcached / MongoDB
# ---------------------------------------------------------------------------


def probe_redis(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    try:
        if tls_initial:
            sock, _ = ctx.open_tls()
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            data["tls"] = tls_info
        else:
            sock = ctx.open_tcp()
        sock.sendall(b"PING\r\n")
        reader = LineReader(sock, ctx.read_timeout)
        response = reader.readline(max_bytes=16384)
        text = response.decode("utf-8", "replace").strip()
        data["response"] = truncate(text, 500)
        sock.close()
        sock = None
        if tls_info is not None:
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            findings.extend(tls_findings(tls_info))
        upper = text.upper()
        auth_required = False
        if upper.startswith("+PONG"):
            findings.append(
                Finding(
                    "high",
                    "REDIS_UNAUTHENTICATED",
                    "Redis responds to unauthenticated PING",
                    "The server is reachable and no authentication challenge was observed.",
                    {"response": text[:200]},
                )
            )
            auth_required = False
        elif upper.startswith("-NOAUTH"):
            auth_required = True
            findings.append(
                Finding(
                    "info",
                    "REDIS_AUTH_REQUIRED",
                    "Redis requires authentication",
                    "The server replied NOAUTH to an unauthenticated PING.",
                    {"response": text[:200]},
                )
            )
        elif "PROTECTED MODE" in upper:
            findings.append(
                Finding(
                    "info",
                    "REDIS_PROTECTED_MODE",
                    "Redis is running in protected mode",
                    "Protected mode rejects non-loopback clients until explicitly configured.",
                    {"response": text[:300]},
                )
            )
        elif upper.startswith("-ERR") or upper.startswith("-WRONGPASS"):
            data["unexpected"] = text[:300]
        protections = {
            "transport": "TLS" if tls_initial else "cleartext",
            "authentication": "required" if auth_required else "not-observed",
            "tls_version": tls_info.get("version") if tls_info else None,
        }
        summary = "Redis "
        if upper.startswith("+PONG"):
            summary += "unauthenticated PING succeeded"
        elif auth_required:
            summary += "authentication required"
        else:
            summary += truncate(text, 120) or "no response"
        return ProbeResult("redis", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("redis", f"Redis probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_memcached(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    try:
        if tls_initial:
            sock, _ = ctx.open_tls()
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            data["tls"] = tls_info
        else:
            sock = ctx.open_tcp()
        sock.sendall(b"version\r\n")
        reader = LineReader(sock, ctx.read_timeout)
        response = reader.readline(max_bytes=16384)
        text = response.decode("utf-8", "replace").strip()
        data["response"] = truncate(text, 500)
        sock.close()
        sock = None
        if tls_info is not None:
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            findings.extend(tls_findings(tls_info))
        version = None
        if text.upper().startswith("VERSION "):
            version = text[8:].strip()
            findings.append(
                Finding(
                    "high",
                    "MEMCACHED_UNAUTHENTICATED",
                    "Memcached responds without authentication",
                    "The version command is readable without a credential exchange.",
                    {"version": version},
                )
            )
        elif text.upper().startswith("ERROR"):
            findings.append(
                Finding(
                    "info",
                    "MEMCACHED_AUTH_POSSIBLE",
                    "Memcached rejected the unauthenticated version command",
                    "SASL or another access control layer may be enabled.",
                    {"response": text[:200]},
                )
            )
        protections = {
            "transport": "TLS" if tls_initial else "cleartext",
            "authentication": "not-observed" if version else "possibly-required",
            "version": version,
            "tls_version": tls_info.get("version") if tls_info else None,
        }
        summary = f"Memcached {version}" if version else f"Memcached: {truncate(text, 120)}"
        return ProbeResult("memcached", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("memcached", f"Memcached probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# Minimal BSON encoder/decoder for MongoDB OP_MSG handshakes.
def _bson_cstring(value: str) -> bytes:
    return value.encode("utf-8") + b"\x00"


def _bson_element(key: str, value: Any) -> bytes:
    if isinstance(value, bool):
        return b"\x08" + _bson_cstring(key) + (b"\x01" if value else b"\x00")
    if value is None:
        return b"\x0A" + _bson_cstring(key)
    if isinstance(value, float):
        return b"\x01" + _bson_cstring(key) + struct.pack("<d", value)
    if isinstance(value, int):
        if -2147483648 <= value <= 2147483647:
            return b"\x10" + _bson_cstring(key) + struct.pack("<i", value)
        return b"\x12" + _bson_cstring(key) + struct.pack("<q", value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return b"\x02" + _bson_cstring(key) + struct.pack("<i", len(encoded) + 1) + encoded + b"\x00"
    if isinstance(value, dict):
        return b"\x03" + _bson_cstring(key) + _bson_document(value)
    if isinstance(value, (list, tuple)):
        return b"\x04" + _bson_cstring(key) + _bson_document({str(i): v for i, v in enumerate(value)})
    raise TypeError(f"unsupported BSON value for {key!r}: {type(value).__name__}")


def _bson_document(document: dict[str, Any]) -> bytes:
    body = b"".join(_bson_element(key, value) for key, value in document.items())
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _bson_read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset)
    if end < 0:
        raise ValueError("unterminated BSON cstring")
    return data[offset:end].decode("utf-8", "replace"), end + 1


def _bson_decode_document(data: bytes, offset: int = 0, depth: int = 0) -> tuple[dict[str, Any], int]:
    if depth > 20:
        raise ValueError("BSON nesting too deep")
    if offset + 4 > len(data):
        raise ValueError("truncated BSON document")
    length = struct.unpack("<i", data[offset : offset + 4])[0]
    if length < 5 or offset + length > len(data):
        raise ValueError("invalid BSON document length")
    end = offset + length - 1
    pos = offset + 4
    result: dict[str, Any] = {}
    while pos < end:
        etype = data[pos]
        pos += 1
        key, pos = _bson_read_cstring(data, pos)
        if etype == 0x01:
            value = struct.unpack("<d", data[pos : pos + 8])[0]
            pos += 8
        elif etype == 0x02 or etype == 0x0D or etype == 0x0E:
            slen = struct.unpack("<i", data[pos : pos + 4])[0]
            pos += 4
            value = data[pos : pos + slen - 1].decode("utf-8", "replace")
            pos += slen
        elif etype == 0x03:
            value, pos = _bson_decode_document(data, pos, depth + 1)
        elif etype == 0x04:
            arr, pos = _bson_decode_document(data, pos, depth + 1)
            value = list(arr.values())
        elif etype == 0x05:
            blen = struct.unpack("<i", data[pos : pos + 4])[0]
            pos += 4
            subtype = data[pos]
            pos += 1
            value = {"subtype": subtype, "bytes": blen}
            pos += blen
        elif etype == 0x07:
            value = data[pos : pos + 12].hex()
            pos += 12
        elif etype == 0x08:
            value = data[pos] != 0
            pos += 1
        elif etype == 0x09 or etype == 0x11:
            value = struct.unpack("<q", data[pos : pos + 8])[0]
            pos += 8
        elif etype == 0x0A:
            value = None
        elif etype == 0x10:
            value = struct.unpack("<i", data[pos : pos + 4])[0]
            pos += 4
        elif etype == 0x12:
            value = struct.unpack("<q", data[pos : pos + 8])[0]
            pos += 8
        else:
            # Unknown type: stop parsing element values safely.
            result.setdefault("_unknown_types", []).append(etype)
            break
        result[key] = value
    return result, end + 1


def _mongo_command(ctx: ProbeContext, command: dict[str, Any], tls_initial: bool) -> dict[str, Any]:
    sock = None
    try:
        if tls_initial:
            sock, _ = ctx.open_tls()
        else:
            sock = ctx.open_tcp()
        request_id = random.randint(1, 2**31 - 1)
        body = struct.pack("<I", 0) + b"\x00" + _bson_document(command)
        message = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013) + body
        sock.sendall(message)
        reader = LineReader(sock, ctx.read_timeout)
        header = reader.read_exact(16)
        length, resp_to, _, opcode = struct.unpack("<iiii", header)
        if length < 21 or length > 4 * 1024 * 1024:
            raise ValueError(f"invalid MongoDB message length {length}")
        payload = reader.read_exact(length - 16)
        if opcode != 2013:
            raise ValueError(f"unexpected MongoDB opcode {opcode}")
        if len(payload) < 5:
            raise ValueError("truncated MongoDB OP_MSG")
        flag_bits = struct.unpack("<I", payload[:4])[0]
        kind = payload[4]
        if kind != 0:
            raise ValueError(f"unsupported MongoDB section kind {kind}")
        document, _ = _bson_decode_document(payload, 5)
        return {"document": document, "opcode": opcode, "flags": flag_bits, "response_to": resp_to}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_mongodb(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    try:
        if tls_initial:
            # The TLS handshake is opened separately for metadata, then closed.
            meta_sock = None
            try:
                meta_sock, _ = ctx.open_tls()
                tls_info = tls_metadata(meta_sock, ctx.tls_hostname)
                data["tls"] = tls_info
            finally:
                if meta_sock is not None:
                    meta_sock.close()
            if tls_info is not None:
                if ctx.tls_matrix:
                    tls_info["versions"] = probe_tls_versions(ctx)
                findings.extend(tls_findings(tls_info))
        response = _mongo_command(ctx, {"hello": 1, "$db": "admin"}, tls_initial)
        document = response["document"]
        data["hello"] = document
        error_code = document.get("code")
        if document.get("ok") == 0 and error_code == 59:
            response = _mongo_command(ctx, {"isMaster": 1, "$db": "admin"}, tls_initial)
            document = response["document"]
            data["isMaster"] = document
            error_code = document.get("code")
        ok = document.get("ok")
        if ok == 1:
            findings.append(
                Finding(
                    "info",
                    "MONGODB_HELLO",
                    "MongoDB accepted an unauthenticated hello command",
                    "The hello/isMaster handshake is normally unauthenticated and does not prove access to data.",
                    {
                        "maxWireVersion": document.get("maxWireVersion"),
                        "isWritablePrimary": document.get("isWritablePrimary"),
                    },
                )
            )
        elif error_code in (13, 18):
            findings.append(
                Finding(
                    "info",
                    "MONGODB_AUTH_REQUIRED",
                    "MongoDB requires authentication",
                    f"Server error code {error_code}: {document.get('errmsg', '')}",
                    {"code": error_code, "errmsg": document.get("errmsg")},
                )
            )
        protections = {
            "transport": "TLS" if tls_initial else "cleartext",
            "tls_version": tls_info.get("version") if tls_info else None,
            "authentication": "required" if error_code in (13, 18) else "hello-only",
            "maxWireVersion": document.get("maxWireVersion"),
        }
        summary = "MongoDB hello"
        if document.get("maxWireVersion") is not None:
            summary += f" maxWireVersion={document['maxWireVersion']}"
        if error_code is not None:
            summary += f" code={error_code}"
        return ProbeResult("mongodb", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("mongodb", f"MongoDB probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _ssh_namelist(items: Iterable[str]) -> bytes:
    return _ssh_string(",".join(items).encode("ascii", "ignore"))


def _ssh_build_kexinit() -> bytes:
    kex = [
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
    ]
    host_key = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ]
    encryption = [
        "chacha20-poly1305@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-ctr",
        "aes256-ctr",
    ]
    mac = [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    ]
    payload = (
        b"\x14"
        + os.urandom(16)
        + _ssh_namelist(kex)
        + _ssh_namelist(host_key)
        + _ssh_namelist(encryption)
        + _ssh_namelist(encryption)
        + _ssh_namelist(mac)
        + _ssh_namelist(mac)
        + _ssh_namelist(["none"])
        + _ssh_namelist(["none"])
        + _ssh_namelist([])
        + _ssh_namelist([])
        + b"\x00"
        + struct.pack(">I", 0)
    )
    block = 8
    pad_len = block - ((5 + len(payload)) % block)
    if pad_len < 4:
        pad_len += block
    packet_length = 1 + len(payload) + pad_len
    return struct.pack(">I", packet_length) + bytes([pad_len]) + payload + os.urandom(pad_len)


def _ssh_read_packet(reader: LineReader) -> bytes:
    length_raw = reader.read_exact(4)
    packet_length = struct.unpack(">I", length_raw)[0]
    if packet_length < 5 or packet_length > 256 * 1024:
        raise ValueError(f"invalid SSH packet length {packet_length}")
    rest = reader.read_exact(packet_length)
    padding_length = rest[0]
    if padding_length < 4 or padding_length >= packet_length:
        raise ValueError("invalid SSH padding length")
    return rest[1 : packet_length - padding_length]


def _ssh_parse_namelists(payload: bytes) -> dict[str, list[str]]:
    if not payload or payload[0] != 20:
        raise ValueError("SSH packet is not SSH_MSG_KEXINIT")
    pos = 17  # message type + 16-byte cookie
    labels = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_client_to_server",
        "encryption_server_to_client",
        "mac_client_to_server",
        "mac_server_to_client",
        "compression_client_to_server",
        "compression_server_to_client",
        "language_client_to_server",
        "language_server_to_client",
    ]
    result: dict[str, list[str]] = {}
    for label in labels:
        if pos + 4 > len(payload):
            raise ValueError("truncated SSH name-list length")
        length = struct.unpack(">I", payload[pos : pos + 4])[0]
        pos += 4
        if length > len(payload) - pos:
            raise ValueError("truncated SSH name-list")
        raw = payload[pos : pos + length].decode("ascii", "replace")
        pos += length
        result[label] = [item for item in raw.split(",") if item]
    result["first_kex_packet_follows"] = bool(payload[pos]) if pos < len(payload) else None
    return result


SSH_WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-",
}
SSH_WEAK_HOSTKEY = {"ssh-dss", "ssh-rsa", "ssh-rsa-cert-v01@openssh.com"}
SSH_WEAK_ENCRYPTION = {
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
}
SSH_WEAK_MAC = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-ripemd160",
}


def probe_ssh(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    sock = None
    try:
        sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        sock.sendall(b"SSH-2.0-PortScope_1.0\r\n")
        banner = b""
        for _ in range(8):
            line = reader.readline(max_bytes=4096)
            if not line:
                break
            if line.startswith(b"SSH-"):
                banner = line.strip()
                break
        if not banner:
            raise RuntimeError("no SSH identification string received")
        banner_text = banner.decode("utf-8", "replace")
        match = re.match(r"SSH-([0-9.]+)-(.+)", banner_text)
        protocol = match.group(1) if match else ""
        software = match.group(2) if match else banner_text
        data.update(
            {
                "banner": banner_text,
                "protocol": protocol,
                "software": software,
            }
        )
        if protocol.startswith("1."):
            findings.append(
                Finding(
                    "high",
                    "SSH_PROTOCOL_1",
                    "SSH protocol version 1 is offered",
                    f"Server banner: {banner_text}",
                    {"protocol": protocol},
                )
            )
        sock.sendall(_ssh_build_kexinit())
        kex: Optional[dict[str, Any]] = None
        for _ in range(4):
            payload = _ssh_read_packet(reader)
            if payload and payload[0] == 20:
                kex = _ssh_parse_namelists(payload)
                break
        if kex:
            data["kexinit"] = kex
            weak_kex = sorted(set(kex["kex_algorithms"]) & SSH_WEAK_KEX)
            weak_host = sorted(set(kex["server_host_key_algorithms"]) & SSH_WEAK_HOSTKEY)
            weak_enc = sorted(
                (set(kex["encryption_client_to_server"]) | set(kex["encryption_server_to_client"]))
                & SSH_WEAK_ENCRYPTION
            )
            weak_mac = sorted(
                (set(kex["mac_client_to_server"]) | set(kex["mac_server_to_client"]))
                & SSH_WEAK_MAC
            )
            data["weak_algorithms"] = {
                "kex": weak_kex,
                "host_key": weak_host,
                "encryption": weak_enc,
                "mac": weak_mac,
            }
            if weak_kex or weak_host or weak_enc or weak_mac:
                findings.append(
                    Finding(
                        "medium",
                        "SSH_WEAK_ALGORITHMS",
                        "SSH server offers weak or legacy algorithms",
                        "Weak algorithm families: "
                        + ", ".join(
                            part
                            for part in (
                                "kex=" + ",".join(weak_kex) if weak_kex else "",
                                "hostkey=" + ",".join(weak_host) if weak_host else "",
                                "enc=" + ",".join(weak_enc) if weak_enc else "",
                                "mac=" + ",".join(weak_mac) if weak_mac else "",
                            )
                            if part
                        ),
                        data["weak_algorithms"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        "info",
                        "SSH_ALGORITHMS_MODERN",
                        "SSH server does not offer the common weak algorithm set",
                        "No known-weak algorithm names were present in the KEXINIT lists.",
                        {},
                    )
                )
        else:
            data["kexinit_error"] = "server did not send SSH_MSG_KEXINIT"
        protections = {
            "transport": "SSH",
            "protocol": protocol,
            "host_key_algorithms": kex["server_host_key_algorithms"] if kex else None,
            "encryption": kex["encryption_client_to_server"] if kex else None,
            "kex": kex["kex_algorithms"] if kex else None,
            "authentication": "not-tested",
        }
        summary = f"SSH {software}"
        if kex:
            summary += f"; {len(kex['kex_algorithms'])} kex, {len(kex['server_host_key_algorithms'])} host-key algorithms"
        return ProbeResult("ssh", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("ssh", f"SSH probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# VNC / Telnet
# ---------------------------------------------------------------------------


VNC_SECURITY_TYPES = {
    0: "Invalid",
    1: "None",
    2: "VNC Authentication",
    5: "RA2",
    6: "RA2ne",
    16: "Tight",
    18: "TLS",
    19: "VeNCrypt",
    20: "SASL",
    21: "MD5",
    22: "xvp",
    30: "Apple Remote Desktop",
}


def probe_vnc(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    sock = None
    try:
        sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        version_raw = reader.read_exact(12)
        version_text = version_raw.decode("ascii", "replace").strip()
        data["server_version"] = version_text
        match = re.match(r"RFB (\d{3})\.(\d{3})", version_text)
        if not match:
            raise RuntimeError(f"unexpected VNC greeting: {version_text!r}")
        major, minor = int(match.group(1)), int(match.group(2))
        if (major, minor) >= (3, 7):
            sock.sendall(b"RFB 003.008\n")
            count_raw = reader.read_exact(1)
            count = count_raw[0]
            security_types: list[int] = []
            reason = ""
            if count == 0:
                reason_len = struct.unpack(">I", reader.read_exact(4))[0]
                reason = reader.read_exact(min(reason_len, 4096)).decode("utf-8", "replace")
            else:
                security_types = list(reader.read_exact(count))
        else:
            sock.sendall(b"RFB 003.003\n")
            security_types = [struct.unpack(">I", reader.read_exact(4))[0]]
            reason = ""
        data["security_types"] = [
            {"id": value, "name": VNC_SECURITY_TYPES.get(value, f"unknown({value})")}
            for value in security_types
        ]
        if reason:
            data["failure_reason"] = reason
        if 1 in security_types:
            findings.append(
                Finding(
                    "high",
                    "VNC_NO_AUTHENTICATION",
                    "VNC server offers the 'None' security type",
                    "A client can request no authentication and may obtain an interactive desktop session.",
                    {"security_types": security_types},
                )
            )
        if 2 in security_types:
            findings.append(
                Finding(
                    "info",
                    "VNC_PASSWORD_AUTH",
                    "VNC server uses the legacy VNC password challenge",
                    "The VNC authentication scheme truncates passwords to eight characters and uses DES.",
                    {"security_types": security_types},
                )
            )
        if 18 in security_types or 19 in security_types:
            findings.append(
                Finding(
                    "info",
                    "VNC_TLS_AVAILABLE",
                    "VNC server offers a TLS-capable security type",
                    "TLS/VeNCrypt may protect the session if the client selects it.",
                    {"security_types": security_types},
                )
            )
        if not security_types:
            findings.append(
                Finding(
                    "info",
                    "VNC_NO_SECURITY_TYPES",
                    "VNC server returned no security types",
                    reason or "The server may be refusing connections or require a different protocol version.",
                    {"reason": reason},
                )
            )
        protections = {
            "transport": "RFB (plaintext)",
            "authentication": "none" if 1 in security_types else "vnc-password" if 2 in security_types else "unknown",
            "security_types": security_types,
        }
        summary = f"VNC {version_text}; security=" + ",".join(
            VNC_SECURITY_TYPES.get(v, str(v)) for v in security_types
        )
        return ProbeResult("vnc", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("vnc", f"VNC probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


TELNET_OPTIONS = {
    0: "BINARY",
    1: "ECHO",
    2: "SUPPRESS-GO-AHEAD",
    3: "STATUS",
    4: "TIMING-MARK",
    5: "EXTENDED-OPTIONS",
    24: "TERMINAL-TYPE",
    31: "WINDOW-SIZE",
    32: "TERMINAL-SPEED",
    33: "REMOTE-FLOW-CONTROL",
    34: "LINEMODE",
    35: "X-DISPLAY-LOCATION",
    36: "ENVIRON",
    39: "NEW-ENVIRON",
}


def probe_telnet(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    sock = None
    try:
        sock = ctx.open_tcp()
        reader = LineReader(sock, ctx.read_timeout)
        raw = reader.read_some(8192, timeout=min(ctx.read_timeout, 1.5), idle=0.2)
        clean = bytearray()
        index = 0
        while index < len(raw):
            if raw[index] == 255 and index + 1 < len(raw):
                command = raw[index + 1]
                if command == 250:  # IAC SB ... IAC SE
                    end = raw.find(b"\xff\xf0", index + 2)
                    index = len(raw) if end < 0 else end + 2
                    continue
                if command in (251, 252, 253, 254):
                    index += 3
                    continue
                index += 2
                continue
            clean.append(raw[index])
            index += 1
        data["banner_preview"] = printable_preview(bytes(clean), 500)
        data["raw_hex"] = hex_preview(raw, 128)
        negotiations = []
        i = 0
        while i + 2 < len(raw):
            if raw[i] != 255:
                i += 1
                continue
            command = raw[i + 1]
            if command in (251, 252, 253, 254) and i + 2 < len(raw):
                option = raw[i + 2]
                negotiations.append(
                    {
                        "command": {251: "WILL", 252: "WONT", 253: "DO", 254: "DONT"}.get(command, str(command)),
                        "option": option,
                        "option_name": TELNET_OPTIONS.get(option, f"option-{option}"),
                    }
                )
                i += 3
            elif command == 250:  # subnegotiation
                end = raw.find(b"\xff\xf0", i + 2)
                i = len(raw) if end < 0 else end + 2
            else:
                i += 2
        data["negotiations"] = negotiations
        findings.append(
            Finding(
                "high",
                "TELNET_CLEARTEXT",
                "Telnet service is exposed",
                "Telnet transports credentials and session data without encryption and should be replaced by SSH.",
                {"port": ctx.port},
            )
        )
        if negotiations:
            findings.append(
                Finding(
                    "info",
                    "TELNET_OPTION_NEGOTIATION",
                    "Telnet option negotiation observed",
                    ", ".join(
                        f"{n['command']} {n['option_name']}" for n in negotiations[:10]
                    ),
                    {"negotiations": negotiations},
                )
            )
        protections = {
            "transport": "Telnet (cleartext)",
            "authentication": "not-tested",
            "options": negotiations,
        }
        summary = "Telnet"
        if data["banner_preview"]:
            summary += ": " + truncate(data["banner_preview"], 120)
        return ProbeResult("telnet", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("telnet", f"Telnet probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------


SMB2_DIALECTS = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

SMB_STATUS_NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BA: "STATUS_FILE_IS_A_DIRECTORY",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC00000CC: "STATUS_BAD_NETWORK_NAME",
}


def _nb_wrap(payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFF:
        raise ValueError("NetBIOS payload too large")
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _nb_read(reader: LineReader) -> bytes:
    header = reader.read_exact(4)
    length = int.from_bytes(header[1:4], "big")
    if length <= 0 or length > 4 * 1024 * 1024:
        raise ValueError(f"invalid NetBIOS payload length {length}")
    return reader.read_exact(length)


def _smb2_negotiate_request() -> bytes:
    header = (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + struct.pack("<H", 0)
        + struct.pack("<H", 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", 0)
        + b"\x00" * 16
    )
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = (
        struct.pack("<H", 36)
        + struct.pack("<H", len(dialects))
        + struct.pack("<H", 1)  # signing enabled, not required
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + os.urandom(16)
        + struct.pack("<Q", 0)
        + b"".join(struct.pack("<H", value) for value in dialects)
    )
    return _nb_wrap(header + body)


def _smb2_parse(packet: bytes) -> dict[str, Any]:
    if len(packet) < 64 or packet[:4] != b"\xfeSMB":
        raise ValueError("not an SMB2 packet")
    status = struct.unpack("<I", packet[8:12])[0]
    command = struct.unpack("<H", packet[12:14])[0]
    result: dict[str, Any] = {
        "status": status,
        "status_name": SMB_STATUS_NAMES.get(status, f"0x{status:08X}"),
        "command": command,
    }
    if status != 0:
        return result
    body = packet[64:]
    if len(body) < 64:
        raise ValueError("truncated SMB2 NEGOTIATE response")
    structure_size = struct.unpack("<H", body[0:2])[0]
    security_mode = struct.unpack("<H", body[2:4])[0]
    dialect = struct.unpack("<H", body[4:6])[0]
    result.update(
        {
            "structure_size": structure_size,
            "security_mode": security_mode,
            "signing_enabled": bool(security_mode & 0x01),
            "signing_required": bool(security_mode & 0x02),
            "dialect": dialect,
            "dialect_name": SMB2_DIALECTS.get(dialect, f"0x{dialect:04X}"),
            "server_guid": body[8:24].hex(),
            "capabilities": struct.unpack("<I", body[24:28])[0],
            "max_transact_size": struct.unpack("<I", body[28:32])[0],
            "max_read_size": struct.unpack("<I", body[32:36])[0],
            "max_write_size": struct.unpack("<I", body[36:40])[0],
        }
    )
    return result


def _smb1_negotiate_request() -> bytes:
    header = (
        b"\xffSMB"
        + b"\x72"
        + b"\x00" * 4
        + b"\x18"
        + struct.pack("<H", 0x0001)
        + struct.pack("<H", 0)
        + b"\x00" * 8
        + struct.pack("<H", 0)
        + struct.pack("<H", 0)
        + struct.pack("<H", 0xFFFF)
        + struct.pack("<H", 0)
        + struct.pack("<H", 0)
    )
    dialects = [
        "NT LM 0.12",
        "LANMAN2.1",
        "LM1.2X002",
        "PC NETWORK PROGRAM 1.0",
    ]
    data = b"".join(b"\x02" + dialect.encode("ascii") + b"\x00" for dialect in dialects)
    params = b"\x00" + struct.pack("<H", len(data)) + data
    return _nb_wrap(header + params)


def _smb1_parse(packet: bytes) -> dict[str, Any]:
    if len(packet) < 33 or packet[:4] != b"\xffSMB":
        raise ValueError("not an SMB1 packet")
    status = struct.unpack("<I", packet[5:9])[0]
    flags2 = struct.unpack("<H", packet[10:12])[0]
    result: dict[str, Any] = {
        "status": status,
        "status_name": SMB_STATUS_NAMES.get(status, f"0x{status:08X}"),
        "flags2": flags2,
        "extended_security": bool(flags2 & 0x0800),
    }
    word_count = packet[32]
    words_start = 33
    words_end = words_start + word_count * 2
    if words_end > len(packet):
        return result
    words = packet[words_start:words_end]
    if len(words) >= 4:
        result["dialect_index"] = struct.unpack("<H", words[0:2])[0]
        security_mode = struct.unpack("<H", words[2:4])[0]
        result["security_mode"] = security_mode
        result["signing_enabled"] = bool(security_mode & 0x04)
        result["signing_required"] = bool(security_mode & 0x08)
    if len(words) >= 24:
        result["capabilities"] = struct.unpack("<I", words[20:24])[0]
    if words_end + 2 <= len(packet):
        byte_count = struct.unpack("<H", packet[words_end : words_end + 2])[0]
        data_start = words_end + 2
        data = packet[data_start : data_start + byte_count]
        result["data_bytes"] = len(data)
        if result.get("extended_security") and len(data) >= 16:
            result["server_guid"] = data[:16].hex()
        elif data:
            result["data_preview"] = hex_preview(data, 64)
    return result


def probe_smb(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    sock = None
    try:
        parsed: dict[str, Any] = {}
        try:
            sock = ctx.open_tcp()
            sock.sendall(_smb2_negotiate_request())
            reader = LineReader(sock, ctx.read_timeout)
            packet = _nb_read(reader)
            parsed = _smb2_parse(packet)
            data["smb2"] = parsed
        except Exception as exc:
            # An SMB1-only server may close the connection or answer with an
            # SMB1 packet. Fall through to the legacy negotiation.
            data["smb2_error"] = short_exc(exc)
        if parsed.get("status") == 0:
            dialect = parsed.get("dialect_name", "")
            if not parsed.get("signing_required"):
                findings.append(
                    Finding(
                        "medium",
                        "SMB_SIGNING_NOT_REQUIRED",
                        "SMB signing is not required",
                        "The server negotiated SMB2/3 without the signing-required bit, allowing unsigned sessions.",
                        {"security_mode": parsed.get("security_mode"), "dialect": dialect},
                    )
                )
            if parsed.get("signing_required"):
                findings.append(
                    Finding(
                        "info",
                        "SMB_SIGNING_REQUIRED",
                        "SMB signing is required",
                        "The server set the signing-required bit.",
                        {"dialect": dialect},
                    )
                )
            if parsed.get("dialect") in {0x0202, 0x0210}:
                findings.append(
                    Finding(
                        "low",
                        "SMB_LEGACY_DIALECT",
                        "SMB server negotiated a legacy dialect",
                        f"Negotiated dialect: {dialect}. SMB 3.x is preferred.",
                        {"dialect": dialect},
                    )
                )
            protections = {
                "transport": "SMB2/3",
                "dialect": dialect,
                "signing_enabled": parsed.get("signing_enabled"),
                "signing_required": parsed.get("signing_required"),
                "authentication": "not-tested",
            }
            summary = f"SMB2/3 {dialect}; signing " + (
                "required" if parsed.get("signing_required") else "not required"
            )
            return ProbeResult("smb", summary, data=data, findings=findings, protections=protections)
        # SMB2 failed: try SMB1 for legacy Metasploitable-style targets.
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        sock = ctx.open_tcp()
        sock.sendall(_smb1_negotiate_request())
        reader = LineReader(sock, ctx.read_timeout)
        packet = _nb_read(reader)
        parsed1 = _smb1_parse(packet)
        data["smb1"] = parsed1
        if parsed1.get("status") == 0:
            findings.append(
                Finding(
                    "high",
                    "SMB1_ENABLED",
                    "SMB1 is enabled",
                    "SMB1 is obsolete and has a long history of critical vulnerabilities; disable it unless a legacy requirement is documented.",
                    {"dialect_index": parsed1.get("dialect_index")},
                )
            )
            if not parsed1.get("signing_required"):
                findings.append(
                    Finding(
                        "medium",
                        "SMB1_SIGNING_NOT_REQUIRED",
                        "SMB1 signing is not required",
                        "Unsigned SMB1 sessions are susceptible to tampering.",
                        {"security_mode": parsed1.get("security_mode")},
                    )
                )
            protections = {
                "transport": "SMB1",
                "signing_enabled": parsed1.get("signing_enabled"),
                "signing_required": parsed1.get("signing_required"),
                "authentication": "not-tested",
            }
            summary = "SMB1 enabled; signing " + (
                "required" if parsed1.get("signing_required") else "not required"
            )
            return ProbeResult("smb", summary, data=data, findings=findings, protections=protections)
        raise RuntimeError(
            "SMB2: "
            + (
                str(parsed.get("status_name"))
                if parsed
                else data.get("smb2_error", "no usable response")
            )
            + f"; SMB1: {parsed1.get('status_name')}"
        )
    except Exception as exc:
        return ProbeResult("smb", f"SMB probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------


def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(value: int) -> bytes:
    if value == 0:
        raw = b"\x00"
    elif value > 0:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    else:
        length = max(1, (value.bit_length() + 8) // 8)
        raw = value.to_bytes(length, "big", signed=True)
    return _ber_tlv(0x02, raw)


def _ber_octet(value: bytes) -> bytes:
    return _ber_tlv(0x04, value)


def _ber_oid(parts: Iterable[int]) -> bytes:
    values = list(parts)
    if len(values) < 2:
        raise ValueError("OID needs at least two arcs")
    encoded = bytearray([values[0] * 40 + values[1]])
    for value in values[2:]:
        chunk = bytearray([value & 0x7F])
        value >>= 7
        while value:
            chunk.insert(0, 0x80 | (value & 0x7F))
            value >>= 7
        encoded.extend(chunk)
    return _ber_tlv(0x06, bytes(encoded))


def _ber_read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated BER header")
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("invalid BER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = first
    if offset + length > len(data):
        raise ValueError("truncated BER value")
    return tag, data[offset : offset + length], offset + length


def _ber_read_stream(reader: LineReader) -> tuple[int, bytes]:
    tag = reader.read_exact(1)[0]
    first = reader.read_exact(1)[0]
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise ValueError("invalid BER length")
        length = int.from_bytes(reader.read_exact(count), "big")
    else:
        length = first
    if length > 8 * 1024 * 1024:
        raise ValueError("BER message too large")
    return tag, reader.read_exact(length)


def _ber_children(value: bytes) -> list[tuple[int, bytes]]:
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, child, offset = _ber_read_tlv(value, offset)
        children.append((tag, child))
    return children


def probe_ldap(ctx: ProbeContext, tls_initial: bool) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    tls_info: Optional[dict[str, Any]] = None
    sock = None
    try:
        if tls_initial:
            sock, _ = ctx.open_tls()
            tls_info = tls_metadata(sock, ctx.tls_hostname)
            if ctx.tls_matrix:
                tls_info["versions"] = probe_tls_versions(ctx)
            data["tls"] = tls_info
            findings.extend(tls_findings(tls_info))
        else:
            sock = ctx.open_tcp()
        bind_request = _ber_tlv(
            0x60,
            _ber_int(3) + _ber_octet(b"") + _ber_tlv(0x80, b""),
        )
        message = _ber_tlv(0x30, _ber_int(1) + bind_request)
        sock.sendall(message)
        reader = LineReader(sock, ctx.read_timeout)
        tag, value = _ber_read_stream(reader)
        if tag != 0x30:
            raise RuntimeError(f"unexpected LDAP response tag 0x{tag:02x}")
        children = _ber_children(value)
        result_code = None
        diagnostic = ""
        matched_dn = ""
        if len(children) >= 2:
            op_tag, op_value = children[1]
            if op_tag == 0x61:
                op_children = _ber_children(op_value)
                for child_tag, child_value in op_children:
                    if child_tag == 0x0A and child_value:
                        result_code = int.from_bytes(child_value, "big", signed=True)
                    elif child_tag == 0x04:
                        text = child_value.decode("utf-8", "replace")
                        if not matched_dn:
                            matched_dn = text
                        else:
                            diagnostic = text
        data.update(
            {
                "result_code": result_code,
                "matched_dn": matched_dn,
                "diagnostic_message": diagnostic,
            }
        )
        if result_code == 0:
            findings.append(
                Finding(
                    "medium",
                    "LDAP_ANONYMOUS_BIND",
                    "LDAP permits anonymous bind",
                    "The server accepted an empty distinguished name and password.",
                    {"result_code": result_code},
                )
            )
        elif result_code == 49:
            findings.append(
                Finding(
                    "info",
                    "LDAP_AUTH_REQUIRED",
                    "LDAP requires authentication for bind",
                    "The server returned invalidCredentials for an anonymous bind.",
                    {"result_code": result_code},
                )
            )
        elif result_code is not None:
            findings.append(
                Finding(
                    "info",
                    "LDAP_BIND_REFUSED",
                    "LDAP bind was refused",
                    f"Result code {result_code}: {truncate(diagnostic, 300)}",
                    {"result_code": result_code, "diagnostic": diagnostic},
                )
            )
        try:
            sock.sendall(_ber_tlv(0x30, _ber_int(2) + _ber_tlv(0x42, b"")))
        except OSError:
            pass
        protections = {
            "transport": "TLS" if tls_initial else "cleartext",
            "tls_version": tls_info.get("version") if tls_info else None,
            "authentication": "anonymous-allowed" if result_code == 0 else "required",
        }
        summary = "LDAP " + (
            "anonymous bind accepted" if result_code == 0 else f"bind result={result_code}"
        )
        return ProbeResult("ldap", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("ldap", f"LDAP probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# NTP / SNMP
# ---------------------------------------------------------------------------


def probe_ntp(ctx: ProbeContext) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    try:
        now = time.time() + 2208988800
        seconds = int(now)
        fraction = int((now - seconds) * (2**32))
        request = bytearray(48)
        request[0] = 0x23  # LI=0, VN=4, Mode=3 (client)
        request[40:48] = struct.pack(">II", seconds & 0xFFFFFFFF, fraction & 0xFFFFFFFF)
        response = ctx.udp_exchange(bytes(request))
        if len(response) < 48:
            raise RuntimeError(f"NTP response too short ({len(response)} bytes)")
        first = response[0]
        leap = (first >> 6) & 0x03
        version = (first >> 3) & 0x07
        mode = first & 0x07
        stratum = response[1]
        poll = struct.unpack("b", response[2:3])[0]
        precision = struct.unpack("b", response[3:4])[0]
        refid = response[12:16]
        try:
            refid_text = refid.decode("ascii")
            if not refid_text.isprintable():
                refid_text = refid.hex()
        except UnicodeDecodeError:
            refid_text = refid.hex()
        data.update(
            {
                "leap": leap,
                "version": version,
                "mode": mode,
                "stratum": stratum,
                "poll": poll,
                "precision": precision,
                "refid": refid_text,
            }
        )
        if mode != 4:
            findings.append(
                Finding(
                    "info",
                    "NTP_UNEXPECTED_MODE",
                    "NTP response has an unexpected mode",
                    f"Mode {mode} (expected server mode 4).",
                    {"mode": mode},
                )
            )
        if stratum == 0:
            findings.append(
                Finding(
                    "info",
                    "NTP_KISS_CODE",
                    "NTP server returned a kiss-o'-death or unsynchronized status",
                    f"Reference ID: {refid_text}",
                    {"refid": refid_text},
                )
            )
        else:
            findings.append(
                Finding(
                    "info",
                    "NTP_SERVICE",
                    "NTP service responded",
                    f"Version {version}, stratum {stratum}, reference ID {refid_text}.",
                    {"stratum": stratum, "refid": refid_text},
                )
            )
        protections = {"transport": "UDP", "authentication": "not-tested", "stratum": stratum}
        summary = f"NTP v{version} stratum={stratum} refid={refid_text}"
        return ProbeResult("ntp", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("ntp", f"NTP probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))


def _snmp_value_to_text(tag: int, value: bytes) -> Any:
    if tag == 0x04:
        return value.decode("utf-8", "replace")
    if tag == 0x02:
        return int.from_bytes(value, "big", signed=True) if value else 0
    if tag in (0x41, 0x42, 0x43):
        return int.from_bytes(value, "big") if value else 0
    if tag == 0x06:
        return value.hex(".")
    if tag == 0x40:
        return socket.inet_ntop(socket.AF_INET, value) if len(value) == 4 else value.hex()
    return value.hex(" ")


def probe_snmp(ctx: ProbeContext, community: str) -> ProbeResult:
    findings: list[Finding] = []
    data: dict[str, Any] = {"community_tested": community}
    try:
        varbind = _ber_tlv(
            0x30,
            _ber_oid([1, 3, 6, 1, 2, 1, 1, 1, 0]) + _ber_tlv(0x05, b""),
        )
        get_pdu = _ber_tlv(
            0xA0,
            _ber_int(random.randint(1, 2**31 - 1))
            + _ber_int(0)
            + _ber_int(0)
            + _ber_tlv(0x30, varbind),
        )
        message = _ber_tlv(0x30, _ber_int(1) + _ber_octet(community.encode()) + get_pdu)
        response = ctx.udp_exchange(message)
        tag, value, _ = _ber_read_tlv(response, 0)
        if tag != 0x30:
            raise RuntimeError("not an SNMP BER sequence")
        children = _ber_children(value)
        if len(children) < 3:
            raise RuntimeError("truncated SNMP response")
        pdu_tag, pdu_value = children[2]
        if pdu_tag not in (0xA2, 0xA0):
            raise RuntimeError(f"unexpected SNMP PDU tag 0x{pdu_tag:02x}")
        pdu_children = _ber_children(pdu_value)
        error_status = 0
        error_index = 0
        sys_descr = None
        if len(pdu_children) >= 2:
            error_status = int.from_bytes(pdu_children[1][1], "big", signed=True) if pdu_children[1][1] else 0
        if len(pdu_children) >= 3:
            error_index = int.from_bytes(pdu_children[2][1], "big", signed=True) if pdu_children[2][1] else 0
        if len(pdu_children) >= 4:
            varbinds = _ber_children(pdu_children[3][1])
            if varbinds:
                vb_children = _ber_children(varbinds[0][1])
                if len(vb_children) >= 2:
                    sys_descr = _snmp_value_to_text(*vb_children[1])
        data.update(
            {
                "error_status": error_status,
                "error_index": error_index,
                "sys_descr": sys_descr,
            }
        )
        if error_status:
            findings.append(
                Finding(
                    "info",
                    "SNMP_ERROR",
                    "SNMP GET returned an error",
                    f"error-status={error_status}, error-index={error_index}",
                    {"error_status": error_status},
                )
            )
        elif sys_descr:
            findings.append(
                Finding(
                    "medium",
                    "SNMP_READABLE",
                    "SNMP sysDescr is readable with the supplied community",
                    f"sysDescr.0: {truncate(sys_descr, 500)}",
                    {"community": community, "sys_descr": sys_descr},
                )
            )
            if community.lower() in {"public", "private", "community"}:
                findings.append(
                    Finding(
                        "high",
                        "SNMP_DEFAULT_COMMUNITY",
                        "SNMP default community string is accepted",
                        f"The community string {community!r} is a well-known default.",
                        {"community": community},
                    )
                )
        protections = {
            "transport": "UDP",
            "authentication": "community-string",
            "readable": bool(sys_descr),
        }
        summary = f"SNMP sysDescr={truncate(sys_descr, 120)}" if sys_descr else "SNMP response without sysDescr"
        return ProbeResult("snmp", summary, data=data, findings=findings, protections=protections)
    except Exception as exc:
        return ProbeResult("snmp", f"SNMP probe failed: {short_exc(exc)}", data=data, findings=findings, error=short_exc(exc))


# ---------------------------------------------------------------------------
# Probe dispatch and per-port diagnosis
# ---------------------------------------------------------------------------


def dispatch_probe(rec: PortRecord, ctx: ProbeContext, config: Config) -> ProbeResult:
    service = rec.service_guess
    tls = rec.tls_initial
    if rec.protocol == "udp":
        if service == "dns" or rec.port == 53:
            return probe_dns(ctx, tls)
        if service == "ntp":
            return probe_ntp(ctx)
        if service == "snmp":
            if config.snmp_community:
                return probe_snmp(ctx, config.snmp_community)
            return ProbeResult(
                "snmp",
                "SNMP/UDP port selected; supply --snmp-community to query sysDescr.0",
                data={"community_configured": False},
                protections={"transport": "UDP", "authentication": "not-tested"},
            )
        return ProbeResult(
            "udp",
            "UDP port selected; no safe generic payload exists for this service",
            data={"note": "Use Nmap version detection or a protocol-specific tool."},
            protections={"transport": "UDP"},
        )

    if service in {"http", "https", "docker", "elasticsearch", "kubernetes"}:
        return probe_http(ctx, tls, service)
    if service == "ssh":
        return probe_ssh(ctx)
    if service == "ftp":
        return probe_ftp(ctx, tls)
    if service == "smtp":
        return probe_smtp(ctx, tls)
    if service == "imap":
        return probe_imap(ctx, tls)
    if service == "pop3":
        return probe_pop3(ctx, tls)
    if service == "dns":
        return probe_dns(ctx, tls)
    if service == "rdp":
        return probe_rdp(ctx)
    if service == "mysql":
        return probe_mysql(ctx)
    if service == "postgres":
        return probe_postgres(ctx)
    if service == "redis":
        return probe_redis(ctx, tls)
    if service == "memcached":
        return probe_memcached(ctx, tls)
    if service == "mongodb":
        return probe_mongodb(ctx, tls)
    if service == "vnc":
        return probe_vnc(ctx)
    if service == "telnet":
        return probe_telnet(ctx)
    if service == "smb":
        return probe_smb(ctx)
    if service == "ldap":
        return probe_ldap(ctx, tls)
    if service == "ntp":
        return ProbeResult(
            "ntp",
            "NTP is a UDP service; re-run with --protocol udp",
            protections={"transport": "UDP"},
        )
    if service == "snmp":
        return ProbeResult(
            "snmp",
            "SNMP is a UDP service; re-run with --protocol udp and --snmp-community",
            protections={"transport": "UDP"},
        )
    if service in {"unknown", "tcpwrapped"} and config.http_fallback:
        return probe_http(ctx, tls, "http")
    if tls:
        return probe_tls_generic(ctx)
    return probe_generic(ctx, rec.nmap)


def _error_kind(exc: BaseException) -> str:
    if isinstance(exc, socket.gaierror):
        return "dns-error"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "closed"
    if isinstance(exc, OSError):
        import errno

        if exc.errno in {errno.ECONNREFUSED}:
            return "closed"
        if exc.errno in {errno.ETIMEDOUT}:
            return "timeout"
        if exc.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH}:
            return "unreachable"
        if exc.errno in {errno.EACCES, errno.EPERM}:
            return "local-error"
        return "error"
    return "error"


def tcp_liveness(ctx: ProbeContext, attempts: int) -> tuple[str, list[dict[str, Any]], Optional[float], Optional[str]]:
    records: list[dict[str, Any]] = []
    connect_ms: Optional[float] = None
    last_error: Optional[str] = None
    for index in range(max(1, attempts)):
        started = time.monotonic()
        try:
            sock = ctx.open_tcp()
            elapsed = (time.monotonic() - started) * 1000
            sock.close()
            records.append({"attempt": index + 1, "outcome": "open", "ms": round(elapsed, 2)})
            connect_ms = elapsed
            return "open", records, connect_ms, None
        except Exception as exc:
            elapsed = (time.monotonic() - started) * 1000
            kind = _error_kind(exc)
            last_error = short_exc(exc)
            records.append(
                {
                    "attempt": index + 1,
                    "outcome": kind,
                    "ms": round(elapsed, 2),
                    "error": last_error,
                }
            )
            if kind in {"closed", "unreachable", "local-error", "dns-error"}:
                return ("closed" if kind == "closed" else kind), records, None, last_error
    if records and all(r["outcome"] == "timeout" for r in records):
        return "filtered", records, None, last_error
    return "filtered", records, None, last_error


def _state_finding(rec: PortRecord) -> Optional[Finding]:
    nmap_state = rec.nmap_state
    live = rec.live_state
    if nmap_state == "unknown" or live == "unknown":
        return None
    if nmap_state in {"open", "open|filtered"} and live != "open":
        return Finding(
            "medium",
            "NMAP_STATE_CHANGED",
            "Port state changed since the Nmap scan",
            f"Nmap reported {nmap_state!r} ({rec.nmap_reason or 'no reason'}), "
            f"but the live TCP handshake ended as {live!r}.",
            {"nmap_state": nmap_state, "live_state": live, "attempts": rec.attempts},
        )
    if nmap_state in {"filtered", "closed"} and live == "open":
        return Finding(
            "info",
            "NMAP_STATE_OPEN_NOW",
            "Port accepted a TCP connection despite the Nmap state",
            f"Nmap reported {nmap_state!r} ({rec.nmap_reason or 'no reason'}); "
            "the live handshake succeeded. This may reflect scan timing, a stateful "
            "firewall, or a service that started after the Nmap scan.",
            {"nmap_state": nmap_state, "live_state": live},
        )
    return None


def diagnose_port(
    address: str,
    hostname: Optional[str],
    nmap_port: Optional[NmapPort],
    config: Config,
    pacer: Pacer,
) -> PortRecord:
    port = nmap_port.port if nmap_port else 0
    proto = nmap_port.protocol if nmap_port else config.protocol
    rec = PortRecord(
        address=address,
        port=port,
        protocol=proto,
        nmap=nmap_port,
        hostname=hostname,
    )
    started = time.monotonic()
    override = config.service_overrides.get((proto, port))
    rec.service_guess = infer_service(nmap_port, override)
    rec.tls_initial = infer_tls_initial(nmap_port, rec.service_guess, port)
    ctx = ProbeContext(
        host=address,
        port=port,
        protocol=proto,
        connect_timeout=config.connect_timeout,
        read_timeout=config.read_timeout,
        pacer=pacer,
        sni=config.sni,
        max_body=config.max_body,
        user_agent=config.user_agent,
        http_path=config.http_path,
        tls_matrix=config.tls_matrix,
        snmp_community=config.snmp_community,
        hostname=hostname,
    )
    if nmap_port and nmap_port.scripts:
        rec.notes.append("Nmap scripts: " + ", ".join(sorted(nmap_port.scripts)))
    try:
        if proto == "tcp":
            live, attempts, connect_ms, last_error = tcp_liveness(ctx, config.attempts)
            rec.live_state = live
            rec.attempts = attempts
            rec.connect_ms = connect_ms
            if last_error and live != "open":
                rec.notes.append(f"Last connect error: {last_error}")
            if live == "open":
                probe = dispatch_probe(rec, ctx, config)
                rec.probe = probe
                merge_findings(rec.findings, probe.findings)
                if probe.error:
                    rec.notes.append(f"Probe error: {probe.error}")
            else:
                rec.notes.append(
                    f"No completed TCP handshake after {len(attempts)} attempt(s); "
                    "this is consistent with a drop filter, host-side block, or service outage."
                )
        else:
            # UDP has no handshake. A response means open; silence is ambiguous.
            probe = dispatch_probe(rec, ctx, config)
            rec.probe = probe
            merge_findings(rec.findings, probe.findings)
            if probe.error:
                rec.live_state = "open|filtered" if "timed out" in probe.error.lower() else "unknown"
            elif probe.protocol in {"dns", "ntp", "snmp"} and not (
                probe.protocol == "snmp" and probe.data.get("community_configured") is False
            ):
                rec.live_state = "open"
            else:
                rec.live_state = nmap_port.state if nmap_port else "unknown"
            if probe.error:
                rec.notes.append(f"Probe error: {probe.error}")
        state_finding = _state_finding(rec)
        if state_finding:
            rec.findings.append(state_finding)
        if nmap_port and nmap_port.service == "tcpwrapped" and rec.live_state == "open":
            rec.notes.append(
                "Nmap classified the service as tcpwrapped; the live TCP handshake succeeded, "
                "but application data may require a specific source or handshake."
            )
    except Exception as exc:
        rec.error = short_exc(exc)
        rec.notes.append(f"Diagnosis failed: {rec.error}")
    finally:
        rec.elapsed_ms = (time.monotonic() - started) * 1000
    return rec


def _selected_ports(host: HostRecord, config: Config) -> list[NmapPort]:
    selected: list[NmapPort] = []
    for port in host.ports:
        if config.protocol != "both" and port.protocol != config.protocol:
            continue
        if not config.states_explicit:
            if port.state == "unknown":
                selected.append(port)
            elif port.state in config.states:
                selected.append(port)
        elif port.state in config.states:
            selected.append(port)
    return sorted(selected, key=lambda p: (p.protocol, p.port))


def diagnose_host(host: HostRecord, config: Config, pacer: Pacer) -> HostRecord:
    if host.status == "down" and not config.include_down:
        host.notes.append("Host is marked down in Nmap; use --include-down to probe anyway.")
        host.ports = []
        return host
    selected = _selected_ports(host, config)
    if not selected:
        host.notes.append(
            "No ports matched the requested protocol/state filter. "
            "Try --states all or --include-closed."
        )
        host.ports = []
        return host
    records = [
        PortRecord(
            address=host.address,
            port=port.port,
            protocol=port.protocol,
            nmap=port,
            hostname=host.hostname,
        )
        for port in selected
    ]
    # Replace Nmap's port objects with enriched diagnosis records.
    host.ports = []
    if config.verbose:
        print(
            f"[*] {host.address}: diagnosing {len(records)} port(s) with profile {config.profile.name}",
            file=sys.stderr,
        )
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, config.workers)) as executor:
        futures = [
            executor.submit(diagnose_port, host.address, host.hostname, port, config, pacer)
            for port in selected
        ]
        for record, future in zip(records, futures):
            try:
                result = future.result()
            except Exception as exc:  # defensive; diagnose_port catches most errors
                result = record
                result.error = short_exc(exc)
                result.notes.append(f"Worker failure: {result.error}")
            host.ports.append(result)
            if config.verbose:
                summary = result.probe.summary if result.probe else result.live_state
                print(
                    f"    {result.port}/{result.protocol} {result.live_state}: {truncate(summary, 140)}",
                    file=sys.stderr,
                )
    host.ports.sort(key=lambda p: (p.protocol, p.port))
    return host


def make_direct_host(target: str, ports_spec: str, config: Config) -> HostRecord:
    ports = parse_ports(ports_spec)
    host = HostRecord(address=target, hostname=None if is_ip_literal(target) else target, status="up")
    protocols = ["tcp", "udp"] if config.protocol == "both" else [config.protocol]
    for proto in protocols:
        for port in ports:
            host.ports.append(
                NmapPort(
                    port=port,
                    protocol=proto,
                    state="unknown",
                    service="",
                )
            )
    return host


def enforce_port_limit(hosts: list[HostRecord], config: Config) -> None:
    total = 0
    for host in hosts:
        total += len(_selected_ports(host, config))
    if config.max_ports > 0 and total > config.max_ports:
        raise ValueError(
            f"{total} ports selected, above --max-ports {config.max_ports}; "
            "narrow the port list or raise the limit deliberately"
        )


# ---------------------------------------------------------------------------
# Optional Nmap NSE script execution and vulnerability hints
# ---------------------------------------------------------------------------


def parse_nse_scripts(value: str) -> list[str]:
    names = [item.strip() for item in re.split(r"[, ]+", value or "") if item.strip()]
    if not names:
        return []
    unknown = [name for name in names if name not in SAFE_NSE_SCRIPTS]
    if unknown:
        unsafe = [
            name
            for name in unknown
            if any(
                token in name.lower()
                for token in (
                    "brute",
                    "exploit",
                    "flood",
                    "dos",
                    "backdoor",
                    "psexec",
                    "cmdshell",
                    "query",
                    "dump",
                )
            )
        ]
        if unsafe:
            raise ValueError(
                "refusing to auto-run intrusive/credential scripts: "
                + ", ".join(unsafe)
                + ". PortScope only executes its curated low-impact script set; "
                "review and run intrusive scripts yourself after authorization."
            )
        raise ValueError(
            "unsupported NSE script(s): "
            + ", ".join(unknown)
            + ". Allowed low-impact scripts are listed in README.md."
        )
    return list(dict.fromkeys(names))


def nse_scripts_for_host(host: HostRecord, config: Config) -> list[str]:
    if config.nse_scripts:
        return list(config.nse_scripts)
    scripts: set[str] = set()
    for port in host.ports:
        if port.live_state != "open" or port.protocol != "tcp":
            continue
        scripts.update(NSE_SAFE_BY_SERVICE.get(port.service_guess, []))
        if port.tls_initial:
            scripts.add("ssl-cert")
    return sorted(scripts)


def apply_nse_findings(record: PortRecord) -> None:
    findings: list[Finding] = []
    for script, output in record.nse.items():
        lower = output.lower()
        if script == "ftp-anon" and "anonymous ftp login allowed" in lower:
            findings.append(
                Finding(
                    "high",
                    "NSE_FTP_ANONYMOUS",
                    "Nmap NSE confirmed anonymous FTP access",
                    truncate(output, 500),
                    {"script": script, "output": truncate(output, 1000)},
                )
            )
        if "not vulnerable" in lower:
            continue
        if re.search(r"\bVULNERABLE\b", output):
            findings.append(
                Finding(
                    "high",
                    "NSE_SCRIPT_VULNERABLE",
                    f"Nmap NSE reported a vulnerable state: {script}",
                    truncate(output, 500),
                    {"script": script, "output": truncate(output, 1500)},
                )
            )
    merge_findings(record.findings, findings)


def run_nse_for_host(host: HostRecord, config: Config) -> None:
    if not config.run_nse:
        return
    if not host.ports:
        host.nse_error = "NSE not run: no diagnosed ports."
        return
    open_ports = sorted(
        {
            port.port
            for port in host.ports
            if port.live_state == "open" and port.protocol == "tcp"
        }
    )
    if not open_ports:
        host.nse_error = "NSE not run: no open TCP ports."
        return
    scripts = nse_scripts_for_host(host, config)
    if not scripts:
        host.nse_error = "NSE not run: no safe scripts matched the observed services."
        return
    nmap_bin = shutil.which(config.nmap_bin) if not os.path.isabs(config.nmap_bin) else config.nmap_bin
    if not nmap_bin or not Path(nmap_bin).exists():
        host.nse_error = f"NSE not run: Nmap executable not found ({config.nmap_bin!r})."
        return
    timing = {"fast": "-T4", "polite": "-T3", "slow": "-T2"}.get(config.profile.name, "-T3")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="portscope-nse-") as tmp:
        xml_path = os.path.join(tmp, "nse.xml")
        command = [
            nmap_bin,
            "-Pn",
            "-n",
            "-sV",
            "--version-light",
            timing,
            "-p",
            ",".join(str(port) for port in open_ports),
            "--script",
            ",".join(scripts),
            "--script-timeout",
            f"{config.script_timeout:g}s",
            "-oX",
            xml_path,
            host.address,
        ]
        host.nse_command = " ".join(shlex.quote(part) for part in command)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=config.nse_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            host.nse_error = f"NSE timed out after {config.nse_timeout:g}s."
            host.nse_elapsed_ms = (time.monotonic() - started) * 1000
            return
        except FileNotFoundError:
            host.nse_error = f"NSE not run: Nmap executable not found ({config.nmap_bin!r})."
            host.nse_elapsed_ms = (time.monotonic() - started) * 1000
            return
        except OSError as exc:
            host.nse_error = f"NSE failed to start: {short_exc(exc)}"
            host.nse_elapsed_ms = (time.monotonic() - started) * 1000
            return
        host.nse_elapsed_ms = (time.monotonic() - started) * 1000
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            host.nse_error = (
                f"Nmap NSE exited {completed.returncode}"
                + (f": {truncate(detail, 500)}" if detail else ".")
            )
        if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
            if not host.nse_error:
                host.nse_error = "Nmap NSE produced no XML output."
            return
        try:
            nse_hosts = parse_nmap_xml(xml_path)
        except ValueError as exc:
            host.nse_error = f"Cannot parse NSE XML: {short_exc(exc)}"
            return
    by_key = {(port.protocol, port.port): port for port in host.ports}
    merged = 0
    host_findings: list[Finding] = []
    for nse_host in nse_hosts:
        if nse_host.nse_host:
            host.nse_host.update(nse_host.nse_host)
            merged += len(nse_host.nse_host)
            for script, output in nse_host.nse_host.items():
                if "not vulnerable" in output.lower():
                    continue
                if re.search(r"\bVULNERABLE\b", output):
                    host_findings.append(
                        Finding(
                            "high",
                            "NSE_SCRIPT_VULNERABLE",
                            f"Nmap NSE reported a vulnerable state: {script}",
                            truncate(output, 500),
                            {"script": script, "output": truncate(output, 1500)},
                        )
                    )
        for nse_port in nse_host.ports:
            record = by_key.get((nse_port.protocol, nse_port.port))
            scripts = {
                key: value
                for key, value in nse_port.scripts.items()
                if key != "fingerprint-strings"
            }
            if record is None or not scripts:
                continue
            record.nse.update(scripts)
            merged += len(scripts)
            apply_nse_findings(record)
    merge_findings(host.findings, host_findings)
    if merged == 0 and not host.nse_error:
        host.nse_error = "Nmap NSE completed but returned no script output."
    if config.verbose:
        print(
            f"    NSE: {len(scripts)} script(s), {merged} result(s)"
            + (f" ({host.nse_error})" if host.nse_error else ""),
            file=sys.stderr,
        )


def _port_hint_text(record: PortRecord) -> str:
    pieces: list[str] = [record.service_guess]
    if record.nmap:
        pieces.extend(
            [
                record.nmap.service,
                record.nmap.product,
                record.nmap.version,
                record.nmap.extrainfo,
            ]
        )
    if record.probe:
        pieces.append(record.probe.summary)
        for key in ("banner", "server", "title", "version", "response"):
            value = record.probe.data.get(key)
            if value:
                pieces.append(str(value))
    pieces.extend(record.nse.values())
    return " ".join(part for part in pieces if part).lower()


def _nmap_version_tuple(text: str) -> Optional[tuple[int, ...]]:
    match = re.search(r"(\d+(?:\.\d+){1,3})", text)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def build_vulnerability_hints(record: PortRecord) -> list[VulnerabilityHint]:
    svc = record.service_guess
    text = _port_hint_text(record)
    codes = {finding.code for finding in record.findings}
    hints: list[VulnerabilityHint] = []

    def add(
        category: str,
        likelihood: str,
        title: str,
        rationale: str,
        scripts: Optional[list[str]] = None,
        references: Optional[list[str]] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> None:
        if len(hints) >= 9:
            return
        if any(hint.category == category and hint.title == title for hint in hints):
            return
        hints.append(
            VulnerabilityHint(
                category=category,
                likelihood=likelihood,
                title=title,
                rationale=rationale,
                suggested_scripts=scripts or [],
                references=references or [],
                evidence=evidence or {},
            )
        )

    if svc in {"http", "https"}:
        add(
            "Injection",
            "test",
            "SQL/command injection candidate",
            "This is an HTTP application surface. PortScope did not send injection "
            "payloads; use authorized application testing for SQL, command, template, "
            "and deserialization injection.",
            ["http-sql-injection"],
            ["OWASP Top 10 A03:2021"],
        )
        add(
            "Authentication",
            "test",
            "Login brute-force / weak credentials candidate",
            "If the application exposes a login, test rate limiting, lockout, default "
            "accounts, and weak passwords under an approved credential-audit plan.",
            ["http-brute", "http-form-brute"],
        )

    if svc in {"mysql", "postgres", "mssql", "oracle"}:
        scripts = {
            "mysql": ["mysql-info", "mysql-brute", "mysql-empty-password"],
            "postgres": ["pgsql-brute"],
            "mssql": ["ms-sql-info", "ms-sql-brute", "ms-sql-empty-password"],
            "oracle": ["oracle-brute", "oracle-sid-brute"],
        }.get(svc, [])
        add(
            "Database access",
            "possible",
            "SQL service weak-credential / data-exposure candidate",
            "A database listener is directly reachable. Test for weak, default, or "
            "blank credentials only with authorization; brute-force scripts can lock "
            "accounts and are not executed by PortScope.",
            scripts,
        )
        if "POSTGRES_TRUST_AUTH" in codes:
            add(
                "Database access",
                "likely",
                "PostgreSQL trust authentication observed",
                "The server accepted a startup without a password challenge. Confirm "
                "which accounts and databases are reachable.",
                ["pgsql-brute"],
            )

    if svc == "ssh":
        add(
            "Authentication",
            "possible",
            "SSH password brute-force candidate",
            "SSH exposes an authentication surface. Password spraying and brute force "
            "can lock or alert; run a rate-limited authorized audit, not an automatic "
            "high-volume attack.",
            ["ssh-brute", "ssh-auth-methods"],
        )
        if "SSH_WEAK_ALGORITHMS" in codes or "SSH_PROTOCOL_1" in codes:
            add(
                "Cryptography",
                "possible",
                "Legacy SSH algorithms or protocol",
                "The server advertised weak/legacy algorithms or SSH protocol 1. "
                "Validate the policy and client compatibility before disabling them.",
                ["ssh2-enum-algos", "sshv1"],
            )

    if svc == "ftp":
        add(
            "Access control",
            "likely" if "NSE_FTP_ANONYMOUS" in codes else "possible",
            "Anonymous FTP / weak-credential candidate",
            "Test anonymous access and weak FTP credentials only with authorization. "
            "The safe NSE profile can confirm anonymous login with ftp-anon.",
            ["ftp-anon", "ftp-brute"],
        )
        if "vsftpd 2.3.4" in text:
            add(
                "Backdoor",
                "likely",
                "vsftpd 2.3.4 backdoor signature",
                "The banner matches the vsftpd 2.3.4 source backdoor. Treat this host "
                "as potentially compromised until the package and binaries are verified.",
                ["ftp-vsftpd-backdoor"],
                ["CVE-2011-2523"],
            )
        if "proftpd 1.3.3c" in text:
            add(
                "Backdoor",
                "likely",
                "ProFTPD 1.3.3c backdoor signature",
                "The banner matches a ProFTPD version associated with a distributed "
                "backdoor. Verify the binary and package provenance.",
                ["ftp-proftpd-backdoor"],
            )
        if "unrealircd 3.2.8.1" in text:
            add(
                "Backdoor",
                "likely",
                "UnrealIRCd 3.2.8.1 backdoor signature",
                "The banner matches the UnrealIRCd 3.2.8.1 backdoor. Verify the "
                "installed binary and investigate for compromise.",
                ["irc-unrealircd-backdoor"],
                ["CVE-2010-2075"],
            )

    if svc == "smb":
        add(
            "SMB / lateral movement",
            "possible",
            "SMB null-session, share, and credential exposure",
            "SMB can expose shares, users, and authentication policy. Test null "
            "sessions and weak credentials only within scope.",
            ["smb-enum-shares", "smb-enum-users", "smb-brute"],
        )
        if "SMB1_ENABLED" in codes and "samba" not in text:
            add(
                "SMB vulnerabilities",
                "possible",
                "SMB1 legacy vulnerability candidates",
                "SMB1 is enabled on what appears to be a Windows SMB service. Patching "
                "state is unknown; check for MS17-010 and other legacy SMB issues "
                "before assuming exploitation is possible.",
                ["smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-vuln-ms06-025"],
            )
        if "samba" in text:
            add(
                "SMB / Samba",
                "possible",
                "Samba vulnerability checks",
                "A Samba service is exposed. Validate its exact version and patch level; "
                "SambaCry and related issues depend on version and configuration.",
                ["smb-vuln-cve-2017-7494", "smb-enum-shares"],
            )

    if svc == "rdp":
        add(
            "Remote access",
            "possible",
            "RDP weak-credential / legacy-security candidate",
            "RDP is exposed. Test account lockout and NLA policy under an approved "
            "credential audit; do not run high-volume guesses.",
            ["rdp-enum-encryption", "rdp-ntlm-info"],
        )

    if svc in {"vnc", "telnet"}:
        add(
            "Remote access",
            "possible" if svc == "vnc" else "likely",
            "Interactive remote-access exposure",
            "This service may expose an interactive session or cleartext credentials. "
            "Confirm authentication and network ACLs.",
            ["vnc-info", "vnc-brute"] if svc == "vnc" else ["telnet-brute"],
        )

    if svc == "redis":
        add(
            "Data exposure",
            "likely" if "REDIS_UNAUTHENTICATED" in codes else "possible",
            "Redis unauthenticated / weak-credential candidate",
            "Redis may expose data and configuration. Test authentication and network "
            "ACLs only with authorization.",
            ["redis-info", "redis-brute"],
        )

    if svc == "memcached":
        add(
            "Data exposure",
            "likely" if "MEMCACHED_UNAUTHENTICATED" in codes else "possible",
            "Memcached unauthenticated data exposure",
            "Memcached has no authentication by design in many deployments. Confirm "
            "whether it is reachable from untrusted networks.",
            ["memcached-info"],
        )

    if svc == "mongodb":
        add(
            "Database access",
            "possible",
            "MongoDB authentication / data-exposure candidate",
            "Test whether authentication is required and whether databases are "
            "reachable; avoid writes or collection dumps without explicit scope.",
            ["mongodb-info", "mongodb-brute"],
        )

    if svc in {"docker", "elasticsearch", "kubernetes"}:
        add(
            "API exposure",
            "likely" if codes & {"DOCKER_API_EXPOSED", "ELASTICSEARCH_UNAUTHENTICATED"} else "possible",
            "Unauthenticated API / data exposure candidate",
            "The HTTP API may expose management or data-plane functionality. Confirm "
            "authentication, network ACLs, and TLS before using it.",
            ["http-title", "http-headers"],
        )

    if svc == "ldap":
        add(
            "Directory access",
            "likely" if "LDAP_ANONYMOUS_BIND" in codes else "possible",
            "LDAP anonymous bind / weak-credential candidate",
            "Anonymous bind may expose directory metadata. Test bind policy and "
            "credential strength under authorization.",
            ["ldap-rootdse", "ldap-brute"],
        )

    if svc in {"smtp", "imap", "pop3"}:
        add(
            "Mail authentication",
            "possible",
            "Mail service brute-force / weak-credential candidate",
            "Mail services expose authentication endpoints. Use a rate-limited, "
            "authorized credential audit and watch for lockout.",
            {
                "smtp": ["smtp-brute"],
                "imap": ["imap-brute"],
                "pop3": ["pop3-brute"],
            }.get(svc, []),
        )

    if svc == "snmp":
        add(
            "Information exposure",
            "possible",
            "SNMP community / information-disclosure candidate",
            "Test community strings and read-only views only with authorization. "
            "SNMP can disclose extensive host and network information.",
            ["snmp-brute"],
        )

    if svc == "dns":
        add(
            "DNS exposure",
            "test",
            "DNS recursion / zone-transfer candidate",
            "Check whether recursion is restricted and whether authoritative zones "
            "allow unintended AXFR/IXFR transfers. Only query zones in scope.",
            ["dns-nsid", "dns-zone-transfer"],
        )

    if svc == "ntp":
        add(
            "Information exposure",
            "possible",
            "NTP information / amplification exposure",
            "Check whether the server is publicly reachable and whether monitoring or "
            "amplification controls are appropriate.",
            ["ntp-info"],
        )

    if not hints:
        add(
            "Discovery",
            "test",
            "Unidentified or custom service",
            "PortScope has no specific hint for this service. Try Nmap -sV, "
            "--http-fallback, --service-map, and authorized NSE discovery/vulnerability "
            "checks rather than assuming a vulnerability class.",
            [],
        )

    hints.sort(key=lambda hint: (HINT_LIKELIHOOD_ORDER[hint.likelihood], hint.category))
    return hints


def apply_vulnerability_hints(host: HostRecord, config: Config) -> None:
    if not config.show_hints:
        return
    for record in host.ports:
        if record.live_state != "open":
            continue
        record.hints = build_vulnerability_hints(record)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def collect_findings(hosts: Iterable[HostRecord]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host in hosts:
        for finding in host.findings:
            rows.append(
                {
                    "host": host.address,
                    "hostname": host.hostname,
                    "port": None,
                    "protocol": None,
                    "finding": finding,
                }
            )
        for port in host.ports:
            for finding in port.findings:
                rows.append(
                    {
                        "host": host.address,
                        "hostname": host.hostname,
                        "port": port.port,
                        "protocol": port.protocol,
                        "finding": finding,
                    }
                )
    return rows


def collect_hints(hosts: Iterable[HostRecord]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host in hosts:
        for port in host.ports:
            for hint in port.hints:
                item = hint.to_dict()
                item.update(
                    {
                        "host": host.address,
                        "hostname": host.hostname,
                        "port": port.port,
                        "protocol": port.protocol,
                    }
                )
                rows.append(item)
    return rows


def build_report(
    hosts: list[HostRecord],
    config: Config,
    source: str,
    started_at: str,
    elapsed: float,
) -> dict[str, Any]:
    rows = collect_findings(hosts)
    severity_counts = {key: 0 for key in SEVERITY_ORDER}
    for row in rows:
        severity_counts[row["finding"].severity] += 1
    live_counts: dict[str, int] = {}
    protocol_counts: dict[str, int] = {}
    total_ports = 0
    for host in hosts:
        for port in host.ports:
            total_ports += 1
            live_counts[port.live_state] = live_counts.get(port.live_state, 0) + 1
            protocol_counts[port.protocol] = protocol_counts.get(port.protocol, 0) + 1
    max_sev = "none"
    for key in SEVERITY_ORDER:
        if severity_counts.get(key):
            max_sev = key
    findings_list = []
    for row in rows:
        item = row["finding"].to_dict()
        item.update(
            {
                "host": row["host"],
                "hostname": row["hostname"],
                "port": row["port"],
                "protocol": row["protocol"],
            }
        )
        findings_list.append(item)
    findings_list.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(item["severity"], 0),
            item.get("host") or "",
            item.get("port") or 0,
        )
    )
    hint_rows = collect_hints(hosts)
    hint_counts = {key: 0 for key in HINT_LIKELIHOOD_ORDER}
    for hint in hint_rows:
        hint_counts[hint["likelihood"]] = hint_counts.get(hint["likelihood"], 0) + 1
    hint_rows.sort(
        key=lambda item: (
            HINT_LIKELIHOOD_ORDER.get(item["likelihood"], 99),
            item.get("host") or "",
            item.get("port") or 0,
            item.get("category") or "",
        )
    )
    nse_hosts = [host for host in hosts if host.nse_command]
    return {
        "tool": "PortScope",
        "version": VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "started_at": started_at,
        "elapsed_seconds": round(elapsed, 3),
        "source": source,
        "authorization_notice": AUTHORIZATION_NOTICE,
        "limitations": LIMITATIONS,
        "profile": {
            "name": config.profile.name,
            "description": config.profile.description,
            "connect_timeout": config.connect_timeout,
            "read_timeout": config.read_timeout,
            "attempts": config.attempts,
            "delay_min": config.delay_min,
            "delay_max": config.delay_max,
            "workers": config.workers,
            "tls_version_probe": config.tls_matrix,
            "http_fallback": config.http_fallback,
            "nse_enabled": config.run_nse,
            "nse_scripts": config.nse_scripts,
        },
        "summary": {
            "hosts": len(hosts),
            "ports": total_ports,
            "protocols": protocol_counts,
            "live_states": live_counts,
            "findings": severity_counts,
            "max_severity": max_sev,
            "hints": hint_counts,
            "nse_hosts": len(nse_hosts),
        },
        "findings": findings_list,
        "hints": hint_rows,
        "nse": {
            "enabled": config.run_nse,
            "mode": (
                "explicit"
                if config.nse_scripts
                else "automatic"
                if config.run_nse
                else "disabled"
            ),
            "scripts_requested": config.nse_scripts,
            "allowed_scripts": list(SAFE_NSE_SCRIPTS),
            "hosts_with_errors": [
                {"host": host.address, "error": host.nse_error}
                for host in hosts
                if host.nse_error
            ],
        },
        "hosts": [host.to_dict() for host in hosts],
    }


def render_table(
    headers: list[str],
    rows: list[list[str]],
    max_widths: Optional[list[int]] = None,
) -> str:
    if not rows:
        return ""
    widths = []
    for index, header in enumerate(headers):
        width = max(
            [len(header)] + [len(str(row[index])) for row in rows if index < len(row)]
        )
        if max_widths and index < len(max_widths):
            width = min(width, max_widths[index])
        widths.append(max(3, width))
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    lines = [border]
    lines.append(
        "| " + " | ".join(header.ljust(widths[i]) for i, header in enumerate(headers)) + " |"
    )
    lines.append(border)
    for row in rows:
        cells = []
        for index in range(len(headers)):
            value = str(row[index]) if index < len(row) else ""
            value = value.replace("\r", " ").replace("\n", " ")
            if len(value) > widths[index]:
                value = value[: max(0, widths[index] - 3)] + "..."
            cells.append(value.ljust(widths[index]))
        lines.append("| " + " | ".join(cells) + " |")
    lines.append(border)
    return "\n".join(lines)


def _finding_line(row: dict[str, Any], verbose: bool = False) -> str:
    if "finding" in row:
        finding = row["finding"]
        severity = finding.severity
        title = finding.title
        code = finding.code
        detail = finding.detail
    else:
        severity = row.get("severity", "info")
        title = row.get("title", "")
        code = row.get("code", "")
        detail = row.get("detail", "")
    port = f"{row['port']}/{row['protocol']}" if row.get("port") else "host"
    text = f"[{str(severity).upper():8}] {port:10} {title} ({code})"
    if verbose and detail:
        text += f" -- {detail}"
    return text


def render_text(report: dict[str, Any], verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(f"PortScope {report['version']} - protocol-aware post-Nmap diagnosis")
    lines.append(f"Generated: {report['generated_at']}  Elapsed: {report['elapsed_seconds']:.2f}s")
    lines.append(f"Source: {report['source']}")
    profile = report["profile"]
    lines.append(
        "Profile: "
        f"{profile['name']} ({profile['connect_timeout']}s connect, "
        f"{profile['read_timeout']}s read, {profile['attempts']} attempt(s), "
        f"{profile['delay_min']}-{profile['delay_max']}s spacing, {profile['workers']} workers)"
    )
    lines.append(f"Authorization: {report['authorization_notice']}")
    lines.append("")
    summary = report["summary"]
    live = ", ".join(f"{k}={v}" for k, v in sorted(summary["live_states"].items())) or "none"
    lines.append(f"Summary: {summary['hosts']} host(s), {summary['ports']} port(s); live={live}")
    sev_bits = ", ".join(
        f"{key}={summary['findings'].get(key, 0)}"
        for key in ("critical", "high", "medium", "low", "info")
    )
    lines.append(f"Findings: {sev_bits}; max severity={summary['max_severity']}")
    hint_counts = summary.get("hints", {})
    if any(hint_counts.values()):
        lines.append(
            "Hints: "
            + ", ".join(
                f"{key}={hint_counts.get(key, 0)}" for key in ("likely", "possible", "test")
            )
            + " (candidate areas, not confirmed vulnerabilities)"
        )
    if report["findings"]:
        lines.append("")
        lines.append("Findings")
        for row in report["findings"]:
            lines.append("  " + _finding_line(row, verbose=verbose))
            if verbose and row.get("detail"):
                lines.append(f"             {row['detail']}")
    lines.append("")

    for host in report["hosts"]:
        title = host["address"]
        if host.get("hostname") and host["hostname"] != host["address"]:
            title += f" ({host['hostname']})"
        lines.append(f"Host {title} [nmap status: {host['status']}]")
        if host.get("os_matches"):
            best = host["os_matches"][0]
            lines.append(
                f"  OS hint: {truncate(best.get('name', ''), 120)} "
                f"(accuracy {best.get('accuracy', '?')}%)"
            )
        for note in host.get("notes", []):
            lines.append(f"  Note: {note}")
        if host.get("nse_command"):
            lines.append(f"  NSE command: {host['nse_command']}")
        if host.get("nse_error"):
            lines.append(f"  NSE note: {host['nse_error']}")
        if host.get("nse_host"):
            lines.append("  Host-level NSE results:")
            for script, output in host["nse_host"].items():
                lines.append(f"    {script}: {truncate(output, 500)}")
        if host.get("ports"):
            rows = []
            for port in host["ports"]:
                probe = port.get("probe") or {}
                summary_text = probe.get("summary") or ""
                if not summary_text:
                    summary_text = ", ".join(port.get("notes", [])[:1])
                if port.get("error"):
                    summary_text = f"error: {port['error']}"
                service = port.get("service_guess") or "unknown"
                rows.append(
                    [
                        port["label"],
                        port.get("nmap_state") or "-",
                        port.get("live_state") or "-",
                        human_ms(port.get("connect_ms")),
                        service,
                        summary_text,
                    ]
                )
            lines.append(
                render_table(
                    ["Port", "Nmap", "Live", "Connect", "Probe", "Observation"],
                    rows,
                    max_widths=[12, 12, 12, 10, 14, 72],
                )
            )
            lines.append("  Port details")
            for port in host["ports"]:
                probe = port.get("probe") or {}
                nmap = port.get("nmap") or {}
                service_bits = []
                if nmap.get("service"):
                    service_bits.append(nmap["service"])
                if nmap.get("product"):
                    service_bits.append(nmap["product"])
                if nmap.get("version"):
                    service_bits.append(nmap["version"])
                nmap_text = " ".join(service_bits) or "unknown"
                lines.append(
                    f"  [{port['label']}] {port.get('live_state')} - {truncate(nmap_text, 140)}"
                )
                lines.append(
                    f"    Nmap: {port.get('nmap_state')} "
                    f"({port.get('nmap_reason') or 'no reason'}), "
                    f"service={nmap.get('service') or 'unknown'}"
                )
                if port.get("attempts"):
                    attempts = ", ".join(
                        f"{a.get('attempt')}:{a.get('outcome')}@{a.get('ms')}ms"
                        for a in port["attempts"][:6]
                    )
                    lines.append(f"    Connect attempts: {attempts}")
                if probe:
                    lines.append(f"    Probe: {probe.get('protocol')} - {probe.get('summary')}")
                    if probe.get("error"):
                        lines.append(f"    Probe error: {probe['error']}")
                    protections = probe.get("protections") or {}
                    if protections:
                        lines.append(
                            "    Protections: "
                            + truncate(
                                json.dumps(protections, ensure_ascii=False, default=str),
                                1200,
                            )
                        )
                for note in port.get("notes", []):
                    lines.append(f"    Note: {note}")
                if port.get("findings"):
                    for finding in port["findings"]:
                        lines.append(
                            f"    [{finding['severity'].upper()}] {finding['title']} "
                            f"({finding['code']}): {truncate(finding['detail'], 500)}"
                        )
                if port.get("nse"):
                    lines.append("    NSE script results:")
                    for script, output in port["nse"].items():
                        lines.append(f"      {script}: {truncate(output, 500)}")
                if port.get("nse_error"):
                    lines.append(f"    NSE error: {port['nse_error']}")
                if port.get("hints"):
                    lines.append("    Likely vulnerability areas (candidates, not confirmed):")
                    for hint in port["hints"]:
                        scripts = ", ".join(hint.get("suggested_scripts") or [])
                        refs = ", ".join(hint.get("references") or [])
                        lines.append(
                            f"      [{hint['likelihood'].upper()}] {hint['category']}: "
                            f"{hint['title']}"
                        )
                        lines.append(f"        {hint['rationale']}")
                        if scripts:
                            lines.append(
                                f"        Suggested NSE scripts (manual, not run): {scripts}"
                            )
                        if refs:
                            lines.append(f"        References: {refs}")
                if verbose and probe.get("data"):
                    evidence = json.dumps(probe["data"], indent=2, ensure_ascii=False, default=str)
                    lines.append("    Evidence:")
                    lines.extend("      " + line for line in evidence.splitlines()[:120])
        lines.append("")

    if verbose:
        lines.append("Limitations:")
        for limitation in report["limitations"]:
            lines.append(f"  - {limitation}")
    return "\n".join(lines).rstrip() + "\n"


def _md_escape(value: Any) -> str:
    text = str(value) if value is not None else ""
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any], verbose: bool = False) -> str:
    summary = report["summary"]
    lines = [
        "# PortScope report",
        "",
        f"**Generated:** {report['generated_at']}  ",
        f"**Elapsed:** {report['elapsed_seconds']:.2f}s  ",
        f"**Source:** {report['source']}  ",
        f"**Profile:** {report['profile']['name']}  ",
        f"**Authorization:** {report['authorization_notice']}",
        "",
        "## Summary",
        "",
        f"- Hosts: {summary['hosts']}",
        f"- Ports: {summary['ports']}",
        "- Live states: "
        + (
            ", ".join(f"**{k}**={v}" for k, v in sorted(summary["live_states"].items()))
            or "none"
        ),
        "- Findings: "
        + ", ".join(
            f"**{key}**={summary['findings'].get(key, 0)}"
            for key in ("critical", "high", "medium", "low", "info")
        ),
        f"- Max severity: **{summary['max_severity']}**",
        "- Vulnerability hints: "
        + ", ".join(
            f"**{key}**={summary.get('hints', {}).get(key, 0)}"
            for key in ("likely", "possible", "test")
        ),
        "",
        "## Hosts",
        "",
    ]
    for host in report["hosts"]:
        title = host["address"] + (
            f" ({host['hostname']})"
            if host.get("hostname") and host["hostname"] != host["address"]
            else ""
        )
        lines.extend([f"### {title}", "", f"Nmap status: {host['status']}", ""])
        if host.get("os_matches"):
            best = host["os_matches"][0]
            lines.append(
                f"OS hint: {_md_escape(best.get('name', ''))} "
                f"(accuracy {best.get('accuracy', '?')}%)"
            )
            lines.append("")
        for note in host.get("notes", []):
            lines.append(f"> Note: {_md_escape(note)}")
        if host.get("notes"):
            lines.append("")
        if host.get("nse_command"):
            lines.append(f"NSE command: {_md_escape(host['nse_command'])}")
            lines.append("")
        if host.get("nse_error"):
            lines.append(f"> NSE note: {_md_escape(host['nse_error'])}")
            lines.append("")
        if host.get("nse_host"):
            lines.append("Host-level NSE results:")
            for script, output in host["nse_host"].items():
                lines.append(f"- {script}: {_md_escape(truncate(output, 500))}")
            lines.append("")
        if host.get("ports"):
            lines.append("| Port | Nmap | Live | Connect | Probe | Observation |")
            lines.append("|---|---|---|---|---|---|")
            for port in host["ports"]:
                probe = port.get("probe") or {}
                observation = probe.get("summary") or port.get("error") or ""
                lines.append(
                    "| "
                    + " | ".join(
                        _md_escape(value)
                        for value in (
                            port["label"],
                            port.get("nmap_state"),
                            port.get("live_state"),
                            human_ms(port.get("connect_ms")),
                            port.get("service_guess"),
                            observation,
                        )
                    )
                    + " |"
                )
            lines.append("")
    lines.extend(["## Findings", ""])
    if not report["findings"]:
        lines.append("No findings.")
    else:
        lines.append("| Severity | Host | Port | Code | Title |")
        lines.append("|---|---|---|---|---|")
        for row in report["findings"]:
            port = f"{row['port']}/{row['protocol']}" if row.get("port") else "host"
            lines.append(
                "| "
                + " | ".join(
                    _md_escape(value)
                    for value in (
                        row["severity"],
                        row["host"],
                        port,
                        row["code"],
                        row["title"],
                    )
                )
                + " |"
            )
    lines.append("")
    lines.extend(["## Vulnerability hints", ""])
    if not report.get("hints"):
        lines.append("No service-specific vulnerability hints were generated.")
    else:
        lines.append("These are candidate test areas, not confirmed vulnerabilities.")
        lines.append("")
        lines.append("| Likelihood | Host | Port | Category | Hint | Suggested scripts (manual) |")
        lines.append("|---|---|---|---|---|---|")
        for row in report["hints"]:
            port = f"{row['port']}/{row['protocol']}" if row.get("port") else "host"
            lines.append(
                "| "
                + " | ".join(
                    _md_escape(value)
                    for value in (
                        row["likelihood"],
                        row["host"],
                        port,
                        row["category"],
                        row["title"],
                        ", ".join(row.get("suggested_scripts") or []),
                    )
                )
                + " |"
            )
    lines.append("")
    lines.extend(["## Port details", ""])
    for host in report["hosts"]:
        for port in host["ports"]:
            probe = port.get("probe") or {}
            lines.extend(
                [
                    f"### {host['address']} - {port['label']}",
                    "",
                    f"- Nmap state: {port.get('nmap_state')} "
                    f"({port.get('nmap_reason') or 'no reason'})",
                    f"- Live state: {port.get('live_state')}",
                    f"- Service guess: {port.get('service_guess')}",
                    f"- Probe: {probe.get('protocol', 'none')} - "
                    f"{_md_escape(probe.get('summary', ''))}",
                ]
            )
            if port.get("attempts"):
                lines.append(
                    "- Attempts: "
                    + ", ".join(
                        f"{a.get('attempt')}:{a.get('outcome')}"
                        for a in port["attempts"][:8]
                    )
                )
            if probe.get("protections"):
                lines.append(
                    "- Protections: "
                    + _md_escape(
                        json.dumps(probe["protections"], ensure_ascii=False, default=str)
                    )
                )
            if port.get("findings"):
                lines.append("- Findings:")
                for finding in port["findings"]:
                    lines.append(
                        f"  - **{finding['severity'].upper()}** {finding['code']}: "
                        f"{_md_escape(finding['detail'])}"
                    )
            if port.get("nse"):
                lines.append("- NSE script results:")
                for script, output in port["nse"].items():
                    lines.append(f"  - {script}: {_md_escape(truncate(output, 500))}")
            if port.get("nse_error"):
                lines.append(f"- NSE error: {_md_escape(port['nse_error'])}")
            if port.get("hints"):
                lines.append("- Vulnerability hints (candidates, not confirmed):")
                for hint in port["hints"]:
                    scripts = ", ".join(hint.get("suggested_scripts") or [])
                    lines.append(
                        f"  - **{hint['likelihood'].upper()}** {hint['category']}: "
                        f"{_md_escape(hint['title'])}. {_md_escape(hint['rationale'])}"
                        + (f" Suggested scripts (manual): {_md_escape(scripts)}." if scripts else "")
                    )
            if verbose and probe.get("data"):
                lines.append("")
                lines.append("~~~json")
                lines.append(
                    json.dumps(probe["data"], indent=2, ensure_ascii=False, default=str)[:12000]
                )
                lines.append("~~~")
            lines.append("")
    if verbose:
        lines.extend(["## Limitations", ""])
        for limitation in report["limitations"]:
            lines.append(f"- {limitation}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_output(path: str, content: str) -> None:
    target = Path(path).expanduser()
    parent = target.parent
    if parent and str(parent) not in {"", "."}:
        parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")

# ---------------------------------------------------------------------------
# Listen mode (continuous TCP state monitoring)
# ---------------------------------------------------------------------------


LISTEN_SAFE_INTERVAL = 0.5  # seconds; below this we emit an overspeed warning


class _Spinner:
    """Terminal progress spinner used by --listen.

    Writes only to stderr.  When stderr is not a TTY (e.g. redirected to a
    file) the spinner thread exits immediately and only explicit messages
    are emitted, so non-interactive runs stay readable.
    """

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._lock = threading.Lock()
        self._is_tty = sys.stderr.isatty()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="portscope-spinner"
        )
        self._thread.start()

    def _run(self) -> None:
        if not self._is_tty:
            return
        chars = "\\/"
        index = 0
        while not self._stop.is_set():
            if not self._paused.is_set():
                with self._lock:
                    sys.stderr.write("\r[Listen] " + chars[index % 2])
                    sys.stderr.flush()
            index += 1
            self._stop.wait(0.15)

    def message(self, text: str) -> None:
        with self._lock:
            if self._is_tty:
                sys.stderr.write("\r" + " " * 40 + "\r")
            sys.stderr.write(text + "\n")
            sys.stderr.flush()

    def pause(self) -> None:
        self._paused.set()
        if self._is_tty:
            with self._lock:
                sys.stderr.write("\r" + " " * 40 + "\r")
                sys.stderr.flush()

    def resume(self) -> None:
        self._paused.clear()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        if self._is_tty:
            with self._lock:
                sys.stderr.write("\r" + " " * 40 + "\r")
                sys.stderr.flush()


def _prompt_save_output(
    buffer: list[str],
    text_limit: int,
    spinner: "_Spinner",
) -> bool:
    """Ask the user whether to save buffered listen output to a file.

    Pauses the spinner for the duration of the interaction.  Invalid answers
    or unwritable paths cause a re-prompt rather than terminating the run.
    Returns True if the buffer was written and may be cleared.
    """
    total = sum(len(chunk) for chunk in buffer)
    if total == 0:
        return False
    spinner.pause()
    try:
        while True:
            try:
                answer = input(
                    f"[!] Listen output buffer has reached {total} bytes "
                    f"(limit {text_limit}). Save to a text file? [y/N]: "
                ).strip().lower()
            except EOFError:
                print("", file=sys.stderr)
                return False
            if answer in ("", "n", "no"):
                return False
            if answer in ("y", "yes"):
                break
            print("Please answer 'y' or 'n'.", file=sys.stderr)
        while True:
            try:
                path = input("Enter output file path: ").strip()
            except EOFError:
                print("", file=sys.stderr)
                return False
            if not path:
                print("Path cannot be empty; please try again.", file=sys.stderr)
                continue
            try:
                write_output(path, "".join(buffer))
            except Exception as exc:
                print(
                    f"[!] Cannot write {path!r}: {short_exc(exc)}. Try again.",
                    file=sys.stderr,
                )
                continue
            print(f"[+] Saved {total} bytes to {path}", file=sys.stderr)
            return True
    finally:
        spinner.resume()


def run_listen_mode(
    target: str,
    ports: list[int],
    config: Config,
    args: argparse.Namespace,
) -> int:
    """Continuously monitor TCP state changes for the selected ports.

    There is intentionally no overall timeout.  Individual TCP connect
    attempts still honour the configured connect timeout.  The loop runs
    until Ctrl+C.
    """
    interval = float(args.listen_interval)
    if interval <= 0:
        raise ValueError("--listen-interval must be positive")
    text_limit = int(args.text_limit)
    if text_limit < 256:
        raise ValueError("--text-limit must be >= 256 bytes")
    if config.max_ports > 0 and len(ports) > config.max_ports:
        raise ValueError(
            f"{len(ports)} ports selected, above --max-ports {config.max_ports}; "
            "narrow the list or raise the limit deliberately"
        )

    hostname = None if is_ip_literal(target) else target
    spinner = _Spinner()
    states: dict[int, str] = {}
    buffer: list[str] = []
    buffer_size = 0
    last_packet_ts = 0.0
    last_warn_ts = 0.0

    if interval < LISTEN_SAFE_INTERVAL:
        print(
            f"[!] --listen-interval {interval:g}s is below the "
            f"{LISTEN_SAFE_INTERVAL:g}s safety floor; monitoring may be noisy "
            "or trigger rate limiting.",
            file=sys.stderr,
        )

    spinner.start()
    try:
        print(
            f"[Listen] Monitoring {target} on ports "
            f"{','.join(str(p) for p in ports)} every ~{interval:g}s "
            "(Ctrl+C to stop)",
            file=sys.stderr,
        )
        while True:
            for port in ports:
                packet_start = time.monotonic()
                if last_packet_ts and (packet_start - last_packet_ts) < LISTEN_SAFE_INTERVAL:
                    if (packet_start - last_warn_ts) > 5.0:
                        spinner.message(
                            f"[!] Overspeed: "
                            f"{packet_start - last_packet_ts:.3f}s between packets "
                            f"(safety floor {LISTEN_SAFE_INTERVAL:g}s). "
                            "Increase --listen-interval or reduce port count."
                        )
                        last_warn_ts = packet_start
                last_packet_ts = packet_start

                ctx = ProbeContext(
                    host=target,
                    port=port,
                    protocol="tcp",
                    connect_timeout=config.connect_timeout,
                    read_timeout=config.read_timeout,
                    pacer=Pacer(0.0, 0.0),
                    sni=config.sni,
                    max_body=config.max_body,
                    user_agent=config.user_agent,
                    http_path=config.http_path,
                    tls_matrix=False,
                    snmp_community=None,
                    hostname=hostname,
                )
                try:
                    live, _attempts, _connect_ms, _last_error = tcp_liveness(ctx, 1)
                except Exception:  # defensive: tcp_liveness already swallows most
                    live = "error"
                previous = states.get(port)
                states[port] = live
                timestamp = utc_now()
                line: Optional[str] = None
                if previous is None:
                    line = f"{timestamp}  {port}/tcp  initial state: {live}"
                elif previous != live:
                    line = f"{timestamp}  {port}/tcp  CHANGED  {previous} -> {live}"
                    if previous in {"closed", "unreachable", "error"} and live == "open":
                        line += "  (service started responding)"
                    elif previous == "open" and live in {"closed", "unreachable", "error"}:
                        line += "  (service stopped responding)"
                    elif previous == "open" and live == "filtered":
                        line += "  (filter/firewall likely blocked the port)"
                    elif previous == "filtered" and live == "open":
                        line += "  (filter/firewall likely removed)"
                if line:
                    spinner.message(line)
                    buffer.append(line + "\n")
                    buffer_size += len(line) + 1
                    if buffer_size >= text_limit:
                        if _prompt_save_output(buffer, text_limit, spinner):
                            buffer.clear()
                            buffer_size = 0

                # Per-packet pacing: packet_start -> next packet_start >= interval.
                elapsed = time.monotonic() - packet_start
                remaining = interval - elapsed
                if remaining > 0:
                    time.sleep(remaining)
    except KeyboardInterrupt:
        spinner.message("[Listen] stopped by user")
        return 0
    finally:
        spinner.stop()


def _run_listen_entry(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    conflicts: list[str] = []
    if args.nmap:
        conflicts.append("--nmap")
    if args.nse:
        conflicts.append("--nse")
    if args.nse_scripts:
        conflicts.append("--nse-scripts")
    if args.json:
        conflicts.append("--json")
    if args.markdown:
        conflicts.append("--markdown")
    if args.text:
        conflicts.append("--text")
    if args.fail_on and args.fail_on != "none":
        conflicts.append("--fail-on")
    if args.protocol != "tcp":
        conflicts.append("--protocol (listen mode only supports tcp)")
    if conflicts:
        parser.error("--listen cannot be combined with: " + ", ".join(conflicts))
    if not args.target:
        parser.error("--listen requires --target")
    if not args.ports:
        parser.error("--listen requires --ports")
    try:
        config = build_config(args)
    except ValueError as exc:
        print(f"portscope: error: {exc}", file=sys.stderr)
        return 2
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"portscope: error: {exc}", file=sys.stderr)
        return 2
    try:
        return run_listen_mode(args.target, ports, config, args)
    except ValueError as exc:
        print(f"portscope: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("portscope: interrupted", file=sys.stderr)
        return 130
# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscope",
        description=(
            "Protocol-aware diagnosis of ports already discovered by Nmap. "
            "Read-only probes; authorized testing only."
        ),
        epilog=(
            "Examples:\n"
            "  python3 portscope.py --nmap scan.xml --profile polite --json report.json\n"
            "  python3 portscope.py --target 192.168.56.101 --ports 21,22,80,445,3306 --profile fast\n"
            "  python3 portscope.py --target 10.0.0.5 --ports 22,443 --profile slow --verbose\n"
            "  python3 portscope.py --nmap scan.xml --nse --json report.json\n"
            "  python3 portscope.py --nmap scan.xml --nse-scripts http-title,ssh-auth-methods\n"
            "  python3 portscope.py --nmap scan.xml --snmp-community public --protocol both\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--nmap", metavar="XML", help="Nmap XML output (nmap -oX)")
    source.add_argument("--target", metavar="HOST", help="Target host/IP for direct port diagnosis")
    parser.add_argument(
        "--ports",
        metavar="LIST",
        help="Ports for --target (e.g. 22,80,8000-8010); with --nmap, filters discovered ports",
    )
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp", "both"],
        default="tcp",
        help="Transport to diagnose (default: tcp)",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="polite",
        help="Timing profile (default: polite)",
    )
    parser.add_argument("--timeout", type=float, help="TCP connect timeout in seconds")
    parser.add_argument("--read-timeout", type=float, help="Protocol read timeout in seconds")
    parser.add_argument("--attempts", type=int, help="TCP connect attempts per port")
    parser.add_argument(
        "--delay",
        nargs=2,
        type=float,
        metavar=("MIN", "MAX"),
        help="Override minimum/maximum spacing between connection attempts",
    )
    parser.add_argument("--workers", type=int, help="Worker threads")
    parser.add_argument(
        "--states",
        help=f"Comma-separated Nmap states (default: {DEFAULT_STATES})",
    )
    parser.add_argument("--include-closed", action="store_true", help="Include closed Nmap ports")
    parser.add_argument("--include-down", action="store_true", help="Probe hosts marked down by Nmap")
    parser.add_argument(
        "--max-ports",
        type=int,
        default=512,
        help="Safety cap on selected ports (0 = unlimited; default: 512)",
    )
    parser.add_argument(
        "--service-map",
        action="append",
        default=[],
        metavar="PORT=SERVICE",
        help="Override service inference, e.g. 8000=http or tcp/8000=http",
    )
    parser.add_argument("--sni", help="TLS SNI / certificate hostname to expect")
    parser.add_argument("--http-path", default="/", help="HTTP path to request (default: /)")
    parser.add_argument(
        "--user-agent",
        default="PortScope/1.0 (authorized diagnostic)",
        help="HTTP User-Agent",
    )
    parser.add_argument(
        "--max-body",
        type=int,
        default=65536,
        help="Maximum HTTP body bytes retained (default: 65536)",
    )
    parser.add_argument(
        "--no-tls-version-probe",
        action="store_true",
        help="Skip the TLS 1.0/1.1/1.2/1.3 matrix (one extra handshake per version)",
    )
    parser.add_argument(
        "--snmp-community",
        help="Community string for a read-only SNMP GET (e.g. public); omitted by default",
    )
    parser.add_argument(
        "--http-fallback",
        action="store_true",
        help=(
            "For services Nmap could not identify, try a single HTTP GET/OPTIONS "
            "instead of only a passive banner read"
        ),
    )
    parser.add_argument(
        "--nse",
        action="store_true",
        help=(
            "Run a curated set of low-impact Nmap NSE scripts and merge results "
            "into the report; credential/exploit scripts are only recommended"
        ),
    )
    parser.add_argument(
        "--nse-scripts",
        metavar="LIST",
        help=(
            "Comma-separated low-impact NSE scripts to run instead of the automatic "
            "safe set; implies --nse"
        ),
    )
    parser.add_argument(
        "--nmap-bin",
        default="nmap",
        metavar="PATH",
        help="Nmap executable used by --nse (default: nmap)",
    )
    parser.add_argument(
        "--nse-timeout",
        type=float,
        default=180.0,
        metavar="SECONDS",
        help="Overall timeout for the Nmap NSE run per host (default: 180)",
    )
    parser.add_argument(
        "--script-timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="Nmap per-script timeout (default: 30)",
    )
    parser.add_argument(
        "--no-hints",
        action="store_true",
        help="Disable the service-specific vulnerability candidate suggestions",
    )
    parser.add_argument("--json", metavar="PATH", help="Write full JSON report")
    parser.add_argument("--markdown", metavar="PATH", help="Write Markdown report")
    parser.add_argument("--text", metavar="PATH", help="Write text report instead of stdout")
    parser.add_argument("--quiet", action="store_true", help="Do not print the text report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Progress and full evidence")
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="Exit 10 if the maximum finding severity is at least this level",
    )
    parser.add_argument("--version", action="version", version=f"PortScope {VERSION}")
    parser.add_argument(
        "--listen",
        action="store_true",
        help=(
            "Continuously monitor --target/--ports for TCP state changes. "
            "Conflicts with one-shot reporting/NSE options; no overall timeout."
        ),
    )
    parser.add_argument(
        "--listen-interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help=(
            "Minimum spacing between listen-mode packets (default: 2.0). "
            "Values below 0.5 are flagged as overspeed."
        ),
    )
    parser.add_argument(
        "--text-limit",
        type=int,
        default=10240,
        metavar="BYTES",
        help=(
            "Listen-mode buffered-output threshold before prompting to save "
            "to a file (default: 10240 bytes = 10KB)"
        ),
    )
    return parser


def build_config(args: argparse.Namespace) -> Config:
    profile = PROFILES[args.profile]
    connect_timeout = args.timeout if args.timeout is not None else profile.connect_timeout
    read_timeout = args.read_timeout
    if read_timeout is None:
        read_timeout = (
            max(profile.read_timeout, connect_timeout * 1.2)
            if args.timeout
            else profile.read_timeout
        )
    attempts = args.attempts if args.attempts is not None else profile.attempts
    delay_min, delay_max = profile.delay_min, profile.delay_max
    if args.delay:
        delay_min, delay_max = args.delay
    workers = args.workers if args.workers is not None else profile.workers
    if min(connect_timeout, read_timeout) <= 0:
        raise ValueError("timeouts must be positive")
    if attempts < 1:
        raise ValueError("--attempts must be >= 1")
    if workers < 1:
        raise ValueError("--workers must be >= 1")
    if delay_min < 0 or delay_max < 0 or delay_max < delay_min:
        raise ValueError("--delay must satisfy 0 <= MIN <= MAX")
    if args.max_ports < 0:
        raise ValueError("--max-ports must be >= 0")
    if args.max_body < 1024:
        raise ValueError("--max-body must be >= 1024")
    if args.nse_timeout <= 0 or args.script_timeout <= 0:
        raise ValueError("--nse-timeout and --script-timeout must be positive")
    nse_scripts = parse_nse_scripts(args.nse_scripts or "")
    run_nse = bool(args.nse or nse_scripts)
    states_explicit = args.states is not None
    states = parse_states(args.states) if args.states else parse_states(DEFAULT_STATES)
    if args.include_closed:
        states.add("closed")
    return Config(
        profile=profile,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        attempts=attempts,
        delay_min=delay_min,
        delay_max=delay_max,
        workers=workers,
        max_ports=args.max_ports,
        states=states,
        states_explicit=states_explicit,
        include_down=args.include_down,
        protocol=args.protocol,
        service_overrides=parse_service_overrides(args.service_map),
        sni=args.sni,
        http_path=args.http_path,
        user_agent=args.user_agent,
        max_body=args.max_body,
        tls_matrix=not args.no_tls_version_probe,
        snmp_community=args.snmp_community,
        http_fallback=args.http_fallback,
        run_nse=run_nse,
        nse_scripts=nse_scripts,
        nmap_bin=args.nmap_bin,
        nse_timeout=args.nse_timeout,
        script_timeout=args.script_timeout,
        show_hints=not args.no_hints,
        verbose=args.verbose,
        quiet=args.quiet,
        fail_on=args.fail_on,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.listen:                                      # <-- add
        return _run_listen_entry(parser, args)           # <-- add
    try:
        config = build_config(args)
        source: str
        if args.nmap:
            hosts = parse_nmap_xml(args.nmap)
            source = f"Nmap XML: {args.nmap}"
            if args.ports:
                allowed = set(parse_ports(args.ports))
                for host in hosts:
                    host.ports = [port for port in host.ports if port.port in allowed]
        else:
            if not args.ports:
                parser.error("--ports is required with --target")
            hosts = [make_direct_host(args.target, args.ports, config)]
            source = f"direct target: {args.target}, ports: {args.ports}"
        enforce_port_limit(hosts, config)
        started_at = utc_now()
        started = time.monotonic()
        pacer = Pacer(config.delay_min, config.delay_max)
        for host in hosts:
            diagnose_host(host, config, pacer)
            run_nse_for_host(host, config)
            apply_vulnerability_hints(host, config)
        elapsed = time.monotonic() - started
        report = build_report(hosts, config, source, started_at, elapsed)
        text = render_text(report, verbose=config.verbose)
        markdown = render_markdown(report, verbose=config.verbose)
        if args.text:
            try:
                write_output(args.text, text)
            except OSError as exc:
                raise ValueError(f"cannot write text report {args.text!r}: {short_exc(exc)}") from exc
            if not config.quiet:
                print(f"[+] text report: {args.text}", file=sys.stderr)
        elif not config.quiet:
            print(text, end="")
        if args.json:
            try:
                write_output(
                    args.json,
                    json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                )
            except OSError as exc:
                raise ValueError(f"cannot write JSON report {args.json!r}: {short_exc(exc)}") from exc
            if not config.quiet:
                print(f"[+] JSON report: {args.json}", file=sys.stderr)
        if args.markdown:
            try:
                write_output(args.markdown, markdown)
            except OSError as exc:
                raise ValueError(
                    f"cannot write Markdown report {args.markdown!r}: {short_exc(exc)}"
                ) from exc
            if not config.quiet:
                print(f"[+] Markdown report: {args.markdown}", file=sys.stderr)
        if args.fail_on != "none" and sev_at_least(
            report["summary"]["max_severity"], args.fail_on
        ):
            return 10
        if report["summary"]["ports"] == 0:
            return 3
        return 0
    except ValueError as exc:
        print(f"portscope: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("portscope: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

if __name__ == "__main__":
    raise SystemExit(main())
