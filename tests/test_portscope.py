#!/usr/bin/env python3
"""Tests for PortScope. All network fixtures bind to 127.0.0.1."""

from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import portscope  # noqa: E402


class HttpHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<html><head><title>PortScope Test</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Set-Cookie", "sid=secret; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Allow", "GET, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        return


def start_http_server(tls_context: Optional[ssl.SSLContext] = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), HttpHandler)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stop_server(server) -> None:
    server.shutdown()
    server.server_close()


def run_scan(args: list[str]) -> tuple[int, dict]:
    with tempfile.TemporaryDirectory() as tmp:
        output = os.path.join(tmp, "report.json")
        command = [
            "--profile",
            "fast",
            "--no-tls-version-probe",
            "--quiet",
            "--json",
            output,
        ] + args
        code = portscope.main(command)
        with open(output, "r", encoding="utf-8") as handle:
            report = json.load(handle)
        return code, report


class UtilityTests(unittest.TestCase):
    def test_parse_ports(self) -> None:
        self.assertEqual(portscope.parse_ports("22,80,79-81"), [22, 79, 80, 81])
        with self.assertRaises(ValueError):
            portscope.parse_ports("0")
        with self.assertRaises(ValueError):
            portscope.parse_ports("70000")

    def test_parse_nmap_xml(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up" reason="syn-ack"/>
            <address addr="192.0.2.10" addrtype="ipv4"/>
            <hostnames><hostname name="example.test"/></hostnames>
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack"/>
                <service name="https" product="nginx" version="1.27"/>
                <script id="ssl-cert" output="subject=CN=example.test"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scan.xml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(xml)
            hosts = portscope.parse_nmap_xml(path)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].address, "192.0.2.10")
        self.assertEqual(hosts[0].hostname, "example.test")
        self.assertEqual(hosts[0].ports[0].port, 443)
        self.assertEqual(hosts[0].ports[0].service, "https")
        self.assertIn("ssl-cert", hosts[0].ports[0].scripts)

    def test_infer_service_and_tls(self) -> None:
        nmap = portscope.NmapPort(port=8443, protocol="tcp", state="open", service="http-alt")
        self.assertEqual(portscope.infer_service(nmap), "http")
        self.assertTrue(portscope.infer_tls_initial(nmap, "http", 8443))
        nmap = portscope.NmapPort(port=22, protocol="tcp", state="open", service="ssh")
        self.assertEqual(portscope.infer_service(nmap), "ssh")
        self.assertFalse(portscope.infer_tls_initial(nmap, "ssh", 22))

    def test_vulnerability_hints_and_nse_allowlist(self) -> None:
        record = portscope.PortRecord(
            address="192.0.2.20",
            port=21,
            protocol="tcp",
            live_state="open",
            service_guess="ftp",
        )
        record.nmap = portscope.NmapPort(
            port=21,
            protocol="tcp",
            state="open",
            service="ftp",
            product="vsftpd",
            version="2.3.4",
        )
        hints = portscope.build_vulnerability_hints(record)
        self.assertTrue(
            any(hint.category == "Backdoor" and "vsftpd" in hint.title for hint in hints)
        )
        self.assertTrue(
            any("ftp-anon" in hint.suggested_scripts for hint in hints)
        )
        self.assertEqual(
            portscope.parse_nse_scripts("http-title,ssh-auth-methods"),
            ["http-title", "ssh-auth-methods"],
        )
        with self.assertRaises(ValueError):
            portscope.parse_nse_scripts("ssh-brute")

    def test_ssh_kexinit_parser(self) -> None:
        packet = portscope._ssh_build_kexinit()
        packet_length = struct.unpack(">I", packet[:4])[0]
        padding_length = packet[4]
        payload = packet[5 : 4 + packet_length - padding_length]
        parsed = portscope._ssh_parse_namelists(payload)
        self.assertIn("curve25519-sha256", parsed["kex_algorithms"])
        self.assertIn("ssh-ed25519", parsed["server_host_key_algorithms"])
        self.assertEqual(parsed["compression_client_to_server"], ["none"])

    def test_smb2_response_parser(self) -> None:
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
        body = (
            struct.pack("<H", 65)
            + struct.pack("<H", 3)
            + struct.pack("<H", 0x0302)
            + struct.pack("<H", 0)
            + bytes(range(16))
            + struct.pack("<I", 2)
            + struct.pack("<I", 8388608)
            + struct.pack("<I", 8388608)
            + struct.pack("<I", 8388608)
            + struct.pack("<Q", 0)
            + struct.pack("<Q", 0)
            + struct.pack("<H", 0)
            + struct.pack("<H", 0)
            + struct.pack("<I", 0)
        )
        parsed = portscope._smb2_parse(header + body)
        self.assertTrue(parsed["signing_required"])
        self.assertEqual(parsed["dialect_name"], "SMB 3.0.2")

    def test_dns_parser(self) -> None:
        query = portscope._dns_query("version.bind")
        txid = query[:2]
        pos = 12
        while query[pos] != 0:
            pos += query[pos] + 1
        pos += 1 + 4
        question = query[12:pos]
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 60, 6) + b"\x05BIND9"
        response = txid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + question + answer
        parsed = portscope._dns_parse(response)
        self.assertEqual(parsed["answers"][0]["value"], "BIND9")
        self.assertTrue(parsed["recursion_available"])


class IntegrationTests(unittest.TestCase):
    def test_http_probe_and_report(self) -> None:
        server = start_http_server()
        self.addCleanup(stop_server, server)
        port = server.server_address[1]
        code, report = run_scan(
            [
                "--target",
                "127.0.0.1",
                "--ports",
                str(port),
                "--service-map",
                f"{port}=http",
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["ports"], 1)
        port_result = report["hosts"][0]["ports"][0]
        self.assertEqual(port_result["live_state"], "open")
        self.assertEqual(port_result["probe"]["data"]["status_code"], 200)
        codes = {finding["code"] for finding in port_result["findings"]}
        self.assertIn("HTTP_CLEARTEXT", codes)
        self.assertIn("HTTP_SECURITY_HEADERS_MISSING", codes)
        self.assertIn("HTTP_COOKIE_FLAGS", codes)
        self.assertEqual(port_result["probe"]["data"]["allow"], "GET, OPTIONS")

    def test_nse_runner_merges_safe_script_output(self) -> None:
        server = start_http_server()
        self.addCleanup(stop_server, server)
        port = server.server_address[1]
        with tempfile.TemporaryDirectory() as tmp:
            fake_nmap = os.path.join(tmp, "fake-nmap")
            script = f"""#!/usr/bin/env python3
import sys
xml = sys.argv[sys.argv.index("-oX") + 1]
with open(xml, "w", encoding="utf-8") as handle:
    handle.write('''<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="{port}"><state state="open"/><service name="http"/><script id="http-title" output="Fake NSE title"/></port></ports></host></nmaprun>''')
"""
            with open(fake_nmap, "w", encoding="utf-8") as handle:
                handle.write(script)
            os.chmod(fake_nmap, 0o755)
            code, report = run_scan(
                [
                    "--target",
                    "127.0.0.1",
                    "--ports",
                    str(port),
                    "--service-map",
                    f"{port}=http",
                    "--nse-scripts",
                    "http-title",
                    "--nmap-bin",
                    fake_nmap,
                ]
            )
        self.assertEqual(code, 0)
        port_result = report["hosts"][0]["ports"][0]
        self.assertEqual(port_result["nse"]["http-title"], "Fake NSE title")
        self.assertEqual(report["nse"]["scripts_requested"], ["http-title"])

    def test_http_fallback_on_unknown_service(self) -> None:
        server = start_http_server()
        self.addCleanup(stop_server, server)
        port = server.server_address[1]
        code, report = run_scan(
            [
                "--target",
                "127.0.0.1",
                "--ports",
                str(port),
                "--http-fallback",
            ]
        )
        self.assertEqual(code, 0)
        port_result = report["hosts"][0]["ports"][0]
        self.assertEqual(port_result["probe"]["protocol"], "http")
        self.assertEqual(port_result["probe"]["data"]["status_code"], 200)

    def test_redis_unauthenticated(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        port = server.getsockname()[1]
        self.addCleanup(server.close)

        def serve() -> None:
            while True:
                try:
                    client, _ = server.accept()
                except OSError:
                    return
                with client:
                    data = client.recv(1024)
                    if b"PING" in data.upper():
                        client.sendall(b"+PONG\r\n")

        threading.Thread(target=serve, daemon=True).start()
        code, report = run_scan(
            [
                "--target",
                "127.0.0.1",
                "--ports",
                str(port),
                "--service-map",
                f"{port}=redis",
            ]
        )
        self.assertEqual(code, 0)
        port_result = report["hosts"][0]["ports"][0]
        codes = {finding["code"] for finding in port_result["findings"]}
        self.assertIn("REDIS_UNAUTHENTICATED", codes)
        self.assertEqual(port_result["probe"]["data"]["response"], "+PONG")

    def test_https_certificate(self) -> None:
        openssl = subprocess.run(
            ["which", "openssl"], capture_output=True, text=True, check=False
        ).stdout.strip()
        if not openssl:
            self.skipTest("openssl not available")
        with tempfile.TemporaryDirectory() as tmp:
            cert = os.path.join(tmp, "cert.pem")
            key = os.path.join(tmp, "key.pem")
            subprocess.run(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    key,
                    "-out",
                    cert,
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server = start_http_server(context)
            self.addCleanup(stop_server, server)
            port = server.server_address[1]
            code, report = run_scan(
                [
                    "--target",
                    "127.0.0.1",
                    "--ports",
                    str(port),
                    "--service-map",
                    f"{port}=https",
                    "--sni",
                    "localhost",
                ]
            )
        self.assertEqual(code, 0)
        port_result = report["hosts"][0]["ports"][0]
        tls = port_result["probe"]["data"]["tls"]
        self.assertTrue(tls["version"].startswith("TLS"))
        self.assertTrue(tls["certificate"]["self_signed"])
        self.assertTrue(tls["certificate"]["hostname_match"])
        codes = {finding["code"] for finding in port_result["findings"]}
        self.assertIn("TLS_SELF_SIGNED", codes)


if __name__ == "__main__":
    unittest.main()
