#!/usr/bin/env python3
"""Loopback integration regressions for the built Telnet module.

Run after configuring with OpenSSL support and make: python3 tests/test_telnet.py
HYDRA_TEST_BINARY can select another build. No external services are used.
The TLS fixtures use the openssl command to generate temporary certificates.
"""
import os
from pathlib import Path
import re
import secrets
import signal
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

USER = "fixture_user"
PASSWORD = os.environ.get("HYDRA_TEST_PASSWORD", secrets.token_hex(10))
WRONG = secrets.token_hex(10)
BINARY = Path(os.environ.get("HYDRA_TEST_BINARY", Path(__file__).resolve().parents[1] / "hydra"))
IAC = b"\xff\xfb\x01\xff\xfd\x1f"


class Fixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, **options):
        self.options = options
        self.attempts = []
        self.inputs = []
        self.tls_files = None
        self.tls_context = None
        if options.get("tls"):
            self.tls_files = tempfile.TemporaryDirectory(prefix="hydra-telnet-tls-")
            cert = Path(self.tls_files.name) / "cert.pem"
            key = Path(self.tls_files.name) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost"], check=True, capture_output=True, timeout=10)
            self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls_context.load_cert_chain(cert, key)
        super().__init__(("127.0.0.1", 0), Login)

    def get_request(self):
        sock, address = super().get_request()
        if self.tls_context:
            sock.settimeout(3)
            sock = self.tls_context.wrap_socket(sock, server_side=True)
        return sock, address

    def server_close(self):
        super().server_close()
        if self.tls_files:
            self.tls_files.cleanup()


class Login(socketserver.BaseRequestHandler):
    def read_line(self):
        result = bytearray()
        while len(result) < 2048:
            byte = self.request.recv(1)
            if not byte:
                return None
            if byte == b"\xff":
                command = self.request.recv(1)
                if command in (b"\xfb", b"\xfc", b"\xfd", b"\xfe"):
                    self.request.recv(1)
                continue
            if byte in (b"\x00", b"\n") and not result:
                continue
            if byte in (b"\r", b"\n"):
                return result.decode(errors="replace")
            result += byte
        return None

    def send(self, value, split=False):
        if split:
            for part in (value[:2], value[2:]):
                self.request.sendall(part)
                time.sleep(0.15)
        else:
            self.request.sendall(value)

    def handle(self):
        opt = self.server.options
        self.request.settimeout(6)
        try:
            if opt.get("silent_initial"):
                self.request.recv(1024)
                return
            if opt.get("iac"):
                if opt.get("split_iac"):
                    for byte in IAC:
                        self.request.sendall(bytes([byte]))
                        time.sleep(0.15)
                else:
                    self.request.sendall(IAC)
                if opt.get("subnegotiation"):
                    # An escaped IAC in SB must not terminate the payload.
                    self.request.sendall(b"\xff\xfa\x18\x00term\xff\xff\xff\xf0")
                if opt.get("no_linemode"):
                    self.request.sendall(b"\xff\xfe\x22")
            if opt.get("press_enter"):
                self.send(b"Press ENTER to continue")
                if self.read_line() is None:
                    return
            if opt.get("banner"):
                self.send(b"Visit http://example.invalid/ for help\r\n")
                time.sleep(0.15)
            password_only = opt.get("password_only")
            self.send(b"Password: " if password_only else b"login: ", opt.get("split_prompt"))
            for _ in range(8):
                username = USER if password_only else self.read_line()
                if username is None:
                    return
                if not password_only:
                    self.server.inputs.append("username")
                if opt.get("silent_username"):
                    self.request.recv(1024)
                    return
                if not password_only:
                    if opt.get("passwordless") and username == USER:
                        self.server.attempts.append(True)
                        self.send(b"LOCAL_AUTH_OK\r\nfixture@local:~$ ")
                        while self.request.recv(1024):
                            pass
                        return
                    self.send(b"Password: ", opt.get("split_prompt"))
                password = self.read_line()
                if password is None:
                    return
                self.server.inputs.append("password")
                if opt.get("silent_password"):
                    self.request.recv(1024)
                    return
                accepted = username == USER and password == PASSWORD
                self.server.attempts.append(accepted)
                if accepted:
                    if opt.get("split_success"):
                        self.send(b"Last login: Thu Oct 29\r\n")
                        time.sleep(0.15)
                    self.send(b"LOCAL_AUTH_OK\r\nfixture@local:~$ ")
                    while self.request.recv(1024):
                        pass
                    return
                if opt.get("failure_only"):
                    self.send(b"Login incorrect\r\n")
                    return
                if password_only:
                    self.send(b"Login incorrect\r\nPassword: ", opt.get("split_prompt"))
                else:
                    self.send(b"Login incorrect\r\nlogin: ", opt.get("split_prompt"))
        except OSError:
            pass


class TelnetTests(unittest.TestCase):
    def check_login(self, passwords=None, users=None, success=True, marker=None, **options):
        fixture = Fixture(**options)
        thread = threading.Thread(target=fixture.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="hydra-telnet-test-") as directory:
                directory = Path(directory)
                candidates = directory / "passwords.txt"
                candidates.write_text("\n".join(passwords or [PASSWORD]) + "\n")
                argv = [str(BINARY), "-I", "-P", str(candidates), "-t", "1", "-w", "1", "-f",
                        "-s", str(fixture.server_address[1])]
                if users:
                    names = directory / "users.txt"
                    names.write_text("\n".join(users) + "\n")
                    argv += ["-L", str(names)]
                else:
                    argv += ["-l", USER]
                if options.get("tls"):
                    argv.append("-S")
                argv += ["127.0.0.1", "telnet"]
                if marker:
                    argv.append(marker)
                env = {k: v for k, v in os.environ.items() if k not in ("HYDRA_PROXY", "HYDRA_PROXY_HTTP")}
                process = subprocess.Popen(argv, cwd=directory, env=env, start_new_session=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    output, _ = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    output, _ = process.communicate()
                    self.fail("Telnet client did not finish within five seconds")
                reports = re.findall(r"host:\s*127\.0\.0\.1[^\r\n]*?login:\s*(\S+)\s+password:\s*(\S+)", output)
                safe_output = output.replace(PASSWORD, "<fixture-password>").replace(WRONG, "<fixture-password>")
                self.assertNotIn("ERROR: AddressSanitizer", safe_output)
                self.assertNotIn("runtime error:", safe_output)
                self.assertEqual(bool(reports), success, safe_output)
                if success:
                    self.assertEqual(fixture.attempts.count(True), 1, safe_output)
                    self.assertTrue(reports == [(USER, PASSWORD)], "Unexpected reported credential")
                elif not any(options.get(name) for name in ("silent_initial", "silent_username", "silent_password")):
                    self.assertTrue(fixture.attempts, "No candidate actually reached authentication")
                    self.assertFalse(any(fixture.attempts))
                else:
                    self.assertIn("[ERROR]", safe_output)
                return fixture.attempts, fixture.inputs
        finally:
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=1)

    def test_single_prompt(self):
        self.check_login()

    def test_wrong_then_correct_on_same_connection(self):
        attempts, _ = self.check_login(passwords=[WRONG, PASSWORD])
        self.assertEqual(attempts, [False, True])

    def test_all_wrong_on_same_connection(self):
        attempts, _ = self.check_login(passwords=[WRONG, WRONG + "1"], success=False)
        self.assertEqual(attempts, [False, False])

    def test_next_username(self):
        self.check_login(users=["wrong_user", USER])

    def test_password_only(self):
        _, inputs = self.check_login(password_only=True)
        self.assertNotIn("username", inputs)

    def test_password_only_retry(self):
        self.check_login(password_only=True, passwords=[WRONG, PASSWORD])

    def test_password_only_all_wrong(self):
        self.check_login(password_only=True, passwords=[WRONG, WRONG + "1"], success=False)

    def test_split_prompts(self):
        self.check_login(split_prompt=True, passwords=[WRONG, PASSWORD])

    def test_iac_with_prompt(self):
        self.check_login(iac=True)

    def test_split_iac(self):
        self.check_login(iac=True, split_iac=True)

    def test_ssl_iac_with_prompt(self):
        self.check_login(tls=True, iac=True)

    def test_ssl_retry(self):
        self.check_login(tls=True, iac=True, passwords=[WRONG, PASSWORD])

    def test_ssl_linemode_refusal(self):
        self.check_login(tls=True, iac=True, no_linemode=True)

    def test_subnegotiation_and_linemode_refusal(self):
        self.check_login(iac=True, subnegotiation=True, no_linemode=True)

    def test_press_enter(self):
        self.check_login(press_enter=True)

    def test_banner_does_not_authenticate(self):
        self.check_login(banner=True, passwords=[WRONG], success=False)

    def test_split_last_login(self):
        self.check_login(split_success=True)

    def test_explicit_success_and_failure(self):
        self.check_login(passwords=[WRONG, PASSWORD], marker="S=LOCAL_AUTH_OK:F=Login incorrect")

    def test_passwordless_account(self):
        self.check_login(passwordless=True)

    def test_failure_without_reprompt_reconnects(self):
        self.check_login(passwords=[WRONG, PASSWORD], failure_only=True)

    def test_missing_initial_prompt_is_bounded(self):
        self.check_login(silent_initial=True, success=False)

    def test_missing_password_prompt_is_bounded(self):
        self.check_login(silent_username=True, success=False)

    def test_missing_authentication_response_is_bounded(self):
        self.check_login(silent_password=True, success=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
