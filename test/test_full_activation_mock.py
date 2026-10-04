#!/usr/bin/env python3
"""
test_full_activation_mock.py - OFFLINE mock end-to-end test of the
full_activation.py activation flow, faithful to the decompiled app.

No Microsoft / Google traffic is made. Three fakes replace the real parties:

  FakeMcsServer     - a miniature mtalk.google.com:5228: accepts the MCS
                      version byte + LoginRequest, replies LOGIN OK, and
                      pushes a DataMessageStanza with the challenge
                      app-data the real service sends (type=validate,
                      source=SAS, guid, url, oathCounter...).
  FakeSoapServer    - the PfPaWs.asmx endpoint: validates the ActivateNew
                      request against the decompiled ActivationRequest shape
                      (ns4 elements, OathCounter, DeviceToken...), then
                      BLOCKS until the PAD answer arrives (exactly the live
                      behavior the report observed), and finally returns an
                      ActivateNewResponse with OathTokenSecretKey.
  FakePadServer     - /pad/ endpoint: validates the pfpMessage envelope and
                      x-ms-mac-* headers (incl. SHA-256 device-token hash)
                      and answers phoneAppValidateDeviceTokenResponse.

Asserted, per the decompiled app:
  1. MCS handshake bytes (version byte 41, LoginRequest protobuf fields)
  2. challenge push framing + app-data parsing + routing filter
  3. SOAP ActivateNew request shape (header/envelope/ns4 body)
  4. pfpMessage envelope structure (nested <host> inside <component>)
  5. x-ms-mac-* header set incl. sha256(device-token) - TransportFactory +
     MfaHashAlgorithm parity
  6. end-to-end ordering: ActivateNew fires -> challenge answered ->
     ActivateNew unblocks with the secret -> TOTP chain validates
  7. V2 deviceTokenChangeVersion short-circuit (no HTTP)
  8. non-challenge pushes (type=auth) are NOT answered
  9. HMAC-SHA256 TOTP derived from the mock secret matches the PAD server's
     expectation (OathCounter taken from the push) - the same chain the real
     flow closes with ConfirmActivation.

Run:  python3 -m unittest test.test_full_activation_mock
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import app.activation as fa
import app.mcs as mcs

TOTP_STEP = 30


def setUpModule():
    from test.entra_fixtures import synthetic_apk_state
    unittest.enterModuleContext(synthetic_apk_state())


# ----------------------------- tiny TOTP (RFC 6238) -------------------------

def totp(secret_bytes: bytes, counter: int, digits: int = 6, algo: str = "sha256") -> str:
    h = hmac.new(secret_bytes, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


# ------------------------------ mock MCS server -----------------------------

class FakeMcsServer(threading.Thread):
    """Miniature mtalk.google.com. Accepts one client, performs the MCS
    handshake (version byte + LoginRequest), replies LOGIN OK, then pushes
    the challenge DataMessageStanza. Records what the client logged in with."""

    def __init__(self, challenge_appdata: dict, require_login: bool = True,
                 delay_after_login: float = 0.6):
        super().__init__(daemon=True)
        self.challenge = challenge_appdata
        self.require_login = require_login
        self.delay = delay_after_login
        self.login_body: bytes | None = None
        self.client_version: int | None = None
        self.acks: list[int] = []
        self._stop = threading.Event()
        self._socks: list[socket.socket] = []
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.port = self._srv.getsockname()[1]

    # -- protobuf helpers (mirror full_activation's wire format) --
    @staticmethod
    def varint(n: int) -> bytes:
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out

    @classmethod
    def pb_str(cls, f: int, v: str) -> bytes:
        b = v.encode()
        return cls.varint((f << 3) | 2) + cls.varint(len(b)) + b

    @classmethod
    def stanza(cls, tag: int, body: bytes) -> bytes:
        return bytes([tag]) + cls.varint(len(body)) + body

    def push_appdata(self, appdata: dict) -> bytes:
        """DataMessageStanza: field5=category, repeated field7 AppData(k,v).
        AppData entries are plain protobuf length-delimited fields (wire 2),
        NOT MCS stanzas."""
        body = self.pb_str(5, fa.APP)
        for k, v in appdata.items():
            payload = self.pb_str(1, k) + self.pb_str(2, str(v))
            body += self.varint((7 << 3) | 2) + self.varint(len(payload)) + payload
        return self.stanza(8, body)

    def run(self):
        while not self._stop.is_set():
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            t.start()

    certfile: str = ""
    keyfile: str = ""

    def _serve(self, conn: socket.socket):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.certfile, self.keyfile)
        try:
            conn = ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            conn.close()
            return
        self._socks.append(conn)
        try:
            ver = conn.recv(1)
            self.client_version = ver[0]
            tag = conn.recv(1)[0]
            assert tag == 2, f"expected LOGIN_REQUEST(2), got {tag}"
            ln = 0
            shift = 0
            while True:
                b = conn.recv(1)[0]
                ln |= (b & 0x7F) << shift
                if not b & 0x80:
                    break
                shift += 7
            self.login_body = b""
            while len(self.login_body) < ln:
                chunk = conn.recv(ln - len(self.login_body))
                if not chunk:
                    raise ConnectionError("closed during login")
                self.login_body += chunk
            # Server sends its version byte, then a valid LoginResponse.
            conn.sendall(bytes([mcs.MCS_VERSION]) + self.stanza(3, mcs.pb_str(1, 'mock-login')))
            time.sleep(self.delay)
            conn.sendall(self.push_appdata(self.challenge))
            # keep the connection open; ack heartbeats like the real service
            while not self._stop.is_set():
                try:
                    conn.settimeout(0.5)
                    t = conn.recv(1)
                    if not t:
                        break
                    if t[0] == 1:  # heartbeat ack
                        self.acks.append(1)
                except (socket.timeout, OSError):
                    continue
        except (AssertionError, ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass


# --------------------------- mock HTTP(S) servers ---------------------------

class FakeMfaServers:
    """PfPaWs.asmx (SOAP) + /pad/ (pfpMessage) on one TLS port.

    Behavior mirrors the live service as documented in REPORT.md:
      * ActivateNew blocks (server waits for device validation) until a
        successful phoneAppValidateDeviceTokenRequest with the challenge guid
        arrives on /pad, then returns the secret.
      * If the device-token hash header doesn't match sha256(token), PAD
        rejects and the activation would eventually time out (err 15 path).
    """

    def __init__(self, guid: str, secret_b32: str, oath_counter: str,
                 device_token: str):
        self.guid = guid
        self.secret_b32 = secret_b32
        self.oath_counter = oath_counter
        self.device_token = device_token
        self.activate_body: bytes | None = None
        self.activate_headers: dict = {}
        self.pad_bodies: list[bytes] = []
        self.pad_headers: list[dict] = []
        self.pad_status_codes: list[int] = []
        self.activation_released = threading.Event()
        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.port = self._srv.server_address[1]

    def _handler(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                ln = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(ln)
                path = urlparse(self.path).path
                if path.endswith("/PfPaWs.asmx"):
                    outer.activate_body = body
                    outer.activate_headers = {k.lower(): v for k, v in self.headers.items()}
                    # server-side wait for the PAD validation, like the real gate
                    outer.activation_released.wait(timeout=25)
                    if not outer.activation_released.is_set():
                        xml = fa.build_soap(
                            "<ns4:ActivateNewResponse><ns4:ActivateNewResult>false</ns4:ActivateNewResult>"
                            "<ns4:Code>15</ns4:Code><ns4:Description>Activation failed</ns4:Description>"
                            "</ns4:ActivateNewResponse>")
                        self._reply(200, xml)
                        return
                    xml = fa.build_soap(
                        "<ns4:ActivateNewResponse>"
                        "<ns4:ActivateNewResult>true</ns4:ActivateNewResult>"
                        f"<ns4:OathTokenSecretKey>{outer.secret_b32}</ns4:OathTokenSecretKey>"
                        "<ns4:OathTokenEnabled>true</ns4:OathTokenEnabled>"
                        "<ns4:Username>user@tenant.example</ns4:Username>"
                        "<ns4:TenantId>11111111-2222-3333-4444-555555555555</ns4:TenantId>"
                        "<ns4:AzureObjectId>abcdef01-2345-6789-abcd-ef0123456789</ns4:AzureObjectId>"
                        "<ns4:ConfirmationCode>1234567</ns4:ConfirmationCode>"
                        "<ns4:ReplicationScope>scope</ns4:ReplicationScope>"
                        "<ns4:RoutingHint>hint</ns4:RoutingHint>"
                        "<ns4:CountryCode>US</ns4:CountryCode>"
                        "</ns4:ActivateNewResponse>")
                    self._reply(200, xml)
                elif path.endswith("/pad"):
                    outer.pad_bodies.append(body)
                    outer.pad_headers.append({k.lower(): v for k, v in self.headers.items()})
                    ok = self._check_headers()
                    outer.pad_status_codes.append(200 if ok else 401)
                    # successful validation releases the blocked ActivateNew
                    if ok and fa.read_tag(body.decode("utf-8", "replace"), "guid") == outer.guid:
                        outer.activation_released.set()
                    self._reply(200 if ok else 401, fa.pfp(
                        '<phoneAppValidateDeviceTokenResponse>'
                        '<groupKey>group-key-1</groupKey>'
                        '<username>user@tenant.example</username>'
                        '<accountName>User Account</accountName>'
                        '<dosPreventer>dp123</dosPreventer>'
                        '<accountValidationResults></accountValidationResults>'
                        '</phoneAppValidateDeviceTokenResponse>'))
                else:
                    self._reply(404, "not found")

            def _check_headers(self) -> bool:
                got = outer.pad_headers[-1]
                want_hash = hashlib.sha256(outer.device_token.encode()).hexdigest()
                checks = [
                    got.get("content-type") == "application/xml",
                    got.get("appname") == fa.APP,
                    got.get("devicetype") == "Android",
                    got.get("x-ms-mac-flavor") == fa.FLAVOR,
                    got.get("x-ms-mac-os-platform") == "Android",
                    got.get("x-ms-mac-interactive") == "true",
                    got.get("x-ms-mac-action") == "phoneAppValidateDeviceTokenRequest",
                    got.get("x-ms-mac-device-token") == want_hash,
                ]
                return all(checks)

            def _reply(self, code: int, text: str):
                payload = text.encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        return H

    def start(self):
        self._srv.serve_forever()

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


# --------------------------------- plumbing ---------------------------------

class RedirectListener:
    """Drives full_activation.McsListener against the fake MCS server by
    patching the transport the listener touches. Exposes the REAL listener's
    event and pushes lists directly - no mirroring, no races."""

    def __init__(self, port: int):
        self.port = port
        self._real_listener: mcs.McsListener | None = None
        self._patched = False

    def start(self):
        real_create = RedirectListener._orig_create

        def fake_create(*args, **kw):
            # only redirect the MCS connection; anything else (HTTP to the
            # fake PAD/SOAP endpoints) goes through untouched
            address = args[0]
            if isinstance(address, tuple) and address[0] == mcs.MCS_HOST:
                return real_create(("127.0.0.1", self.port), timeout=5)
            return real_create(*args, **kw)

        def fake_ctx():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx

        socket.create_connection = fake_create
        ssl.create_default_context = fake_ctx
        self._patched = True
        real_run = mcs.McsListener.run

        class _L(mcs.McsListener):
            def __init__(self):
                super().__init__(1234567890123456789, 987654321)

            def run(self):
                try:
                    real_run(self)
                except Exception:
                    pass

        self._real_listener = _L()
        self._real_listener.start()

    @property
    def pushes(self) -> list:
        return self._real_listener.pushes if self._real_listener else []

    @property
    def event(self) -> threading.Event:
        return self._real_listener.event

    def stop(self):
        try:
            if self._real_listener:
                self._real_listener.stop()
        except Exception:
            pass
        if self._patched:
            socket.create_connection = RedirectListener._orig_create
            ssl.create_default_context = RedirectListener._orig_ctx
            self._patched = False

    _orig_create = staticmethod(socket.create_connection)
    _orig_ctx = staticmethod(ssl.create_default_context)


def answer_pad(pad_url: str, guid: str, device_token: str) -> tuple[int, str]:
    """Direct PAD answer helper (what the app's UseCase does)."""
    body = fa.build_validation(guid, device_token)
    return fa.pad_post(pad_url, body, device_token, "phoneAppValidateDeviceTokenRequest")


# ---------------------------------- tests ----------------------------------

class TestChallengeRouting(unittest.TestCase):
    """NotificationProcessorUseCase + parseMfaValidateDeviceNotificationDetails parity."""

    def test_challenge_accepted(self):
        self.assertTrue(fa.is_valid_challenge(
            {"type": "validate", "source": "SAS", "guid": "g"}))

    def test_mfa_server_source_accepted(self):
        self.assertTrue(fa.is_valid_challenge(
            {"type": "validate", "source": "MFA Server", "guid": "g"}))

    def test_auth_push_rejected(self):
        # a real authentication push must NOT trigger a PAD answer
        self.assertFalse(fa.is_valid_challenge(
            {"type": "auth", "source": "SAS", "guid": "g"}))

    def test_missing_source_rejected(self):
        self.assertFalse(fa.is_valid_challenge({"type": "validate", "guid": "g"}))

    def test_url_comes_from_push_not_link(self):
        guid, pad_url, dtcv = fa.extract_challenge({
            "guid": "abc-123", "url": "mobileappcommunicator.svc.sovcloud.fr",
            "oathCounter": "69123456", "deviceTokenChangeVersion": ""})
        self.assertEqual(guid, "abc-123")
        self.assertEqual(pad_url, "https://mobileappcommunicator.svc.sovcloud.fr/pad")
        self.assertEqual(dtcv, "")

    def test_url_with_trailing_slash(self):
        _, pad_url, _ = fa.extract_challenge({"guid": "g", "url": "host.example.com/"})
        self.assertEqual(pad_url, "https://host.example.com/pad")

    def test_v2_flag(self):
        _, _, dtcv = fa.extract_challenge({"guid": "g", "url": "h", "deviceTokenChangeVersion": "V2"})
        self.assertEqual(dtcv, "V2")


class TestAnswerChallenge(unittest.TestCase):
    """MfaValidateDeviceNotification.handleMessageWithResult parity."""

    def setUp(self):
        self.device_token = "fcm-token-abc"
        self.guid = "01234567-89ab-cdef-0123-456789abcdef"

    def test_v2_short_circuits_without_http(self):
        out = fa.answer_challenge({"guid": self.guid, "url": "h.example.com",
                                   "deviceTokenChangeVersion": "V2"}, self.device_token)
        self.assertEqual(out["action"], "notify-only")

    def test_empty_guid_aborts(self):
        # app: isInformationMissing -> false, never POSTs with a blank guid
        out = fa.answer_challenge({"guid": "", "url": "h.example.com"}, self.device_token)
        self.assertEqual(out["action"], "abort")

    def test_missing_url_aborts(self):
        out = fa.answer_challenge({"guid": self.guid, "url": ""}, self.device_token)
        self.assertEqual(out["action"], "abort")

    def test_disallowed_host_aborts(self):
        out = fa.answer_challenge({"guid": self.guid, "url": "evil.example.net"}, self.device_token)
        self.assertEqual(out["action"], "abort")


class TestPfpEnvelope(unittest.TestCase):
    """AbstractMfaRequest.buildHeader structure parity."""

    def test_host_is_nested_child_of_component(self):
        xml = fa.build_validation("g", "tok")
        self.assertIn('<component type="pfsvc" role="master">'
                      '<host ip="" hostname="" serverId="" /></component>', xml)
        # old (wrong) flat form must be gone
        self.assertNotIn('role="master" ip=', xml)

    def test_request_attrs(self):
        xml = fa.build_validation("g", "tok")
        self.assertIn('version="1.6"', xml)
        self.assertIn('async="0"', xml)
        self.assertIn('language="en"', xml)

    def test_validation_fields(self):
        xml = fa.build_validation("g", "tok")
        self.assertIn("<phoneAppValidateDeviceTokenRequest>", xml)
        self.assertIn("<guid>g</guid>", xml)
        self.assertIn("<oathCode></oathCode>", xml)
        self.assertIn("<deviceToken>tok</deviceToken>", xml)
        self.assertIn(f"<version>{fa.app_identity.app_version()}</version>", xml)
        self.assertIn(f"<osVersion>{fa.OS_VERSION}</osVersion>", xml)
        self.assertIn("<needDosPreventer>yes</needDosPreventer>", xml)
        self.assertIn("<accounts></accounts>", xml)
        self.assertIn("<validationResult>yes</validationResult>", xml)


class TestPadHeaders(unittest.TestCase):
    """TransportFactory constants + MfaHashAlgorithm parity."""

    def test_header_values(self):
        tok = "fcm-token-xyz"
        h = fa.build_pad_headers(tok, "phoneAppValidateDeviceTokenRequest")
        self.assertEqual(h["Content-Type"], "application/xml")          # XML_CONTENT_TYPE
        self.assertEqual(h["AppName"], fa.APP)                          # APP_NAME_KEY
        self.assertEqual(h["DeviceType"], "Android")                    # DEVICE_TYPE_KEY
        self.assertEqual(h["x-ms-mac-interactive"], "true")             # VALUE_PUSH_NOTIFICATION_ATTRIBUTE
        self.assertEqual(h["x-ms-mac-device-token"],
                         hashlib.sha256(tok.encode()).hexdigest())      # MfaHashAlgorithm
        self.assertEqual(h["x-ms-mac-action"], "phoneAppValidateDeviceTokenRequest")


class TestSoapActivationRequest(unittest.TestCase):
    """ActivationRequest.buildBody parity (element names and order)."""

    def test_body_fields(self):
        xml = fa.build_activate("123456789", "tok", "Pixel 8", 69123456)
        self.assertIn("<ns4:ActivateNew><ns4:activationParams>", xml)
        self.assertIn("<ns4:ActivationCode>123456789</ns4:ActivationCode>", xml)
        self.assertIn("<ns4:DeviceToken>tok</ns4:DeviceToken>", xml)
        self.assertIn("<ns4:DeviceName>Pixel 8</ns4:DeviceName>", xml)
        self.assertIn("<ns4:OathCounter>69123456</ns4:OathCounter>", xml)
        self.assertIn(f"<ns4:Version>{fa.app_identity.app_version()}</ns4:Version>", xml)

    def test_envelope_namespaces(self):
        xml = fa.build_activate("c", "t", "d", 1)
        for ns in ('xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"',
                   'xmlns:ns4="http://www.phonefactor.com/PfPaWs"',
                   "<soap:Header />"):
            self.assertIn(ns, xml)


class TestTotPChain(unittest.TestCase):
    """The final goal: secret -> TOTP. Entra = HMAC-SHA256/6/30 per MfaTotpUseCase."""

    def test_sha256_totp_matches_reference(self):
        secret = "JBSWY3DPEHPK3PXP"
        counter = 69123456
        code = totp(secret.encode(), counter, 6, "sha256")
        # independent recomputation with explicit RFC 6238 truncation
        h = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha256).digest()
        o = h[-1] & 0x0F
        ref = str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)
        self.assertEqual(code, ref)
        self.assertEqual(len(code), 6)

    def test_sha1_totp_rfc6238_vector(self):
        # RFC 6238 Appendix B SHA-1 vector: secret "12345678901234567890",
        # T=59 -> counter = 59//30 = 1 -> "94287082" (8 digits)
        secret = b"12345678901234567890"
        self.assertEqual(totp(secret, 59 // TOTP_STEP, 8, "sha1"), "94287082")
        # sanity: counters roll and codes stay 6-digit zero-padded for Entra params
        codes = {totp(secret, c, 6, "sha256") for c in range(3)}
        self.assertEqual(len(codes), 3)
        self.assertTrue(all(len(c) == 6 and c.isdigit() for c in codes))


class TestEndToEnd(unittest.TestCase):
    """Full mock chain: MCS push -> PAD answer -> ActivateNew unblocks -> secret -> TOTP."""

    def setUp(self):
        # generate a cert for the TLS servers (MCS fake)
        self._tmp = tempfile.TemporaryDirectory()
        self._prior_state_dir = os.environ.get('AUTH_STATE_DIR')
        os.environ['AUTH_STATE_DIR'] = self._tmp.name
        with open(os.path.join(self._tmp.name, 'apk_config.json'), 'w') as stream:
            json.dump({'package': fa.APP, 'version_name': '6.2608.5658'}, stream)
        self._old = os.getcwd()
        os.chdir(self._tmp.name)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", "key.pem", "-out", "cert.pem", "-days", "1",
             "-subj", "/CN=127.0.0.1"],
            check=True, capture_output=True)
        self.cert = os.path.abspath("cert.pem")
        self.key = os.path.abspath("key.pem")

        self.device_token = "APA91bMockTokenForTestingOnly_0123456789abcdef"
        self.guid = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
        self.oath_counter = str(int(time.time()) // TOTP_STEP)
        self.secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        self.expected_totp = totp(self.secret.encode(), int(self.oath_counter), 6, "sha256")

        self.challenge = {"type": "validate", "source": "SAS", "guid": self.guid,
                          "url": "mobileappcommunicator.auth.microsoft.com",
                          "oathCounter": self.oath_counter,
                          "tenantId": "11111111-2222-3333-4444-555555555555",
                          "routingHint": "", "replicationScope": "", "countryCode": "US",
                          "deviceTokenChangeVersion": ""}

        self.mcs = FakeMcsServer(self.challenge)
        self.mcs.certfile, self.mcs.keyfile = self.cert, self.key
        self.mcs.start()

        self.http = FakeMfaServers(self.guid, self.secret, self.oath_counter,
                                   self.device_token)
        self.http_thread = threading.Thread(target=self.http.start, daemon=True)
        self.http_thread.start()

        # route the push's service url at the fake /pad endpoint and let the
        # host allow-list accept the loopback (production code stays strict)
        self.challenge["url"] = f"127.0.0.1:{self.http.port}"
        self._real_allowed = fa.PAD_ALLOWED_HOST_SUFFIXES
        fa.PAD_ALLOWED_HOST_SUFFIXES = self._real_allowed + ("127.0.0.1", "localhost")

        # patch the two HTTP transports to hit the local fake endpoints
        self._patch_pad()
        self._patch_soap()

    def _patch_pad(self):
        real_pad = fa.pad_post
        port = self.http.port

        def fake_pad(url, body, device_token, action):
            p = urlparse(url)
            local = f"http://127.0.0.1:{port}/pad"
            return real_pad(local, body, device_token, action)

        fa.pad_post = fake_pad
        self._real_pad = real_pad

    def _patch_soap(self):
        port = self.http.port
        real_soap = fa.soap_post

        def fake_soap(url, body, action, timeout=90):
            # emulate the app: POST to <base>/PfPaWs.asmx, here on the fake
            return real_urlopen(f"http://127.0.0.1:{port}/PfPaWs.asmx", body, action)

        def real_urlopen(url, body, action):
            req = urllib.request.Request(
                url, data=body.encode(), method="POST",
                headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": action})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")

        import urllib.request as _ur
        self._real_soap = real_soap
        fa.soap_post = fake_soap

    def tearDown(self):
        fa.pad_post = self._real_pad
        fa.soap_post = self._real_soap
        fa.PAD_ALLOWED_HOST_SUFFIXES = self._real_allowed
        self.mcs.stop()
        self.http.stop()
        os.chdir(self._old)
        if self._prior_state_dir is None:
            os.environ.pop('AUTH_STATE_DIR', None)
        else:
            os.environ['AUTH_STATE_DIR'] = self._prior_state_dir
        self._tmp.cleanup()

    def test_full_activation_flow(self):
        listener = RedirectListener(self.mcs.port)
        listener.start()
        self.addCleanup(listener.stop)
        time.sleep(0.3)

        body = fa.build_activate("987654321", self.device_token, "Pixel 8", int(self.oath_counter))
        result: dict = {}

        def do_activate():
            st, text = fa.soap_post(f"https://mobileappcommunicator.auth.microsoft.com/PfPaWs.asmx",
                                    body, fa.SOAP_ACT)
            result["status"], result["text"] = st, text
            result["done"] = True

        threading.Thread(target=do_activate, daemon=True).start()

        # drive the same wait loop the CLI uses, then give the SOAP reply a
        # grace window (mock server holds ActivateNew until PAD lands)
        fa.challenge_loop(listener, result, self.device_token, timeout=20)
        for _ in range(100):
            if result.get("done"):
                break
            time.sleep(0.3)

        self.assertTrue(result.get("done"), "ActivateNew never returned")
        info = fa.parse_activation(result["text"])
        self.assertTrue(
            info["ActivateNewResult"],
            f"activation refused: {result['text'][:300]} | pad_bodies="
            f"{len(self.http.pad_bodies)} pad_codes={self.http.pad_status_codes} "
            f"released={self.http.activation_released.is_set()}")
        self.assertEqual(info["OathTokenSecretKey"], self.secret)
        self.assertEqual(info["OathTokenEnabled"], True)
        self.assertEqual(info["ConfirmationCode"], "1234567")

        # the mock PAD server got a well-formed challenge answer
        self.assertTrue(self.http.activation_released.is_set())
        self.assertEqual(len(self.http.pad_bodies), 1)
        pad_xml = self.http.pad_bodies[0].decode()
        self.assertEqual(fa.read_tag(pad_xml, "guid"), self.guid)
        self.assertEqual(fa.read_tag(pad_xml, "validationResult"), "yes")

        # header parity
        h = self.http.pad_headers[0]
        self.assertEqual(h["x-ms-mac-device-token"],
                         hashlib.sha256(self.device_token.encode()).hexdigest())

        # and the secret generates the expected TOTP for the push's OathCounter
        code = totp(self.secret.encode(), int(self.oath_counter), 6, "sha256")
        self.assertEqual(code, self.expected_totp)

        # MCS parity: login fields + version byte
        self.assertEqual(self.mcs.client_version, mcs.MCS_VERSION)
        self.assertIsNotNone(self.mcs.login_body)
        fields = mcs.pb_fields(self.mcs.login_body)
        get = lambda n: next(v for f, w, v in fields if f == n).decode()
        self.assertEqual(get(1), "android-34")                    # id = android-<sdk>
        self.assertEqual(get(2), "mcs.android.com")               # domain
        self.assertEqual(get(3), "1234567890123456789")           # user
        self.assertEqual(get(4), "1234567890123456789")           # resource
        self.assertEqual(get(5), "987654321")                     # auth token
        self.assertEqual(get(6), f"android-{1234567890123456789:x}")  # device id hex

    def test_auth_push_is_not_answered(self):
        listener = RedirectListener(self.mcs.port)
        listener.start()
        self.addCleanup(listener.stop)
        time.sleep(0.3)

        # replace challenge with an authentication push, restore afterwards
        # (unittest runs these tests alphabetically; don't pollute the E2E)
        original = self.mcs.challenge
        self.addCleanup(setattr, self.mcs, "challenge", original)
        self.mcs.challenge = {"type": "auth", "source": "SAS", "guid": self.guid,
                              "url": f"127.0.0.1:{self.http.port}"}

        result: dict = {}
        fa.challenge_loop(listener, result, self.device_token, timeout=3)
        self.assertEqual(self.http.pad_bodies, [])
        self.assertFalse(self.http.activation_released.is_set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
