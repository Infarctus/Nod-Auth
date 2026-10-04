"""Google MCS transport shared by activation and the approval service.

Reimplements the MCS process described by microG GmsCore (Apache-2.0
reference project); see also the Chromium protocol reference below.
"""
import socket
import ssl
import threading
import time

APP = "com.azure.authenticator"
MCS_HOST, MCS_PORT, MCS_VERSION = "mtalk.google.com", 5228, 41

# ---------------- MCS push listener ----------------

def _vint(data, i):
    shift = val = 0
    while True:
        b = data[i]; i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def varint(n: int) -> bytes:
    """encoder (one arg) - used for all OUTGOING lengths/values"""
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def pb_str(f, v):
    b = v.encode(); return varint((f << 3) | 2) + varint(len(b)) + b


def pb_int(f, v):
    return varint((f << 3) | 0) + varint(v)


def pb_fields(data: bytes):
    i, out = 0, []
    while i < len(data):
        key, i = _vint(data, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, i = _vint(data, i)
        elif wire == 1:
            val = data[i:i + 8]; i += 8
        elif wire == 2:
            ln, i = _vint(data, i); val = data[i:i + ln]; i += ln
        elif wire == 5:
            val = data[i:i + 4]; i += 4
        else:
            raise ValueError(f"wire {wire}")
        out.append((field, wire, val))
    return out


class McsListener(threading.Thread):
    """Logs in with the checked-in identity and captures DataMessageStanza
    pushes for com.azure.authenticator."""

    def __init__(self, android_id: int, security_token: int):
        super().__init__(daemon=True)
        self.android_id, self.security_token = android_id, security_token
        self.pushes = []
        self.event = threading.Event()
        self.ready = threading.Event()
        self.stream_id = 0
        self.login_error_code = None
        # NOTE: do NOT name any attr `_stop` - it collides with
        # threading.Thread._stop() and breaks is_alive().
        self._shutdown = False
        self.sock = None

    def run(self):
        try:
            raw = socket.create_connection((MCS_HOST, MCS_PORT), timeout=30)
            self.sock = raw
            sock = ssl.create_default_context().wrap_socket(raw, server_hostname=MCS_HOST)
            self.sock = sock
            sock.settimeout(15)
            aid = str(self.android_id)
            login = (pb_str(1, f"android-{34}") + pb_str(2, "mcs.android.com") +
                     pb_str(3, aid) + pb_str(4, aid) +
                     pb_str(5, str(self.security_token)) +
                     pb_str(6, f"android-{self.android_id:x}") +
                     pb_int(17, 1) + pb_int(14, 1) + pb_int(16, 2))
            sock.sendall(bytes([MCS_VERSION]))
            sock.sendall(bytes([2]) + varint(len(login)) + login)
            ver = self._read_exact(sock, 1)[0]
            if ver < 38 or ver > MCS_VERSION:
                raise ConnectionError("unsupported MCS version")
            print(f"[mcs] server version {ver}", flush=True)

            while not self._shutdown:
                try:
                    tag_b = self._read_exact(sock, 1)[0]
                    length = 0; shift = 0
                    while True:
                        b = self._read_exact(sock, 1)[0]
                        length |= (b & 0x7F) << shift
                        if not b & 0x80:
                            break
                        shift += 7
                        if shift >= 35:
                            raise ConnectionError("invalid MCS frame length")
                    if length > 1024 * 1024:
                        raise ConnectionError("MCS frame too large")
                    body = self._read_exact(sock, length) if length else b""
                except socket.timeout:
                    continue
                except (ConnectionError, ssl.SSLError) as e:
                    if not self._shutdown:
                        print(f"[mcs] connection lost: {e!r}", flush=True)
                    break
                self.stream_id += 1
                if tag_b == 3:
                    fields = pb_fields(body)
                    error = next((v for f, w, v in fields if f == 3 and w == 2), None)
                    if error is not None:
                        code = next((v for f, w, v in pb_fields(error) if f == 1 and w == 0), -1)
                        if code != 0:
                            self.login_error_code = code
                            print(f"[mcs] LOGIN FAILED code={code}", flush=True)
                            break
                    self.ready.set()
                    print("[mcs] LOGIN OK", flush=True)
                elif tag_b == 0:                      # heartbeat ping -> ack
                    self._send_frame(sock, 1, pb_int(2, self.stream_id))
                elif tag_b == 8:                      # DataMessageStanza
                    if not self.ready.is_set():
                        raise ConnectionError("MCS push before login")
                    fields = pb_fields(body)
                    cat = next((v.decode() for f, w, v in fields if f == 5), "")
                    appdata = {}
                    for f, w, v in fields:
                        if f == 7:
                            inner = pb_fields(v)
                            k = next((x.decode() for xf, xw, x in inner if xf == 1), "")
                            val = next((x.decode(errors="replace") for xf, xw, x in inner if xf == 2), "")
                            appdata[k] = val
                    print(f"[mcs] PUSH category={cat}", flush=True)
                    if cat == APP:
                        self.pushes.append({"category": cat, "app_data": appdata})
                        self.event.set()
                    # RMQ2 StreamAck: IQ SET, extension 13, plus the incoming
                    # stream counter (including login and heartbeat frames).
                    # Ack every data frame, including immediate_ack requests.
                    # https://github.com/chromium/chromium/blob/main/google_apis/gcm/protocol/mcs.proto
                    extension = pb_int(1, 13) + pb_str(2, "")
                    ack = (pb_int(2, 1) + pb_str(3, "") +
                           varint((7 << 3) | 2) + varint(len(extension)) + extension +
                           pb_int(10, self.stream_id))
                    self._send_frame(sock, 7, ack)
                    print(f"[mcs] delivery acknowledged stream={self.stream_id}", flush=True)
                elif tag_b == 4:
                    print("[mcs] server close", flush=True)
                    break
        except Exception as e:
            if not self._shutdown:
                print(f"[mcs] error: {type(e).__name__}", flush=True)
        finally:
            self.ready.clear()
            if self.sock:
                self.sock.close()

    @staticmethod
    def _send_frame(sock, tag, body):
        sock.sendall(bytes([tag]) + varint(len(body)) + body)

    def _read_exact(self, sock, n):
        buf = b""
        started = time.monotonic()
        ping_sent = False
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                if self._shutdown:
                    raise ConnectionError("stopped")
                idle = time.monotonic() - started
                if idle > 90:
                    raise ConnectionError("MCS heartbeat timed out")
                if idle > 45 and not ping_sent:
                    body = pb_int(2, self.stream_id) if self.stream_id else b""
                    self._send_frame(sock, 0, body)
                    ping_sent = True
                continue
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def stop(self):
        self._shutdown = True
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.event.set()


