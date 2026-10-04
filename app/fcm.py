#!/usr/bin/env python3
"""
app.fcm - microG-style Android device check-in + push registration,
done purely off-device with the Microsoft Authenticator's identity.

Device check-in reimplements the process described by microG GmsCore's
CheckinClient and protocol definitions (Apache-2.0 reference project).
Registration uses Firebase Installations and fcmtoken.googleapis.com:
   1. checkin (protobuf, gzipped) -> androidId + securityToken
   2. create Firebase installation -> installation auth token
   3. register with AidLogin device auth -> push registration token
The app identifiers and signing certificate come from apk_config.json.

App identity (Firebase api key / app id / sender, cert SHA1) is NOT hardcoded:
it is read from apk_config.json, which extract_apk_config.py generates from
the local APK (python3 -m app.extract_apk_config - run it first).

Called by app.setup. Device identity and registration state are saved in
AUTH_STATE_DIR (data/ by default).
"""

from __future__ import annotations

import gzip
import json
import os
import secrets
import string
import struct
import time

from app.state import state_path, save_json, save_text, archive_file

STATE_FILE = "checkin_info.json"
APK_CONFIG_FILE = "apk_config.json"
APP = "com.azure.authenticator"
CHECKIN_URL = "https://android.clients.google.com/checkin"

# plausible Pixel 8-ish identity used for the protobuf Build/DeviceConfig
BUILD = {
    "fingerprint": "google/husky/husky:14/UQ1A.240205.002/11476863:user/release-keys",
    "hardware": "husky", "brand": "google", "radio": "g5300-240112-R1",
    "bootloader": "husky-1.0-10769105", "device": "husky",
    "model": "Pixel 8", "manufacturer": "Google", "product": "husky",
    "sdkVersion": 34, "time": 1707100000,
}

# ------------------------- minimal protobuf encoder -------------------------

def varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def tag(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def pb_str(field: int, value: str) -> bytes:
    b = value.encode()
    return tag(field, 2) + varint(len(b)) + b


def pb_msg(field: int, body: bytes) -> bytes:
    return tag(field, 2) + varint(len(body)) + body


def pb_int(field: int, value: int) -> bytes:
    return tag(field, 0) + varint(value)


def pb_bool(field: int, value: bool) -> bytes:
    return pb_int(field, 1 if value else 0)


def pb_fixed64(field: int, value: int) -> bytes:
    return tag(field, 1) + struct.pack("<Q", value)


# ------------------------- CheckinRequest (field #s from checkin.proto) -----

def build_checkin_request(android_id: int = 0, security_token: int = 0,
                          last_checkin: int = 0) -> bytes:
    b = BUILD
    # Build field 8 is an optional check-in client version, not the
    # Authenticator APK version used by FCM registration. Leave it unset.
    # https://github.com/microg/GmsCore/blob/master/play-services-core-proto/src/main/proto/checkin.proto
    build_msg = (pb_str(1, b["fingerprint"]) + pb_str(2, b["hardware"]) +
                 pb_str(3, b["brand"]) + pb_str(4, b["radio"]) +
                 pb_str(5, b["bootloader"]) + pb_str(6, "android-google") +
                 pb_int(7, b["time"]) +
                 pb_str(9, b["device"]) + pb_int(10, b["sdkVersion"]) +
                 pb_str(11, b["model"]) + pb_str(12, b["manufacturer"]) +
                 pb_str(13, b["product"]) + pb_bool(14, False))
    event = pb_str(1, "event_log_start" if android_id == 0 else "system_update")
    if android_id:
        event += pb_str(2, "1536,0,-1,NULL")
    event += pb_int(3, int(time.time() * 1000))
    checkin = (pb_msg(1, build_msg) + pb_int(2, last_checkin) +
               pb_msg(3, event) +
               pb_str(6, "310260") + pb_str(7, "310260") +
               pb_str(8, "mobile-notroaming") + pb_int(9, 0))
    deviceconfig = (pb_int(1, 3) + pb_int(2, 3) + pb_int(3, 1) + pb_int(4, 2) +
                    pb_bool(5, False) + pb_bool(6, False) + pb_int(7, 420) +
                    pb_int(8, 0x00030002) +
                    pb_str(11, "arm64-v8a") + pb_int(12, 1080) + pb_int(13, 2400) +
                    pb_str(14, "en-US"))
    req = (pb_int(2, android_id) + pb_str(3, "") + pb_msg(4, checkin) +
           pb_str(6, "en_US") + pb_int(7, secrets.randbits(62)) +
           pb_str(9, "".join(secrets.choice("0123456789abcdef") for _ in range(12))) +
           pb_str(11, "") + pb_str(12, "Europe/Paris") +
           pb_str(15, "71Q6Rn2DDZl1zPDVaaeEHItd") +
           pb_str(16, "".join(secrets.choice("0123456789abcdef") for _ in range(8))) +
           pb_msg(18, deviceconfig) + pb_str(19, "wifi"))
    if android_id and security_token:
        req += pb_fixed64(13, security_token)
        req += pb_int(20, 1)
    else:
        req += pb_int(20, 0)
    req += pb_int(14, 3)
    return req


def load_apk_config() -> dict:
    """App-embedded identifiers from extract_apk_config.py - never hardcoded."""
    path = state_path(APK_CONFIG_FILE)
    if not os.path.exists(path):
        raise SystemExit(
            f"{APK_CONFIG_FILE} not found. Generate it from the APK first:\n"
            f"    python3 -m app.extract_apk_config        # reads apk/msauth.apk")
    cfg = json.load(open(path))
    fb = cfg.get("firebase") or {}
    missing = [k for k in ("api_key", "app_id", "sender_id", "project") if not fb.get(k)]
    if missing:
        raise SystemExit(f"{APK_CONFIG_FILE} is missing firebase.{missing[0]} - "
                         f"re-run extract_apk_config.py with a current APK.")
    if cfg.get("package") and cfg["package"] != APP:
        raise SystemExit(f"{APK_CONFIG_FILE} package {cfg['package']!r} != {APP!r} "
                         f"- wrong APK?")
    return cfg


# ------------------------- CheckinResponse minimal decoder ------------------

def decode_checkin_response(data: bytes) -> dict:
    out = {"androidId": 0, "securityToken": 0, "timeMs": 0}
    i = 0
    def rd_varint(i):
        shift = val = 0
        while True:
            b = data[i]; i += 1
            val |= (b & 0x7F) << shift
            if not b & 0x80:
                return val, i
            shift += 7
    while i < len(data):
        key, i = rd_varint(i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, i = rd_varint(i)
            if field == 3:
                out["timeMs"] = val
        elif wire == 1:
            val = struct.unpack("<Q", data[i:i+8])[0]; i += 8
            if field == 7:
                out["androidId"] = val
            elif field == 8:
                out["securityToken"] = val
        elif wire == 2:
            ln, i = rd_varint(i)
            i += ln
        elif wire == 5:
            i += 4
        else:
            raise ValueError(f"bad wire type {wire}")
    return out


# ------------------------- transport ---------------------------------------

_http_transport = None


def configure_http_transport(transport):
    """Optional platform transport, configured once at Android app startup."""
    global _http_transport
    if transport is not None and not callable(transport):
        raise ValueError('HTTP transport must be callable')
    _http_transport = transport

def http_post(url: str, data: bytes, headers: dict) -> tuple[int, bytes]:
    """Binary-safe POST using the installed HTTP transport."""
    try:
        if _http_transport is not None:
            return _http_transport(url, data, headers)
        from curl_cffi import requests as cr
        r = cr.post(url, data=data, headers=headers, timeout=30,
                    impersonate="chrome131_android")
        return r.status_code, r.content
    except Exception as exc:
        raise RuntimeError("Google transport failed") from exc


# ------------------------- main flow ---------------------------------------

def do_checkin(force: bool = False) -> dict:
    path = state_path(STATE_FILE)
    state = json.loads(path.read_text()) if path.exists() else {}
    if state.get("androidId") and state.get("securityToken") and not force:
        print(f"[checkin] reusing device identity: androidId={state['androidId']}")
        return state
    if state and not (state.get("androidId") and state.get("securityToken")):
        raise ValueError("incomplete device identity")
    print("[checkin] checking device identity with Google ...")
    req = gzip.compress(build_checkin_request(
        int(state.get("androidId", 0)), int(state.get("securityToken", 0)),
        int(state.get("timeMs", 0))))
    st, body = http_post(CHECKIN_URL, req, {
        "Content-Type": "application/x-protobuffer",
        "Content-Encoding": "gzip",
        "Accept-Encoding": "gzip",
        "User-Agent": "Android-Checkin/2.0 (husky UQ1A.240205.002); gzip",
    })
    if st != 200:
        raise SystemExit(f"checkin HTTP {st}")
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    resp = decode_checkin_response(body)
    if not resp.get("androidId") or not resp.get("securityToken"):
        raise ValueError("checkin returned an incomplete device identity")
    if state and resp != state:
        archive_file(STATE_FILE, "before_checkin_replacement")
    save_json("checkin_info.json", resp)
    print("[checkin] identity saved")
    return resp


def do_register(state: dict) -> str:
    """Initial registration. Runtime renewal is owned by app.registration."""
    from app.fcm_lifecycle import acquire, FcmError
    token = acquire(state)
    if state_path("activation.json").exists():
        current = state_path("fcm_token.txt")
        if not current.exists() or current.read_text().strip() != token:
            raise FcmError("entra_rebinding_required")
    save_text("fcm_token.txt", token + "\n")
    return token
