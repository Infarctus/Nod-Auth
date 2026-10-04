"""Persistent Firebase Installation and Entra FCM acquisition.

This module returns a candidate token. Binding it to Microsoft is a separate
operation, so a failed acquisition never replaces an activated token.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from urllib.parse import urlencode

from app.state import state_path, save_json, archive_file, remove_state
from app.fcm import APP, http_post, load_apk_config

FIS_FILE = "firebase_installation.json"
FIS_AUTH_BUFFER = 3600
FIS_INVALID_FILE = 'firebase_installation.invalid.json'


def invalidate_installation(kind):
    """Keep rejected credentials until a validated replacement is durable."""
    path = state_path(FIS_FILE)
    if not path.exists():
        return
    fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
    marker = state_path(FIS_INVALID_FILE)
    if marker.exists() and json.loads(marker.read_text()).get('fingerprint') == fingerprint:
        return
    archive_file(FIS_FILE, kind)
    save_json(FIS_INVALID_FILE, {'reason': kind, 'fingerprint': fingerprint})



class FcmError(RuntimeError):
    KINDS = frozenset({
        'fis_bad_response', 'fis_bad_state', 'fis_identity_mismatch',
        'fis_auth_invalid', 'fis_retryable', 'fis_bad_config', 'fcm_retryable',
        'fcm_rejected', 'fcm_reset', 'fcm_bad_response', 'checkin_bad_state',
        'entra_rebinding_required',
    })
    SERVER_CODES = frozenset({
        'RST', 'AUTHENTICATION_FAILED', 'INVALID_SENDER', 'INVALID_PARAMETERS',
        'SERVICE_NOT_AVAILABLE', 'INTERNAL_SERVER_ERROR', 'TOO_MANY_REGISTRATIONS',
        'INVALID_ARGUMENT', 'PERMISSION_DENIED', 'UNAUTHENTICATED', 'NOT_FOUND',
        'RESOURCE_EXHAUSTED', 'UNAVAILABLE', 'INTERNAL',
        'API_KEY_INVALID', 'API_KEY_ANDROID_APP_BLOCKED', 'API_KEY_SERVICE_BLOCKED',
    })

    def __init__(self, kind: str, http_status=None, server_code=None):
        super().__init__(kind)
        self.kind = kind
        self.http_status = http_status if type(http_status) is int and 100 <= http_status <= 599 else None
        self.server_code = server_code if isinstance(server_code, str) and server_code in self.SERVER_CODES else None

    @property
    def diagnostic(self):
        detail = self.kind if self.kind in self.KINDS else 'unknown_fcm_error'
        if self.http_status is not None:
            detail += f'; HTTP {self.http_status}'
        if self.server_code:
            detail += f'; {self.server_code}'
        return detail


def _response_error(body):
    """Select only known error labels; never retain response text or messages."""
    if len(body) > 65536:
        return None
    try:
        text = body.decode('utf-8').strip()
        if text.startswith('Error='):
            code = text[6:]
            return code if code in FcmError.SERVER_CODES else None
        error = json.loads(text).get('error', {})
        for item in error.get('details', []):
            code = item.get('reason')
            if isinstance(code, str) and code in FcmError.SERVER_CODES:
                return code
        code = error.get('status')
        return code if isinstance(code, str) and code in FcmError.SERVER_CODES else None
    except (ValueError, UnicodeDecodeError, AttributeError, TypeError):
        return None


def generate_fid() -> str:
    """Firebase Installations RandomFidGenerator's UUID-based encoding."""
    raw = bytearray(uuid.uuid4().bytes)
    raw.append(raw[0])
    raw[0] = (raw[0] & 0x0F) | 0x70
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")[:22]


def _expiry(value) -> int:
    try:
        seconds = int(value[:-1] if isinstance(value, str) and value.endswith("s") else value)
    except (ValueError, TypeError) as exc:
        raise FcmError("fis_bad_response") from exc
    if seconds <= 0:
        raise FcmError("fis_bad_response")
    return seconds


def _parse_json(body: bytes, kind: str) -> dict:
    try:
        value = json.loads(body)
        if isinstance(value, dict):
            return value
    except (ValueError, UnicodeDecodeError):
        pass
    raise FcmError(kind)


def _identity(cfg: dict) -> dict:
    return {"package": APP, "app_id": cfg["firebase"]["app_id"],
            "project": cfg["firebase"]["project"]}


def _fis_status(status: int, body: bytes = b'') -> None:
    if status == 429 or status >= 500:
        raise FcmError("fis_retryable", status, _response_error(body))
    if not 200 <= status < 300:
        raise FcmError("fis_bad_config", status, _response_error(body))


def installation(cfg: dict, now: int | None = None) -> dict:
    """Reuse the FID and refresh its auth credential when necessary."""
    now = int(time.time()) if now is None else now
    path = state_path(FIS_FILE)
    raw = path.read_bytes() if path.exists() else None
    marker = state_path(FIS_INVALID_FILE)
    invalid = json.loads(marker.read_text()) if marker.exists() else {}
    replacing = raw is not None and invalid.get('fingerprint') == hashlib.sha256(raw).hexdigest()
    current = _parse_json(raw, 'fis_bad_state') if raw is not None and not replacing else None
    identity = _identity(cfg)
    headers = {"Content-Type": "application/json",
               "x-goog-api-key": cfg["firebase"]["api_key"],
               "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8)"}
    base = f"https://firebaseinstallations.googleapis.com/v1/projects/{identity['project']}/installations"

    if current:
        if current.get("_identity") and current["_identity"] != identity:
            raise FcmError("fis_identity_mismatch")
        if not current.get("fid") or not current.get("refreshToken"):
            raise FcmError("fis_bad_state")
        auth = current.get("authToken") or {}
        if not isinstance(auth, dict):
            auth = {}
        created = current.get("_auth_created_at")
        if created is not None and auth.get("token"):
            try:
                created_at = int(created)
                expires = _expiry(auth.get("expiresIn"))
            except (ValueError, TypeError, FcmError):
                created_at, expires = 0, 0
            if now + FIS_AUTH_BUFFER < created_at + expires:
                return current
        request = json.dumps({"installation": {"sdkVersion": "a:17.0.0"}}).encode()
        st, body = http_post(f"{base}/{current['fid']}/authTokens:generate",
                             request, {**headers, "Authorization": f"FIS_v2 {current['refreshToken']}"})
        if st in (401, 404):
            raise FcmError("fis_auth_invalid", st, _response_error(body))
        _fis_status(st, body)
        new_auth = _parse_json(body, "fis_bad_response")
        if not new_auth.get("token"):
            raise FcmError("fis_bad_response")
        _expiry(new_auth.get("expiresIn"))
        current["authToken"] = new_auth
        current["_auth_created_at"] = now
        current["_identity"] = identity
        save_json(FIS_FILE, current)
        return current

    fid = generate_fid()
    request = json.dumps({"fid": fid, "appId": identity["app_id"],
                          "authVersion": "FIS_v2", "sdkVersion": "a:17.0.0"}).encode()
    st, body = http_post(base, request, headers)
    _fis_status(st, body)
    current = _parse_json(body, "fis_bad_response")
    if not current.get("fid") or not current.get("refreshToken"):
        raise FcmError("fis_bad_response")
    auth = current.get("authToken") or {}
    if not auth.get("token"):
        raise FcmError("fis_bad_response")
    _expiry(auth.get("expiresIn"))
    current["_auth_created_at"] = now
    current["_identity"] = identity
    save_json(FIS_FILE, current)
    remove_state(FIS_INVALID_FILE)
    return current


def parse_registration(status: int, body: bytes) -> str:
    if status == 429 or status >= 500:
        raise FcmError("fcm_retryable", status, _response_error(body))
    if status != 200:
        raise FcmError("fcm_rejected", status, _response_error(body))
    try:
        value = body.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise FcmError("fcm_bad_response", status) from exc
    if value.startswith("Error="):
        raise FcmError("fcm_reset" if value == "Error=RST" else "fcm_rejected", status, _response_error(body))
    if not value.startswith("token=") or "\n" in value or "\r" in value:
        raise FcmError("fcm_bad_response", status)
    token = value[6:]
    if not token or any(char.isspace() for char in token):
        raise FcmError("fcm_bad_response", status)
    return token


def acquire(state: dict, cfg: dict | None = None) -> str:
    """Fetch with the APK's three-attempt, 200 ms x5 retry policy."""
    for attempt in range(3):
        try:
            return _acquire_once(state, cfg)
        except FcmError as exc:
            if exc.kind not in ("fis_retryable", "fcm_retryable") or attempt == 2:
                raise
        except RuntimeError:
            if attempt == 2:
                raise
        time.sleep(0.2 * (5 ** attempt))
    raise AssertionError("unreachable")


def _acquire_once(state: dict, cfg: dict | None = None) -> str:
    cfg = cfg or load_apk_config()
    fb = cfg["firebase"]
    aid, security = state.get("androidId"), state.get("securityToken")
    if not aid or not security:
        raise FcmError("checkin_bad_state")
    inst = installation(cfg)
    cert = ((cfg.get("signing_cert_sha1") or [None])[0]) or ""
    form = urlencode({"app": APP, "cert": cert, "app_ver": cfg.get("version_code") or 0,
                      "sender": fb["sender_id"], "device": aid, "X-scope": "*",
                      "X-gmp-app-id": fb["app_id"], "X-fid": inst["fid"]}).encode()
    st, body = http_post("https://fcmtoken.googleapis.com/register", form, {
        "Authorization": f"AidLogin {aid}:{security}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Goog-Firebase-Installations-Auth": inst["authToken"]["token"],
        "X-android-package": APP,
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8)",
    })
    return parse_registration(st, body)
