#!/usr/bin/env python3
"""
app.approval - Approve an Entra MFA push (incl. number matching) off-device.

The login page says "Open the app and approve the request. Enter the number
if prompted." The real app receives that push over FCM and answers on the
SAME /pad channel app.activation already uses for the device-token
validation. Two request shapes exist in the decompiled app:

  * number matching ("entropy" flow)  - AuthenticationResultRequestEnum is
    NOT used; MfaAuthViewModel.approveMfaEntropyAsync -> approvePinAuthSuspend
    -> AadMfaAuthenticationManager.performPinAuthRequest sends
    PinValidationRequest -> x-ms-mac-action: phoneAppPinValidationRequest
      <pin stored="no"></pin><authenticate>yes</authenticate>
      <selectedEntropyNumber>42</selectedEntropyNumber>
    The number itself is IN the push payload (firstEntropyChallenge /
    secondEntropyChallenge / thirdEntropyChallenge). Server answers
    <validationResult>6 = VALID_ENTROPY_NUMBER -> approved.

  * plain approve/deny (no number matching) - MfaAuthViewModel.approveSession
    -> performAuthResultRequest sends AuthenticationResultRequest ->
    x-ms-mac-action: phoneAppAuthenticationResultRequest
      <authenticationResult>1</authenticationResult>   (1 approve, 2 deny)
      <newDeviceToken notificationType="gcm">…</newDeviceToken>
    Server answers <result>1 = success.

Used by app.service for bot-driven approvals.
"""

from __future__ import annotations


from app.activation import (
    OS_VERSION, CHALLENGE_SOURCES, PAD_ALLOWED_HOST_SUFFIXES,
    build_pad_headers, pfp,
)
from app import app_identity

# push payload keys (MfaSessionUseCase constants)
K_GUID, K_URL = "guid", "url"
K_ENTROPY = ("firstEntropyChallenge", "secondEntropyChallenge", "thirdEntropyChallenge")
K_SCOPE, K_TENANT, K_HINT, K_CC = "replicationScope", "tenantId", "routingHint", "countryCode"


def build_pin_validation(guid, device_token, entropy_number, oath_counter,
                         app_lock_used=False, app_state="") -> str:
    """PinValidationRequest.buildBody() - element order byte-faithful."""
    version = app_identity.app_version()
    inner = ('<phoneAppPinValidationRequest><phoneAppContext>'
             f'<guid>{guid}</guid>'
             '<oathCode></oathCode>'
             '<needDosPreventer>no</needDosPreventer>'
             f'<deviceToken>{device_token}</deviceToken>'
             f'<version>{version}</version>'
             f'<osVersion>{OS_VERSION}</osVersion>'
             '</phoneAppContext>'
             '<pin stored="no"></pin>'
             '<authenticate>yes</authenticate>'
             f'<oathCounter>{oath_counter}</oathCounter>'
             '<completedInteractively>yes</completedInteractively>'
             f'<selectedEntropyNumber>{entropy_number}</selectedEntropyNumber>'
             f'<isAppLockUsed>{"yes" if app_lock_used else "no"}</isAppLockUsed>'
             f'<appState>{app_state}</appState>'
             '</phoneAppPinValidationRequest>')
    return pfp(inner)


def build_auth_result(guid, device_token, result: int, oath_counter,
                      app_lock_used=False, app_state="") -> str:
    """AuthenticationResultRequest.buildBody() - element order byte-faithful."""
    version = app_identity.app_version()
    inner = ('<phoneAppAuthenticationResultRequest><phoneAppContext>'
             f'<guid>{guid}</guid>'
             '<oathCode></oathCode>'
             '<needDosPreventer>no</needDosPreventer>'
             f'<deviceToken>{device_token}</deviceToken>'
             f'<version>{version}</version>'
             f'<osVersion>{OS_VERSION}</osVersion>'
             '</phoneAppContext>'
             f'<authenticationResult>{result}</authenticationResult>'
             f'<newDeviceToken notificationType="gcm">{device_token}</newDeviceToken>'
             f'<oathCounter>{oath_counter}</oathCounter>'
             '<completedInteractively>yes</completedInteractively>'
             f'<isAppLockUsed>{"yes" if app_lock_used else "no"}</isAppLockUsed>'
             f'<appState>{app_state}</appState>'
             '</phoneAppAuthenticationResultRequest>')
    return pfp(inner)


def routing_headers(appdata: dict) -> dict:
    """AccountInfoCombination -> extra headers (getHeaders overrides)."""
    h = {}
    if appdata.get(K_SCOPE):
        h["x-ms-client-replication-scope"] = appdata[K_SCOPE]
    if appdata.get(K_TENANT):
        h["x-ms-client-tenant-id"] = appdata[K_TENANT]
    if appdata.get(K_HINT):
        h["x-ms-routing-hint"] = appdata[K_HINT]
    if appdata.get(K_CC):
        h["x-ms-client-tenant-country-code"] = appdata[K_CC]
    return h


def is_auth_push(appdata: dict) -> bool:
    """Whether this payload belongs to the supported Entra MFA approval flow."""
    return classify_push(appdata) == "aad_mfa"


# ---------------- other sign-in flows (classification only) ----------------
#   NotificationProcessorUseCase.getNotificationProcessor +
#   MfaNotificationUseCase.getMfaNotificationType  - type=auth / validate are
#     AAD flows and additionally require source SAS / MFA Server;
#   AppNotificationsManager.getKnownNotificationType - sessiontype=NGC is the
#     Entra passwordless push (same source guard); SessionApprovalPending,
#     RemoteNGCPending and ProtectionNotification are personal (MSA) flows
#     handled by MsaNotificationProcessor with no source restriction.
# This service only approves aad_mfa; every other recognized kind is surfaced
# (bot notice or log) instead of being dropped, and never reaches approval.

AAD_NGC_TYPE = "ngc"                      # NgcSession.SESSION_TYPE_NGC
MSA_SESSION_TYPE = "SessionApprovalPending"   # SessionManager constant
MSA_NGC_TYPE = "RemoteNGCPending"             # SessionManager constant
MSA_PROTECTION_TYPE = "ProtectionNotification"

# Per-flow session identifier used for dedup: guid (AAD MFA / validate),
# sessionid (NgcSession.KEY_SESSION_ID), internalSID (MSA session).
PUSH_SESSION_KEYS = {
    "aad_mfa": "guid",
    "aad_validate": "guid",
    "aad_ngc": "sessionid",
    "msa_session": "internalSID",
    "msa_ngc": "internalSID",
    "msa_protection": "internalSID",
}

# Recognized kinds that this bridge can fully approve.
SUPPORTED_KINDS = ("aad_mfa",)

KIND_LABELS = {
    "aad_mfa": "Entra MFA sign-in",
    "aad_validate": "Entra device-token validation",
    "aad_ngc": "Entra passwordless (NGC) sign-in",
    "msa_session": "personal Microsoft account sign-in",
    "msa_ngc": "personal Microsoft account passwordless (NGC) sign-in",
    "msa_protection": "personal Microsoft account protection notice",
    "unknown": "unrecognized push",
}

# Display-only payload fields (MSA Session / SessionManager.parseSessionFromNotification)
# used for user-facing summaries; identifiers are never included.
_DISPLAY_FIELDS = (
    ("displayTitle", "title"),
    ("displayContent", "detail"),
    ("browser", "browser"),
    ("operatingSystem", "os"),
    ("country", "region"),
)


def classify_push(appdata: dict) -> str:
    """Classify SDK MFA types first, then the app's type/sessiontype fallback.

    Missing type is retained as a legacy bridge compatibility allowance,
    only when no other routing field is present and guid + url are supplied.
    """
    kind = appdata.get("type") or ""
    aad_source = appdata.get("source", "") in CHALLENGE_SOURCES
    if aad_source and kind in ("auth", "validate"):
        if kind == "validate":
            return "aad_validate"
        return "aad_mfa" if appdata.get(K_GUID) and appdata.get(K_URL) else "unknown"

    # AppNotificationsManager falls back when type is unrecognized, not
    # merely when it is absent. Never infer MFA from sessiontype=auth.
    for value in (kind, appdata.get("sessiontype") or ""):
        if not isinstance(value, str):
            continue
        if value.lower() == AAD_NGC_TYPE:
            return "aad_ngc" if aad_source else "unknown"
        if value == MSA_SESSION_TYPE:
            return "msa_session"
        if value == MSA_NGC_TYPE:
            return "msa_ngc"
        if value == MSA_PROTECTION_TYPE:
            return "msa_protection"
    if not kind and not appdata.get("sessiontype"):
        if aad_source and appdata.get(K_GUID) and appdata.get(K_URL):
            return "aad_mfa"
    return "unknown"


def _clean(value) -> str:
    """Collapse whitespace/control characters for safe single-line display."""
    collapsed = " ".join(str(value).split())
    return "".join(ch if ch.isprintable() else "?" for ch in collapsed)


def payload_summary(appdata: dict, kind: str) -> str:
    """Short user-facing description of an unsupported push, built from
    display fields only (titles, browser, region). Never identifiers or
    session material; capped to keep bot messages small."""
    fields = []
    for key, label in _DISPLAY_FIELDS:
        value = _clean(appdata.get(key, ""))
        if value:
            fields.append(f"{label}: {value}")
    if not fields:
        return ""
    text = "; ".join(fields)
    return text if len(text) <= 200 else text[:197] + "..."


def pad_url_of(appdata: dict) -> str:
    """PendingAuthentication.getMfaServiceRequestUrl(): https + push url + /pad."""
    svc = (appdata.get(K_URL) or "").strip()
    if svc.startswith("http://"):
        svc = "https://" + svc[len("http://"):]
    elif not svc.startswith("https://"):
        svc = f"https://{svc}"
    return svc.rstrip("/") + "/pad"


def send_pad(url, body, device_token, appdata, action, impersonate) -> tuple[int, str]:
    from urllib.parse import urlparse
    h = urlparse(url).hostname or ""
    if not any(h == x or h.endswith("." + x) for x in PAD_ALLOWED_HOST_SUFFIXES):
        raise SystemExit(f"refusing unexpected push service host: {h}")
    headers = build_pad_headers(device_token, action)
    headers.update(routing_headers(appdata))
    try:
        from curl_cffi import requests as cr
        r = cr.post(url, data=body.encode(), headers=headers,
                    timeout=60, impersonate=impersonate, allow_redirects=False)
        return r.status_code, r.text
    except ImportError:
        import tls_client
        s = tls_client.Session(client_identifier="okhttp4_android_13",
                               random_tls_extension_order=True)
        r = s.post(url, data=body.encode(), headers=headers, timeout_seconds=60)
        return r.status_code, r.text
