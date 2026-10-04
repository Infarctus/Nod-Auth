#!/usr/bin/env python3
"""
app.activation - Complete off-device Entra MFA activation with push
challenge/response, exactly like the real app:

  1. open MCS push socket (mtalk.google.com:5228)  - app.mcs machinery
  2. POST PfPaWs ActivateNew                       - hangs while server waits
  3. receive PAD challenge push (type=validate, source=SAS) on MCS
  4. POST phoneAppValidateDeviceTokenRequest (result=yes) to the service URL
     taken FROM THE PUSH PAYLOAD ("url" key -> https://<url>/pad) - exactly
     like the app: MfaValidateDeviceNotification +
     MfaRegistrationUseCase.getMfaServiceUrl ("https://" + url + "/pad")
  5. Save ActivateNew credentials, including OathTokenSecretKey, in activation.json

Protocol parity with the decompiled app is unit-tested in
 test/test_full_activation_mock.py (offline mocks, no Microsoft/Google traffic).

Called by app.setup after Google device registration. State files live in
AUTH_STATE_DIR (data/ by default).
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
from app.state import state_path, save_json
from app.mcs import McsListener
from app import app_identity


OS_VERSION = "14"
APP = "com.azure.authenticator"
FLAVOR = "Microsoft Authenticator"
UA = "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A.240205.002)"
SOAP_NS = "http://www.phonefactor.com/PfPaWs"
SOAP_ACT = f"{SOAP_NS}/ActivateNew"
SOAP_CONF = f"{SOAP_NS}/ConfirmActivation"

# push routing - NotificationProcessorUseCase.getNotificationProcessor +
# MfaNotificationUseCase.isAadNotification: only source in this set with
# fcm type "validate" reaches MfaValidateDeviceNotification.
CHALLENGE_SOURCES = ("SAS", "MFA Server")

# sanity allow-list for the PAD endpoint that comes from the push payload
PAD_ALLOWED_HOST_SUFFIXES = (
    "microsoft.com", "microsoft.us", "microsoft.cn", "microsoftonline.com",
    "microsoftonline.cn", "windowsazure.com", "windowsazure.us",
    "msftauth.net", "msftauth.us", "phonefactor.net",
    "sovcloud.fr", "sovcloud.de", "sovcloud.sg",
)

# ---------------- shared transport ----------------

def soap_post(url: str, body: str, action: str, timeout: int = 90):
    """Microsoft SOAP - needs the Android TLS fingerprint."""
    import tls_client
    s = tls_client.Session(client_identifier="okhttp4_android_13",
                           random_tls_extension_order=True)
    headers = {"Content-Type": "text/xml; charset=utf-8",
               "SOAPAction": action, "User-Agent": UA}
    try:
        r = s.post(url, data=body.encode(), headers=headers, timeout_seconds=timeout)
    except TypeError:                      # older tls_client without timeout kwarg
        r = s.post(url, data=body.encode(), headers=headers)
    return r.status_code, r.text


def build_pad_headers(device_token: str, action: str) -> dict:
    """Header set of AbstractMfaRequest.getHeaders() +
    ValidateDeviceTokenRequest.getHeaders() (TransportFactory constants):
    XML_CONTENT_TYPE=application/xml, MAC_INTERACTIVE='true' (AadRemoteNgcConstants
    .VALUE_PUSH_NOTIFICATION_ATTRIBUTE), MAC_DEVICE_TOKEN=MfaHashAlgorithm
    .calculateHash = lowercase SHA-256 hex of the raw device token."""
    version = app_identity.app_version()
    return {"Content-Type": "application/xml",
            "AppName": APP,                    # APP_NAME_KEY = flavor name
            "AppVersion": version,
            "DeviceType": "Android",           # DEVICE_TYPE_KEY
            "x-ms-mac-app-version": version,
            "x-ms-mac-os-version": OS_VERSION,
            "x-ms-mac-flavor": FLAVOR,
            "x-ms-mac-os-platform": "Android",
            "x-ms-mac-device-token": hashlib.sha256(device_token.encode()).hexdigest(),
            "x-ms-mac-interactive": "true",
            "x-ms-mac-action": action,
            "User-Agent": UA}


def pad_post(url: str, body: str, device_token: str, action: str):
    """pfpMessage channel (/pad/) with x-ms-mac-* headers."""
    from curl_cffi import requests as cr
    r = cr.post(url, data=body.encode(), headers=build_pad_headers(device_token, action),
                timeout=30, impersonate="chrome131_android", allow_redirects=False)
    return r.status_code, r.text


# ---------------- SOAP builders (from ActivationRequest) ----------------

def build_soap(inner: str) -> str:
    return ('<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
            'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:ns4="{SOAP_NS}"><soap:Header />'
            f"<soap:Body>{inner}</soap:Body></soap:Envelope>")


def build_activate(code, device_token, device_name, oath_counter):
    version = app_identity.app_version()
    return build_soap(
        "<ns4:ActivateNew><ns4:activationParams>"
        f"<ns4:ActivationCode>{code}</ns4:ActivationCode>"
        f"<ns4:DeviceToken>{device_token}</ns4:DeviceToken>"
        f"<ns4:DeviceName>{escape(device_name)}</ns4:DeviceName>"
        f"<ns4:OathCounter>{oath_counter}</ns4:OathCounter>"
        f"<ns4:Version>{version}</ns4:Version>"
        "</ns4:activationParams></ns4:ActivateNew>")


def build_confirm(cc):
    return build_soap(f"<ns4:ConfirmActivation><ns4:confirmationCode>{cc}</ns4:confirmationCode></ns4:ConfirmActivation>")


# ---------------- pfpMessage builders (from AbstractMfaRequest) ----------------

def pfp(inner: str) -> str:
    """pfpMessage envelope - AbstractMfaRequest.buildHeader(): the host
    attributes live on a nested <host> CHILD element of <component>, not on
    the component itself."""
    rid = str(uuid.uuid4())
    return ('<pfpMessage version="1.6"><header><source><component type="pfsvc" '
            'role="master"><host ip="" hostname="" serverId="" /></component>'
            '</source></header>'
            f'<request request-id="{rid}" async="0" response-url="" language="en">'
            f"{inner}</request></pfpMessage>")


def build_validation(guid: str, device_token: str, need_dos_preventer: bool = True,
                     account: dict | None = None, oath_counter: int | None = None,
                     validation_result: bool = True) -> str:
    """ValidateDeviceTokenRequest, including the APK's per-account OATH proof."""
    version = app_identity.app_version()
    root = ET.Element('phoneAppValidateDeviceTokenRequest')
    context = ET.SubElement(root, 'phoneAppContext')
    for key, value in (('guid', guid), ('oathCode', ''), ('deviceToken', device_token),
                       ('version', version), ('osVersion', OS_VERSION),
                       ('needDosPreventer', 'yes' if need_dos_preventer else 'no')):
        ET.SubElement(context, key).text = str(value)
    ET.SubElement(root, 'validationResult').text = 'yes' if validation_result else 'no'
    accounts = ET.SubElement(root, 'accounts')
    if account and oath_counter is not None and account.get('OathTokenEnabled', bool(account.get('OathTokenSecretKey'))):
        from app.entra_registration import oath_validation_code
        if not all(account.get(key) for key in ('AzureObjectId', 'TenantId', 'OathTokenSecretKey')):
            raise ValueError('account validation metadata missing')
        item = ET.SubElement(accounts, 'account')
        for key, value in (('groupKey', account.get('GroupKey', '')),
                           ('username', account.get('Username', '')),
                           ('azureObjectId', account['AzureObjectId']),
                           ('oathCode', oath_validation_code(account['OathTokenSecretKey'], oath_counter)),
                           ('azureTenantId', account['TenantId'])):
            ET.SubElement(item, key).text = value
    return pfp(ET.tostring(root, encoding='unicode', short_empty_elements=False))


# ---------------- push-challenge routing (app-faithful) ----------------

def is_valid_challenge(appdata: dict) -> bool:
    """NotificationProcessorUseCase.getNotificationProcessor(): the push is a
    device-validation challenge only if source is SAS / MFA Server and fcm
    type is 'validate' (or absent - some legacy pushes omit it; a real auth
    push always carries type=auth, which we must NOT answer)."""
    if appdata.get("source", "") not in CHALLENGE_SOURCES:
        return False
    return appdata.get("type", "validate") == "validate"


def extract_challenge(appdata: dict) -> tuple[str, str, str]:
    """(guid, pad_url, deviceTokenChangeVersion) from the push payload -
    MfaSessionUseCase.parseMfaValidateDeviceNotificationDetails +
    MfaRegistrationUseCase.getMfaServiceUrl("https://" + url + "/pad").
    The service URL comes from the PUSH, never from the activation link."""
    guid = (appdata.get("guid") or "").strip()
    svc = (appdata.get("url") or "").strip()
    if svc.startswith("http://"):          # defensive; app expects a bare host
        svc = "https://" + svc[len("http://"):]
    elif not svc.startswith("https://"):
        svc = f"https://{svc}" if svc else ""
    pad_url = svc.rstrip("/") + "/pad" if svc else ""
    return guid, pad_url, (appdata.get("deviceTokenChangeVersion") or "").strip()


def answer_challenge(appdata: dict, device_token: str,
                     need_dos_preventer: bool = True, account: dict | None = None,
                     validation_result: bool = True) -> dict:
    """MfaValidateDeviceNotification.handleMessageWithResult(), ported:
      - empty guid or service URL       -> abort, isInformationMissing=false;
      - deviceTokenChangeVersion == V2  -> no HTTP at all, just notify
        (MfaSdkState.notifyPadComplete) after those required-field checks;
      - otherwise -> POST phoneAppValidateDeviceTokenRequest (result=yes) to
        https://<push-url>/pad with the x-ms-mac-* header set."""
    guid, pad_url, dtcv = extract_challenge(appdata)
    if not guid:
        return {"action": "abort", "reason": "challenge push had empty guid"}
    if not pad_url:
        return {"action": "abort", "reason": "challenge push had no service url"}
    if dtcv.upper() == "V2":
        return {"action": "notify-only", "guid": guid, "url": pad_url,
                "note": "V2 device-token change: nothing to POST"}
    from urllib.parse import urlparse
    h = (urlparse(pad_url).hostname or "").lower().rstrip(".")
    if not any(h == x or h.endswith("." + x) for x in PAD_ALLOWED_HOST_SUFFIXES):
        return {"action": "abort", "reason": f"push service url host not allowed: {h}"}
    try:
        counter = appdata.get('oathCounter', '')
        if counter and (not re.fullmatch(r'[0-9]+', counter) or int(counter) > 2**63 - 1):
            return {'action': 'abort', 'reason': 'invalid OATH counter'}
        vst, vtext = pad_post(pad_url, build_validation(guid, device_token, need_dos_preventer,
                                                      account, int(counter) if counter else None, validation_result),
                              device_token, "phoneAppValidateDeviceTokenRequest")
    except Exception as e:
        return {"action": "error", "reason": type(e).__name__, "guid": guid, "url": pad_url}
    return {"action": "validated", "status": vst, "text": vtext,
            "guid": guid, "url": pad_url}


# ---------------- response parsing ----------------

def read_tag(xml: str, tag: str) -> str:
    try:
        nodes = [node for node in ET.fromstring(xml).iter() if node.tag.rsplit('}', 1)[-1] == tag]
    except ET.ParseError:
        return ''
    return (nodes[0].text or '').strip() if len(nodes) == 1 else ''


def parse_activation(xml: str) -> dict:
    out = {t: read_tag(xml, t) for t in
           ("ActivateNewResult", "OathTokenSecretKey", "OathTokenEnabled", "Username",
            "TenantId", "AzureObjectId", "ConfirmationCode", "Code", "Description",
            "PhoneAppDetailId", "GroupKey", "ReplicationScope", "ReplicationScopes",
            "RoutingHint", "CountryCode", "DosPreventer")}
    out["ActivateNewResult"] = out["ActivateNewResult"].lower() == "true"
    out["OathTokenEnabled"] = out["OathTokenEnabled"].lower() == "true"
    if not out["ReplicationScopes"]:
        out["ReplicationScopes"] = out["ReplicationScope"]
    return out


# ---------------- challenge loop (app: MfaValidateDeviceNotification) ------

def challenge_loop(listener, result: dict, device_token: str, timeout: int = 120) -> bool:
    """Answer each distinct validation push until ActivateNew returns or times out.

    Failed deliveries remain eligible for retry if the same challenge is pushed
    again. Keep every successful response so the eventual SOAP account can be
    matched to its validation evidence.
    """
    started = time.monotonic()
    next_push = 0
    delivered = set()
    answered = False
    while not result.get('done') and time.monotonic() - started < timeout:
        while next_push < len(listener.pushes):
            appdata = listener.pushes[next_push]['app_data']
            next_push += 1
            if not is_valid_challenge(appdata):
                continue
            guid, url, version = extract_challenge(appdata)
            identity = (guid, url, version.upper())
            if identity in delivered:
                continue
            out = answer_challenge(appdata, device_token)
            success = out['action'] == 'notify-only' or (
                out['action'] == 'validated' and 200 <= out.get('status', 0) < 300)
            print(f"[validate] {out['action']}: "
                  f"{out.get('status', out.get('reason', ''))} "
                  f"{'response received' if out.get('text') else ''}", flush=True)
            if not success:
                continue
            delivered.add(identity)
            answered = True
            metadata = {
                'PadUrl': url,
                'ReplicationScope': appdata.get('replicationScope', ''),
                'ReplicationScopes': appdata.get('replicationScope', ''),
                'RoutingHint': appdata.get('routingHint', ''),
                'CountryCode': appdata.get('countryCode', ''),
                'TenantId': appdata.get('tenantId', ''),
            }
            response_xml = out.get('text', '') if out['action'] == 'validated' else ''
            if response_xml:
                metadata['DosPreventer'] = read_tag(response_xml, 'dosPreventer')
            result.setdefault('validation_events', []).append(
                {'metadata': metadata, 'response_xml': response_xml})
            # Retain the historical fields for interrupted-enrollment diagnostics.
            result['challenge_meta'] = metadata
            result['validation_response'] = response_xml
        if not result.get('done'):
            listener.event.wait(timeout=0.5)
            time.sleep(0.1)
    return answered


# ---------------- orchestrator ----------------

def activate(link: str, code: str, device_name: str = "Pixel 8", soap_transport=None) -> str:
    """Back up the enrollment, then stage a new response for an explicit test."""
    if not code:
        raise ValueError('one-time activation code is required')
    send_soap = soap_transport or soap_post
    from urllib.parse import urlparse
    base = link.split('?')[0].rstrip('/')
    parsed = urlparse(base)
    host = (parsed.hostname or '').lower()
    allowed = any(host == h or host.endswith('.' + h) for h in (
        'mobileappcommunicator.auth.microsoft.com', 'adnotifications.windowsazure.com',
        'mobileappcommunicator.auth-ppe.microsoft.com', 'phonefactor.net'))
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in (None, 443) or not allowed:
        raise ValueError('unexpected activation endpoint')
    paf_url = base + '/PfPaWs.asmx'
    from app.registration import RegistrationState
    registration = RegistrationState()
    listener = None
    try:
        current = registration.snapshot()
        fcm_token = current['google'] or current['active'] or current['legacy_token']
        candidate_id = registration.begin_enrollment(fcm_token)
        state = json.loads(state_path('checkin_info.json').read_text())
        body = build_activate(code, fcm_token, device_name, int(time.time() // 30))
        print('Starting Microsoft device activation; previous enrollment backed up')
        listener = McsListener(state['androidId'], state['securityToken'])
        listener.start()
        if not listener.ready.wait(timeout=45):
            raise SystemExit('MCS login did not succeed; activation was not sent. Rerun setup.')
        result = {}

        def do_activate():
            try:
                result['status'], result['text'] = send_soap(paf_url, body, SOAP_ACT)
                registration.retain_activation_response(candidate_id, result['text'], result['status'])
            except Exception as exc:
                result['error'] = type(exc).__name__
            result['done'] = True

        worker = threading.Thread(target=do_activate, daemon=True)
        worker.start()
        challenge_loop(listener, result, fcm_token, timeout=120)
        if not result.get('done'):
            raise SystemExit('Activation result is unknown; previous enrollment retained. Do not reuse the one-time code.')
        if 'error' in result:
            raise SystemExit('Activation transport failed; previous enrollment retained.')
        info = parse_activation(result['text'])
        events = result.get('validation_events') or [{
            'metadata': result.get('challenge_meta', {}),
            'response_xml': result.get('validation_response', '')}]
        metadata, validation_xml = {}, ''
        for event in events:
            candidate_meta = event['metadata']
            candidate_xml = event['response_xml']
            tenant_matches = bool(info['TenantId']) and candidate_meta.get('TenantId') == info['TenantId']
            username_matches = bool(info['Username']) and read_tag(candidate_xml, 'username') == info['Username']
            object_matches = bool(info['AzureObjectId']) and read_tag(candidate_xml, 'azureObjectId') == info['AzureObjectId']
            object_id = read_tag(candidate_xml, 'azureObjectId')
            if (not (candidate_meta.get('TenantId') and not tenant_matches)
                    and not (object_id and not object_matches)
                    and (username_matches or (tenant_matches and object_matches))):
                metadata, validation_xml = candidate_meta, candidate_xml
                break
        if metadata:
            username_matches = bool(info['Username']) and read_tag(validation_xml, 'username') == info['Username']
            for key, value in metadata.items():
                if value and key != 'TenantId':
                    info[key] = value
            if username_matches:
                info['GroupKey'] = read_tag(validation_xml, 'groupKey') or info['GroupKey']
        # Preserve unproven metadata too as evidence, without applying it to the account.
        registration.stage_activation(candidate_id, info, result['text'], evidence={
            'metadata': metadata or result.get('challenge_meta', {}),
            'response_xml': validation_xml or result.get('validation_response', ''),
            'events': events})
        if not 200 <= result['status'] < 300 or not info['ActivateNewResult']:
            raise SystemExit('Activation was refused; response retained in staging.')
        cc = info.get('ConfirmationCode')
        if cc and cc != '0':
            status, xml = send_soap(paf_url, build_confirm(cc), SOAP_CONF)
            registration.retain_activation_response(candidate_id, xml, status, confirmation=True)
            if not 200 <= status < 300 or read_tag(xml, 'ConfirmActivationResult').lower() != 'true':
                raise SystemExit('ConfirmActivation was refused or unconfirmed; staged credentials retained.')
            detail = read_tag(xml, 'phoneAppDetailId')
            if detail:
                info['PhoneAppDetailId'] = detail
                registration.stage_activation(candidate_id, info, result['text'])
        registration.confirm_staged(candidate_id)
        print('New Entra activation staged. A confirmed sign-in test is required before replacement.')
        return candidate_id
    finally:
        if listener:
            listener.stop()
            listener.join(timeout=3)
        registration.close()
