"""Entra device-token change requests and strictly checked responses."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from app.activation import APP, FLAVOR, OS_VERSION, PAD_ALLOWED_HOST_SUFFIXES
from app.activation import build_pad_headers, pfp
from app import app_identity


class BindingError(RuntimeError):
    def __init__(self, kind: str, uncertain: bool = False, *, diagnostic: str = ""):
        super().__init__(kind)
        self.kind = kind
        self.uncertain = uncertain
        self.diagnostic = diagnostic


def _tag(node: ET.Element, name: str) -> str:
    for child in node.iter():
        if child.tag.rsplit("}", 1)[-1] == name:
            return (child.text or "").strip()
    return ""


def _root(xml: str) -> ET.Element:
    try:
        return ET.fromstring(xml)
    except ET.ParseError as exc:
        raise BindingError("invalid_response") from exc


def endpoint_diagnostic(url: str) -> str:
    """Report URL structure using fixed labels/counts, never supplied values."""
    try:
        parsed = urlparse(url)
        # urlparse separates semicolon parameters from the path as well as
        # query/fragment. A string ending in /pad need not have a path ending
        # in /pad: the suffix may belong to one of those other components.
        suffix_in = next((name for name in ('fragment', 'query', 'params', 'path')
                          if getattr(parsed, name).rstrip('/').endswith('/pad')), 'none')
        fields = {
            'url_ends_pad': url.rstrip('/').endswith('/pad'),
            'path_empty': not parsed.path,
            'path_segments': len([part for part in parsed.path.split('/') if part]),
            'path_ends_pad': parsed.path.rstrip('/').endswith('/pad'),
            'params_present': bool(parsed.params),
            'query_present': bool(parsed.query),
            'fragment_present': bool(parsed.fragment),
            'whitespace_present': any(char.isspace() for char in url),
            'backslash_present': chr(92) in url,
        }
        return ('expected=https_allowed_host ' +
                ' '.join(f'{key}={str(value).lower()}' for key, value in fields.items()) +
                f' suffix_in={suffix_in}')
    except ValueError:
        return 'expected=parseable_https_url parseable=false'


def pad_url(url: str) -> str:
    # PendingAuthentication.getMfaServiceRequestUrl and MfaRegistrationUseCase
    # concatenate https:// + service URL + /pad literally, including queries.
    # Validate the destination authority, not the path/query layout. Do not
    # relocate /pad, remove routing parameters, or reinterpret the service URL.
    # Error labels describe structure only, never the potentially private URL.
    def reject(kind):
        return BindingError(kind, diagnostic=endpoint_diagnostic(url))

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise reject("invalid_endpoint_syntax") from exc
    if parsed.scheme != "https":
        raise reject("invalid_endpoint_scheme")
    if parsed.username is not None or parsed.password is not None:
        raise reject("invalid_endpoint_credentials")
    if port not in (None, 443):
        raise reject("invalid_endpoint_port")
    if not any(host == suffix or host.endswith("." + suffix)
               for suffix in PAD_ALLOWED_HOST_SUFFIXES):
        raise reject("invalid_endpoint_host")
    return url


def _xml(tag: str, value: str) -> str:
    element = ET.Element(tag)
    element.text = str(value)
    return ET.tostring(element, encoding="unicode", short_empty_elements=False)


def build_v1(old: str, new: str, dos: str, scopes: str) -> str:
    if not old or not new:
        raise BindingError("missing_token")
    return pfp(
        "<phoneAppDeviceTokenChangeRequest>"
        + _xml("dosPreventer", dos)
        + _xml("oldDeviceToken", old)
        + f'<newDeviceToken notificationType="gcm">{_escape(new)}</newDeviceToken>'
        + _xml("version", app_identity.app_version())
        + _xml("osVersion", OS_VERSION)
        + _xml("replicationScopes", scopes)
        + "</phoneAppDeviceTokenChangeRequest>")


def _escape(value: str) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def build_start_v2(new: str) -> str:
    if not new:
        raise BindingError("missing_token")
    return pfp("<phoneAppStartDeviceTokenChangeV2Request>"
               + _xml("newDeviceToken", new)
               + _xml("version", app_identity.app_version())
               + _xml("osVersion", OS_VERSION)
               + _xml("appPackageName", APP)
               + _xml("authenticatorFlavor", FLAVOR)
               + _xml("notificationType", "FCM")
               + "</phoneAppStartDeviceTokenChangeV2Request>")


def oath_validation_code(secret_base32: str, counter: int) -> str:
    """MfaTotpUseCase.generateValidationCode: full HMAC-SHA1 hex."""
    if not 0 <= counter <= 2**63 - 1:
        raise BindingError("invalid_oath_counter")
    cleaned = re.sub(r"[^A-Za-z2-7]", "", secret_base32).upper()
    if not cleaned:
        raise BindingError("missing_oath_secret")
    try:
        secret = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8), casefold=True)
    except ValueError as exc:
        raise BindingError("invalid_oath_secret") from exc
    return hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).hexdigest().upper()


def build_complete_v2(new: str, account: dict, counter: int) -> str:
    required = ("AzureObjectId", "TenantId", "PhoneAppDetailId", "OathTokenSecretKey")
    if not all(account.get(field) for field in required):
        raise BindingError("metadata_required")
    code = oath_validation_code(account["OathTokenSecretKey"], counter)
    return pfp("<phoneAppCompleteDeviceTokenChangeV2Request><accounts><account>"
               + _xml("azureObjectId", account["AzureObjectId"])
               + _xml("azureTenantId", account["TenantId"])
               + _xml("oathCode", code)
               + _xml("phoneAppDetailId", account["PhoneAppDetailId"])
               + "</account></accounts>"
               + _xml("newDeviceToken", new)
               + _xml("version", app_identity.app_version())
               + _xml("osVersion", OS_VERSION)
               + "</phoneAppCompleteDeviceTokenChangeV2Request>")


def result_code(xml: str) -> int:
    value = _tag(_root(xml), "deviceTokenChangeResult")
    if not re.fullmatch(r"-?[0-9]{1,4}", value):
        raise BindingError("invalid_response")
    return int(value)


def complete_success(xml: str, account: dict) -> bool:
    root = _root(xml)
    matches = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] != "accountValidationResult":
            continue
        if (_tag(node, "azureObjectId") == account["AzureObjectId"]
                and _tag(node, "azureTenantId") == account["TenantId"]
                and _tag(node, "phoneAppDetailId") == account["PhoneAppDetailId"]):
            matches.append(_tag(node, "validationResult").lower() == "success")
    return len(matches) == 1 and matches[0]


def headers(token: str, action: str, account: dict | None = None) -> dict:
    result = build_pad_headers(token, action)
    if action == "phoneAppDeviceTokenChangeRequest":
        result["x-ms-mac-interactive"] = "0"
    if account and action != "phoneAppDeviceTokenChangeRequest":
        result["x-ms-client-replication-scope"] = account.get("ReplicationScope", "")
        result["x-ms-client-tenant-id"] = account.get("TenantId", "")
        if account.get("RoutingHint"):
            result["x-ms-routing-hint"] = account["RoutingHint"]
        if account.get("CountryCode"):
            result["x-ms-client-tenant-country-code"] = account["CountryCode"]
    return result


def post(url: str, xml: str, token: str, action: str, account: dict | None = None):
    from curl_cffi import requests as cr
    response = cr.post(pad_url(url), data=xml.encode(), headers=headers(token, action, account),
                       timeout=30, impersonate="chrome131_android", allow_redirects=False)
    if response.status_code == 429 or response.status_code >= 500:
        raise BindingError("server_retryable", uncertain=True)
    if response.status_code < 200 or response.status_code >= 300:
        raise BindingError("server_rejected")
    return response.text


def change_v1(account: dict, old: str, new: str) -> None:
    url = account.get("PadUrl", "")
    scopes = account.get("ReplicationScopes", "")
    dos = account.get("DosPreventer", "")
    if not url or not scopes or not dos:
        raise BindingError("metadata_required")
    action = "phoneAppDeviceTokenChangeRequest"
    xml = build_v1(old, new, dos, scopes)
    response = post(url, xml, new, action)
    try:
        code = result_code(response)
    except BindingError as exc:
        raise BindingError("invalid_response", uncertain=True) from exc
    if code == 1:
        return
    if code == 100:
        raise BindingError("invalid_dos_preventer")
    # The server returned an explicit failure; the APK retries all non-success
    # results except an invalid DOS preventer. A transport timeout stays uncertain.
    raise BindingError(f"device_token_change_{code}")


def v2_challenge(appdata: dict, account: dict) -> dict:
    if (appdata.get("source") not in ("SAS", "MFA Server")
            or appdata.get("type", "validate") != "validate"
            or appdata.get("deviceTokenChangeVersion", "").upper() != "V2"):
        raise BindingError("unrelated_challenge")
    if not str(appdata.get("guid") or "").strip():
        raise BindingError("missing_guid")
    if not appdata.get("oathCounter", "").isdigit():
        raise BindingError("missing_oath_counter")
    for wire, saved in (("tenantId", "TenantId"), ("replicationScope", "ReplicationScope"),
                        ("routingHint", "RoutingHint"), ("countryCode", "CountryCode")):
        if appdata.get(wire, "") != account.get(saved, ""):
            raise BindingError("wrong_tenant" if wire == "tenantId" else "wrong_account_combination")
    if int(appdata["oathCounter"]) > 2**63 - 1:
        raise BindingError("invalid_oath_counter")
    from app.activation import extract_challenge
    _, url, _ = extract_challenge(appdata)
    return {"url": pad_url(url), "counter": int(appdata["oathCounter"]),
            "TenantId": appdata.get("tenantId", ""),
            "ReplicationScope": appdata.get("replicationScope", ""),
            "RoutingHint": appdata.get("routingHint", ""),
            "CountryCode": appdata.get("countryCode", "")}


def response_node(xml: str, name: str) -> ET.Element:
    nodes = [node for node in _root(xml).iter() if node.tag.rsplit('}', 1)[-1] == name]
    if len(nodes) != 1:
        raise BindingError('unexpected_response_type')
    return nodes[0]


def unique_text(node: ET.Element, *names: str) -> str:
    values = [(child.text or '').strip() for child in node.iter()
              if child.tag.rsplit('}', 1)[-1] in names]
    if len(values) > 1:
        raise BindingError('ambiguous_response_field')
    return values[0] if values else ''


def matches_account(node: ET.Element, account: dict) -> bool:
    tenant = unique_text(node, 'tenantId', 'azureTenantId')
    obj = unique_text(node, 'azureObjectId')
    detail = unique_text(node, 'phoneAppDetailId')
    return (bool(account.get('TenantId') and account.get('AzureObjectId'))
            and tenant == account['TenantId'] and obj == account['AzureObjectId']
            and (not account.get('PhoneAppDetailId') or detail == account['PhoneAppDetailId']))


def push_matches_account(data: dict, account: dict) -> bool:
    """A push is a hint; absent identity is verified by the subsequent response."""
    for wire, saved in (('tenantId', 'TenantId'), ('azureObjectId', 'AzureObjectId'),
                        ('phoneAppDetailId', 'PhoneAppDetailId'), ('groupKey', 'GroupKey')):
        if data.get(wire) and account.get(saved) and data[wire] != account[saved]:
            return False
    return True


def push_identifies_account(data: dict, account: dict) -> bool:
    """APK notification lookup: detail ID, then object hash plus group key.

    Conflicting explicit identity still rejects the push. Ambiguous/older
    notifications use the authentication fetch instead of guessing an account.
    """
    if not push_matches_account(data, account):
        return False
    if data.get('phoneAppDetailId') and data['phoneAppDetailId'] == account.get('PhoneAppDetailId'):
        return True
    obj = account.get('AzureObjectId', '')
    group = account.get('GroupKey', '')
    digest = data.get('userObjectId', '').lower()
    return bool(obj and group and data.get('groupKey') == group and digest and
                any(hmac.compare_digest(digest, hashlib.sha256(value.encode()).hexdigest())
                    for value in (obj, obj.lower())))


def build_authentication(guid: str, token: str, oath_code: str = '', *,
                         need_dos_preventer: bool = False) -> str:
    return pfp('<phoneAppAuthenticationRequest><phoneAppContext>'
               + _xml('guid', guid) + _xml('oathCode', oath_code)
               + _xml('needDosPreventer', 'yes' if need_dos_preventer else 'no')
               + _xml('deviceToken', token)
               + _xml('version', app_identity.app_version()) + _xml('osVersion', OS_VERSION)
               + '</phoneAppContext></phoneAppAuthenticationRequest>')


def authentication_details(xml: str, data: dict, account: dict) -> dict:
    # AuthenticationResponse.parseXml scans the response document; it does not
    # require a phoneAppAuthenticationResponse wrapper. Keep uniqueness and
    # account/session checks across the document to reject mixed responses.
    node = _root(xml)
    if unique_text(node, 'guid') != data.get('guid') or not matches_account(node, account):
        raise BindingError('unmatched_authentication_response')
    fields = {}
    for source, dest in (('phoneAppDetailId', 'PhoneAppDetailId'), ('groupKey', 'GroupKey'),
                         ('replicationScope', 'ReplicationScope'), ('routingHint', 'RoutingHint'),
                         ('countryCode', 'CountryCode')):
        value = unique_text(node, source)
        if value:
            fields[dest] = value
    # Preserve credentials actually returned for the matched account.
    dos = unique_text(node, 'dosPreventer')
    if dos:
        fields['DosPreventer'] = dos
    if fields.get('ReplicationScope'):
        fields['ReplicationScopes'] = fields['ReplicationScope']
    token = unique_text(node, 'pushNotificationDeviceToken')
    if token and any(char.isspace() for char in token):
        raise BindingError('invalid_response_token')
    verified_push = dict(data)
    for key in ('firstEntropyChallenge', 'secondEntropyChallenge', 'thirdEntropyChallenge', 'isAppLockRequired'):
        value = unique_text(node, key)
        if value:
            verified_push[key] = value
    fields['PadUrl'] = pad_url_of_push(data)
    return {'fields': fields, 'server_token': token, 'push': verified_push}


def pad_url_of_push(data: dict) -> str:
    from app.approval import pad_url_of
    try:
        return pad_url(pad_url_of(data))
    except BindingError as exc:
        exc.diagnostic = 'stage=push_service_url ' + exc.diagnostic
        raise


def fetch_authentication(data: dict, account: dict, token: str) -> dict:
    if not push_matches_account(data, account) or not data.get('guid'):
        raise BindingError('unmatched_authentication_push')
    url = pad_url_of_push(data)
    response = post(url, build_authentication(data['guid'], token,
                    need_dos_preventer=not bool(account.get('DosPreventer'))), token,
                    'phoneAppAuthenticationRequest', account)
    return authentication_details(response, data, account)


def validation_metadata(xml: str, account: dict) -> tuple[dict, bool]:
    """Read only this account's result, never another account's credentials."""
    node = response_node(xml, 'phoneAppValidateDeviceTokenResponse')
    entries = [child for child in node.iter() if child.tag.rsplit('}', 1)[-1] == 'accountValidationResult']
    matches = [child for child in entries if matches_account(child, account)]
    fields = {}
    if entries:
        if len(matches) != 1 or unique_text(matches[0], 'validationResult').lower() != 'success':
            raise BindingError('unmatched_validation_response')
        match = matches[0]
        for wire, saved in (('phoneAppDetailId', 'PhoneAppDetailId'), ('groupKey', 'GroupKey')):
            value = unique_text(match, wire)
            if value:
                fields[saved] = value
        dos = unique_text(node, 'dosPreventer')
        if dos:
            fields['DosPreventer'] = dos
        return fields, True
    # Older responses identify an account by groupKey + username only.
    if (not account.get('GroupKey') or not account.get('Username')
            or unique_text(node, 'groupKey') != account['GroupKey']
            or unique_text(node, 'username') != account['Username']):
        raise BindingError('unmatched_validation_response')
    dos = unique_text(node, 'dosPreventer')
    if dos:
        fields['DosPreventer'] = dos
    return fields, False
