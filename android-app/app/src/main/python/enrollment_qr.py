"""Parse Microsoft Entra MFA QR contents without following the scanned URL."""
import re
from urllib.parse import parse_qs, urlsplit

from app.state_bundle import BundleError


def parse_qr(raw):
    try:
        if not isinstance(raw, str) or len(raw) > 4096 or any(ord(c) < 32 for c in raw):
            raise ValueError()
        outer = urlsplit(raw.strip())
        if (outer.scheme != 'https' or outer.hostname != 'login.microsoftonline.com'
                or outer.username or outer.password or outer.port not in (None, 443)
                or outer.path != '/authenticatorApp/activateAccount' or outer.fragment):
            raise ValueError()
        fields = parse_qs(outer.query, strict_parsing=True, keep_blank_values=True, max_num_fields=12)
        if (set(fields) - {'accountType', 'source', 'url', 'code'}
                or any(len(v) != 1 for v in fields.values())
                or fields.get('accountType') != ['mfa']):
            raise ValueError()
        code, link = fields['code'][0], fields['url'][0]
        endpoint = urlsplit(link)
        if (not re.fullmatch(r'[0-9]{6,12}', code)
                or endpoint.scheme != 'https' or endpoint.username or endpoint.password
                or endpoint.port not in (None, 443) or endpoint.query or endpoint.fragment
                or endpoint.hostname not in ('mobileappcommunicator.auth.microsoft.com',
                    'mobileappcommunicator.auth-ppe.microsoft.com', 'adnotifications.windowsazure.com')
                or not re.fullmatch(r'/activatev2/[0-9]+/[A-Za-z0-9_-]+/?', endpoint.path)):
            raise ValueError()
        return link.rstrip('/'), code
    except (ValueError, KeyError, TypeError):
        raise BundleError('Use a Microsoft work or school MFA setup QR code. This code is not supported.') from None


def qr_summary(raw):
    link, _ = parse_qr(raw)
    return urlsplit(link).hostname
