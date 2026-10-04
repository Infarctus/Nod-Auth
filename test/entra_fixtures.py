"""Synthetic Entra values shared by offline lifecycle tests."""
from contextlib import contextmanager
import os
import tempfile
from unittest.mock import patch


@contextmanager
def synthetic_apk_state():
    """Provide public test APK metadata without reading a developer's real state."""
    from app.state import save_json
    with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, AUTH_STATE_DIR=root):
        save_json('apk_config.json', {
            'package': 'com.azure.authenticator', 'version_name': '6.2608.5658',
        })
        yield


ACCOUNT = {'ActivateNewResult': True, 'TenantId': 'tenant', 'AzureObjectId': 'object',
           'Username': 'user@example.test', 'PhoneAppDetailId': 'detail', 'GroupKey': 'group',
           'PadUrl': 'https://phonefactor.net/pad', 'DosPreventer': 'dos',
           'ReplicationScope': 'scope', 'ReplicationScopes': 'scope',
           'RoutingHint': '', 'CountryCode': '', 'OathTokenEnabled': True,
           'OathTokenSecretKey': 'JBSWY3DPEHPK3PXP'}
PUSH = {'source': 'SAS', 'type': 'auth', 'guid': 'request', 'url': 'phonefactor.net',
        'tenantId': 'tenant', 'replicationScope': 'scope', 'firstEntropyChallenge': '12',
        'secondEntropyChallenge': '34', 'thirdEntropyChallenge': '56'}


def auth_response(token='A', **changes):
    from xml.etree.ElementTree import Element, SubElement, tostring
    fields = {'guid': 'request', 'tenantId': 'tenant', 'azureObjectId': 'object',
              'phoneAppDetailId': 'detail', 'groupKey': 'group', 'replicationScope': 'scope',
              'pushNotificationDeviceToken': token}
    fields.update(changes)
    root = Element('phoneAppAuthenticationResponse')
    for key, value in fields.items():
        SubElement(root, key).text = value
    return tostring(root, encoding='unicode')


def validation_response():
    return ('<phoneAppValidateDeviceTokenResponse><accountValidationResults>'
            '<accountValidationResult><azureObjectId>object</azureObjectId>'
            '<azureTenantId>tenant</azureTenantId><phoneAppDetailId>detail</phoneAppDetailId>'
            '<validationResult>Success</validationResult></accountValidationResult>'
            '</accountValidationResults></phoneAppValidateDeviceTokenResponse>')
