"""Entra token-change wire format and failure classification."""
import base64
import hashlib
import hmac
import struct
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from app import entra_registration as renewal


ACCOUNT = {"AzureObjectId": "object", "TenantId": "tenant",
           "PhoneAppDetailId": "detail", "OathTokenSecretKey": "JBSWY3DPEHPK3PXP",
           "PadUrl": "https://phonefactor.net/pad",
           "ReplicationScopes": "scope", "ReplicationScope": "scope", "DosPreventer": "dos"}


def setUpModule():
    from test.entra_fixtures import synthetic_apk_state
    unittest.enterModuleContext(synthetic_apk_state())


class ProtocolTests(unittest.TestCase):
    def test_activation_parser_retains_optional_renewal_metadata(self):
        from app.activation import parse_activation
        info = parse_activation("<r><ActivateNewResult>true</ActivateNewResult>"
                                "<PhoneAppDetailId>detail</PhoneAppDetailId>"
                                "<ReplicationScope>scope</ReplicationScope>"
                                "<DosPreventer>dos</DosPreventer></r>")
        self.assertEqual(info["PhoneAppDetailId"], "detail")
        self.assertEqual(info["ReplicationScope"], "scope")
        self.assertEqual(info["DosPreventer"], "dos")

    def test_v1_body_and_result(self):
        root = ET.fromstring(renewal.build_v1("old", "new", "dos", "scope"))
        req = root.find(".//phoneAppDeviceTokenChangeRequest")
        self.assertEqual(req.findtext("oldDeviceToken"), "old")
        self.assertEqual(req.find("newDeviceToken").attrib["notificationType"], "gcm")
        self.assertEqual(req.findtext("replicationScopes"), "scope")
        self.assertEqual(renewal.result_code("<response><deviceTokenChangeResult>1</deviceTokenChangeResult></response>"), 1)
        with patch.object(renewal, "post", return_value="<r><deviceTokenChangeResult>100</deviceTokenChangeResult></r>"):
            with self.assertRaisesRegex(renewal.BindingError, "invalid_dos_preventer"):
                renewal.change_v1(ACCOUNT, "old", "new")

    def test_explicit_v1_server_timeout_is_retryable_not_uncertain(self):
        with patch.object(renewal, 'post', return_value='<r><deviceTokenChangeResult>102</deviceTokenChangeResult></r>'):
            with self.assertRaises(renewal.BindingError) as caught:
                renewal.change_v1(ACCOUNT, 'old', 'new')
        self.assertEqual(caught.exception.kind, 'device_token_change_102')
        self.assertFalse(caught.exception.uncertain)

    def test_v2_uses_full_server_counter_hmac(self):
        counter = 12345678
        secret = base64.b32decode(ACCOUNT["OathTokenSecretKey"])
        expected = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).hexdigest().upper()
        root = ET.fromstring(renewal.build_complete_v2("new", ACCOUNT, counter))
        request = root.find(".//phoneAppCompleteDeviceTokenChangeV2Request")
        self.assertEqual(request.findtext(".//oathCode"), expected)
        self.assertEqual(len(expected), 40)
        self.assertEqual(request.findtext(".//phoneAppDetailId"), "detail")
        start = ET.fromstring(renewal.build_start_v2("new"))
        self.assertEqual(start.findtext(".//notificationType"), "FCM")

    def test_complete_requires_matching_per_account_success(self):
        response = ("<r><accountValidationResult><phoneAppDetailId>detail</phoneAppDetailId>"
                    "<azureObjectId>object</azureObjectId><azureTenantId>tenant</azureTenantId>"
                    "<validationResult>Success</validationResult></accountValidationResult></r>")
        self.assertTrue(renewal.complete_success(response, ACCOUNT))
        self.assertFalse(renewal.complete_success(response.replace("Success", "TransientFailure"), ACCOUNT))
        self.assertFalse(renewal.complete_success(response.replace("object", "other"), ACCOUNT))
        self.assertFalse(renewal.complete_success("<r/>", ACCOUNT))

    def test_challenge_and_endpoint_rejection(self):
        challenge = {"source": "SAS", "type": "validate", "deviceTokenChangeVersion": "V2",
                     "guid": "challenge", "oathCounter": "123", "tenantId": "tenant", "url": "phonefactor.net",
                     "replicationScope": "scope"}
        self.assertEqual(renewal.v2_challenge(challenge, ACCOUNT)["counter"], 123)
        for change, kind in [({"guid": ""}, "missing_guid"),
                             ({"tenantId": "other"}, "wrong_tenant"),
                             ({"url": "evil.example"}, "invalid_endpoint"),
                             ({"oathCounter": "bad"}, "missing_oath_counter")]:
            with self.subTest(change=change):
                with self.assertRaisesRegex(renewal.BindingError, kind):
                    renewal.v2_challenge({**challenge, **change}, ACCOUNT)


if __name__ == "__main__":
    unittest.main()


class ValidationProofTests(unittest.TestCase):
    def test_v1_uses_apk_account_fields_and_full_sha1_hmac(self):
        from app.activation import build_validation
        from test.entra_fixtures import ACCOUNT
        account = {**ACCOUNT, 'OathTokenSecretKey': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                   'Username': 'A&B@example.test'}
        xml = ET.fromstring(build_validation('g', 'token', False, account, 0))
        request = xml.find('.//phoneAppValidateDeviceTokenRequest')
        proof = request.find('accounts/account')
        self.assertEqual([node.tag for node in proof], ['groupKey', 'username', 'azureObjectId', 'oathCode', 'azureTenantId'])
        self.assertEqual(proof.findtext('oathCode'), 'CC93CF18508D94934C64B65D8BA7667FB7CDE4B0')
        self.assertEqual(proof.findtext('username'), 'A&B@example.test')
        self.assertEqual(request.findtext('phoneAppContext/oathCode'), '')
        self.assertEqual(request.findtext('phoneAppContext/needDosPreventer'), 'no')

    def test_v1_counter_absent_or_oath_disabled_has_no_account_proof(self):
        from app.activation import build_validation
        from test.entra_fixtures import ACCOUNT
        for account, counter in ((ACCOUNT, None), ({**ACCOUNT, 'OathTokenEnabled': False}, 1), (None, 1)):
            xml = ET.fromstring(build_validation('g', 'token', account=account, oath_counter=counter))
            self.assertIsNone(xml.find('.//accounts/account'))

    def test_v1_invalid_counter_aborts_without_network(self):
        from app.activation import answer_challenge
        from test.entra_fixtures import ACCOUNT
        with patch('app.activation.pad_post') as network:
            for value in ('-1', 'abc', str(2**63)):
                result = answer_challenge({'guid': 'g', 'url': 'phonefactor.net', 'oathCounter': value}, 'token', account=ACCOUNT)
                self.assertEqual(result['action'], 'abort')
        network.assert_not_called()

    def test_auth_request_can_request_a_dos_preventer(self):
        for needed in (False, True):
            root = ET.fromstring(renewal.build_authentication('g', 'token', need_dos_preventer=needed))
            self.assertEqual(root.findtext('.//needDosPreventer'), 'yes' if needed else 'no')

    def test_validation_response_cannot_mix_account_identity_and_metadata(self):
        from test.entra_fixtures import ACCOUNT, validation_response
        good = validation_response()
        mixed = good.replace('</accountValidationResults>', '<accountValidationResult><azureObjectId>other</azureObjectId>'
                             '<azureTenantId>tenant</azureTenantId><phoneAppDetailId>evil-detail</phoneAppDetailId>'
                             '<validationResult>Success</validationResult><groupKey>evil</groupKey>'
                             '</accountValidationResult></accountValidationResults>')
        fields, confirmed = renewal.validation_metadata(mixed, ACCOUNT)
        self.assertTrue(confirmed)
        self.assertEqual(fields['PhoneAppDetailId'], 'detail')
        self.assertNotIn('evil', str(fields))
