"""An unconfirmed Entra activation must not become persisted binding state."""
import json
import os
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from app import activation
from app.state import state_path


class ActivationCommitTests(unittest.TestCase):
    def test_confirm_failure_keeps_account_unbound(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, AUTH_STATE_DIR=directory):
            state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
            state_path("checkin_info.json").write_text(
                json.dumps({"androidId": 1, "securityToken": 2}))
            state_path("fcm_token.txt").write_text("token\n")
            listener = Mock()
            listener.ready.wait.return_value = True

            def soap(url, body, action, timeout=90):
                if action == activation.SOAP_ACT:
                    return 200, ("<r><ActivateNewResult>true</ActivateNewResult>"
                                 "<TenantId>tenant</TenantId><AzureObjectId>object</AzureObjectId>"
                                 "<OathTokenSecretKey>saved-secret</OathTokenSecretKey>"
                                 "<ConfirmationCode>confirm</ConfirmationCode></r>")
                return 200, "<r><ConfirmActivationResult>false</ConfirmActivationResult></r>"

            def wait_for_result(_listener, result, _token, timeout=120):
                deadline = time.monotonic() + 1
                while not result.get("done") and time.monotonic() < deadline:
                    time.sleep(0.001)
                return True

            with patch.object(activation, "McsListener", return_value=listener), \
                 patch.object(activation, "soap_post", side_effect=soap), \
                 patch.object(activation, "challenge_loop", side_effect=wait_for_result):
                with self.assertRaisesRegex(SystemExit, "ConfirmActivation was refused"):
                    activation.activate("https://phonefactor.net", "code")
            self.assertFalse(state_path("activation.json").exists())
            self.assertTrue(state_path("registration.sqlite3").exists())
            staged = json.loads(state_path("activation.pending.json").read_text())
            self.assertEqual(staged["account"]["OathTokenSecretKey"], "saved-secret")
            self.assertEqual(staged["status"], "confirmation_required")
            self.assertFalse(state_path("setup_complete.json").exists())


if __name__ == "__main__":
    unittest.main()


class ActivationStagingTests(unittest.TestCase):
    def test_successful_confirmation_retains_detail_id_and_waits_for_sign_in(self):
        from app.registration import RegistrationState
        from test.entra_fixtures import ACCOUNT
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, AUTH_STATE_DIR=directory):
            state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
            state_path('checkin_info.json').write_text(json.dumps({'androidId': 1, 'securityToken': 2}))
            registry = RegistrationState()
            registry.google_success('token')
            registry.mark_activation('token', ACCOUNT)
            registry.close()
            listener = Mock()
            listener.ready.wait.return_value = True
            def soap(url, body, action, timeout=90):
                if action == activation.SOAP_ACT:
                    return 200, ('<r><ActivateNewResult>true</ActivateNewResult><TenantId>tenant</TenantId>'
                                 '<AzureObjectId>new-object</AzureObjectId><Username>new@example.test</Username>'
                                 '<OathTokenEnabled>true</OathTokenEnabled><OathTokenSecretKey>new-secret</OathTokenSecretKey>'
                                 '<ConfirmationCode>confirm</ConfirmationCode></r>')
                return 200, '<r><ConfirmActivationResult>true</ConfirmActivationResult><phoneAppDetailId>new-detail</phoneAppDetailId></r>'
            def wait(_listener, result, _token, timeout=120):
                until = time.monotonic() + 2
                while not result.get('done') and time.monotonic() < until:
                    time.sleep(0.001)
                result['validation_response'] = '<r><username>new@example.test</username></r>'
                result['challenge_meta'] = {'TenantId': 'foreign', 'PadUrl': 'https://wrong.microsoft.com/pad', 'DosPreventer': 'unmatched'}
            with patch.object(activation, 'McsListener', return_value=listener), \
                 patch.object(activation, 'soap_post') as desktop_transport, \
                 patch.object(activation, 'challenge_loop', side_effect=wait):
                native_transport = Mock(side_effect=soap)
                activation.activate('https://phonefactor.net', 'one-time-code', soap_transport=native_transport)
                self.assertEqual([call.args[2] for call in native_transport.call_args_list],
                                 [activation.SOAP_ACT, activation.SOAP_CONF])
                desktop_transport.assert_not_called()
            registry = RegistrationState()
            try:
                staged = registry.state['staged']
                self.assertEqual(staged['account']['PhoneAppDetailId'], 'new-detail')
                self.assertEqual(staged['account']['OathTokenSecretKey'], 'new-secret')
                self.assertEqual(staged['status'], 'test_required')
                self.assertNotIn('PadUrl', staged['account'])
                self.assertNotEqual(staged['account'].get('DosPreventer'), 'unmatched')
                self.assertIn('new-detail', staged['confirmation_response_xml'])
                self.assertEqual(staged['validation_evidence']['metadata']['DosPreventer'], 'unmatched')
                self.assertEqual(registry.state['account'], ACCOUNT)
                self.assertEqual(json.loads(state_path('activation.json').read_text()), ACCOUNT)
                self.assertFalse(state_path('setup_complete.json').exists())
            finally:
                registry.close()

class ActivationChallengeSelectionTests(unittest.TestCase):
    def test_later_matching_validation_metadata_wins(self):
        from app.registration import RegistrationState
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, AUTH_STATE_DIR=directory):
            state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
            state_path('checkin_info.json').write_text(json.dumps({'androidId': 1, 'securityToken': 2}))
            registry = RegistrationState()
            registry.google_success('token')
            registry.close()
            listener = Mock()
            listener.ready.wait.return_value = True

            def soap(url, body, action, timeout=90):
                return 200, ('<r><ActivateNewResult>true</ActivateNewResult>'
                             '<TenantId>tenant</TenantId><AzureObjectId>object</AzureObjectId>'
                             '<Username>user@example.test</Username>'
                             '<OathTokenEnabled>true</OathTokenEnabled>'
                             '<OathTokenSecretKey>saved-secret</OathTokenSecretKey></r>')

            def wait(_listener, result, _token, timeout=120):
                until = time.monotonic() + 2
                while not result.get('done') and time.monotonic() < until:
                    time.sleep(0.001)
                result['validation_events'] = [
                    {'metadata': {'TenantId': 'foreign', 'PadUrl': 'https://wrong.phonefactor.net/pad',
                                  'DosPreventer': 'wrong'},
                     'response_xml': '<r><username>other@example.test</username></r>'},
                    {'metadata': {'TenantId': 'tenant', 'PadUrl': 'https://phonefactor.net/pad',
                                  'DosPreventer': 'matched'},
                     'response_xml': '<r><azureObjectId>object</azureObjectId></r>'},
                ]

            with patch.object(activation, 'McsListener', return_value=listener), \
                 patch.object(activation, 'soap_post', side_effect=soap), \
                 patch.object(activation, 'challenge_loop', side_effect=wait):
                activation.activate('https://phonefactor.net', 'one-time-code')
            registry = RegistrationState()
            try:
                account = registry.state['staged']['account']
                self.assertEqual(account['DosPreventer'], 'matched')
                self.assertEqual(account['PadUrl'], 'https://phonefactor.net/pad')
                self.assertEqual(len(registry.state['staged']['validation_evidence']['events']), 2)
            finally:
                registry.close()
