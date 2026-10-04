"""DOS-preventer recovery through genuine, account-matched Entra requests."""
import json
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from app.entra_registration import BindingError
from app.registration import RegistrationState
from app.state import state_path
from test.entra_fixtures import ACCOUNT, PUSH, auth_response, validation_response
from test import test_registration_runtime as runtime_fixtures


class DosRecoveryTests(unittest.TestCase):
    setUp = runtime_fixtures.RuntimeTests.setUp

    def authentication(self, response):
        self.coordinator.on_mfa_push(PUSH)
        with patch('app.entra_registration.post', return_value=response) as post:
            self.coordinator._learn_responses()
        return post

    def block_binding(self):
        self.registry.google_success('B')
        with patch('app.registration_runtime.entra.change_v1',
                   side_effect=BindingError('invalid_dos_preventer')):
            self.coordinator.tick()
        self.assertEqual(self.registry.state['account']['DosPreventer'], '')

    def test_requests_only_when_missing_and_keeps_existing_credential(self):
        post = self.authentication(auth_response())
        self.assertEqual(ET.fromstring(post.call_args.args[1]).findtext('.//needDosPreventer'), 'no')
        self.assertEqual(self.registry.state['account']['DosPreventer'], 'dos')
        self.registry.update_account({'DosPreventer': ''})
        post = self.authentication(auth_response(dosPreventer='replacement'))
        self.assertEqual(ET.fromstring(post.call_args.args[1]).findtext('.//needDosPreventer'), 'yes')
        self.assertEqual(self.registry.state['account']['DosPreventer'], 'replacement')
        self.assertEqual(self.registry.state['account']['OathTokenSecretKey'], ACCOUNT['OathTokenSecretKey'])
        self.assertTrue(self.registry.status()['has_dos_preventer'])
        self.assertFalse(self.registry.status()['dos_recovery_needed'])
        self.assertNotIn('replacement', json.dumps(self.registry.status()))

    def test_invalid_then_recovered_credential_survives_restart_and_daily_gate(self):
        self.block_binding()
        failed_at = self.clock
        self.clock += 60
        self.authentication(auth_response(dosPreventer='replacement'))
        self.assertEqual(self.registry.state['phase'], 'pending')
        self.assertEqual(self.registry.state['binding_due_at'], failed_at + 86400)
        self.assertEqual(self.registry.active_token, 'A')
        self.assertEqual(self.registry.state['pending'], 'B')
        history = json.loads(state_path('entra_history.json').read_text())
        self.assertTrue(any(e['state']['account'].get('DosPreventer') == 'dos' for e in history))
        reopened = RegistrationState(now=lambda: self.clock, spread_hours=lambda: 0)
        try:
            self.assertEqual(reopened.state['account']['DosPreventer'], 'replacement')
            self.assertEqual(reopened.state['pending'], 'B')
            self.assertEqual(reopened.state['binding_due_at'], failed_at + 86400)
        finally:
            reopened.close()
        with patch('app.registration_runtime.entra.change_v1') as change:
            self.coordinator.tick()
            change.assert_not_called()
            self.clock = failed_at + 86400
            self.coordinator.tick()
        change.assert_called_once()
        self.assertEqual(change.call_args.args[0]['DosPreventer'], 'replacement')
        self.assertEqual(change.call_args.args[1:], ('A', 'B'))
        self.assertEqual(self.registry.active_token, 'B')

    def test_missing_metadata_resumes_without_an_extra_day_after_recovery(self):
        self.registry.update_account({'DosPreventer': ''})
        self.registry.google_success('B')
        self.coordinator.tick()
        self.assertEqual(self.registry.state['phase'], 'metadata_required')
        self.clock += 60
        self.authentication(auth_response(dosPreventer='replacement'))
        self.assertEqual(self.registry.state['binding_due_at'], self.clock)
        with patch('app.registration_runtime.entra.change_v1') as change:
            self.coordinator.tick()
        change.assert_called_once()

    def test_missing_or_empty_response_does_not_claim_recovery(self):
        self.block_binding()
        for response in (auth_response(), auth_response(dosPreventer='')):
            self.authentication(response)
            self.assertEqual(self.registry.state['account']['DosPreventer'], '')
            self.assertEqual(self.registry.state['phase'], 'retry')
            self.assertTrue(self.registry.status()['dos_recovery_needed'])

    def test_wrong_identity_or_duplicate_dos_does_not_update_or_prompt(self):
        self.block_binding()
        for fields in ({'guid': 'wrong'}, {'tenantId': 'wrong'},
                       {'azureObjectId': 'wrong'}, {'phoneAppDetailId': 'wrong'}):
            with self.subTest(fields=fields):
                self.authentication(auth_response(dosPreventer='untrusted', **fields))
                self.assertEqual(self.registry.state['account']['DosPreventer'], '')
                self.assertFalse(self.coordinator.take_auth_results())
        response = auth_response(dosPreventer='one').replace('</phoneAppAuthenticationResponse>',
                   '<dosPreventer>two</dosPreventer></phoneAppAuthenticationResponse>')
        self.authentication(response)
        self.assertEqual(self.registry.state['account']['DosPreventer'], '')
        self.assertFalse(self.coordinator.take_auth_results())

    def test_network_failure_preserves_credentials_and_pending_binding(self):
        self.block_binding()
        before = self.registry.snapshot()
        self.coordinator.on_mfa_push(PUSH)
        with patch('app.entra_registration.post', side_effect=TimeoutError):
            self.coordinator._learn_responses()
        self.assertEqual(self.registry.snapshot(), before)
        self.assertFalse(self.coordinator.take_auth_results())

    def test_recovered_dos_preventer_is_used_on_daily_retry(self):
        self.registry.google_success('B')
        self.registry.binding_started('v1_sent')
        self.registry.binding_failure('timeout')
        self.registry.update_account({'DosPreventer': ''})
        self.authentication(auth_response(dosPreventer='replacement'))
        self.assertEqual(self.registry.state['phase'], 'uncertain')
        self.assertEqual(self.registry.state['account']['DosPreventer'], 'replacement')
        with patch('app.registration_runtime.entra.change_v1') as change:
            self.clock += 86399
            self.coordinator.tick()
            change.assert_not_called()
            self.clock += 1
            self.coordinator.tick()
        change.assert_called_once()
        self.assertEqual(change.call_args.args[0]['DosPreventer'], 'replacement')
        self.assertEqual(self.registry.active_token, 'B')

    def test_rejected_old_credential_cannot_clear_concurrent_replacement(self):
        self.registry.google_success('B')
        def reject_after_replacement(*_):
            self.authentication(auth_response(dosPreventer='replacement'))
            raise BindingError('invalid_dos_preventer')
        with patch('app.registration_runtime.entra.change_v1', side_effect=reject_after_replacement):
            self.coordinator.tick()
        self.assertEqual(self.registry.state['account']['DosPreventer'], 'replacement')
        self.assertEqual(self.registry.state['phase'], 'pending')
        self.assertEqual(self.registry.state['binding_due_at'], self.clock + 86400)

    def test_stale_response_cannot_reinstall_rejected_credential(self):
        self.registry.google_success('B')
        self.registry.binding_started('v1_sent')
        context = self.registry.verification_material()
        self.registry.invalidate_dos_preventer('dos')
        self.registry.binding_failure('invalid_dos_preventer', uncertain=False)
        with patch('app.entra_registration.post', return_value=auth_response(dosPreventer='dos')):
            self.coordinator._authentication(PUSH, context)
        self.assertEqual(self.registry.state['account']['DosPreventer'], '')
        self.assertFalse(self.coordinator.take_auth_results())

    def test_matched_validation_can_also_resume_blocked_binding(self):
        self.registry.update_account({'DosPreventer': ''})
        self.registry.google_success('B')
        self.coordinator.tick()
        self.coordinator.on_push({**PUSH, 'type': 'validate'})
        response = validation_response().replace('</phoneAppValidateDeviceTokenResponse>',
                    '<dosPreventer>replacement</dosPreventer></phoneAppValidateDeviceTokenResponse>')
        with patch('app.activation.answer_challenge', return_value={
                'action': 'validated', 'status': 200, 'text': response}) as answer:
            self.coordinator._learn_responses()
        self.assertTrue(answer.call_args.kwargs['need_dos_preventer'])
        self.assertFalse(answer.call_args.kwargs['validation_result'])
        self.assertEqual(self.registry.state['phase'], 'pending')
        self.assertEqual(self.registry.state['account']['DosPreventer'], 'replacement')
        self.assertEqual(self.registry.active_token, 'A')

    def test_archive_failure_prevents_replacement(self):
        self.registry.update_account({'DosPreventer': ''})
        context = self.registry.verification_material()
        with patch.object(self.registry, '_archive', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.registry.learn(context, {'DosPreventer': 'replacement'})
        self.assertEqual(self.registry.state['account']['DosPreventer'], '')
        self.assertEqual(json.loads(state_path('activation.json').read_text())['DosPreventer'], '')

    def test_staged_recovery_does_not_replace_active_enrollment(self):
        candidate = self.registry.begin_enrollment('A')
        self.registry.stage_activation(candidate, {**ACCOUNT, 'DosPreventer': ''})
        self.registry.confirm_staged(candidate)
        self.coordinator.verification_only = True
        post = self.authentication(auth_response(dosPreventer='staged-replacement'))
        self.assertEqual(ET.fromstring(post.call_args.args[1]).findtext('.//needDosPreventer'), 'yes')
        self.assertEqual(self.registry.state['staged']['account']['DosPreventer'], 'staged-replacement')
        self.assertEqual(self.registry.state['account']['DosPreventer'], 'dos')
        self.assertEqual(self.registry.state['staged']['status'], 'test_required')

    def test_recovery_waits_for_other_required_metadata(self):
        self.registry.update_account({'DosPreventer': '', 'ReplicationScope': '', 'ReplicationScopes': ''})
        self.registry.google_success('B')
        self.coordinator.tick()
        self.authentication(auth_response(dosPreventer='replacement', replicationScope=''))
        self.assertEqual(self.registry.state['account']['DosPreventer'], 'replacement')
        self.assertEqual(self.registry.state['phase'], 'metadata_required')
        self.assertEqual(self.registry.active_token, 'A')


if __name__ == '__main__':
    unittest.main()
