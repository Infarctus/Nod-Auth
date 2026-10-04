"""Offline lifecycle and original-app validation dispatch regression tests."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from app.registration import RegistrationState
from app.registration_runtime import RegistrationCoordinator
from app.entra_registration import BindingError
from app.state import state_path, save_json
from test.entra_fixtures import ACCOUNT, PUSH, auth_response, validation_response


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        env = patch.dict(os.environ, AUTH_STATE_DIR=self.directory.name)
        env.start()
        self.addCleanup(env.stop)
        state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
        self.clock = 100000
        self.registry = RegistrationState(now=lambda: self.clock, spread_hours=lambda: 0)
        self.registry.google_success('A', 42)
        self.registry.mark_activation('A', ACCOUNT)
        save_json('checkin_info.json', {'androidId': 1, 'securityToken': 2})
        self.coordinator = RegistrationCoordinator(self.registry, now=lambda: self.clock)
        self.coordinator.set_transport_ready(True)
        self.addCleanup(self.coordinator.stop)

    def test_startup_checks_seven_day_cache_and_app_version(self):
        self.clock += 7 * 86400
        with patch('app.registration_runtime.fcm_lifecycle.load_apk_config', return_value={'version_code': 42}), \
             patch.object(self.coordinator.thread, 'start'), patch.object(self.coordinator.auth_thread, 'start'):
            self.coordinator.start()
        self.assertEqual(self.registry.state['google_due_at'], self.clock)

    def test_google_change_then_confirmed_v1_binding(self):
        self.registry.state['google_due_at'] = 0
        with patch('app.registration_runtime.fcm_lifecycle.load_apk_config', return_value={'version_code': 42}), \
             patch('app.registration_runtime.fcm_lifecycle.acquire', return_value='B'), \
             patch('app.registration_runtime.entra.change_v1') as change:
            self.coordinator.tick()
        self.assertEqual(change.call_args.args[1:], ('A', 'B'))
        self.assertEqual(self.registry.active_token, 'B')

    def test_does_not_bind_until_listener_is_ready(self):
        self.registry.google_success('B')
        self.coordinator.set_transport_ready(False)
        with patch('app.registration_runtime.entra.change_v1') as change:
            self.coordinator.tick()
        change.assert_not_called()
        self.assertEqual(self.registry.state['pending'], 'B')

    def test_lost_v1_response_retries_once_per_day_and_preserves_old_token(self):
        self.registry.google_success('B')
        with patch('app.registration_runtime.entra.change_v1', side_effect=[TimeoutError(), None]) as change:
            self.coordinator.tick()
            self.assertEqual(self.registry.state['phase'], 'uncertain')
            self.assertEqual(self.registry.active_token, 'A')
            self.clock += 86399
            self.coordinator.tick()
            change.assert_called_once()
            self.clock += 1
            self.coordinator.tick()
        self.assertEqual(change.call_count, 2)
        self.assertEqual(self.registry.active_token, 'B')
        self.assertEqual(self.registry.state['phase'], 'bound')
        self.assertEqual(self.registry.state['attempt_history'][0]['outcome'],
                         'retry_after_ambiguous_response')

    def test_rejected_retry_keeps_last_confirmed_binding(self):
        self.registry.google_success('B')
        responses = [TimeoutError(), BindingError('device_token_change_101'), None]
        with patch('app.registration_runtime.entra.change_v1', side_effect=responses) as change:
            self.coordinator.tick()
            self.clock += 86400
            self.coordinator.tick()
            self.assertEqual(self.registry.active_token, 'A')
            self.assertEqual(self.registry.state['phase'], 'retry')
            self.clock += 86399
            self.coordinator.tick()
            self.assertEqual(change.call_count, 2)
            self.clock += 1
            self.coordinator.tick()
        self.assertEqual(change.call_count, 3)
        self.assertEqual(self.registry.active_token, 'B')

    def test_account_matched_observation_recovers_before_retry(self):
        self.registry.google_success('B')
        with patch('app.registration_runtime.entra.change_v1', side_effect=TimeoutError):
            self.coordinator.tick()
        self.coordinator.on_mfa_push(PUSH)
        with patch('app.registration_runtime.entra.post', return_value=auth_response('B')):
            self.coordinator._learn_responses()
        self.assertEqual(self.registry.active_token, 'B')
        self.assertEqual(self.registry.state['phase'], 'bound')
        self.assertEqual(self.coordinator.take_auth_results()[0][1]['token'], 'B')

    def test_old_auth_response_does_not_claim_rollback(self):
        self.registry.google_success('B')
        self.registry.binding_started('v1_sent')
        self.registry.binding_failure('timeout')
        self.coordinator.on_mfa_push(PUSH)
        with patch('app.registration_runtime.entra.post', return_value=auth_response('A')):
            self.coordinator._learn_responses()
        self.assertEqual(self.registry.state['phase'], 'uncertain')
        self.assertEqual(self.registry.state['attempt']['target'], 'B')

    def test_metadata_required_preserves_account(self):
        self.registry.update_account({'DosPreventer': ''})
        self.registry.google_success('B')
        self.coordinator.tick()
        self.assertEqual(self.registry.active_token, 'A')
        self.assertEqual(self.registry.state['phase'], 'metadata_required')

    def test_invalid_dos_waits_for_a_real_challenge_and_retains_other_secrets(self):
        self.registry.google_success('B')
        with patch('app.registration_runtime.entra.change_v1', side_effect=BindingError('invalid_dos_preventer')):
            self.coordinator.tick()
        self.assertEqual(self.registry.state['account']['DosPreventer'], '')
        self.assertEqual(self.registry.state['account']['OathTokenSecretKey'], ACCOUNT['OathTokenSecretKey'])
        self.clock += 86400
        with patch('app.registration_runtime.entra.post') as post:
            self.coordinator.tick()
        post.assert_not_called()
        self.assertEqual(self.registry.state['phase'], 'metadata_required')

    def test_incomplete_fis_keeps_original_file_and_archive(self):
        from app.fcm_lifecycle import FcmError
        save_json('firebase_installation.json', {'fid': 'old'})
        self.registry.state['google_due_at'] = 0
        with patch('app.registration_runtime.fcm_lifecycle.load_apk_config', return_value={'version_code': 42}), \
             patch('app.registration_runtime.fcm_lifecycle.acquire', side_effect=FcmError('fis_bad_state')):
            self.coordinator.tick()
        self.assertEqual(json.loads(state_path('firebase_installation.json').read_text()), {'fid': 'old'})
        self.assertTrue(state_path('credential_history.json').exists())
        self.assertEqual(self.registry.active_token, 'A')

    def test_explicit_mcs_rejection_rechecks_existing_identity(self):
        self.coordinator.request_recheckin()
        with patch('app.fcm.do_checkin') as checkin, \
             patch('app.registration_runtime.fcm_lifecycle.load_apk_config', return_value={'version_code': 42}), \
             patch('app.registration_runtime.fcm_lifecycle.acquire', return_value='A'):
            self.coordinator.tick()
        checkin.assert_called_once_with(force=True)
        self.coordinator.request_recheckin()
        self.assertFalse(self.coordinator.recheckin_requested)

    def test_push_alone_cannot_overwrite_endpoint_or_secrets(self):
        self.coordinator.on_mfa_push({**PUSH, 'url': 'different.microsoft.com', 'replicationScope': 'wrong'})
        self.assertEqual(self.registry.state['account']['PadUrl'], ACCOUNT['PadUrl'])
        with patch('app.registration_runtime.entra.post', return_value=auth_response('B', azureObjectId='other')):
            self.coordinator._learn_responses()
        self.assertEqual(self.registry.state['account'], ACCOUNT)
        self.assertFalse(self.coordinator.take_auth_results())

    def test_matching_fetch_can_update_metadata_and_bindings(self):
        self.coordinator.on_mfa_push(PUSH)
        with patch('app.registration_runtime.entra.post', return_value=auth_response('server-old', replicationScope='new-scope')):
            self.coordinator._learn_responses()
        self.assertEqual(self.registry.state['bound'], 'server-old')
        self.assertEqual(self.registry.state['pending'], 'A')
        self.assertEqual(self.registry.state['account']['ReplicationScopes'], 'new-scope')
        self.assertTrue(any(row['token'] == 'A' for row in self.registry.state['token_history']))

    def test_foreign_and_malformed_responses_never_change_state(self):
        for response in (auth_response('B', tenantId='other'), auth_response('B', phoneAppDetailId='other'),
                         auth_response('B', guid='other'), '<r><dosPreventer>bad</dosPreventer></r>',
                         auth_response('B').replace('</phoneAppAuthenticationResponse>', '<tenantId>tenant</tenantId></phoneAppAuthenticationResponse>')):
            self.coordinator.on_mfa_push(PUSH)
            with patch('app.registration_runtime.entra.post', return_value=response):
                self.coordinator._learn_responses()
            self.assertEqual(self.registry.active_token, 'A')
            self.assertEqual(self.registry.state['account'], ACCOUNT)
            self.assertFalse(self.coordinator.take_auth_results())

    def test_v1_validation_uses_current_google_token_without_local_change(self):
        self.registry.google_success('B')
        data = {**PUSH, 'type': 'validate', 'guid': 'validation', 'oathCounter': '123'}
        self.coordinator.on_push(data)
        self.coordinator.on_push(data)
        with patch('app.activation.answer_challenge', return_value={'action': 'validated', 'status': 200,
                   'text': validation_response()}) as answer:
            self.coordinator._learn_responses()
        answer.assert_called_once()
        self.assertEqual(answer.call_args.args[1], 'B')
        self.assertEqual(answer.call_args.kwargs['account'], ACCOUNT)
        self.assertFalse(answer.call_args.kwargs['validation_result'])
        self.assertEqual(self.registry.active_token, 'A')
        self.assertFalse(self.coordinator.take_auth_results())

    def test_validation_is_affirmative_only_while_change_is_in_progress(self):
        self.registry.google_success('B')
        data = {**PUSH, 'type': 'validate', 'guid': 'v1-active', 'oathCounter': '123'}
        def change(*_):
            self.coordinator.on_push(data)
            self.coordinator._learn_responses()
        with patch('app.registration_runtime.entra.change_v1', side_effect=change), \
             patch('app.activation.answer_challenge', return_value={'action': 'validated', 'status': 200,
                   'text': validation_response()}) as answer:
            self.coordinator._binding()
        self.assertTrue(answer.call_args.kwargs['validation_result'])
        self.assertEqual(self.registry.active_token, 'B')

    def test_validation_cannot_update_different_account(self):
        data = {**PUSH, 'type': 'validate', 'guid': 'validation', 'oathCounter': '123'}
        self.registry.google_success('B')
        self.coordinator.on_push(data)
        with patch('app.activation.answer_challenge', return_value={'action': 'validated', 'status': 200,
                   'text': validation_response().replace('object', 'other')}):
            self.coordinator._learn_responses()
        self.assertEqual(self.registry.active_token, 'A')

    def test_v2_accepts_early_push_and_matches_all_combination_fields(self):
        self.registry.update_account({'BindingProtocol': 'V2', 'RoutingHint': 'hint', 'CountryCode': 'FR'})
        self.registry.google_success('B')
        data = {**PUSH, 'type': 'validate', 'deviceTokenChangeVersion': 'V2', 'oathCounter': '123',
                'routingHint': 'hint', 'countryCode': 'FR'}
        def post(url, xml, token, action, account=None):
            if action == 'phoneAppStartDeviceTokenChangeV2Request':
                for key in ('tenantId', 'replicationScope', 'routingHint', 'countryCode'):
                    self.coordinator.on_push({**data, key: 'wrong'})
                self.assertTrue(self.coordinator.challenges.empty())
                self.coordinator.on_push({**data, 'guid': ''})
                self.assertTrue(self.coordinator.challenges.empty())
                self.coordinator.on_push(data)
                return '<r><deviceTokenChangeResult>1</deviceTokenChangeResult></r>'
            return validation_response()
        with patch('app.registration_runtime.entra.post', side_effect=post) as network:
            self.coordinator._binding()
        self.assertEqual(network.call_count, 2)
        self.assertEqual(self.registry.active_token, 'B')
        self.coordinator.on_push(data)
        self.assertTrue(self.coordinator.challenges.empty())

    def test_lost_v2_complete_response_restarts_after_daily_gate(self):
        self.registry.update_account({'BindingProtocol': 'V2'})
        self.registry.google_success('B')
        data = {**PUSH, 'type': 'validate', 'deviceTokenChangeVersion': 'V2',
                'oathCounter': '123'}
        completes = 0

        def post(url, xml, token, action, account=None):
            nonlocal completes
            if action == 'phoneAppStartDeviceTokenChangeV2Request':
                self.coordinator.on_push(data)
                return '<r><deviceTokenChangeResult>1</deviceTokenChangeResult></r>'
            completes += 1
            if completes == 1:
                raise TimeoutError()
            return validation_response()

        with patch('app.registration_runtime.entra.post', side_effect=post) as network:
            self.coordinator.tick()
            self.assertEqual(self.registry.state['phase'], 'uncertain')
            self.assertEqual(self.registry.active_token, 'A')
            self.clock += 86399
            self.coordinator.tick()
            self.assertEqual(network.call_count, 2)
            self.clock += 1
            self.coordinator.tick()
        self.assertEqual(network.call_count, 4)
        self.assertEqual(self.registry.active_token, 'B')
        self.assertEqual(self.registry.state['phase'], 'bound')

    def test_v2_without_attempt_is_ignored(self):
        self.coordinator.on_push({**PUSH, 'type': 'validate', 'deviceTokenChangeVersion': 'V2', 'oathCounter': '1'})
        self.assertTrue(self.coordinator.challenges.empty())
        self.assertTrue(self.coordinator.events.empty())

    def test_new_account_revision_rejects_queued_metadata(self):
        context = self.registry.verification_material()
        self.registry.state['revision'] = 'new-revision'
        with patch('app.registration_runtime.entra.post') as network:
            self.coordinator._authentication(PUSH, context)
        network.assert_not_called()


    def test_failed_validation_can_be_redelivered_and_then_deduplicated(self):
        data = {**PUSH, 'type': 'validate', 'guid': 'retry-validation', 'oathCounter': '123'}
        self.coordinator.on_push(data)
        with patch('app.activation.answer_challenge', return_value={'action': 'error'}):
            self.coordinator._learn_responses()
        self.coordinator.on_push(data)
        self.coordinator.on_push(data)
        with patch('app.activation.answer_challenge', return_value={'action': 'validated', 'status': 200,
                   'text': validation_response()}) as answer:
            self.coordinator._learn_responses()
        answer.assert_called_once()

    def test_same_validation_may_change_from_no_to_yes_for_new_attempt(self):
        self.registry.google_success('B')
        data = {**PUSH, 'type': 'validate', 'guid': 'same-guid', 'oathCounter': '123'}
        self.coordinator.on_push(data)
        with patch('app.activation.answer_challenge', return_value={'action': 'validated', 'status': 200,
                   'text': validation_response()}) as answer:
            self.coordinator._learn_responses()
            self.registry.binding_started('v1_sent')
            self.coordinator.binding_in_progress = True
            self.coordinator.on_push(data)
            self.coordinator._learn_responses()
        self.assertEqual([call.kwargs['validation_result'] for call in answer.call_args_list],
                         [False, True])

    def test_v2_start_503_retries_after_daily_gate_without_losing_tokens(self):
        self.registry.update_account({'BindingProtocol': 'V2'})
        self.registry.google_success('B')
        with patch('app.registration_runtime.entra.post', side_effect=BindingError('server_retryable', uncertain=True)) as post:
            self.coordinator.tick()
            self.assertEqual(post.call_count, 1)
            self.assertEqual(self.registry.state['phase'], 'retry')
            self.assertEqual(self.registry.state['bound'], 'A')
            self.assertEqual(self.registry.state['pending'], 'B')
            self.clock += 86399
            self.coordinator.tick()
            self.assertEqual(post.call_count, 1)
            self.clock += 1
            self.coordinator.tick()
            self.assertEqual(post.call_count, 2)


if __name__ == '__main__':
    unittest.main()
