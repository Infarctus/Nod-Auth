"""Fault-injection tests for enrollment archives, staging and crash recovery."""
import contextlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app.registration import RegistrationState, main
from app.state import state_path, save_json
from test.entra_fixtures import ACCOUNT


class EnrollmentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        env = patch.dict(os.environ, AUTH_STATE_DIR=self.directory.name)
        env.start()
        self.addCleanup(env.stop)
        state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
        self.now = 100000
        self.registry = self.open()
        self.registry.google_success('A')
        self.registry.mark_activation('A', ACCOUNT)
        self.registry.commit_test(self.registry.verification_material(True))
        self.addCleanup(lambda: self.registry.close())
        self.new_account = {**ACCOUNT, 'AzureObjectId': 'new-object', 'OathTokenSecretKey': 'MZXW6YTBOI======'}

    def open(self):
        return RegistrationState(now=lambda: self.now, spread_hours=lambda: 0)

    def stage(self):
        candidate = self.registry.begin_enrollment('A')
        self.registry.stage_activation(candidate, self.new_account, '<response>new-secret</response>')
        self.registry.confirm_staged(candidate)
        return self.registry.verification_material(True)

    def reopen(self):
        self.registry.close()
        self.registry = self.open()

    def test_stage_keeps_original_until_successful_test(self):
        context = self.stage()
        self.assertEqual(json.loads(state_path('activation.json').read_text()), ACCOUNT)
        self.assertEqual(self.registry.state['account'], ACCOUNT)
        self.assertTrue(state_path('activation.pending.json').exists())
        history = json.loads(state_path('entra_history.json').read_text())
        self.assertTrue(any(row['state']['account'].get('OathTokenSecretKey') == ACCOUNT['OathTokenSecretKey'] for row in history))
        self.registry.commit_test(context)
        self.assertEqual(self.registry.state['account'], self.new_account)
        self.assertEqual(json.loads(state_path('activation.json').read_text()), self.new_account)
        self.assertFalse(state_path('activation.pending.json').exists())
        self.assertEqual(json.loads(state_path('setup_complete.json').read_text())['revision'], self.registry.state['revision'])

    def test_failed_test_then_restart_retains_both_enrollments(self):
        self.stage()
        self.reopen()
        self.assertEqual(self.registry.state['account'], ACCOUNT)
        self.assertEqual(self.registry.state['staged']['account'], self.new_account)
        self.assertEqual(self.registry.verification_material(True)['account'], self.new_account)

    def test_archive_failure_cannot_replace_enrollment_or_start_staging(self):
        with patch('app.registration.save_json', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.registry.begin_enrollment('A')
        self.assertIsNone(self.registry.state['staged'])
        self.assertEqual(self.registry.state['account'], ACCOUNT)

    def test_interrupted_export_is_repaired_from_committed_database(self):
        context = self.stage()
        with patch.object(self.registry, '_export', side_effect=OSError('power loss')):
            with self.assertRaises(OSError):
                self.registry.commit_test(context)
        self.assertEqual(json.loads(state_path('activation.json').read_text()), ACCOUNT)
        self.reopen()
        self.assertEqual(json.loads(state_path('activation.json').read_text()), self.new_account)
        self.assertFalse(state_path('activation.pending.json').exists())
        self.assertTrue(state_path('setup_complete.json').exists())

    def test_sql_commit_failure_keeps_original_and_staged_secret(self):
        context = self.stage()
        self.registry.db.execute("CREATE TRIGGER reject_lifecycle BEFORE INSERT ON lifecycle BEGIN SELECT RAISE(ABORT, 'disk simulation'); END")
        self.registry.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.registry.commit_test(context)
        self.assertEqual(self.registry.state['account'], ACCOUNT)
        self.assertEqual(self.registry.state['staged']['account'], self.new_account)
        self.assertEqual(json.loads(state_path('activation.json').read_text()), ACCOUNT)

    def test_restore_retains_current_google_identity_and_requires_test(self):
        context = self.stage()
        entries = json.loads(state_path('entra_history.json').read_text())
        entry = next(row for row in entries if row['reason'] == 'before_enrollment')
        self.registry.commit_test(context)
        self.registry.google_success('B')
        self.registry.restore(entry['id'])
        self.assertEqual(self.registry.state['account'], ACCOUNT)
        self.assertEqual(self.registry.state['google'], 'B')
        self.assertEqual(self.registry.state['legacy_token'], 'A')
        self.assertEqual(self.registry.active_token, '')
        self.assertFalse(state_path('setup_complete.json').exists())
        entries = json.loads(state_path('entra_history.json').read_text())
        self.assertEqual(entries[-1]['state']['account'], self.new_account)

    def test_old_approval_cannot_commit_replacement_stage(self):
        old_context = self.stage()
        self.registry.begin_enrollment('A')
        with self.assertRaisesRegex(ValueError, 'staged enrollment'):
            self.registry.commit_test(old_context)
        self.assertEqual(self.registry.state['account'], ACCOUNT)

    def test_incomplete_activation_retains_raw_response_and_original(self):
        candidate = self.registry.begin_enrollment('A')
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.registry.stage_activation(candidate, {'OathTokenSecretKey': 'recover-me'}, '<r>recover-me</r>')
        self.reopen()
        self.assertEqual(self.registry.state['staged']['response_xml'], '<r>recover-me</r>')
        self.assertEqual(self.registry.state['account'], ACCOUNT)

    def test_restart_after_v1_send_preserves_attempt_until_daily_gate(self):
        self.registry.google_success('B')
        attempt = self.registry.binding_started('v1_sent')
        self.reopen()
        self.assertEqual(self.registry.state['phase'], 'uncertain')
        self.assertEqual(self.registry.state['attempt']['id'], attempt['id'])
        self.assertEqual(self.registry.state['attempt']['old'], 'A')
        self.registry.google_success('C')
        self.assertEqual(self.registry.state['attempt']['target'], 'B')
        self.registry.learn(self.registry.verification_material(), {}, 'B')
        self.assertEqual(self.registry.state['bound'], 'B')
        self.assertEqual(self.registry.state['pending'], 'C')
        self.assertIsNone(self.registry.state['attempt'])

    def test_restart_after_v2_complete_is_uncertain(self):
        self.registry.google_success('B')
        self.registry.binding_started('v2_complete_sent')
        self.reopen()
        self.assertEqual(self.registry.state['phase'], 'uncertain')
        self.assertEqual(self.registry.active_token, 'A')

    def test_verified_observation_during_send_can_resolve_timeout(self):
        self.registry.google_success('B')
        self.registry.binding_started('v1_sent')
        self.registry.learn(self.registry.verification_material(), {}, 'B')
        self.assertEqual(self.registry.state['phase'], 'v1_sent')
        self.registry.binding_failure('timeout')
        self.assertEqual(self.registry.active_token, 'B')
        self.assertEqual(self.registry.state['phase'], 'bound')

    def test_old_unverified_schema_cannot_promote_legacy_token(self):
        self.registry.state.update(schema=1, binding_verified=False, phase='legacy_binding_unverified', active='wrong', bound='wrong')
        self.registry._save()
        self.reopen()
        self.assertEqual(self.registry.active_token, '')
        self.assertEqual(self.registry.state['bound'], '')
        self.assertEqual(self.registry.state['legacy_token'], 'wrong')
        self.assertFalse(state_path('setup_complete.json').exists())

    def test_status_and_history_do_not_print_secrets(self):
        self.stage()
        for command in ('status', 'history'):
            stream = io.StringIO()
            with patch('sys.argv', ['registration', command]), contextlib.redirect_stdout(stream):
                main()
            text = stream.getvalue()
            for secret in (ACCOUNT['OathTokenSecretKey'], self.new_account['OathTokenSecretKey'], 'new-secret'):
                self.assertNotIn(secret, text)

    def test_existing_files_and_archives_get_private_permissions(self):
        self.stage()
        state_path('activation.json').chmod(0o644)
        self.reopen()
        for name in ('activation.json', 'activation.pending.json', 'entra_history.json', 'registration.sqlite3'):
            self.assertEqual(state_path(name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(state_path('activation.json').parent.stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()


class StagedApprovalIntegrationTests(unittest.TestCase):
    setUp = EnrollmentRecoveryTests.setUp
    open = EnrollmentRecoveryTests.open
    stage = EnrollmentRecoveryTests.stage

    # Only share fixture helpers; the cases below exercise protocol -> bot -> commit.
    def test_staged_approval_requires_matched_fetch_and_valid_number_before_commit(self):
        from unittest.mock import Mock
        from app.service import Bridge
        from app.config import Config
        from app.bots.base import Reply
        from app.registration_runtime import RegistrationCoordinator
        from test.entra_fixtures import PUSH, auth_response
        self.stage()
        coordinator = RegistrationCoordinator(self.registry, verification_only=True)
        bot = Mock()
        bot.request.return_value = '10'
        bot.updates.return_value = []
        submit = Mock(return_value=(200, '<validationResult>6</validationResult>'))
        bridge = Bridge(bot, Config(), submit, coordinator)
        self.addCleanup(bridge.db.close)
        bridge.capture(PUSH)
        self.assertFalse(bridge.pending)
        with patch('app.registration_runtime.entra.post', return_value=auth_response('A', azureObjectId='new-object')):
            coordinator._learn_responses()
        bridge.poll()
        self.assertIn('10', bridge.pending)
        bridge.handle(Reply('10', '99'))
        submit.assert_not_called()
        self.assertEqual(self.registry.state['account'], ACCOUNT)
        bridge.handle(Reply('10', '12'))
        self.assertTrue(bridge.approved)
        self.assertEqual(self.registry.state['account']['AzureObjectId'], 'new-object')
        self.assertIsNone(self.registry.state['staged'])

    def test_foreign_account_authentication_never_commits_staging(self):
        from app.registration_runtime import RegistrationCoordinator
        from test.entra_fixtures import PUSH, auth_response
        self.stage()
        coordinator = RegistrationCoordinator(self.registry, verification_only=True)
        coordinator.on_mfa_push(PUSH)
        with patch('app.registration_runtime.entra.post', return_value=auth_response('A')):
            coordinator._learn_responses()
        self.assertFalse(coordinator.take_auth_results())
        self.assertEqual(self.registry.state['account'], ACCOUNT)
        self.assertEqual(self.registry.state['staged']['account'], self.new_account)
