"""Crash and generation behaviour for the durable registration state."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from app.registration import RegistrationState
from test.entra_fixtures import ACCOUNT


class StateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        env = patch.dict(os.environ, AUTH_STATE_DIR=self.directory.name)
        env.start()
        self.addCleanup(env.stop)
        self.now = 1000

    def open_state(self):
        return RegistrationState(now=lambda: self.now, spread_hours=lambda: 0)

    def test_import_rotation_and_restart(self):
        with open(os.path.join(self.directory.name, "fcm_token.txt"), "w") as stream:
            stream.write("A\n")
        with open(os.path.join(self.directory.name, "activation.json"), "w") as stream:
            json.dump(ACCOUNT, stream)
        first = self.open_state()
        self.assertEqual(first.state["phase"], "legacy_binding_unverified")
        self.assertTrue(first.google_success("B"))
        self.assertEqual(first.active_token, "")
        self.assertEqual(first.state["bound"], "")
        self.assertEqual(first.state["pending"], "B")
        first.close()

        second = self.open_state()
        self.assertEqual(second.state["pending"], "B")
        second.learn(second.verification_material(testing=True), {}, 'A')
        second.binding_started('v1_sent')
        self.assertTrue(second.google_success('C'))
        second.binding_success('B')
        self.assertEqual(second.state['bound'], 'B')
        self.assertEqual(second.state['pending'], 'C')
        second.binding_started('v1_sent')
        second.binding_success('C')
        self.assertEqual(second.active_token, "C")
        second.close()
        with open(os.path.join(self.directory.name, "fcm_token.txt")) as stream:
            self.assertEqual(stream.read(), "C\n")

    def test_failure_preserves_binding_and_retries_unchanged_token(self):
        state = self.open_state()
        state.google_success("A")
        state.mark_activation("A", {"ActivateNewResult": True})
        state.google_success("B")
        state.binding_failure("timeout")
        self.assertEqual(state.active_token, "A")
        self.assertEqual(state.state["phase"], "retry")
        self.now += 500
        self.assertFalse(state.google_success("B"))
        self.assertTrue(state.state["binding_failed"])
        self.assertEqual(state.state["pending"], "B")
        self.assertNotIn("A", str(state.status()))
        state.close()

    def test_google_return_to_bound_token_cancels_pending_rebind(self):
        state = self.open_state()
        state.google_success("A")
        state.mark_activation("A", {"ActivateNewResult": True})
        state.google_success("B")
        self.assertTrue(state.state["pending"])
        state.google_success("A")
        self.assertEqual(state.state["pending"], "")
        self.assertEqual(state.active_token, "A")
        self.assertEqual(state.state["phase"], "bound")
        state.close()

    def test_ambiguous_v2_completion_waits_one_day_then_preserves_history(self):
        state = self.open_state()
        state.google_success("A")
        state.mark_activation("A", {"ActivateNewResult": True, "BindingProtocol": "V2"})
        state.google_success("B")
        first = state.binding_started("v2_complete_sent")
        state.binding_failure("TimeoutError")
        self.assertEqual(state.state["phase"], "uncertain")
        self.assertEqual(state.state["binding_due_at"], self.now + 86400)
        self.now += 86399
        self.assertFalse(state.retry_uncertain())
        self.now += 1
        self.assertTrue(state.retry_uncertain())
        self.assertEqual(state.state["phase"], "retry")
        self.assertEqual(state.active_token, "A")
        self.assertEqual(state.state['attempt_history'][0]['id'], first['id'])
        self.assertEqual(state.state['attempt_history'][0]['outcome'],
                         'retry_after_ambiguous_response')
        state.close()

    def test_later_google_rotation_retries_current_token_after_daily_gate(self):
        state = self.open_state()
        state.google_success("A")
        state.mark_activation("A", {"ActivateNewResult": True, "BindingProtocol": "V2"})
        state.google_success("B")
        state.binding_started("v2_complete_sent")
        state.binding_failure("TimeoutError")
        state.google_success("C")
        self.assertEqual(state.state["phase"], "uncertain")
        self.assertEqual(state.state["pending"], "C")
        self.assertEqual(state.state["bound"], "A")
        self.assertFalse(state.force_rebind("server-B"))
        self.now += 86400
        self.assertTrue(state.retry_uncertain())
        self.assertEqual(state.state['attempt_history'][0]['target'], 'B')
        self.assertEqual(state.state['pending'], 'C')
        self.assertEqual(state.active_token, 'A')
        retry = state.binding_started('v2_start')
        self.assertEqual(retry['target'], 'C')
        state.close()

    def test_restart_after_sent_request_retries_only_after_daily_gate(self):
        state = self.open_state()
        state.google_success('A')
        state.mark_activation('A', {"ActivateNewResult": True})
        state.google_success('B')
        first = state.binding_started('v1_sent')
        state.close()

        state = self.open_state()
        self.assertEqual(state.state['phase'], 'uncertain')
        self.assertEqual(state.state['binding_due_at'], self.now + 86400)
        self.assertFalse(state.retry_uncertain())
        self.now += 86400
        self.assertTrue(state.retry_uncertain())
        self.assertEqual(state.state['attempt_history'][0]['id'], first['id'])
        self.assertEqual(state.active_token, 'A')
        state.close()

    def test_restart_upgrades_permanently_paused_attempt_to_daily_retry(self):
        state = self.open_state()
        state.google_success('A')
        state.mark_activation('A', {"ActivateNewResult": True})
        state.google_success('B')
        state.binding_started('v1_sent')
        state.binding_failure('TimeoutError')
        state.state['binding_due_at'] = 2**63 - 1  # Previous bridge format.
        state._save()
        state.close()

        state = self.open_state()
        self.assertEqual(state.state['phase'], 'uncertain')
        self.assertEqual(state.state['binding_due_at'], self.now + 86400)
        self.assertFalse(state.retry_uncertain())
        self.now += 86400
        self.assertTrue(state.retry_uncertain())
        self.assertEqual(state.active_token, 'A')
        state.close()

    def test_server_mismatch_schedules_forced_rebind(self):
        state = self.open_state()
        state.google_success("A")
        state.mark_activation("A", {"ActivateNewResult": True})
        self.assertTrue(state.force_rebind("server-old"))
        self.assertEqual(state.state["bound"], "server-old")
        self.assertEqual(state.state["pending"], "A")
        self.assertEqual(state.active_token, "server-old")
        self.assertFalse(state.force_rebind("A"))
        state.close()

    def test_status_command_redacts_credentials(self):
        import contextlib
        import io
        from app.registration import main
        state = self.open_state()
        state.google_success("sensitive-token")
        state.update_account({"DosPreventer": "sensitive-dos"})
        state.close()
        output = io.StringIO()
        with patch("sys.argv", ["registration", "status"]), contextlib.redirect_stdout(output):
            main()
        self.assertNotIn("sensitive-token", output.getvalue())
        self.assertNotIn("sensitive-dos", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["phase"], "initial")

    def test_coordinator_restore_precedes_bridge_startup(self):
        from app.registration_runtime import RegistrationCoordinator
        from app.service import Bridge
        from app.config import Config
        state = self.open_state()
        state.google_success("A")
        state.close()
        os.unlink(os.path.join(self.directory.name, "fcm_token.txt"))
        coordinator = RegistrationCoordinator()
        bridge = Bridge(None, Config(enabled=False), registration=coordinator)
        self.assertEqual(bridge.token, "A")
        bridge.db.close()
        coordinator.stop()

    def test_restores_active_file_after_interrupted_commit(self):
        state = self.open_state()
        state.google_success("A")
        state.mark_activation("A", {"ActivateNewResult": True})
        state.google_success("B")
        state.binding_success("B")
        state.close()
        with open(os.path.join(self.directory.name, "fcm_token.txt"), "w") as stream:
            stream.write("A\n")
        again = self.open_state()
        self.assertEqual(again.active_token, "B")
        again.close()
        with open(os.path.join(self.directory.name, "fcm_token.txt")) as stream:
            self.assertEqual(stream.read(), "B\n")


if __name__ == "__main__":
    unittest.main()


class AuthenticationObservationTests(unittest.TestCase):
    setUp = StateTests.setUp
    open_state = StateTests.open_state
    def test_late_response_cannot_revert_completed_binding(self):
        state = self.open_state()
        self.addCleanup(state.close)
        state.google_success('A')
        state.mark_activation('A', ACCOUNT)
        state.google_success('B')
        context = state.verification_material()
        state.binding_started('v1_sent')
        state.binding_success('B')
        self.assertFalse(state.learn(context, {'GroupKey': 'stale'}, 'A'))
        self.assertEqual(state.active_token, 'B')
        self.assertEqual(state.state['account'], ACCOUNT)
        with self.assertRaisesRegex(ValueError, 'previous token binding'):
            state.commit_test(context)

    def test_same_bound_token_does_not_postpone_pending_change(self):
        state = self.open_state()
        self.addCleanup(state.close)
        state.google_success('A')
        state.mark_activation('A', ACCOUNT)
        state.google_success('B')
        state.binding_failure('metadata_required')
        before = state.snapshot()
        self.now += 600
        self.assertTrue(state.learn(state.verification_material(), {}, 'A'))
        after = state.snapshot()
        for key in ('binding_due_at', 'phase', 'last_error', 'token_history'):
            self.assertEqual(after[key], before[key], key)
