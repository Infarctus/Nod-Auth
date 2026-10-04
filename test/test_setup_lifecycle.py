"""Setup keeps initial Google registration and Entra activation in sync."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from app import setup
from app.config import Config
from app.registration import RegistrationState
from test.entra_fixtures import ACCOUNT
from app.state import state_path


class SetupLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        env = patch.dict(os.environ, AUTH_STATE_DIR=self.directory.name)
        env.start()
        self.addCleanup(env.stop)
        state_path("apk_config.json").write_text("{}")

    def test_new_registration_is_recorded_before_activation(self):
        def register(_):
            state_path("fcm_token.txt").write_text("new-token\n")
            return "new-token"

        def activate(*_, device_name):
            self.assertEqual(device_name, 'Pixel 8')
            state = RegistrationState()
            self.assertEqual(state.active_token, "new-token")
            candidate = state.begin_enrollment("new-token")
            state.stage_activation(candidate, ACCOUNT)
            state.confirm_staged(candidate)
            state.close()

        with patch.object(setup, "load_config", return_value=Config(enabled=False)), \
             patch.object(setup, "setup_bot"), \
             patch("app.fcm.do_checkin", return_value={"androidId": 1, "securityToken": 2}), \
             patch("app.fcm.do_register", side_effect=register), \
             patch("app.activation.activate", side_effect=activate), \
             patch("builtins.input", return_value="https://example"), \
             patch("getpass.getpass", return_value="code"):
            setup.main()
        state = RegistrationState()
        self.assertEqual(state.state["bound"], "")
        self.assertEqual(state.state["staged"]["token"], "new-token")
        self.assertFalse(state_path("setup_complete.json").exists())
        state.close()

    def test_existing_activation_without_token_is_not_replaced(self):
        state_path("activation.json").write_text(json.dumps({"ActivateNewResult": True}))
        with patch.object(setup, "load_config", return_value=Config(enabled=False)), \
             patch("app.fcm.do_checkin", return_value={"androidId": 1, "securityToken": 2}), \
             patch("app.fcm.do_register") as register:
            with self.assertRaisesRegex(ValueError, "no confirmed local FCM token"):
                setup.main()
        register.assert_not_called()


if __name__ == "__main__":
    unittest.main()
