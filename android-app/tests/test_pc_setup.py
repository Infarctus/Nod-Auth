"""PC setup shares Docker enrollment and exports state for phone verification."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app/src/main/python'))
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT.parent))

from create_setup import create_setup
from app.state_bundle import extract_bundle
from app.enrollment import prepare_registration
from app.fcm_lifecycle import FcmError
from app.registration import RegistrationState
from app.state import save_text
from test.entra_fixtures import ACCOUNT


class PcSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.archive = self.root / 'setup.zip'
        self.apk = self.root / 'not-needed-with-saved-config.apk'
        env = patch.dict(os.environ, AUTH_STATE_DIR=str(self.state))
        env.start()
        self.addCleanup(env.stop)
        self.device = {'androidId': 123, 'securityToken': 456}
        (self.state / 'checkin_info.json').write_text(json.dumps(self.device))
        (self.state / 'apk_config.json').write_text(json.dumps({
            'package': 'com.azure.authenticator', 'version_name': '6.2609.0',
            'firebase': {'app_id': 'app', 'project': 'project', 'api_key': 'key', 'sender_id': 'sender'}}))

    def register(self, device):
        self.assertEqual(device, self.device)
        save_text('fcm_token.txt', 'SYNTHETIC\n')
        return 'SYNTHETIC'

    def activate(self, link, code):
        self.assertEqual((link, code), ('https://example.invalid', 'sample-code'))
        registry = RegistrationState()
        try:
            self.assertEqual(registry.snapshot()['google'], 'SYNTHETIC')
            candidate = registry.begin_enrollment('SYNTHETIC')
            registry.stage_activation(candidate, ACCOUNT)
            registry.confirm_staged(candidate)
        finally:
            registry.close()

    def enroll(self):
        with patch('app.enrollment.prepare_registration', wraps=prepare_registration) as shared, \
             patch('app.fcm.do_register', side_effect=self.register), \
             patch('app.activation.activate', side_effect=self.activate), \
             patch('getpass.getpass', side_effect=['https://example.invalid', 'sample-code']):
            create_setup(self.apk, self.state, self.archive)
        shared.assert_called_once_with(self.apk.resolve())

    def test_fresh_setup_exports_staged_enrollment_for_phone_verification(self):
        self.enroll()
        imported = self.root / 'phone'
        self.assertFalse(extract_bundle(self.archive, imported))
        self.assertTrue((imported / 'activation.pending.json').exists())
        self.assertFalse((imported / 'setup_complete.json').exists())

    def test_resume_exports_without_registering_or_sending_another_activation(self):
        self.enroll()
        with patch('app.fcm.do_register') as register, \
             patch('app.activation.activate') as activate, \
             patch('getpass.getpass') as prompt:
            create_setup(self.apk, self.state, self.root / 'resumed.zip')
        register.assert_not_called()
        activate.assert_not_called()
        prompt.assert_not_called()

    def test_google_failure_preserves_identity_without_prompting_or_activation(self):
        original = (self.state / 'checkin_info.json').read_bytes()
        with patch('app.fcm.do_register', side_effect=FcmError('fis_bad_config', 403)), \
             patch('app.activation.activate') as activate, \
             patch('getpass.getpass') as prompt:
            with self.assertRaises(FcmError):
                create_setup(self.apk, self.state, self.archive)
        activate.assert_not_called()
        prompt.assert_not_called()
        self.assertFalse(self.archive.exists())
        self.assertEqual((self.state / 'checkin_info.json').read_bytes(), original)

    def test_existing_account_without_token_is_not_overwritten(self):
        (self.state / 'activation.json').write_text(json.dumps(ACCOUNT))
        with patch('app.fcm.do_register') as register, \
             patch('app.activation.activate') as activate:
            with self.assertRaisesRegex(ValueError, 'no confirmed local FCM token'):
                create_setup(self.apk, self.state, self.archive)
        register.assert_not_called()
        activate.assert_not_called()
        self.assertEqual(json.loads((self.state / 'activation.json').read_text()), ACCOUNT)
