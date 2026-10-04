"""Offline tests of QR parsing and isolated phone enrollment; no real activation."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app/src/main/python'))
sys.path.insert(0, str(ROOT.parent))
from enrollment_qr import parse_qr
from mobile_runtime import MobileRuntime
from app.state_bundle import BundleError, extract_bundle
from app.registration import RegistrationState
from app.state import save_json, save_text
from test.entra_fixtures import ACCOUNT

LINK = 'https://mobileappcommunicator.auth.microsoft.com/activatev2/123456789/SAMPLE'
CODE = '012345678'
def qr(link=LINK, code=CODE, account_type='mfa'):
    return 'https://login.microsoftonline.com/authenticatorApp/activateAccount?' + urlencode(
        {'accountType': account_type, 'source': 'qrCode', 'code': code, 'url': link})
CONFIG = {'package': 'com.azure.authenticator', 'version_name': '6.2609.0',
          'firebase': {'api_key': 'key', 'app_id': 'app', 'sender_id': 'sender', 'project': 'project'}}


class QrTests(unittest.TestCase):
    def test_supported_qr_keeps_leading_zero_in_code(self):
        self.assertEqual(parse_qr(qr()), (LINK, CODE))

    def test_untrusted_or_unsupported_payloads_are_rejected(self):
        for raw in (qr(link='https://evil.test/activatev2/123/END'),
                    qr(link=LINK.replace('https:', 'http:')),
                    qr(link=LINK + '?redirect=bad'), qr(code='not-a-code'), qr(account_type='msa'),
                    qr() + '&code=999999999', qr().replace('login.microsoftonline.com', 'login.microsoftonline.com.evil.test'),
                    'otpauth://totp/account?secret=SYNTHETIC', qr() + '\n', 'https://example.test',
                    qr(link='https://user@mobileappcommunicator.auth.microsoft.com/activatev2/123/END')):
            with self.subTest(raw=raw), self.assertRaises(BundleError):
                parse_qr(raw)


class PhoneSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        self.root = Path(self.temp.name)
        self.runtime = MobileRuntime(self.root)
        (self.root / 'source-apk-config.json').write_text(json.dumps(CONFIG))

    def checkin(self):
        device = {'androidId': 123, 'securityToken': 456}
        save_json('checkin_info.json', device)
        return device

    def register(self, _):
        save_text('fcm_token.txt', 'SYNTHETIC\n')
        return 'SYNTHETIC'

    def activate(self, link, code, soap_transport):
        self.assertEqual((link, code), (LINK, CODE))
        self.assertEqual(soap_transport, self.runtime._android_soap)
        self.assertEqual(Path(os.environ['AUTH_STATE_DIR']), self.root / 'setup-draft')
        registry = RegistrationState()
        try:
            self.assertEqual(registry.snapshot()['google'], 'SYNTHETIC')
            candidate = registry.begin_enrollment('SYNTHETIC')
            registry.stage_activation(candidate, ACCOUNT)
            registry.confirm_staged(candidate)
        finally:
            registry.close()

    def enroll(self):
        with patch('app.fcm.do_checkin', side_effect=self.checkin), \
             patch('app.fcm.do_register', side_effect=self.register), \
             patch('app.activation.activate', side_effect=self.activate):
            return self.runtime.enroll(qr())

    def test_phone_enrollment_is_staged_for_explicit_sign_in_and_backup_round_trip(self):
        self.assertTrue(self.enroll())
        self.assertEqual(Path(os.environ['AUTH_STATE_DIR']), self.runtime.state_dir)
        self.assertFalse((self.runtime.state_dir / 'setup_complete.json').exists())
        self.assertTrue(json.loads(self.runtime.snapshot())['has_setup'])
        archive = self.root / 'backup.zip'
        self.runtime.export_setup(archive)
        self.assertFalse(extract_bundle(archive, self.root / 'restored'))

    def test_failed_activation_keeps_existing_enrollment_and_recovery(self):
        active = self.runtime.state_dir
        active.mkdir()
        (active / 'original').write_text('SYNTHETIC OLD STATE')
        with patch('app.fcm.do_checkin', side_effect=self.checkin), \
             patch('app.fcm.do_register', side_effect=self.register), \
             patch('app.activation.activate', side_effect=RuntimeError('SENSITIVE URL AND CODE')):
            self.assertFalse(self.runtime.enroll(qr()))
        self.assertEqual((active / 'original').read_text(), 'SYNTHETIC OLD STATE')
        self.assertTrue((self.root / 'setup-draft/checkin_info.json').exists())
        self.assertEqual(Path(os.environ['AUTH_STATE_DIR']), active)
        self.assertNotIn('SENSITIVE', self.runtime.snapshot())

    def test_invalid_qr_makes_no_network_request_and_does_not_create_draft(self):
        with patch('app.fcm.do_checkin') as request:
            with self.assertRaises(BundleError): self.runtime.enroll('not-a-QR')
        request.assert_not_called()
        self.assertFalse((self.root / 'setup-draft').exists())

    def test_listener_and_operations_cannot_race(self):
        self.runtime.worker = Mock()
        self.runtime.worker.is_alive.return_value = True
        with patch('app.fcm.do_checkin') as request, self.assertRaises(BundleError):
            self.runtime.enroll(qr())
        request.assert_not_called()
        self.runtime.worker = None
        with self.runtime._operation(), patch('threading.Thread') as thread:
            self.runtime.start()
            thread.assert_not_called()

    def test_ready_draft_can_resume_after_commit_failure_without_another_activation(self):
        from app.state import sync_directory
        def fail_commit(path):
            if Path(path) == self.root:
                raise OSError('disk full')
            return sync_directory(path)
        with patch('app.fcm.do_checkin', side_effect=self.checkin), \
             patch('app.fcm.do_register', side_effect=self.register), \
             patch('app.activation.activate', side_effect=self.activate), \
             patch('app.state.sync_directory', side_effect=fail_commit):
            self.assertFalse(self.runtime.enroll(qr()))
        self.assertTrue(json.loads(self.runtime.snapshot())['draft_ready'])
        with patch('app.activation.activate') as activate:
            self.runtime.resume_setup()
        activate.assert_not_called()
        self.assertTrue((self.runtime.state_dir / 'activation.pending.json').exists())
