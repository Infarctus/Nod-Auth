"""Offline checks for consent, replay prevention and setup import boundaries."""
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app/src/main/python'))
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT.parent))
from mobile_runtime import MobileRuntime, PendingRequest, choices_for
from app.state_bundle import BundleError, extract_bundle, FILES
from export_setup import export_setup
from test.entra_fixtures import ACCOUNT, PUSH


class ConsentTests(unittest.TestCase):
    def test_stale_expired_and_consumed_requests_cannot_approve(self):
        pending = PendingRequest(PUSH, {})
        self.assertFalse(pending.consume('old-screen', '12', False))
        self.assertFalse(pending.consume(pending.id, '12', False, pending.deadline))
        self.assertTrue(pending.consume(pending.id, '12', False, pending.deadline - 1))
        self.assertFalse(pending.consume(pending.id, 'DENY', False, pending.deadline - 1))

    def test_app_lock_requires_real_native_unlock_but_deny_remains_available(self):
        pending = PendingRequest({**PUSH, 'isAppLockRequired': 'true'}, {})
        self.assertFalse(pending.consume(pending.id, '12', False))
        self.assertTrue(pending.consume(pending.id, '12', True))
        deny = PendingRequest({**PUSH, 'isAppLockRequired': 'true'}, {})
        self.assertTrue(deny.consume(deny.id, 'DENY', False))

    def test_invalid_choices_are_not_approved(self):
        self.assertEqual(choices_for({**PUSH, 'secondEntropyChallenge': '12'}), [])
        self.assertEqual(choices_for({**PUSH, 'firstEntropyChallenge': '<x>'}), [])
        pending = PendingRequest(PUSH, {})
        self.assertFalse(pending.consume(pending.id, '99', False))

    def test_ambiguous_submission_consumed_once_and_never_retried(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = MobileRuntime(temp)
            pending = PendingRequest(PUSH, {'token': 'SYNTHETIC'})
            runtime.pending = pending
            coordinator = Mock(verification_only=False)
            coordinator.context_is_current.return_value = True
            with patch('app.approval.build_pin_validation', return_value='body'), \
                    patch('app.approval.send_pad', side_effect=TimeoutError()) as submit:
                runtime.answer(pending.id, '12')
                runtime.answer(pending.id, '12')
                runtime._submit(coordinator)
                self.assertEqual(submit.call_count, 1)
                self.assertIsNone(runtime.pending)

    def test_duplicate_push_and_superseded_screen_do_not_resurrect(self):
        with tempfile.TemporaryDirectory() as temp, sqlite3.connect(':memory:') as db:
            runtime = MobileRuntime(temp)
            db.execute('CREATE TABLE seen (guid TEXT PRIMARY KEY)')
            runtime._capture(PUSH, {}, db)
            first = runtime.pending
            runtime._capture(PUSH, {}, db)
            self.assertIs(runtime.pending, first)
            runtime._capture({**PUSH, 'guid': 'new-request'}, {}, db)
            self.assertFalse(runtime.pending.consume(first.id, '12', False))


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.archive = self.root / 'setup.zip'
        env = patch.dict(os.environ, AUTH_STATE_DIR=str(self.source))
        env.start()
        self.addCleanup(env.stop)
        from app.registration import RegistrationState
        registry = RegistrationState()
        registry.state.update(account=ACCOUNT, google='SYNTHETIC', active='SYNTHETIC',
                              bound='SYNTHETIC', binding_verified=True, confirmed_at=1)
        registry._save()
        registry._export()
        registry.close()
        (self.source / 'checkin_info.json').write_text(json.dumps({'androidId': '123', 'securityToken': '456'}))
        (self.source / 'apk_config.json').write_text(json.dumps({
            'package': 'com.azure.authenticator', 'version_name': '6.2609.0',
            'firebase': {'app_id': 'app', 'project': 'project', 'api_key': 'key', 'sender_id': 'sender'}}))

    def test_round_trip_preserves_bot_credentials_and_skips_runtime_files(self):
        credentials = json.dumps({'bot_token': 'SYNTHETIC', 'user_id': 42, 'chat_id': 42})
        (self.source / 'telegram.json').write_text(credentials)
        (self.source / 'service.log').write_text('NEVER INCLUDE')
        export_setup(self.source, self.archive)
        with zipfile.ZipFile(self.archive) as z:
            self.assertEqual(set(z.namelist()), {'data/' + p.name for p in self.source.iterdir() if p.name in FILES})
            self.assertNotIn('data/service.lock', z.namelist())
            self.assertNotIn('data/service.log', z.namelist())
        dest = self.root / 'import'
        self.assertTrue(extract_bundle(self.archive, dest))
        self.assertEqual((dest / 'telegram.json').read_text(), credentials)
        self.assertEqual((dest / 'registration.sqlite3').stat().st_mode & 0o777, 0o600)

    def test_live_pc_listener_blocks_export(self):
        with (self.source / 'service.lock').open('a') as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BundleError):
                export_setup(self.source, self.archive)

    def test_zipped_desktop_data_imports_and_phone_export_restores_on_desktop(self):
        from app.config import Config
        from app.registration import RegistrationState
        from app.service import Bridge
        credentials = json.dumps({'bot_token': 'SYNTHETIC', 'user_id': 42, 'chat_id': 42})
        (self.source / 'telegram.json').write_text(credentials)
        # Ordinary ZIP of data/; no special exporter or manifest.
        with zipfile.ZipFile(self.archive, 'w') as archive:
            archive.writestr('data/', '')
            for path in self.source.iterdir():
                archive.write(path, 'data/' + path.name)
        runtime = MobileRuntime(self.root / 'phone')
        runtime.root.mkdir()
        runtime.import_setup(self.archive)
        with sqlite3.connect(runtime.state_dir / 'requests.sqlite3') as db:
            db.execute('CREATE TABLE seen (guid TEXT PRIMARY KEY)')
            db.execute('INSERT INTO seen VALUES (?)', ('answered-on-phone',))
        exported = self.root / 'phone.zip'
        runtime.export_setup(exported)
        desktop = self.root / 'desktop'
        with zipfile.ZipFile(exported) as archive:
            archive.extractall(desktop)
        with patch.dict(os.environ, AUTH_STATE_DIR=str(desktop / 'data')):
            registry = RegistrationState()
            try:
                self.assertEqual(registry.verification_material()['account'], ACCOUNT)
            finally:
                registry.close()
            bridge = Bridge(None, Config(enabled=False))
            try:
                self.assertEqual(bridge.db.execute('SELECT guid FROM seen').fetchall(), [('answered-on-phone',)])
            finally:
                bridge.db.close()
        self.assertEqual((desktop / 'data/telegram.json').read_text(), credentials)

    def test_pending_google_rotation_preserves_the_active_microsoft_token(self):
        from app.registration import RegistrationState
        registry = RegistrationState()
        registry.state.update(google='NEW-GOOGLE', pending='NEW-GOOGLE')
        registry._save()
        registry._export()
        registry.close()
        export_setup(self.source, self.archive)
        destination = self.root / 'rotated'
        self.assertTrue(extract_bundle(self.archive, destination))
        self.assertEqual((destination / 'fcm_token.txt').read_text().strip(), 'SYNTHETIC')

    def test_traversal_and_duplicate_zip_entries_rejected(self):
        for paths in [['../escaped', 'fcm_token.txt'], ['fcm_token.txt', 'fcm_token.txt']]:
            with zipfile.ZipFile(self.archive, 'w') as z:
                for p in paths: z.writestr(p, '{}')
            with self.assertRaises(BundleError): extract_bundle(self.archive, self.root / ('import-' + str(len(paths[0]))))
            self.assertFalse((self.root / 'escaped').exists())

    def test_invalid_token_preserves_installed_enrollment(self):
        export_setup(self.source, self.archive)
        bad = self.root / 'bad.zip'
        with zipfile.ZipFile(self.archive) as original, zipfile.ZipFile(bad, 'w') as altered:
            for info in original.infolist():
                altered.writestr(info.filename, b'changed' if info.filename == 'data/fcm_token.txt' else original.read(info.filename))
        phone = self.root / 'phone'
        phone.mkdir()
        runtime = MobileRuntime(phone)
        runtime.import_setup(self.archive)
        before = (phone / 'enrollment/registration.sqlite3').read_bytes()
        with self.assertRaises(BundleError): runtime.import_setup(bad)
        self.assertEqual((phone / 'enrollment/registration.sqlite3').read_bytes(), before)

    def test_partial_activation_is_rejected_without_replacing_state(self):
        (self.source / 'registration.sqlite3').write_bytes(b'not a database')
        with self.assertRaises(BundleError): export_setup(self.source, self.archive)
        self.assertFalse(self.archive.exists())

    def test_failed_commit_restores_the_previous_setup(self):
        export_setup(self.source, self.archive)
        phone = self.root / 'phone'
        phone.mkdir()
        runtime = MobileRuntime(phone)
        runtime.import_setup(self.archive)
        marker = phone / 'enrollment/previous-marker'
        marker.write_text('previous setup')
        with patch('app.state.sync_directory', side_effect=OSError('synthetic fsync failure')):
            with self.assertRaises(OSError): runtime.import_setup(self.archive)
        self.assertEqual(marker.read_text(), 'previous setup')


if __name__ == '__main__':
    unittest.main()
