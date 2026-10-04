"""Plain data/ ZIP portability, validation and desktop restore without network."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from app.config import Config
from app.registration import RegistrationState
from app.service import Bridge
from app.state_bundle import BundleError, FILES, export_bundle, extract_bundle, main
from test.entra_fixtures import ACCOUNT


class DataZipTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / 'data'
        self.source.mkdir()
        env = patch.dict(os.environ, AUTH_STATE_DIR=str(self.source))
        env.start()
        self.addCleanup(env.stop)
        registry = RegistrationState()
        registry.state.update(account=ACCOUNT, google='SYNTHETIC', active='SYNTHETIC',
                              bound='SYNTHETIC', binding_verified=True, confirmed_at=1,
                              phase='bound')
        registry._save()
        registry._export()
        registry.close()
        (self.source / 'checkin_info.json').write_text(json.dumps({'androidId': 123, 'securityToken': 456}))
        (self.source / 'apk_config.json').write_text(json.dumps({
            'package': 'com.azure.authenticator', 'version_name': '6.2609.0',
            'firebase': {'app_id': 'app', 'project': 'project', 'api_key': 'key', 'sender_id': 'sender'}}))
        self.archive = self.root / 'transfer.zip'

    def raw_zip(self, layout='folder'):
        if layout == 'folder':
            shutil.make_archive(str(self.archive.with_suffix('')), 'zip', self.root, 'data')
        elif layout == 'dot':
            shutil.make_archive(str(self.archive.with_suffix('')), 'zip', self.source, '.')
        else:
            with zipfile.ZipFile(self.archive, 'w') as archive:
                for path in self.source.iterdir():
                    archive.write(path, path.name)

    def test_plain_folder_flat_and_dot_archives_preserve_state(self):
        (self.source / 'service.log').write_text('ignored')
        (self.source / 'NOTES.md').write_text('ignored')
        (self.source / '.state-interrupted').write_text('ignored')
        for layout in ('folder', 'flat', 'dot'):
            with self.subTest(layout=layout):
                self.raw_zip(layout)
                destination = self.root / layout
                self.assertTrue(extract_bundle(self.archive, destination))
                self.assertEqual({p.name for p in destination.iterdir()},
                                 {p.name for p in self.source.iterdir() if p.name in FILES})
                for path in destination.iterdir():
                    self.assertEqual(path.read_bytes(), (self.source / path.name).read_bytes())
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o700)

    def test_export_can_be_unzipped_directly_as_desktop_data(self):
        with sqlite3.connect(self.source / 'requests.sqlite3') as db:
            db.execute('CREATE TABLE seen (guid TEXT PRIMARY KEY)')
            db.execute('INSERT INTO seen VALUES (?)', ('already-answered',))
        export_bundle(self.source, self.archive)
        desktop = self.root / 'desktop'
        with zipfile.ZipFile(self.archive) as archive:
            self.assertTrue(all(name.startswith('data/') for name in archive.namelist()))
            self.assertNotIn('manifest.json', archive.namelist())
            archive.extractall(desktop)
        with patch.dict(os.environ, AUTH_STATE_DIR=str(desktop / 'data')):
            registry = RegistrationState()
            try:
                self.assertEqual(registry.verification_material()['account'], ACCOUNT)
                self.assertEqual(registry.active_token, 'SYNTHETIC')
            finally:
                registry.close()
            bridge = Bridge(None, Config(enabled=False))
            try:
                self.assertEqual(bridge.db.execute('SELECT guid FROM seen').fetchall(), [('already-answered',)])
            finally:
                bridge.db.close()

    def test_round_trip_preserves_all_current_portable_files(self):
        for name in FILES - {'registration.sqlite3', 'requests.sqlite3'}:
            if not (self.source / name).exists():
                (self.source / name).write_text(json.dumps({'fixture': name}))
        (self.source / 'activation.pending.json').unlink()
        with sqlite3.connect(self.source / 'requests.sqlite3') as db:
            db.execute('CREATE TABLE seen (guid TEXT PRIMARY KEY)')
        self.raw_zip()
        phone = self.root / 'phone'
        extract_bundle(self.archive, phone)
        phone_export = self.root / 'phone.zip'
        export_bundle(phone, phone_export)
        desktop = self.root / 'restored'
        self.assertTrue(extract_bundle(phone_export, desktop))
        for path in self.source.iterdir():
            if path.name in FILES and not path.name.endswith('.sqlite3'):
                self.assertEqual((desktop / path.name).read_bytes(), path.read_bytes())

    def test_bad_paths_unknown_files_and_mixed_layouts_are_rejected(self):
        for name in ('../escape', 'data/../escape', '/escape', 'data/nested/file',
                     'data/evil.py', 'data\\fcm_token.txt', 'C:\\escape', 'flat.json',
                     'manifest.json', 'state/fcm_token.txt'):
            with self.subTest(name=name):
                self.raw_zip()
                with zipfile.ZipFile(self.archive, 'a') as archive:
                    archive.writestr(name, 'ignored')
                destination = self.root / 'rejected'
                with self.assertRaises(BundleError):
                    extract_bundle(self.archive, destination)
                self.assertFalse(destination.exists())
                self.assertFalse((self.root / 'escape').exists())

    def test_symlink_entry_is_rejected(self):
        self.raw_zip()
        info = zipfile.ZipInfo('data/symlink.log')
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.archive, 'a') as archive:
            archive.writestr(info, '/outside')
        with self.assertRaises(BundleError):
            extract_bundle(self.archive, self.root / 'rejected')

    def test_duplicate_normalized_path_is_rejected(self):
        self.raw_zip('flat')
        with zipfile.ZipFile(self.archive, 'a') as archive:
            archive.writestr('./fcm_token.txt', 'SYNTHETIC')
        with self.assertRaises(BundleError):
            extract_bundle(self.archive, self.root / 'rejected')

    def test_nonempty_sqlite_journals_are_not_silently_dropped(self):
        for suffix in ('-wal', '-journal'):
            with self.subTest(suffix=suffix):
                self.raw_zip()
                with zipfile.ZipFile(self.archive, 'a') as archive:
                    archive.writestr('data/registration.sqlite3' + suffix, 'pending writes')
                with self.assertRaisesRegex(BundleError, 'Stop the listener'):
                    extract_bundle(self.archive, self.root / 'rejected')

    def test_corrupt_optional_database_is_rejected(self):
        (self.source / 'requests.sqlite3').write_bytes(b'broken database')
        self.raw_zip()
        with self.assertRaises(BundleError):
            extract_bundle(self.archive, self.root / 'rejected')

    def test_size_and_entry_count_limits(self):
        for limit, value in (('MAX_BYTES', 10), ('MAX_ENTRIES', 2)):
            with self.subTest(limit=limit):
                self.raw_zip()
                with patch('app.state_bundle.' + limit, value), self.assertRaises(BundleError):
                    extract_bundle(self.archive, self.root / 'rejected')

    def test_export_is_a_consistent_sqlite_snapshot_with_pending_wal(self):
        with sqlite3.connect(self.source / 'requests.sqlite3') as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE seen (guid TEXT PRIMARY KEY)')
            db.execute('INSERT INTO seen VALUES (?)', ('saved-in-wal',))
            db.commit()
            self.assertGreater((self.source / 'requests.sqlite3-wal').stat().st_size, 0)
            export_bundle(self.source, self.archive)
        destination = self.root / 'snapshot'
        extract_bundle(self.archive, destination)
        with sqlite3.connect(destination / 'requests.sqlite3') as db:
            self.assertEqual(db.execute('SELECT guid FROM seen').fetchall(), [('saved-in-wal',)])

    def test_desktop_import_cli_never_overwrites_existing_data(self):
        self.raw_zip()
        destination = self.root / 'restored'
        arguments = ['state_bundle', 'import', '--archive', str(self.archive), '--state-dir', str(destination)]
        with patch('sys.argv', arguments), contextlib.redirect_stdout(io.StringIO()):
            main()
        before = (destination / 'registration.sqlite3').read_bytes()
        with patch('sys.argv', arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main()
        self.assertEqual((destination / 'registration.sqlite3').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
