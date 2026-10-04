"""Portable ADB discovery for the installer and command wrapper."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import adb


class AdbDiscoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for context in (patch.dict(os.environ, {}, clear=True),
                        patch.object(adb, 'ROOT', self.root),
                        patch.object(adb, 'WINDOWS_USERS', self.root / 'Users'),
                        patch.object(adb.shutil, 'which', return_value=None)):
            context.start()
            self.addCleanup(context.stop)

    def executable(self, relative):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        return str(path)

    def test_explicit_adb_overrides_discovery(self):
        with patch.dict(os.environ, ANDROID_ADB='/custom path/adb.exe'):
            self.assertEqual(adb.find_adb(), '/custom path/adb.exe')

    def test_adb_on_path_precedes_windows_downloads(self):
        self.executable('Users/Example/Downloads/platform-tools-latest-windows/platform-tools/adb.exe')
        with patch.object(adb.shutil, 'which', side_effect=lambda name: '/bin/adb' if name == 'adb' else None):
            self.assertEqual(adb.find_adb(), '/bin/adb')

    def test_windows_download_uses_any_profile_name(self):
        path = self.executable('Users/Example User/Downloads/platform-tools-latest-windows/platform-tools/adb.exe')
        self.assertEqual(adb.find_adb(), path)

    def test_multiple_windows_downloads_require_explicit_choice(self):
        for profile in ('First', 'Second'):
            self.executable(f'Users/{profile}/Downloads/platform-tools-latest-windows/platform-tools/adb.exe')
        with self.assertRaisesRegex(FileNotFoundError, 'Multiple Windows ADB installations'):
            adb.find_adb()

    def test_configured_sdk_precedes_project_sdk(self):
        configured = self.executable('sdk/platform-tools/adb')
        self.executable('.toolchain/sdk/platform-tools/adb')
        with patch.dict(os.environ, ANDROID_HOME=str(self.root / 'sdk')):
            self.assertEqual(adb.find_adb(), configured)

    def test_project_sdk_is_a_fallback(self):
        path = self.executable('.toolchain/sdk/platform-tools/adb')
        self.assertEqual(adb.find_adb(), path)

    def test_missing_adb_explains_configuration(self):
        with self.assertRaisesRegex(FileNotFoundError, 'Set ANDROID_ADB'):
            adb.find_adb()

    def test_wrapper_preserves_arguments_and_exit_status(self):
        with patch.dict(os.environ, ANDROID_ADB='/custom path/adb'), \
                patch.object(sys, 'argv', ['adb.py', '-s', 'serial', 'shell', 'pm', 'path', 'io.github.infarctus.nodauth']), \
                patch.object(adb.subprocess, 'call', return_value=7) as run:
            self.assertEqual(adb.main(), 7)
            run.assert_called_once_with(['/custom path/adb', '-s', 'serial', 'shell', 'pm', 'path', 'io.github.infarctus.nodauth'])
