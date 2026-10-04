"""APK version propagation through Microsoft request builders."""
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from app import activation, approval, app_identity, entra_registration
from app.state import state_path


class AppVersionTests(unittest.TestCase):
    def test_old_apk_version_is_used_across_requests(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ', AUTH_STATE_DIR=directory):
            state_path('apk_config.json').write_text(json.dumps({
                'package': 'com.azure.authenticator', 'version_name': '6.2608.5658'}))
            self.assertEqual(app_identity.app_version(), '6.2608.5658')
            self.assertEqual(activation.build_pad_headers('token', 'action')['AppVersion'], '6.2608.5658')
            self.assertEqual(activation.build_pad_headers('token', 'action')['x-ms-mac-app-version'], '6.2608.5658')
            self.assertEqual(ET.fromstring(activation.build_activate('code', 'token', 'Pixel 8', 1)).findtext('.//{*}Version'), '6.2608.5658')
            self.assertEqual(ET.fromstring(activation.build_validation('guid', 'token')).findtext('.//phoneAppContext/version'), '6.2608.5658')
            self.assertEqual(ET.fromstring(approval.build_pin_validation('guid', 'token', '12', 1)).findtext('.//phoneAppContext/version'), '6.2608.5658')
            self.assertEqual(ET.fromstring(approval.build_auth_result('guid', 'token', 1, 1)).findtext('.//phoneAppContext/version'), '6.2608.5658')
            self.assertEqual(ET.fromstring(entra_registration.build_start_v2('token')).findtext('.//version'), '6.2608.5658')
            state_path('apk_config.json').write_text(json.dumps({
                'package': 'com.azure.authenticator', 'version_name': '6.2609.6214'}))
            self.assertEqual(app_identity.app_version(), '6.2609.6214')
            self.assertEqual(activation.build_pad_headers('token', 'action')['AppVersion'], '6.2609.6214')

    def test_missing_or_invalid_version_fails(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ', AUTH_STATE_DIR=directory):
            with self.assertRaisesRegex(ValueError, 'missing'):
                app_identity.app_version()
            state_path('apk_config.json').write_text(json.dumps({
                'package': 'com.azure.authenticator', 'version_name': 'bogus'}))
            with self.assertRaisesRegex(ValueError, 'valid'):
                app_identity.app_version()
