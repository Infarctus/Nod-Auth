"""First-registration regression coverage; no external requests or real state."""
import gzip
import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import app.fcm as fcm
from app.setup import failure_message
from app.mcs import pb_fields


class CheckinTests(unittest.TestCase):
    def test_optional_platform_transport_preserves_binary_request_and_reply(self):
        transport = Mock(return_value=(200, b'\x00\xffbinary'))
        fcm.configure_http_transport(transport)
        try:
            headers = {'Content-Type': 'application/x-protobuffer'}
            self.assertEqual(fcm.http_post('https://example.test', b'\xff\x00request', headers), (200, b'\x00\xffbinary'))
            transport.assert_called_once_with('https://example.test', b'\xff\x00request', headers)
        finally:
            fcm.configure_http_transport(None)
    def test_fresh_checkin_builds_request_and_persists_identity(self):
        reply = fcm.pb_fixed64(7, 123456) + fcm.pb_fixed64(8, 987654)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'checkin_info.json')
            with patch.dict(os.environ, AUTH_STATE_DIR=directory), patch.object(fcm, 'STATE_FILE', path), patch.object(fcm, 'http_post', return_value=(200, reply)) as post:
                state = fcm.do_checkin()
                request = pb_fields(gzip.decompress(post.call_args.args[1]))
                self.assertIn((2, 0, 0), request)  # New device has no Android ID.
                self.assertTrue(any(f == 4 and w == 2 for f, w, _ in request))
                with open(path) as stream:
                    self.assertEqual(json.load(stream), state)
                self.assertEqual(state['securityToken'], 987654)
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertEqual(fcm.do_checkin(), state)
                post.assert_called_once()

    def test_recheckin_encodes_existing_identity(self):
        fields = pb_fields(fcm.build_checkin_request(123456, 987654))
        self.assertIn((2, 0, 123456), fields)
        self.assertTrue(any(f == 13 and w == 1 for f, w, _ in fields))
        self.assertIn((20, 0, 1), fields)

    def test_forced_recheckin_preserves_identity_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            saved = {"androidId": 123, "securityToken": 456, "timeMs": 789}
            path = os.path.join(directory, "checkin_info.json")
            with open(path, "w") as stream:
                json.dump(saved, stream)
            with patch.dict(os.environ, AUTH_STATE_DIR=directory), patch.object(fcm, "http_post", return_value=(200, b"")) as post:
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    fcm.do_checkin(force=True)
                request = pb_fields(gzip.decompress(post.call_args.args[1]))
                self.assertIn((2, 0, 123), request)
            with open(path) as stream:
                self.assertEqual(json.load(stream), saved)

    def test_incomplete_cached_identity_is_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "checkin_info.json"), "w") as stream:
                json.dump({"androidId": 123}, stream)
            with patch.dict(os.environ, AUTH_STATE_DIR=directory):
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    fcm.do_checkin()

    def test_error_reports_location_without_secret(self):
        try:
            raise ValueError('sensitive-token')
        except ValueError as exc:
            message = failure_message(exc)
        self.assertIn('ValueError', message)
        self.assertIn('test_fcm_register.py:', message)
        self.assertNotIn('sensitive-token', message)

    def test_error_reports_fcm_classification_and_http_status_without_body(self):
        from app import fcm_lifecycle
        body = json.dumps({'error': {'status': 'PERMISSION_DENIED',
                                    'message': 'sensitive-token',
                                    'details': [{'reason': 'API_KEY_ANDROID_APP_BLOCKED'}]}}).encode()
        try:
            fcm_lifecycle._fis_status(403, body)
        except fcm_lifecycle.FcmError as exc:
            message = failure_message(exc)
        self.assertIn('fis_bad_config', message)
        self.assertIn('HTTP 403', message)
        self.assertIn('API_KEY_ANDROID_APP_BLOCKED', message)
        self.assertNotIn('sensitive-token', message)

    def test_unrecognized_upstream_labels_and_kinds_are_not_printed(self):
        from app import fcm_lifecycle
        with self.assertRaises(fcm_lifecycle.FcmError) as caught:
            fcm_lifecycle.parse_registration(200, b'Error=sensitive-token')
        message = failure_message(caught.exception)
        self.assertIn('fcm_rejected', message)
        self.assertIn('HTTP 200', message)
        self.assertNotIn('sensitive-token', message)
        self.assertNotIn('sensitive-token', failure_message(fcm_lifecycle.FcmError('sensitive-token')))


if __name__ == '__main__':
    unittest.main()
