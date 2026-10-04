"""Google registration lifecycle without external requests."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from app import fcm_lifecycle as fcm


CONFIG = {
    "firebase": {"api_key": "api", "app_id": "app-id", "project": "project",
                 "sender_id": "sender"},
    "signing_cert_sha1": ["sha1"], "version_code": 42,
}
DEVICE = {"androidId": 123, "securityToken": 456}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        env = patch.dict(os.environ, AUTH_STATE_DIR=self.directory.name)
        env.start()
        self.addCleanup(env.stop)

    def test_fid_has_sdk_shape(self):
        for _ in range(10):
            fid = fcm.generate_fid()
            self.assertEqual(len(fid), 22)
            self.assertIn(fid[0], "cdef")

    def test_reuses_canonical_fid_then_renews_auth(self):
        requests = []

        def post(url, body, headers):
            requests.append((url, body, headers))
            if url.endswith("/installations"):
                return 201, json.dumps({
                    "fid": "canonical-fid", "refreshToken": "refresh",
                    "authToken": {"token": "auth1", "expiresIn": "7200s"}}).encode()
            if url.endswith("/authTokens:generate"):
                return 200, b'{"token":"auth2","expiresIn":"7200s"}'
            return 200, b"token=registered"

        with patch.object(fcm, "http_post", side_effect=post):
            with patch("app.fcm_lifecycle.time.time", return_value=100):
                self.assertEqual(fcm.acquire(DEVICE, CONFIG), "registered")
            with patch("app.fcm_lifecycle.time.time", return_value=200):
                self.assertEqual(fcm.acquire(DEVICE, CONFIG), "registered")
            with patch("app.fcm_lifecycle.time.time", return_value=4000):
                self.assertEqual(fcm.acquire(DEVICE, CONFIG), "registered")
        self.assertEqual(len([url for url, _, _ in requests if url.endswith("/installations")]), 1)
        self.assertEqual(len([url for url, _, _ in requests if url.endswith("/authTokens:generate")]), 1)
        forms = [parse_qs(body.decode()) for url, body, _ in requests
                 if url.endswith("/register")]
        self.assertEqual([form["X-fid"] for form in forms], [["canonical-fid"]] * 3)
        self.assertEqual(requests[-1][2]["X-Goog-Firebase-Installations-Auth"], "auth2")

    def test_bad_registration_and_fis_auth_preserve_installation(self):
        saved = {"fid": "old", "refreshToken": "refresh",
                 "authToken": {"token": "auth", "expiresIn": "7200s"},
                 "_auth_created_at": 100, "_identity": fcm._identity(CONFIG)}
        with open(os.path.join(self.directory.name, fcm.FIS_FILE), "w") as stream:
            json.dump(saved, stream)
        with patch.object(fcm, "http_post", return_value=(200, b"unexpected")):
            with patch("app.fcm_lifecycle.time.time", return_value=200):
                with self.assertRaisesRegex(fcm.FcmError, "fcm_bad_response"):
                    fcm.acquire(DEVICE, CONFIG)
        with patch.object(fcm, "http_post", return_value=(401, b"")):
            with patch("app.fcm_lifecycle.time.time", return_value=7000):
                with self.assertRaisesRegex(fcm.FcmError, "fis_auth_invalid"):
                    fcm.acquire(DEVICE, CONFIG)
        with open(os.path.join(self.directory.name, fcm.FIS_FILE)) as stream:
            self.assertEqual(json.load(stream), saved)

    def test_initial_registration_does_not_replace_activated_token(self):
        from app import fcm as initial
        with open(os.path.join(self.directory.name, "activation.json"), "w") as stream:
            stream.write("{}")
        with open(os.path.join(self.directory.name, "fcm_token.txt"), "w") as stream:
            stream.write("old\n")
        with patch.object(fcm, "acquire", return_value="new"):
            with self.assertRaisesRegex(fcm.FcmError, "entra_rebinding_required"):
                initial.do_register(DEVICE)
        with open(os.path.join(self.directory.name, "fcm_token.txt")) as stream:
            self.assertEqual(stream.read(), "old\n")

    def test_corrupt_fis_timing_refreshes_auth_without_losing_identity(self):
        saved = {"fid": "old", "refreshToken": "refresh",
                 "authToken": {"token": "auth", "expiresIn": "garbled"},
                 "_auth_created_at": "bad", "_identity": fcm._identity(CONFIG)}
        with open(os.path.join(self.directory.name, fcm.FIS_FILE), "w") as stream:
            json.dump(saved, stream)
        with patch.object(fcm, 'http_post', return_value=(200, b'{"token":"new","expiresIn":"7200s"}')) as post:
            result = fcm.installation(CONFIG, now=100)
        self.assertTrue(post.call_args.args[0].endswith('/old/authTokens:generate'))
        self.assertEqual(result['fid'], 'old')
        self.assertEqual(result['refreshToken'], 'refresh')

    def test_acquisition_retries_only_transient_errors_three_times(self):
        with patch.object(fcm, "_acquire_once", side_effect=[
                fcm.FcmError("fcm_retryable"), fcm.FcmError("fis_retryable"), "good"]) as acquire, \
             patch.object(fcm.time, "sleep") as sleep:
            self.assertEqual(fcm.acquire(DEVICE, CONFIG), "good")
        self.assertEqual(acquire.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.2, 1.0])
        with patch.object(fcm, "_acquire_once", side_effect=fcm.FcmError("fis_bad_config")) as acquire:
            with self.assertRaises(fcm.FcmError):
                fcm.acquire(DEVICE, CONFIG)
        acquire.assert_called_once()

    def test_malformed_and_throttled_responses(self):
        for status, body, kind in [
            (200, b"token=", "fcm_bad_response"),
            (200, b"Error=RST", "fcm_reset"),
            (200, b"token=x\nother", "fcm_bad_response"),
            (429, b"", "fcm_retryable"),
            (503, b"", "fcm_retryable"),
        ]:
            with self.subTest(status=status, body=body):
                with self.assertRaisesRegex(fcm.FcmError, kind):
                    fcm.parse_registration(status, body)


if __name__ == "__main__":
    unittest.main()


class InstallationRetentionTests(unittest.TestCase):
    setUp = LifecycleTests.setUp

    def test_failed_replacement_keeps_rejected_credentials_then_commits_new_ones(self):
        from app.state import save_json, state_path
        old = {'fid': 'old-fid', 'refreshToken': 'old-refresh', 'authToken': {'token': 'old-auth'}}
        save_json(fcm.FIS_FILE, old)
        fcm.invalidate_installation('fis_auth_invalid')
        with patch.object(fcm, 'http_post', return_value=(503, b'')):
            with self.assertRaises(fcm.FcmError):
                fcm.installation(CONFIG)
        self.assertEqual(json.loads(state_path(fcm.FIS_FILE).read_text()), old)
        fresh = {'fid': 'new-fid', 'refreshToken': 'new-refresh',
                 'authToken': {'token': 'new-auth', 'expiresIn': '7200s'}}
        with patch.object(fcm, 'http_post', return_value=(201, json.dumps(fresh).encode())):
            result = fcm.installation(CONFIG)
        self.assertEqual(result['fid'], 'new-fid')
        self.assertFalse(state_path(fcm.FIS_INVALID_FILE).exists())
        import base64
        entry = json.loads(state_path('credential_history.json').read_text())[0]
        self.assertEqual(json.loads(base64.b64decode(entry['content_base64'])), old)

    def test_stale_invalidation_marker_cannot_delete_new_installation_after_crash(self):
        from app.state import save_json, state_path
        save_json(fcm.FIS_FILE, {'fid': 'old', 'refreshToken': 'old'})
        fcm.invalidate_installation('fis_auth_invalid')
        new = {'fid': 'new', 'refreshToken': 'new-refresh', '_auth_created_at': 100,
               'authToken': {'token': 'auth', 'expiresIn': '7200s'}}
        save_json(fcm.FIS_FILE, new)
        with patch.object(fcm, 'http_post') as network:
            self.assertEqual(fcm.installation(CONFIG, now=200)['fid'], 'new')
        network.assert_not_called()
