"""APK-derived notification routing and response parser regressions (offline)."""
import contextlib
import hashlib
import io
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from app import entra_registration as entra
from app.bots.base import Reply
from app.config import Config
from app.registration import RegistrationState
from app.registration_runtime import RegistrationCoordinator
from app.service import Bridge
from app.state import save_json, state_path
from test.entra_fixtures import ACCOUNT, PUSH, auth_response


class AuthenticationCompatibilityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        env = patch.dict(os.environ, AUTH_STATE_DIR=directory.name)
        env.start()
        self.addCleanup(env.stop)
        save_json('apk_config.json', {'package': 'com.azure.authenticator', 'version_name': '6.2609.6214'})
        # Import the files produced by the last committed version, not an
        # artificially pre-verified registration created by mark_activation.
        save_json('activation.json', ACCOUNT)
        state_path('fcm_token.txt').write_text('legacy-token')
        self.registry = RegistrationState()
        self.coordinator = RegistrationCoordinator(self.registry)
        self.addCleanup(self.coordinator.stop)
        self.bot = Mock()
        self.bot.request.return_value = '1'
        self.bot.updates.return_value = []
        self.submit = Mock(return_value=(200, '<validationResult>6</validationResult>'))
        self.bridge = Bridge(self.bot, Config(), self.submit, self.coordinator)
        self.addCleanup(self.bridge.db.close)

    def deliver(self, data):
        self.bridge.capture(data)
        self.coordinator._learn_responses()
        self.bridge.poll()

    def test_legacy_notification_reaches_bot_and_approves_without_fetch(self):
        data = {**PUSH, 'phoneAppDetailId': 'detail', 'pushNotificationDeviceToken': 'untrusted',
                'dosPreventer': 'untrusted'}
        with patch.object(entra, 'post', side_effect=entra.BindingError('server_rejected')) as network:
            self.deliver(data)
            self.bridge.handle(Reply('1', '12'))
            self.deliver(data)
        network.assert_not_called()
        self.bot.request.assert_called_once()
        self.submit.assert_called_once()
        self.assertEqual(self.submit.call_args.args[2], 'legacy-token')
        self.assertTrue(self.bridge.approved)
        self.assertFalse(self.registry.snapshot()['binding_verified'])
        self.assertEqual(self.registry.snapshot()['account'], ACCOUNT)

    def test_hashed_object_and_group_lookup_avoids_fetch(self):
        data = {**PUSH, 'userObjectId': hashlib.sha256(b'object').hexdigest(), 'groupKey': 'group'}
        with patch.object(entra, 'post') as network:
            self.deliver(data)
        network.assert_not_called()
        self.bot.request.assert_called_once()

    def test_unknown_push_identity_still_fetches(self):
        with patch.object(entra, 'post', return_value=auth_response('legacy-token')) as network:
            self.deliver({**PUSH, 'userObjectId': 'not-the-account', 'groupKey': 'group'})
        network.assert_called_once()
        self.bot.request.assert_called_once()

    def test_conflicting_identity_never_prompts_or_fetches(self):
        with patch.object(entra, 'post') as network:
            for fields in ({'tenantId': 'other'}, {'phoneAppDetailId': 'other'}, {'groupKey': 'other'}):
                self.deliver({**PUSH, 'phoneAppDetailId': 'detail', **fields})
        network.assert_not_called()
        self.bot.request.assert_not_called()

    def test_known_account_does_not_bypass_endpoint_validation(self):
        self.deliver({**PUSH, 'phoneAppDetailId': 'detail', 'url': 'evil.example'})
        self.bot.request.assert_not_called()

    def test_queued_push_cannot_survive_account_replacement(self):
        self.bridge.capture({**PUSH, 'phoneAppDetailId': 'detail'})
        self.registry.state['revision'] = 'replacement'
        self.coordinator._learn_responses()
        self.bridge.poll()
        self.bot.request.assert_not_called()

    def test_setup_can_confirm_legacy_notification_only_after_success(self):
        self.coordinator.verification_only = True
        with patch.object(entra, 'post') as network:
            self.deliver({**PUSH, 'phoneAppDetailId': 'detail'})
            self.assertFalse(self.registry.snapshot()['binding_verified'])
            self.bridge.handle(Reply('1', '12'))
        network.assert_not_called()
        self.assertEqual(self.registry.active_token, 'legacy-token')

    def test_fetch_parser_accepts_envelopes_without_invented_wrapper(self):
        # AuthenticationResponse.parseXml scans tags regardless of wrapper;
        # this shape is derived from its fields, not a captured live response.
        response = auth_response('legacy-token').replace('phoneAppAuthenticationResponse', 'response')
        response = '<PhoneFactorMessage xmlns="urn:test"><phoneAppInfo mode="pin">' + response + '</phoneAppInfo></PhoneFactorMessage>'
        with patch.object(entra, 'post', return_value=response):
            self.deliver(PUSH)
        self.bot.request.assert_called_once()
        self.assertEqual(self.registry.active_token, 'legacy-token')

    def test_legacy_fetch_without_token_hint_can_approve_without_claiming_binding(self):
        response = auth_response('')
        with patch.object(entra, 'post', return_value=response):
            self.deliver(PUSH)
            self.bridge.handle(Reply('1', '12'))
        self.assertTrue(self.bridge.approved)
        self.assertEqual(self.submit.call_args.args[2], 'legacy-token')
        self.assertFalse(self.registry.snapshot()['binding_verified'])

    def test_service_path_prefix_survives_fetch_and_approval(self):
        data = {**PUSH, 'url': 'phonefactor.net/service/tenant-route'}
        expected = 'https://phonefactor.net/service/tenant-route/pad'
        with patch.object(entra, 'post', return_value=auth_response('legacy-token')) as network:
            self.deliver(data)
            self.bridge.handle(Reply('1', '12'))
        self.assertEqual(network.call_args.args[0], expected)
        self.assertEqual(self.submit.call_args.args[0], expected)
        self.assertEqual(self.registry.snapshot()['account']['PadUrl'], expected)
        self.assertTrue(self.bridge.approved)

    def test_matched_notification_accepts_service_path_prefix(self):
        with patch.object(entra, 'post') as network:
            self.deliver({**PUSH, 'phoneAppDetailId': 'detail',
                          'url': 'phonefactor.net/service/tenant-route'})
            self.bridge.handle(Reply('1', '12'))
        network.assert_not_called()
        self.assertEqual(self.submit.call_args.args[0],
                         'https://phonefactor.net/service/tenant-route/pad')
        self.assertTrue(self.bridge.approved)

    def test_endpoint_rejections_identify_structure_without_exposing_url(self):
        cases = [('http://phonefactor.net/pad', 'scheme'),
                 ('https://user:secret@phonefactor.net/pad', 'credentials'),
                 ('https://phonefactor.net:8443/pad', 'port'),
                 ('https://phonefactor.net.evil.example/pad', 'host'),
                 ('https://phonefactor.net:invalid/pad', 'syntax')]
        for url, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(entra.BindingError) as caught:
                    entra.pad_url(url)
                self.assertEqual(caught.exception.kind, 'invalid_endpoint_' + reason)
                self.assertNotIn('secret', str(caught.exception))

    def test_envelope_flexibility_still_rejects_missing_mismatched_or_duplicate_identity(self):
        responses = [auth_response(guid='other'), auth_response(tenantId='other'),
                     auth_response(azureObjectId='other'), auth_response(phoneAppDetailId='other'),
                     '<response><dosPreventer>secret</dosPreventer></response>',
                     '<response>' + auth_response() + auth_response() + '</response>']
        for response in responses:
            with self.subTest(response=response):
                with self.assertRaises(entra.BindingError):
                    entra.authentication_details(response.replace('phoneAppAuthenticationResponse', 'response'), PUSH, ACCOUNT)

    def test_query_bearing_push_reaches_fetch_and_approval_unchanged(self):
        # Reproduces the reported structure: two path segments, /pad in query.
        # PendingAuthentication literally concatenates https:// + service + /pad.
        data = {**PUSH, 'url': 'phonefactor.net/service/route?context=opaque%2Fvalue&v=1'}
        expected = 'https://' + data['url'] + '/pad'
        diagnostic = entra.endpoint_diagnostic(expected)
        self.assertIn('path_segments=2', diagnostic)
        self.assertIn('path_ends_pad=false', diagnostic)
        self.assertIn('query_present=true', diagnostic)
        self.assertIn('suffix_in=query', diagnostic)
        with patch.object(entra, 'post', return_value=auth_response('legacy-token')) as network:
            self.deliver(data)
            self.bridge.handle(Reply('1', '12'))
        network.assert_called_once()
        self.assertEqual(network.call_args.args[0], expected)
        self.assertEqual(self.submit.call_args.args[0], expected)
        self.assertEqual(self.registry.snapshot()['account']['PadUrl'], expected)
        self.assertTrue(self.bridge.approved)

    def test_query_bearing_matched_push_reaches_approval_without_fetch(self):
        data = {**PUSH, 'phoneAppDetailId': 'detail',
                'url': 'phonefactor.net/service/route?context=opaque%2Fvalue'}
        with patch.object(entra, 'post') as network:
            self.deliver(data)
            self.bridge.handle(Reply('1', '12'))
        network.assert_not_called()
        self.assertEqual(self.submit.call_args.args[0], 'https://' + data['url'] + '/pad')
        self.assertTrue(self.bridge.approved)

    def test_approval_submission_does_not_follow_redirects(self):
        from app.approval import send_pad
        response = Mock(status_code=302, text='')
        with patch('curl_cffi.requests.post', return_value=response) as http:
            self.assertEqual(send_pad('https://phonefactor.net/pad', '<request/>',
                                      'legacy-token', PUSH,
                                      'phoneAppPinValidationRequest', 'chrome131_android'), (302, ''))
        self.assertFalse(http.call_args.kwargs['allow_redirects'])

    def test_transport_preserves_query_bearing_endpoint_for_auth_and_registration(self):
        # Exercise the real post helper too: mocking entra.post in the bridge
        # tests alone would miss a second endpoint rejection at HTTP submission.
        endpoint = 'https://phonefactor.net/service/route?context=opaque%2Fvalue/pad'
        response = Mock(status_code=200, text='<response/>')
        with patch('curl_cffi.requests.post', return_value=response) as http:
            for action in ('phoneAppAuthenticationRequest', 'phoneAppDeviceTokenChangeRequest'):
                self.assertEqual(entra.post(endpoint, '<request/>', 'legacy-token', action), '<response/>')
                self.assertEqual(http.call_args.args[0], endpoint)

    def test_endpoint_does_not_impose_path_query_or_fragment_layout(self):
        for endpoint in ('https://phonefactor.net/service/route?context=value/pad',
                         'https://phonefactor.net/service/route#value/pad',
                         'https://phonefactor.net/service/route;parameter=value/pad',
                         'https://phonefactor.net/service/route'):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(entra.pad_url(endpoint), endpoint)

    def test_endpoint_diagnostics_remain_private_for_rejected_host(self):
        output = io.StringIO()
        with patch.object(entra, 'post') as network, contextlib.redirect_stdout(output):
            self.deliver({**PUSH, 'url': 'private.example/service/route?secret=value'})
        network.assert_not_called()
        log = output.getvalue()
        self.assertIn('reason=invalid_endpoint_host', log)
        self.assertIn('stage=push_service_url', log)
        self.assertIn('suffix_in=query', log)
        for private in ('private.example', 'secret', 'legacy-token'):
            self.assertNotIn(private, log)

    def test_failure_reason_is_logged_without_upstream_secrets(self):
        for error, expected in ((entra.BindingError('server_rejected'), 'reason=server_rejected'),
                                (RuntimeError('secret-token'), 'RuntimeError')):
            output = io.StringIO()
            with patch.object(entra, 'post', side_effect=error), contextlib.redirect_stdout(output):
                self.deliver(PUSH)
            self.assertIn(expected, output.getvalue())
            self.assertNotIn('secret-token', output.getvalue())
        self.bot.request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
