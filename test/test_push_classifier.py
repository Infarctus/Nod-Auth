"""Push-kind classification and unsupported-flow routing tests."""
import tempfile
import unittest
from unittest.mock import Mock, patch

from app.approval import (classify_push, payload_summary, KIND_LABELS,
                          PUSH_SESSION_KEYS, SUPPORTED_KINDS)
from app.service import Bridge
from app.state import state_path
from app.config import Config


def aad_push(**changes):
    push = {'type': 'auth', 'source': 'SAS', 'guid': 'g1',
            'url': 'example.microsoft.com'}
    push.update(changes)
    return push


class ClassifyTests(unittest.TestCase):
    def test_supported_entra_mfa_push(self):
        self.assertEqual(classify_push(aad_push()), 'aad_mfa')
        self.assertEqual(classify_push(aad_push(source='MFA Server')), 'aad_mfa')

    def test_auth_push_without_guid_or_url_is_not_answerable(self):
        for changes in ({'guid': ''}, {'url': None}, {'guid': None}):
            with self.subTest(changes=changes):
                self.assertEqual(classify_push(aad_push(**changes)), 'unknown')

    def test_non_aad_source_never_classifies_as_aad(self):
        for source in ('', 'other', None):
            with self.subTest(source=source):
                self.assertEqual(classify_push(aad_push(source=source)), 'unknown')
                self.assertEqual(classify_push(aad_push(source=source, sessiontype='NGC')),
                                 'unknown')

    def test_entra_passwordless_ngc_via_sessiontype_or_type(self):
        expected = [('sessiontype', 'ngc'), ('sessiontype', 'NGC'), ('type', 'NGC')]
        for key, value in expected:
            push = aad_push()
            push.pop('type')
            push[key] = value
            with self.subTest(key=key, value=value):
                self.assertEqual(classify_push(push), 'aad_ngc')

    def test_unknown_type_falls_back_to_recognized_sessiontype(self):
        self.assertEqual(classify_push(aad_push(type='other', sessiontype='NGC')),
                         'aad_ngc')
        self.assertEqual(classify_push({'type': 'other',
                                       'sessiontype': 'SessionApprovalPending'}),
                         'msa_session')

    def test_sdk_type_takes_precedence_over_sessiontype(self):
        self.assertEqual(classify_push(aad_push(sessiontype='NGC')), 'aad_mfa')
        self.assertEqual(classify_push(aad_push(type='validate', sessiontype='NGC')),
                         'aad_validate')
        self.assertEqual(classify_push({'type': 'RemoteNGCPending',
                                       'sessiontype': 'SessionApprovalPending'}),
                         'msa_ngc')

    def test_sessiontype_cannot_invent_mfa_or_validation(self):
        for value in ('auth', 'validate'):
            with self.subTest(sessiontype=value):
                self.assertEqual(classify_push(aad_push(type='', sessiontype=value)),
                                 'unknown')

    def test_validate_challenges_classify_separately(self):
        self.assertEqual(classify_push(aad_push(type='validate')), 'aad_validate')
        self.assertEqual(classify_push(aad_push(type='validate', source='x')), 'unknown')

    def test_msa_flows_need_no_source(self):
        cases = {'SessionApprovalPending': 'msa_session',
                 'RemoteNGCPending': 'msa_ngc',
                 'ProtectionNotification': 'msa_protection'}
        for pushed, kind in cases.items():
            with self.subTest(type=pushed):
                self.assertEqual(classify_push({'type': pushed}), kind)

    def test_unknown_and_missing_types(self):
        for pushed in ('', 'auth2', 'Auth', 'anythingelse'):
            with self.subTest(type=pushed):
                self.assertEqual(classify_push({'type': pushed}), 'unknown')
        self.assertEqual(classify_push({}), 'unknown')

    def test_constants_stay_in_sync(self):
        self.assertEqual(SUPPORTED_KINDS, ('aad_mfa',))
        self.assertEqual(set(PUSH_SESSION_KEYS),
                         {'aad_mfa', 'aad_validate', 'aad_ngc',
                          'msa_session', 'msa_ngc', 'msa_protection'})
        self.assertEqual(set(KIND_LABELS),
                         set(PUSH_SESSION_KEYS) | {'unknown'})

    def test_payload_summary_uses_display_fields_only(self):
        summary = payload_summary({'displayTitle': 'Sign-in  request',
                                   'browser': 'Firefox\n', 'country': 'NO',
                                   'internalSID': 'secret', 'guid': 'g1'},
                                  'msa_session')
        self.assertIn('title: Sign-in request', summary)
        self.assertIn('browser: Firefox', summary)
        self.assertIn('region: NO', summary)
        self.assertNotIn('secret', summary)
        self.assertNotIn('g1', summary)
        self.assertEqual(payload_summary({'guid': 'g1'}, 'msa_session'), '')


class UnsupportedRoutingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        env = patch.dict('os.environ', AUTH_STATE_DIR=directory.name)
        env.start()
        self.addCleanup(env.stop)
        state_path('fcm_token.txt').write_text('fake-token')
        self.bot = Mock()
        self.bridge = Bridge(self.bot, Config(), Mock())
        self.addCleanup(self.bridge.db.close)

    def test_each_unsupported_kind_reports_without_approval(self):
        pushes = {
            'aad_validate': aad_push(type='validate'),
            'aad_ngc': aad_push(type='NGC'),
            'msa_session': {'type': 'SessionApprovalPending', 'CID': '1',
                            'internalSID': 's1', 'requestTime': '1',
                            'expirationTime': '2'},
            'msa_ngc': {'type': 'RemoteNGCPending', 'internalSID': 's2'},
            'msa_protection': {'type': 'ProtectionNotification', 'internalSID': 's3'},
            'unknown': {'type': 'bogus'},
            'unknown-source': aad_push(source='evil'),
        }
        for name, push in pushes.items():
            with self.subTest(push=name):
                bot = Mock()
                bridge = Bridge(bot, Config(), Mock())
                self.addCleanup(bridge.db.close)
                bridge.capture(push)
                bridge.submit.assert_not_called()
                bot.request.assert_not_called()
                bot.notify.assert_called_once()
                self.assertIn('not supported', bot.notify.call_args.args[0])
                self.assertFalse(bridge.pending)

    def test_unsupported_push_is_not_persisted_as_seen(self):
        push = aad_push(type='SessionApprovalPending')
        self.bridge.capture(push)
        row = self.bridge.db.execute('SELECT COUNT(*) FROM seen').fetchone()
        self.assertEqual(row[0], 0)

    def test_summary_fields_are_forwarded_to_bot_notice(self):
        push = {'type': 'SessionApprovalPending', 'internalSID': 'sid',
                'displayTitle': 'Contoso sign-in', 'browser': 'Safari'}
        self.bridge.capture(push)
        text = self.bot.notify.call_args.args[0]
        self.assertIn('personal Microsoft account sign-in', text)
        self.assertIn('Contoso sign-in', text)
        self.assertNotIn('sid', text)

    def test_unsupported_push_preserves_pending_and_accepts_future_requests(self):
        self.bot.request.side_effect = ['1', '2']
        self.bridge.capture(aad_push())
        pending = dict(self.bridge.pending)
        self.bridge.capture({'type': 'ProtectionNotification'})
        self.assertEqual(self.bridge.pending, pending)
        self.bridge.submit.assert_not_called()
        self.bridge.capture(aad_push(guid='g2'))
        self.assertEqual(set(self.bridge.pending), {'2'})

    def test_disabled_notifications_ignore_unsupported_without_io(self):
        self.bridge.bot = None
        with patch.object(self.bridge, 'notify') as notify:
            self.bridge.capture({'type': 'RemoteNGCPending'})
        notify.assert_not_called()
        self.bridge.submit.assert_not_called()
        self.assertFalse(self.bridge.pending)

    def test_failed_unsupported_notice_does_not_stop_supported_requests(self):
        self.bot.notify.side_effect = RuntimeError('delivery failed')
        self.bridge.capture({'type': 'RemoteNGCPending'})
        self.bridge.capture(aad_push())
        self.assertEqual(len(self.bridge.pending), 1)

    def test_legacy_push_without_type_still_approves(self):
        push = {'guid': 'legacy', 'source': 'SAS', 'url': 'example.microsoft.com',
                'firstEntropyChallenge': '12'}
        self.bridge.capture(push)
        self.assertEqual(len(self.bridge.pending), 1)

    def test_duplicate_supported_push_is_ignored_not_fatal(self):
        self.bridge.capture(aad_push())
        self.bridge.capture(aad_push())
        self.assertEqual(len(self.bridge.pending), 1)


if __name__ == '__main__':
    unittest.main()
