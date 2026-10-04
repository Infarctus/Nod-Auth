"""Regression checks for Entra validation delivery and persistence."""
import os
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from app.activation import answer_challenge, challenge_loop
from app.registration import RegistrationState


class ValidationDeliveryTests(unittest.TestCase):
    def test_v2_requires_guid_and_service_url_before_notifying(self):
        base = {'source': 'SAS', 'type': 'validate',
                'deviceTokenChangeVersion': 'V2'}
        self.assertEqual(answer_challenge({**base, 'url': 'phonefactor.net'}, 'token')['action'], 'abort')
        self.assertEqual(answer_challenge({**base, 'guid': 'g'}, 'token')['action'], 'abort')
        with patch('app.activation.pad_post') as post:
            self.assertEqual(answer_challenge({**base, 'guid': 'g', 'url': 'phonefactor.net'},
                                              'token')['action'], 'notify-only')
            post.assert_not_called()

    def test_activation_processes_later_challenge_after_failed_first(self):
        class Listener:
            event = threading.Event()
            pushes = [
                {'app_data': {'source': 'SAS', 'type': 'validate', 'guid': 'first',
                              'url': 'phonefactor.net', 'tenantId': 'other'}},
                {'app_data': {'source': 'SAS', 'type': 'validate', 'guid': 'second',
                              'url': 'phonefactor.net', 'tenantId': 'tenant'}},
            ]

        result = {}

        def answer(data, token):
            if data['guid'] == 'first':
                return {'action': 'error', 'reason': 'TimeoutError'}
            result['done'] = True
            return {'action': 'validated', 'status': 200,
                    'text': '<r><username>user@example.test</username></r>'}

        with patch('app.activation.answer_challenge', side_effect=answer) as send:
            self.assertTrue(challenge_loop(Listener(), result, 'token', timeout=1))
        self.assertEqual(send.call_count, 2)
        self.assertEqual(result['validation_events'][0]['metadata']['TenantId'], 'tenant')

    def test_pending_validation_lease_recovers_after_restart(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, AUTH_STATE_DIR=directory):
            clock = [100000]
            state = RegistrationState(now=lambda: clock[0])
            self.assertTrue(state.claim_validation('challenge'))
            state.close()
            state = RegistrationState(now=lambda: clock[0])
            self.assertFalse(state.claim_validation('challenge'))
            clock[0] += 61
            self.assertTrue(state.claim_validation('challenge'))
            state.complete_validation('challenge')
            self.assertFalse(state.claim_validation('challenge'))
            state.close()


    def test_legacy_deduplication_rows_migrate_as_completed(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, AUTH_STATE_DIR=directory):
            with sqlite3.connect(os.path.join(directory, 'registration.sqlite3')) as db:
                db.execute('CREATE TABLE validation_seen (fingerprint TEXT PRIMARY KEY)')
                db.execute('INSERT INTO validation_seen VALUES (?)', ('previous-success',))
            state = RegistrationState(now=lambda: 100000)
            try:
                self.assertFalse(state.claim_validation('previous-success'))
                self.assertTrue(state.claim_validation('new-challenge'))
            finally:
                state.close()

    def test_completed_validation_expires_without_touching_account_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, AUTH_STATE_DIR=directory):
            clock = [100000]
            state = RegistrationState(now=lambda: clock[0])
            try:
                self.assertTrue(state.claim_validation('expired-challenge'))
                state.complete_validation('expired-challenge')
                clock[0] += 30 * 86400 + 1
                self.assertTrue(state.claim_validation('expired-challenge'))
            finally:
                state.close()


if __name__ == '__main__':
    unittest.main()
