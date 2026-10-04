"""Offline authorization, persistence, expiry and submission tests."""
import json
import itertools
import os
import socket
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from app.state import state_path, save_json
from app.service import Bridge, run
from app.bots.telegram import Telegram, TelegramBot
from app.config import Config
from app.mcs import McsListener


class FakeTelegram:
    def __init__(self):
        self.messages = []
        self.incoming = []

    def send(self, chat, text, **extra):
        self.messages.append(text)
        return {'message_id': len(self.messages)}

    def updates(self, offset):
        return self.incoming


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, AUTH_STATE_DIR=self.tmp.name)
        self.env.start()
        state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
        state_path('fcm_token.txt').write_text('fake-token')
        self.tg = FakeTelegram()
        self.config = {'chat_id': 42, 'user_id': 42}
        self.bot = TelegramBot(self.tg, self.config)
        self.submit = Mock(return_value=(200, '<validationResult>6</validationResult>'))
        self.bridge = Bridge(self.bot, Config(), self.submit)
        self.push = {'guid': 'request-one', 'url': 'example.microsoft.com',
                     'source': 'SAS', 'firstEntropyChallenge': '12'}

    def tearDown(self):
        self.bridge.db.close()
        self.env.stop()
        self.tmp.cleanup()

    def reply(self, text='12', user=42, chat=42, mid=1, kind='private'):
        return self.bot.parse_update({'update_id': 9, 'message': {'from': {'id': user},
                'chat': {'id': chat, 'type': kind}, 'text': text,
                'reply_to_message': {'message_id': mid}}}).reply

    def test_lifecycle_validation_routing_and_submission_token(self):
        coordinator = Mock()
        coordinator.active_token = "bound-token"
        coordinator.verification_only = False
        self.bridge.registration = coordinator
        self.bridge.capture({"source": "SAS", "type": "validate",
                             "deviceTokenChangeVersion": "V2", "guid": "challenge",
                             "url": "phonefactor.net"})
        coordinator.on_push.assert_called_once()
        self.assertFalse(self.bridge.pending)
        self.bridge.capture(self.push)
        coordinator.on_mfa_push.assert_called_once()
        self.bridge.capture(self.push, {"token": "bound-token"})
        self.bridge.handle(self.reply())
        self.assertEqual(self.submit.call_args.args[2], "bound-token")
        self.assertIn("<deviceToken>bound-token</deviceToken>", self.submit.call_args.args[1])

    def test_number_reply_submits_once(self):
        self.bridge.capture(self.push)
        self.bridge.handle(self.reply())
        self.bridge.handle(self.reply())
        self.submit.assert_called_once()
        self.assertIn('<selectedEntropyNumber>12</selectedEntropyNumber>', self.submit.call_args.args[1])
        self.assertTrue(self.bridge.approved)

    def test_wrong_sender_chat_group_and_request_rejected(self):
        self.bridge.capture(self.push)
        for reply in (self.reply(user=7), self.reply(chat=7), self.reply(kind='group'), self.reply(mid=99)):
            self.bridge.handle(reply)
        self.submit.assert_not_called()

    def test_expired_and_invalid_replies(self):
        self.bridge.capture(self.push)
        for value in ('APPROVE', '999', '<xml>', '１２'):
            self.bridge.handle(self.reply(value))
        self.submit.assert_not_called()
        ad, _, numbered = self.bridge.pending['1']
        self.bridge.pending['1'] = (ad, time.monotonic() - 1, numbered)
        self.bridge.handle(self.reply())
        self.submit.assert_not_called()

    def test_dedup_survives_restart(self):
        self.bridge.capture(self.push)
        self.bridge.capture(self.push)
        self.bridge.db.close()
        self.bridge = Bridge(self.bot, Config(), self.submit)
        self.bridge.capture(self.push)
        self.assertEqual(len(self.tg.messages), 1)
        self.bridge.handle(self.reply())
        self.submit.assert_not_called()

    def test_deny_never_marks_setup_approved(self):
        self.submit.return_value = (200, '<result>1</result>')
        self.bridge.capture(self.push)
        self.bridge.handle(self.reply('DENY'))
        self.assertIn('<authenticationResult>2</authenticationResult>', self.submit.call_args.args[1])
        self.assertFalse(self.bridge.approved)

    def test_plain_requires_explicit_approval(self):
        self.push.pop('firstEntropyChallenge')
        self.submit.return_value = (200, '<result>1</result>')
        self.bridge.capture(self.push)
        self.submit.assert_not_called()
        self.bridge.handle(self.reply('APPROVE'))
        self.assertTrue(self.bridge.approved)

    def test_network_failure_not_retried(self):
        self.submit.side_effect = TimeoutError()
        self.bridge.capture(self.push)
        self.bridge.handle(self.reply())
        self.bridge.handle(self.reply())
        self.submit.assert_called_once()
        self.assertFalse(self.bridge.approved)

    def test_microsoft_error_is_not_success(self):
        self.submit.return_value = (500, '<validationResult>6</validationResult>')
        self.bridge.capture(self.push)
        self.bridge.handle(self.reply())
        self.assertFalse(self.bridge.approved)

    def test_poll_persists_cursor(self):
        self.tg.incoming = [{'update_id': 9, 'message': {}}]
        self.bridge.poll()
        self.bridge.db.close()
        self.bridge = Bridge(self.bot, Config(), self.submit)
        self.assertEqual(self.bridge.offset, '10')

    def test_registration_push_reported_and_app_lock_answered_as_local_auth(self):
        # A registration challenge at runtime is classified but never approved.
        self.bridge.capture(dict(self.push, type='validate'))
        self.assertFalse(self.bridge.pending)
        self.submit.assert_not_called()
        # App-lock-required sign-ins are answered as if local auth succeeded.
        # The unsupported notice above consumed message ID 1.
        self.bridge.capture(dict(self.push, isAppLockRequired='true'))
        self.bridge.handle(self.reply(mid=2))
        self.submit.assert_called_once()
        self.assertIn('<isAppLockUsed>yes</isAppLockUsed>', self.submit.call_args.args[1])
        self.assertTrue(self.bridge.approved)

    def test_app_lock_flag_absent_reports_no_local_auth(self):
        self.bridge.capture(self.push)
        self.bridge.handle(self.reply())
        self.assertIn('<isAppLockUsed>no</isAppLockUsed>', self.submit.call_args.args[1])

    def test_state_is_private_and_in_bound_directory(self):
        save_json('activation.json', {'secret': 'example'})
        path = state_path('activation.json')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text()), {'secret': 'example'})

    def test_telegram_exception_hides_token(self):
        with patch('urllib.request.urlopen', side_effect=ValueError('secret-token')):
            with self.assertRaises(RuntimeError) as ctx:
                Telegram('secret-token').call('getMe')
        self.assertNotIn('secret-token', str(ctx.exception))


class RuntimeTests(unittest.TestCase):
    def check_reconnect(self, startup_message):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, AUTH_STATE_DIR=directory):
            save_json('telegram.json', {'bot_token': 'fake', 'chat_id': 42, 'user_id': 42})
            save_json('checkin_info.json', {'androidId': 1, 'securityToken': 2})
            first, second = Mock(), Mock()
            first.pushes, second.pushes = [], []
            first.ready.is_set.return_value = False
            second.ready.is_set.return_value = True
            second.is_alive.return_value = True

            def disconnect():
                # Push arrives after the runtime's initial queue drain.
                first.pushes.append({'app_data': {'type': 'auth', 'guid': 'last-push',
                                                  'url': 'example.microsoft.com',
                                                  'source': 'SAS'}})
                return False

            first.is_alive.side_effect = disconnect
            bridge = Mock()
            bridge.poll.side_effect = [None, None, RuntimeError('end-test')]
            tg = Mock()
            tg.call.return_value = {}
            ticks = itertools.count()
            with patch('app.registration_runtime.RegistrationCoordinator'), \
                    patch('app.service.load_bot', return_value=tg), \
                    patch('app.service.Bridge', return_value=bridge), \
                    patch('app.service.McsListener', side_effect=[first, second]), \
                    patch('app.service.signal.signal'), \
                    patch('app.service.time.sleep'), \
                    patch('app.service.time.monotonic', side_effect=lambda: next(ticks)):
                with self.assertRaisesRegex(RuntimeError, 'end-test'):
                    run(config=Config(startup_message=startup_message))
            bridge.capture.assert_called_once_with({'type': 'auth', 'guid': 'last-push',
                                                    'url': 'example.microsoft.com',
                                                    'source': 'SAS'})
            first.stop.assert_called_once()
            second.start.assert_called_once()
            second.stop.assert_called_once()
            if startup_message:
                bridge.notify.assert_called_once()
                self.assertIn('connected', bridge.notify.call_args.args[0])
            else:
                bridge.notify.assert_not_called()
            bridge.db.close.assert_called_once()


    def test_reconnect_preserves_final_push_and_announces_only_ready_connection(self):
        self.check_reconnect(startup_message=True)

    def test_startup_announcements_can_be_disabled(self):
        self.check_reconnect(startup_message=False)


class McsTransportTests(unittest.TestCase):
    def test_timeout_during_partial_frame_preserves_bytes(self):
        listener = McsListener(1, 2)
        sock = Mock()
        sock.recv.side_effect = [b'a', socket.timeout(), b'bc']
        self.assertEqual(listener._read_exact(sock, 3), b'abc')

    def test_idle_heartbeat_then_disconnect(self):
        listener = McsListener(1, 2)
        sock = Mock()
        sock.recv.side_effect = socket.timeout()
        with patch('app.mcs.time.monotonic', side_effect=[0, 46, 91]):
            with self.assertRaises(ConnectionError):
                listener._read_exact(sock, 1)
        sock.sendall.assert_called_once_with(bytes([0, 0]))

    def test_stop_interrupts_socket(self):
        listener = McsListener(1, 2)
        listener.sock = Mock()
        listener.stop()
        listener.sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)


if __name__ == '__main__':
    unittest.main()
