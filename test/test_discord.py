"""Offline Discord authorization, setup, polling and transport tests."""
import io
import json
import socket
import ssl
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

from app.bots import load_bot
from app.bots.base import BotError, Reply
from app.bots.discord import Discord, DiscordBot, DiscordProvider, RateLimited
from app.config import Config, ConfigError
from app.state import state_path, save_json


class DiscordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict('os.environ', AUTH_STATE_DIR=self.tmp.name)
        env.start()
        self.addCleanup(env.stop)
        state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
        self.credentials = {'bot_token': 'fake-secret', 'user_id': '42'}
        self.client = Mock()
        self.bot = DiscordBot(self.client, self.credentials)
        self.bot.channel_id = '73'
        self.message = {'id': '103', 'channel_id': '73', 'type': 19,
                        'author': {'id': '42'}, 'content': '12',
                        'message_reference': {'message_id': '101', 'channel_id': '73'}}

    def test_authorization_and_reply_binding(self):
        self.assertEqual(self.bot.parse_update(self.message).reply, Reply('101', '12'))
        for change in ({'author': {'id': '99'}}, {'author': {'id': '42', 'bot': True}},
                       {'channel_id': '99'}, {'guild_id': '99'}, {'type': 0},
                       {'webhook_id': '99'}, {'content': None},
                       {'message_reference': None},
                       {'message_reference': {'message_id': '101', 'channel_id': '99'}},
                       {'message_reference': {'message_id': '101', 'channel_id': '73', 'type': 1}}):
            message = dict(self.message, **change)
            with self.subTest(change=change):
                update = self.bot.parse_update(message)
                self.assertIsNone(update.reply)
                self.assertEqual(update.cursor, '73:103')

    def test_dm_discovery_and_baseline(self):
        self.client.call.side_effect = [{'bot': True, 'id': '7'}, {'type': 1, 'id': '73', 'recipients': [{'id': '42'}]}, [{'id': '100'}]]
        self.bot.check()
        self.assertEqual(self.bot.channel_id, '73')
        self.assertEqual(self.bot.initial_cursor, '100')
        self.client.call.side_effect = None
        self.client.call.return_value = []
        self.bot.updates('different-channel:999')
        self.client.call.assert_called_with('GET', '/channels/73/messages?after=100&limit=100')

    def test_reject_non_private_channel_or_wrong_recipient(self):
        for channel in ({'type': 3}, {'type': 1, 'recipients': [{'id': '99'}]}):
            self.client.call.side_effect = [{'bot': True, 'id': '7'}, channel]
            with self.assertRaises(RuntimeError):
                self.bot.check()

    def test_order_cursor_and_poll_throttle(self):
        self.client.call.return_value = [self.message, dict(self.message, id='102')]
        with patch('app.bots.discord.time.monotonic', return_value=10):
            updates = self.bot.updates('73:101')
            self.assertEqual([u.cursor for u in updates], ['73:102', '73:103'])
            self.assertEqual(self.bot.updates('73:103'), [])
        self.client.call.assert_called_once_with('GET', '/channels/73/messages?after=101&limit=100')

    def test_rate_limit_defers_poll_without_advancing_cursor(self):
        self.client.call.side_effect = RateLimited(7)
        with patch('app.bots.discord.time.monotonic', return_value=10):
            self.assertEqual(self.bot.updates('0'), [])
        self.assertEqual(self.bot.next_poll, 17)

    def test_send_disables_mentions(self):
        self.client.call.return_value = {'id': '101'}
        self.assertEqual(self.bot.request('request'), '101')
        self.client.call.assert_called_once_with(
            'POST', '/channels/73/messages',
            embeds=[{'title': 'Microsoft sign-in', 'description': 'request', 'color': 0x0078D4}],
            allowed_mentions={'parse': []})

    def test_config_and_saved_credentials(self):
        for options in ({'user_id': True}, {'user_id': 0}, {'user_id': 'abc'},
                        {'user_id': 2**64}, {'bot_token': ''}, {'bot_token': 'secret\n'}, {'channel_id': 1}):
            with self.subTest(options=options), self.assertRaises(ConfigError):
                DiscordProvider.validate_options(options)
        self.assertEqual(DiscordProvider.load(self.credentials).credentials, self.credentials)
        save_json('discord.json', self.credentials)
        self.assertEqual(DiscordProvider.load({'user_id': 43}).credentials['user_id'], 43)
        with patch.object(DiscordBot, 'check') as check:
            self.assertIsInstance(load_bot(Config(provider='discord')), DiscordBot)
            check.assert_called_once()

    def test_setup_prompts_only_for_missing_values_and_saves_after_delivery(self):
        with patch('app.bots.discord.getpass.getpass', return_value='fake-secret') as token, \
                patch('builtins.input', return_value='42') as user, \
                patch.object(DiscordBot, 'check'), patch.object(DiscordBot, 'notify'):
            DiscordProvider.setup({})
            token.assert_called_once()
            user.assert_called_once()
            self.assertEqual(json.loads(state_path('discord.json').read_text()), self.credentials)
            self.assertEqual(state_path('discord.json').stat().st_mode & 0o777, 0o600)
            token.reset_mock(); user.reset_mock()
            DiscordProvider.setup({})
            token.assert_not_called(); user.assert_not_called()

    def test_failed_setup_does_not_save(self):
        with patch.object(DiscordBot, 'check'), patch.object(DiscordBot, 'notify', side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                DiscordProvider.setup(self.credentials)
        self.assertFalse(state_path('discord.json').exists())

    def test_bridge_approval_is_correlated_consumed_and_cursor_persisted(self):
        from app.service import Bridge
        state_path('fcm_token.txt').write_text('fake-token')
        submit = Mock(return_value=(200, '<validationResult>6</validationResult>'))
        config = Config(provider='discord')
        bridge = Bridge(self.bot, config, submit=submit)
        self.addCleanup(bridge.db.close)
        self.client.call.return_value = {'id': '101'}
        bridge.capture({'guid': 'test-request', 'source': 'SAS',
                        'url': 'example.microsoft.com', 'firstEntropyChallenge': '12'})
        # A reply to another message must not consume the pending request.
        wrong = dict(self.message, message_reference={'message_id': '99', 'channel_id': '73'})
        bridge.handle(self.bot.parse_update(wrong).reply)
        submit.assert_not_called()
        self.client.call.side_effect = [[self.message, dict(self.message, id='104')], {'id': '105'}]
        bridge.poll()
        submit.assert_called_once()
        self.assertTrue(bridge.approved)
        self.assertFalse(bridge.pending)
        restarted = Bridge(self.bot, config, submit=submit)
        self.addCleanup(restarted.db.close)
        self.assertEqual(restarted.offset, '73:104')
        self.assertFalse(restarted.pending)

    def test_button_approval_is_not_lost_when_rest_polling_fails(self):
        from app.bots.discord_gateway import DiscordGateway
        from app.service import Bridge

        state_path('fcm_token.txt').write_text('fake-token')
        submit = Mock(return_value=(200, '<validationResult>6</validationResult>'))
        bridge = Bridge(self.bot, Config(provider='discord'), submit=submit)
        self.addCleanup(bridge.db.close)
        self.client.call.return_value = {'id': '101'}
        bridge.capture({'guid': 'test-click', 'source': 'SAS',
                        'url': 'example.microsoft.com', 'firstEntropyChallenge': '12'})
        self.bot.gateway = DiscordGateway(self.credentials, self.bot.channel_id)
        self.bot.gateway.replies.put_nowait(Reply('101', '12'))
        self.client.reset_mock()

        def call(method, path, **data):
            if method == 'GET':
                raise BotError('Discord unavailable')
            return {}

        self.client.call.side_effect = call
        bridge.poll()
        submit.assert_called_once()
        self.assertIn('<selectedEntropyNumber>12</selectedEntropyNumber>', submit.call_args.args[1])
        self.assertTrue(bridge.approved)
        self.assertFalse(bridge.pending)
        self.assertEqual(bridge.offset, '0')
        self.assertTrue(all(call.args[0] == 'PATCH' for call in self.client.call.call_args_list))
        # REST polling still runs on the next call, without replaying the click.
        bridge.poll()
        self.client.call.assert_called_with('GET', '/channels/73/messages?after=0&limit=100')
        self.assertGreater(bridge.poll_retry_at, 0)
        self.assertEqual(bridge.offset, '0')
        submit.assert_called_once()

    def test_http_diagnostics_survive_setup_without_response_secrets(self):
        from app.setup import failure_message
        for status, code, phrase in ((401, 0, 'token was rejected'),
                                     (403, 50007, 'cannot deliver a DM'),
                                     (403, 50278, 'share no server'),
                                     (404, 10013, 'could not find the user'),
                                     (403, 50001, 'lacks access'),
                                     (403, 40333, 'denied access'),
                                     (500, 0, 'availability')):
            with self.subTest(status=status, code=code):
                body = json.dumps({'code': code, 'message': 'fake-secret'}).encode()
                error = urllib.error.HTTPError('fake-secret', status, 'fake-secret', {}, io.BytesIO(body))
                with patch('urllib.request.urlopen', side_effect=error), self.assertRaises(BotError) as caught:
                    Discord('fake-secret').call('POST', '/channels/73/messages', content='private')
                output = failure_message(caught.exception)
                self.assertIn('sending a DM', output)
                self.assertIn(f'HTTP {status}', output)
                self.assertIn(phrase, output)
                self.assertNotIn('fake-secret', output)
                self.assertNotIn('private', output)

    def test_non_json_http_error_and_untrusted_error_code(self):
        for body in (b'<html>fake-secret</html>', b'[]', b'{"code":"fake-secret"}'):
            error = urllib.error.HTTPError('fake-secret', 403, 'fake-secret', {}, io.BytesIO(body))
            with patch('urllib.request.urlopen', side_effect=error), self.assertRaises(BotError) as caught:
                Discord('fake-secret').call('POST', '/users/@me/channels', recipient_id='42')
            self.assertIn('opening your DM channel', str(caught.exception))
            self.assertIn('HTTP 403', str(caught.exception))
            self.assertNotIn('fake-secret', str(caught.exception))

    def test_network_diagnostics_redact_underlying_exceptions(self):
        for reason, phrase in ((socket.gaierror('fake-secret'), 'DNS lookup failed'),
                               (TimeoutError('fake-secret'), 'timed out'),
                               (ssl.SSLCertVerificationError('fake-secret'), 'certificate verification'),
                               (ConnectionResetError('fake-secret'), 'network request failed')):
            with self.subTest(phrase=phrase):
                with patch('urllib.request.urlopen', side_effect=urllib.error.URLError(reason)), self.assertRaises(BotError) as caught:
                    Discord('fake-secret').call('GET', '/users/@me')
                self.assertIn('checking the bot token', str(caught.exception))
                self.assertIn(phrase, str(caught.exception))
                self.assertNotIn('fake-secret', str(caught.exception))

    def test_transport_redaction_and_rate_limit(self):
        client = Discord('fake-secret')
        with patch('urllib.request.urlopen', side_effect=ValueError('fake-secret')):
            with self.assertRaises(RuntimeError) as error:
                client.call('GET', '/users/@me')
            self.assertNotIn('fake-secret', str(error.exception))
        error = urllib.error.HTTPError('url', 429, 'limited', {}, io.BytesIO(b'{"retry_after": 3}'))
        with patch('urllib.request.urlopen', side_effect=error):
            with self.assertRaises(RateLimited) as caught:
                client.call('GET', '/users/@me')
            self.assertEqual(caught.exception.retry_after, 3)


if __name__ == '__main__':
    unittest.main()
