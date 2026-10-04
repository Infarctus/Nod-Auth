"""Configuration, disabled routing, provider boundaries, and state migration."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch

from app.bots import load_bot, setup_bot
from app.bots.base import Reply, Update
from app.bots.telegram import TelegramProvider
from app.config import Config, ConfigError, load_config
from app.service import Bridge, run
from app.state import state_path, save_json
from test.entra_fixtures import ACCOUNT


class ConfigTests(unittest.TestCase):
    def load(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            path.write_text(content)
            return load_config(path)

    def test_defaults_and_overrides(self):
        self.assertEqual(self.load(''), Config())
        config = self.load('''
[notifications]
enabled = false
startup_message = false
[approval]
timeout_seconds = 45
max_pending = 3
[bots.telegram]
chat_id = 42
user_id = 42
''')
        self.assertFalse(config.enabled)
        self.assertFalse(config.startup_message)
        self.assertEqual(config.timeout_seconds, 45)
        self.assertEqual(config.max_pending, 3)
        self.assertEqual(config.bot_options, {'chat_id': 42, 'user_id': 42})

    def test_invalid_settings_fail_before_network(self):
        for content in ('[enrollment]\ndevice_name=8',
                        '[enrollment]\ndevice_name=false',
                        '[enrollment]\nname="test"', 'enrollment=1',
                        '[notifications]\nenabled="false"',
                        '[notifications]\nprovider="unknown"',
                        '[approval]\ntimeout_seconds=0',
                        '[approval]\nmax_pending=true',
                        '[bots.telegram]\nchat_id=-1\nuser_id=42',
                        '[bots.telegram]\nchat_id=42',
                        '[notifications]\nenabeld=false',
                        '[bots.unknown]', 'notifications=1',
                        '[bots.telegram]\nbot_token="secret"', '[bad'):
            with self.subTest(content=content), self.assertRaises(ConfigError) as error:
                self.load(content)
            self.assertNotIn('secret', str(error.exception))

    def test_custom_enrollment_name_reaches_xml_as_text(self):
        from app.activation import build_activate
        name = '  Nod Auth & <Authenticator> "é" 📱  '
        config = self.load('[enrollment]\ndevice_name=' + json.dumps(name, ensure_ascii=False))
        self.assertEqual(config.device_name, name)
        with patch('app.app_identity.app_version', return_value='6.2609.6214'):
            root = ET.fromstring(build_activate('code', 'token', config.device_name, 1))
        self.assertEqual(root.findtext('.//{*}DeviceName'), name)
        self.assertEqual(len(root.findall('.//{*}DeviceName')), 1)

    def test_experimental_names_have_no_local_length_restriction(self):
        for name in ('', ' ', 'x' * 2048):
            with self.subTest(name_length=len(name)):
                self.assertEqual(self.load('[enrollment]\ndevice_name=' + json.dumps(name)).device_name, name)

    def test_discord_provider_options(self):
        config = self.load('[notifications]\nprovider="discord"\n[bots.discord]\nbot_token="fake-token"\nuser_id="123456789012345678"')
        self.assertEqual(config.provider, 'discord')
        self.assertEqual(config.bot_options, {'bot_token': 'fake-token', 'user_id': '123456789012345678'})
        self.assertEqual(self.load('[notifications]\nprovider="discord"').bot_options, {})

    def test_missing_config_is_error(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ConfigError):
            load_config(Path(directory) / 'missing.toml')

    def test_disabled_does_not_initialize_or_pair_provider(self):
        with patch('app.bots.TelegramProvider.load') as load, patch('app.bots.TelegramProvider.setup') as setup:
            self.assertIsNone(load_bot(Config(enabled=False)))
            setup_bot(Config(enabled=False))
            load.assert_not_called()
            setup.assert_not_called()
        with self.assertRaises(ConfigError):
            run(once=True, config=Config(enabled=False))


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict('os.environ', AUTH_STATE_DIR=self.tmp.name)
        self.env.start()
        state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
        state_path('fcm_token.txt').write_text('fake-token')
        self.push = {'guid': 'fake-request', 'source': 'SAS', 'url': 'example.microsoft.com',
                     'firstEntropyChallenge': '12'}

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def bridge(self, bot, config):
        bridge = Bridge(bot, config, submit=Mock(return_value=(200, '<validationResult>6</validationResult>')))
        self.addCleanup(bridge.db.close)
        return bridge

    def test_disabled_mode_sends_and_submits_nothing(self):
        bot = Mock()
        bridge = self.bridge(bot, Config(enabled=False))
        bridge.capture(self.push)
        bridge.handle(Reply('fake-message', '12'))
        bridge.poll()
        self.assertFalse(bot.mock_calls)
        bridge.submit.assert_not_called()
        self.assertFalse(bridge.pending)
        self.assertFalse(bridge.approved)

    def test_generic_provider_approval_and_replacement(self):
        # Uses opaque IDs/cursors and no Telegram message schema.
        bot = Mock()
        bot.request.return_value = 'custom/request-a'
        bridge = self.bridge(bot, Config(provider='custom', timeout_seconds=45, max_pending=1))
        with patch('app.service.time.monotonic', return_value=100):
            bridge.capture(self.push)
        self.assertEqual(bridge.pending['custom/request-a'][1], 145)
        self.assertIn('45 seconds', bot.request.call_args.args[0])
        bot.request.return_value = 'custom/request-b'
        with patch('app.service.time.monotonic', return_value=101):
            bridge.capture(dict(self.push, guid='another-request'))
        self.assertEqual(bot.request.call_count, 2)
        self.assertEqual(bot.update_request.call_args.kwargs['status'], 'cancelled')
        self.assertNotIn('custom/request-a', bridge.pending)
        bot.updates.return_value = [Update('opaque/cursor', Reply('custom/request-b', '12'))]
        with patch('app.service.time.monotonic', return_value=101):
            bridge.poll()
        self.assertTrue(bridge.approved)
        self.assertEqual(bridge.offset, 'opaque/cursor')
        self.assertEqual(self.bridge(bot, Config(provider='custom')).offset, 'opaque/cursor')
        self.assertEqual(self.bridge(bot, Config()).offset, '0')

    def test_legacy_telegram_cursor_is_preserved(self):
        with sqlite3.connect(state_path('requests.sqlite3')) as db:
            db.execute('CREATE TABLE cursor (id INTEGER PRIMARY KEY, value INTEGER)')
            db.execute('INSERT INTO cursor VALUES (1, 123)')
        bridge = self.bridge(Mock(), Config())
        self.assertEqual(bridge.offset, '123')

    def test_existing_telegram_credentials_and_destination_override(self):
        credentials = {'bot_token': 'fake-secret', 'chat_id': 42, 'user_id': 42}
        save_json('telegram.json', credentials)
        bot = TelegramProvider.load({})
        self.assertEqual(bot.credentials, credentials)
        moved = TelegramProvider.load({'chat_id': 73, 'user_id': 73})
        accepted = {'update_id': 5, 'message': {'from': {'id': 73},
                    'chat': {'id': 73, 'type': 'private'}, 'text': '12',
                    'reply_to_message': {'message_id': 7}}}
        self.assertEqual(moved.parse_update(accepted).reply, Reply('7', '12'))
        accepted['message']['from']['id'] = 42
        self.assertIsNone(moved.parse_update(accepted).reply)
        self.assertEqual(json.loads(state_path('telegram.json').read_text()), credentials)

    def test_fresh_setup_activates_then_runs_bot_test(self):
        from app.setup import main
        save_json('apk_config.json', {'fake': True})
        config = Config(device_name='Custom enrollment name')
        calls = Mock()
        with patch('app.setup.load_config', return_value=config), \
                patch('app.fcm.do_checkin', return_value={}), \
                patch('app.fcm.do_register') as register, \
                patch('app.activation.activate', calls.activate), \
                patch('app.setup.run', calls.run), \
                patch('app.setup.setup_bot'), \
                patch('builtins.input', return_value='https://example.test/activatev2'), \
                patch('app.setup.getpass.getpass', return_value='one-time-code'):
            main()
        register.assert_not_called()
        self.assertEqual(calls.mock_calls, [
            unittest.mock.call.activate('https://example.test/activatev2', 'one-time-code',
                                        device_name='Custom enrollment name'),
            unittest.mock.call.run(once=True, config=config),
        ])

    def test_unverified_reuse_runs_test_even_with_old_completion_marker(self):
        from app.setup import main
        save_json('apk_config.json', {'fake': True})
        save_json('activation.json', ACCOUNT)
        save_json('setup_complete.json', {'confirmed_at': 123})
        config = Config()
        with patch('app.setup.load_config', return_value=config), \
             patch('app.fcm.do_checkin', return_value={}), \
             patch('app.setup.setup_bot'), patch('app.activation.activate') as activate, \
             patch('app.setup.run') as runtime, patch('builtins.input', return_value=''):
            main()
        activate.assert_not_called()
        runtime.assert_called_once_with(once=True, config=config)
        self.assertFalse(state_path('setup_complete.json').exists())
        self.assertEqual(json.loads(state_path('activation.json').read_text()), ACCOUNT)

    def test_invalid_saved_account_cannot_finish_setup(self):
        from app.setup import main
        save_json('apk_config.json', {'fake': True})
        save_json('activation.json', {'fake': True})
        with patch('app.setup.load_config', return_value=Config()), \
             patch('app.fcm.do_checkin', return_value={}), patch('app.setup.setup_bot'), \
             patch('app.setup.run') as runtime, patch('builtins.input', return_value=''):
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                main()
        runtime.assert_not_called()
        self.assertFalse(state_path('setup_complete.json').exists())

    def test_disabled_setup_reuses_activation_without_claiming_approval_test(self):
        from app.setup import main
        save_json('apk_config.json', {'fake': True})
        save_json('activation.json', ACCOUNT)
        with patch('app.setup.load_config', return_value=Config(enabled=False)), \
                patch('app.fcm.do_checkin', return_value={}), \
                patch('app.fcm.do_register') as register, \
                patch('app.setup.run') as runtime, \
                patch('builtins.input', return_value=''), \
                patch('app.bots.TelegramProvider.setup') as pair:
            main()
        register.assert_not_called()
        runtime.assert_not_called()
        pair.assert_not_called()
        self.assertFalse(state_path('setup_complete.json').exists())
        self.assertEqual(json.loads(state_path('activation.json').read_text()), ACCOUNT)


if __name__ == '__main__':
    unittest.main()
