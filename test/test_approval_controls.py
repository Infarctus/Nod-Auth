"""Optional plain messages and buttons retain authorization and request binding."""
import asyncio
import copy
from dataclasses import replace
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from app.bots.base import Reply, Update
from app.bots.discord import DiscordBot, RateLimited
from app.bots.discord_gateway import DiscordGateway
from app.bots.telegram import Telegram, TelegramBot
from app.config import Config, ConfigError, load_config
from app.service import Bridge
from app.state import state_path


class ControlsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        env = patch.dict('os.environ', AUTH_STATE_DIR=directory.name)
        env.start()
        self.addCleanup(env.stop)
        state_path('apk_config.json').write_text('{"package": "com.azure.authenticator", "version_name": "6.2609.6214"}')
        state_path('fcm_token.txt').write_text('fake-token')
        self.client = Mock()
        self.client.send.return_value = {'message_id': 10}
        self.bot = TelegramBot(self.client, {'user_id': 42, 'chat_id': 42})
        self.submit = Mock(return_value=(200, '<validationResult>6</validationResult>'))
        self.bridge = Bridge(self.bot, Config(), self.submit)
        self.addCleanup(self.bridge.db.close)
        self.push = {'guid': 'one', 'source': 'SAS', 'url': 'example.microsoft.com',
                     'firstEntropyChallenge': '12', 'secondEntropyChallenge': '34',
                     'thirdEntropyChallenge': '56'}

    def test_number_outside_choices_is_silently_ignored_and_request_stays_live(self):
        self.bridge.capture(self.push)
        self.client.reset_mock()
        for answer in ('99', '999', '0'):
            self.bridge.handle(Reply('10', answer))
        self.submit.assert_not_called()
        self.client.assert_not_called()
        self.client.send.assert_not_called()
        self.client.call.assert_not_called()
        self.assertIn('10', self.bridge.pending)
        self.bridge.handle(Reply('10', '34'))
        self.submit.assert_called_once()

    def test_partial_choices_never_submit_an_unlisted_number(self):
        self.bridge.capture(dict(self.push, thirdEntropyChallenge=''))
        self.bridge.handle(Reply('10', '99'))
        self.submit.assert_not_called()
        self.assertIn('10', self.bridge.pending)
        self.bridge.handle(Reply('10', '12'))
        self.submit.assert_called_once()

    def callback(self, value='12', **changes):
        query = {'id': 'click', 'from': {'id': 42}, 'data': 'approval:' + value,
                 'message': {'message_id': 10, 'chat': {'id': 42, 'type': 'private'}}}
        query.update(changes)
        return self.bot.parse_update({'update_id': 20, 'callback_query': query})

    def test_buttons_submit_selected_number_once_and_acknowledge(self):
        self.bridge.config = replace(self.bridge.config, show_number_buttons=True)
        self.bridge.capture(self.push)
        markup = self.client.send.call_args.kwargs['reply_markup']['inline_keyboard'][0]
        self.assertEqual([button['text'] for button in markup], ['12', '34', '56', 'DENY'])
        update = self.callback('34')
        self.assertEqual(update.cursor, '21')
        self.client.call.assert_called_with('answerCallbackQuery', callback_query_id='click')
        self.bridge.handle(update.reply)
        self.bridge.handle(update.reply)
        self.submit.assert_called_once()
        self.assertIn('<selectedEntropyNumber>34</selectedEntropyNumber>', self.submit.call_args.args[1])

    def test_callback_authorization_and_expiry(self):
        self.bridge.capture(self.push)
        for changes in ({'from': {'id': 99}}, {'from': {'id': 42, 'is_bot': True}},
                        {'message': {'message_id': 10, 'chat': {'id': 99, 'type': 'private'}}},
                        {'message': {'message_id': 10, 'chat': {'id': 42, 'type': 'group'}}},
                        {'message': {}}, {'data': 'approval:999'}, {'data': '<xml>'}):
            with self.subTest(changes=changes):
                self.assertIsNone(self.callback(**changes).reply)
        self.bridge.handle(self.callback(message={'message_id': 99, 'chat': {'id': 42, 'type': 'private'}}).reply)
        ad, _, numbered = self.bridge.pending['10']
        self.bridge.pending['10'] = (ad, time.monotonic() - 1, numbered)
        self.bridge.handle(self.callback().reply)
        self.submit.assert_not_called()

    def test_deny_button_submits_denial(self):
        self.bridge.capture(self.push)
        self.submit.return_value = (200, '<result>1</result>')
        self.bridge.handle(self.callback('DENY').reply)
        self.assertIn('<authenticationResult>2</authenticationResult>', self.submit.call_args.args[1])
        self.assertFalse(self.bridge.approved)

    def test_plain_message_toggle_and_ambiguity(self):
        message = {'update_id': 20, 'message': {'message_id': 11, 'from': {'id': 42},
                   'chat': {'id': 42, 'type': 'private'}, 'text': '12'}}
        self.assertIsNone(self.bot.parse_update(message).reply)
        self.bot.require_reply = False
        reply = self.bot.parse_update(message).reply
        self.assertEqual(reply, Reply(None, '12', '11'))
        self.bridge.capture(self.push)
        self.bridge.handle(reply)  # Service independently enforces the default.
        self.submit.assert_not_called()
        self.bridge.config = replace(self.bridge.config, require_reply=False)
        self.bridge.handle(Reply(None, '12', '9'))  # Queued before the prompt.
        self.bridge.handle(Reply(None, '12'))
        self.submit.assert_not_called()
        self.client.send.return_value = {'message_id': 12}
        self.bridge.capture(dict(self.push, guid='two'))
        self.bridge.handle(reply)
        self.submit.assert_not_called()
        self.bridge.handle(Reply('10', '12'))
        self.bridge.handle(Reply(None, '34', '13'))
        self.assertEqual(self.submit.call_count, 1)
        self.assertNotIn('reply_markup', self.client.send.call_args.kwargs)

    def test_partial_invalid_duplicate_choices_fall_back_to_text(self):
        self.bridge.config = replace(self.bridge.config, show_number_buttons=True)
        for index, value in enumerate(('', '999', '１２', '<xml>', '12')):
            self.bridge.capture(dict(self.push, guid=str(index), thirdEntropyChallenge=value))
            self.assertEqual(self.client.send.call_args.kwargs['reply_markup'],
                             {'force_reply': True, 'selective': True})
        self.bridge.capture({'guid': 'plain', 'source': 'SAS', 'url': 'example.microsoft.com'})
        markup = self.client.send.call_args.kwargs['reply_markup']['inline_keyboard'][0]
        self.assertEqual([button['text'] for button in markup], ['APPROVE', 'DENY'])

    def test_buttons_hidden_by_default(self):
        self.bridge.capture(self.push)
        self.assertNotIn('inline_keyboard', self.client.send.call_args.kwargs['reply_markup'])

    def test_config_boolean_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            path.write_text('[approval]\nrequire_reply=false\nshow_number_buttons=true\n')
            config = load_config(path)
            self.assertFalse(config.require_reply)
            self.assertTrue(config.show_number_buttons)
            for key in ('require_reply', 'show_number_buttons'):
                path.write_text(f'[approval]\n{key}="true"\n')
                with self.assertRaises(ConfigError):
                    load_config(path)

    def test_telegram_poll_subscribes_to_callbacks(self):
        telegram = Telegram('fake')
        with patch.object(telegram, 'call', return_value=[]) as call:
            telegram.updates(21)
        self.assertEqual(call.call_args.kwargs['allowed_updates'], ['message', 'callback_query'])

    def test_button_status_edits_surround_submission_and_remove_keyboard(self):
        self.bridge.config = replace(self.bridge.config, show_number_buttons=True)
        self.bridge.capture(self.push)
        events = []
        self.client.call.side_effect = lambda method, **data: events.append((method, data))

        def submit(*args):
            self.assertNotIn('10', self.bridge.pending)
            events.append(('submit', {}))
            return 200, '<validationResult>6</validationResult>'

        self.submit.side_effect = submit
        self.bridge.handle(Reply('10', '34'))
        self.bridge.handle(Reply('10', '34'))
        self.assertEqual([event[0] for event in events], ['editMessageText', 'submit', 'editMessageText'])
        for _, data in (events[0], events[2]):
            self.assertEqual(data['chat_id'], 42)
            self.assertEqual(data['message_id'], 10)
            self.assertEqual(data['reply_markup'], {'inline_keyboard': []})
        self.assertIn('Sending…', events[0][1]['text'])
        self.assertIn('Sign-in approved.', events[2][1]['text'])
        self.client.send.assert_called_once()  # No duplicate result notification.
        self.assertFalse(self.bridge.button_requests)
        self.submit.assert_called_once()

    def test_button_result_states_include_deny_rejection_and_unknown_result(self):
        self.bridge.config = replace(self.bridge.config, show_number_buttons=True)
        cases = [
            ('DENY', (200, '<result>1</result>'), None, 'denied', 'Denial sent.'),
            ('12', (200, '<validationResult>2</validationResult>'), None,
             'failed', 'Microsoft did not confirm success'),
            ('12', None, TimeoutError(), 'failed', 'Could not confirm the result'),
        ]
        for index, (answer, result, error, status, text) in enumerate(cases):
            with self.subTest(status=status, text=text):
                self.bridge.capture(dict(self.push, guid=str(index)))
                self.submit.return_value, self.submit.side_effect = result, error
                with patch.object(self.bot, 'update_request') as edit:
                    self.bridge.handle(Reply('10', answer))
                self.assertEqual(edit.call_args_list[0].args, ('10', 'Sending…'))
                self.assertEqual(edit.call_args.kwargs['status'], status)
                self.assertIn(text, edit.call_args.args[1])

    def test_edit_failures_do_not_cancel_or_repeat_submission(self):
        self.bridge.config = replace(self.bridge.config, show_number_buttons=True)
        self.bridge.capture(self.push)
        with patch.object(self.bot, 'update_request', side_effect=RuntimeError('unavailable')) as edit:
            self.bridge.handle(Reply('10', '12'))
            self.bridge.handle(Reply('10', '12'))
        self.assertEqual(edit.call_count, 2)
        self.submit.assert_called_once()
        self.assertTrue(self.bridge.approved)
        self.client.send.assert_called_with(42, 'Sign-in approved.')

    def test_text_requests_are_edited_without_buttons(self):
        for index, enabled in enumerate((False, True)):
            self.bridge.config = replace(self.bridge.config, show_number_buttons=enabled)
            self.bridge.capture(dict(self.push, guid=str(index), thirdEntropyChallenge=''))
            with patch.object(self.bot, 'update_request') as edit:
                self.bridge.handle(Reply('10', '12'))
                self.assertEqual(edit.call_count, 2)
                self.assertEqual(edit.call_args.kwargs['status'], 'succeeded')

    def test_invalid_and_unknown_replies_do_not_edit_buttons(self):
        self.bridge.config = replace(self.bridge.config, show_number_buttons=True)
        self.bridge.capture(self.push)
        with patch.object(self.bot, 'update_request') as edit:
            self.bridge.handle(Reply('99', '12'))
            self.bridge.handle(Reply('10', 'invalid'))
            edit.assert_not_called()
        self.submit.assert_not_called()

    def test_button_expiry_edits_message_without_submission(self):
        self.bridge.config = replace(self.bridge.config, show_number_buttons=True)
        for index, use_poll in enumerate((False, True)):
            self.bridge.capture(dict(self.push, guid=str(index)))
            ad, _, numbered = self.bridge.pending['10']
            self.bridge.pending['10'] = (ad, time.monotonic() - 1, numbered)
            with patch.object(self.bot, 'update_request') as edit:
                if use_poll:
                    self.client.updates.return_value = []
                    self.bridge.poll()
                else:
                    self.bridge.handle(Reply('10', '12'))
                edit.assert_called_once()
                self.assertEqual(edit.call_args.kwargs['status'], 'expired')
            self.assertFalse(self.bridge.button_requests)
        self.submit.assert_not_called()

    def test_new_request_cancels_old_before_sending_and_stale_reply_is_ignored(self):
        for buttons in (False, True):
            with self.subTest(buttons=buttons):
                self.bridge.config = replace(self.bridge.config, show_number_buttons=buttons, max_pending=1)
                self.client.send.return_value = {'message_id': 10}
                self.bridge.capture(dict(self.push, guid=f'old-{buttons}'))
                self.client.send.return_value = {'message_id': 20}
                with patch.object(self.bot, 'update_request') as edit:
                    self.bridge.capture(dict(self.push, guid=f'new-{buttons}'))
                self.assertEqual(edit.call_args.args[0], '10')
                self.assertEqual(edit.call_args.kwargs['status'], 'cancelled')
                self.assertEqual(set(self.bridge.pending), {'20'})
                self.assertNotIn('10', self.bridge.button_requests)
                self.bridge.handle(Reply('10', '12'))
                self.submit.assert_not_called()
                self.bridge.handle(Reply('20', '12'))
                self.submit.assert_called_once()
                self.submit.reset_mock()

    def test_duplicate_does_not_cancel_current_request_or_extend_deadline(self):
        self.bridge.capture(self.push)
        original = self.bridge.pending.copy()
        with patch.object(self.bot, 'update_request') as edit:
            self.bridge.capture(self.push)
        edit.assert_not_called()
        self.assertEqual(self.bridge.pending, original)
        self.client.send.assert_called_once()

    def test_poll_failure_expires_requests_and_recovers_with_backoff(self):
        with patch('app.service.time.monotonic', return_value=100):
            self.bridge.capture(self.push)
            self.client.updates.side_effect = TimeoutError()
            self.bridge.poll()
        with patch('app.service.time.monotonic', return_value=100.5):
            self.bridge.poll()
        self.client.updates.assert_called_once()
        self.client.updates.side_effect = None
        self.client.updates.return_value = []
        with patch('app.service.time.monotonic', return_value=200):
            self.bridge.poll()
        self.assertFalse(self.bridge.pending)
        self.assertIn('expired', self.client.call.call_args.kwargs['text'])
        self.assertEqual(self.client.updates.call_count, 2)
        self.bridge.handle(Reply('10', '12'))
        self.submit.assert_not_called()
        self.client.send.return_value = {'message_id': 20}
        self.bridge.capture(dict(self.push, guid='recovered'))
        self.bridge.handle(Reply('20', '12'))
        self.submit.assert_called_once()

    def test_expiry_during_failed_poll_and_failed_notifications_is_safe(self):
        with patch('app.service.time.monotonic', return_value=100):
            self.bridge.capture(self.push)
        self.client.updates.side_effect = TimeoutError()
        self.client.call.side_effect = RuntimeError()
        self.client.send.side_effect = RuntimeError()
        with patch('app.service.time.monotonic', side_effect=[180, 180, 200, 200]):
            self.bridge.poll()
        self.assertFalse(self.bridge.pending)
        self.submit.assert_not_called()

    def test_failed_cancellation_edit_and_delivery_do_not_keep_old_request(self):
        self.bridge.capture(self.push)
        self.client.call.side_effect = RuntimeError()
        self.client.send.side_effect = RuntimeError()
        self.bridge.capture(dict(self.push, guid='two'))
        self.assertFalse(self.bridge.pending)
        self.bridge.handle(Reply('10', '12'))
        self.submit.assert_not_called()
        self.client.call.side_effect = None
        self.client.send.side_effect = None
        self.client.send.return_value = {'message_id': 30}
        self.bridge.capture(dict(self.push, guid='three'))
        self.bridge.handle(Reply('30', '12'))
        self.submit.assert_called_once()

    def test_expired_request_is_marked_expired_before_replacement(self):
        with patch('app.service.time.monotonic', return_value=100):
            self.bridge.capture(self.push)
        self.client.send.return_value = {'message_id': 20}
        with patch('app.service.time.monotonic', return_value=200), patch.object(self.bot, 'update_request') as edit:
            self.bridge.capture(dict(self.push, guid='two'))
        self.assertEqual(edit.call_args.kwargs['status'], 'expired')
        self.assertEqual(set(self.bridge.pending), {'20'})


class DiscordControlsTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.client.call.return_value = {'id': '100'}
        self.bot = DiscordBot(self.client, {'user_id': '42', 'bot_token': 'fake'})
        self.bot.channel_id = '73'

    def test_embed_and_four_buttons_start_gateway_only_once(self):
        with patch('app.bots.discord_gateway.DiscordGateway') as gateway:
            for _ in range(2):
                self.assertEqual(self.bot.request('Choose a number', choices=['12', '34', '56', 'DENY']), '100')
            gateway.return_value.start.assert_called_once()
            payload = self.client.call.call_args.kwargs
            self.assertNotIn('content', payload)
            self.assertEqual(payload['embeds'][0]['description'], 'Choose a number')
            buttons = payload['components'][0]['components']
            self.assertEqual([b['label'] for b in buttons], ['12', '34', '56', 'Deny'])
            self.assertEqual(buttons[-1]['style'], 4)
            self.assertEqual(buttons[1]['custom_id'], 'approval:34')
            self.bot.close()
            gateway.return_value.close.assert_called_once()

    def test_status_edit_replaces_embed_and_removes_buttons(self):
        for status in ('sending', 'succeeded', 'denied', 'failed', 'expired', 'cancelled'):
            self.bot.update_request('100', 'result text', status=status)
            args = self.client.call.call_args
            self.assertEqual(args.args, ('PATCH', '/channels/73/messages/100'))
            self.assertEqual(args.kwargs['components'], [])
            self.assertEqual(args.kwargs['embeds'][0]['description'], 'result text')
            self.assertEqual(args.kwargs['allowed_mentions'], {'parse': []})

    def test_plain_dm_requires_toggle_and_keeps_authorization(self):
        message = {'id': '101', 'channel_id': '73', 'type': 0,
                   'author': {'id': '42'}, 'content': '12'}
        self.assertIsNone(self.bot.parse_update(message).reply)
        self.bot.require_reply = False
        self.assertEqual(self.bot.parse_update(message).reply, Reply(None, '12', '101'))
        for changes in ({'guild_id': '1'}, {'author': {'id': '99'}}, {'webhook_id': '1'},
                        {'channel_id': '99'}, {'author': {'id': '42', 'bot': True}},
                        {'message_reference': {'message_id': '1'}}):
            self.assertIsNone(self.bot.parse_update(dict(message, **changes)).reply)

    def test_buttons_do_not_skip_rest_messages_or_wait_for_poll_interval(self):
        self.bot.gateway = Mock()
        self.bot.gateway.drain.side_effect = [[Reply('100', '12')],
                                             [Reply('100', '12')], [], []]
        self.bot.next_poll = float('inf')
        self.assertEqual(self.bot.updates('73:90'), [Update('73:90', Reply('100', '12'))])
        self.client.call.assert_not_called()
        self.bot.next_poll = 0
        self.client.call.return_value = [{'id': '91', 'channel_id': '73'}]
        self.assertEqual(self.bot.updates('73:90'), [Update('73:90', Reply('100', '12'))])
        self.client.call.assert_not_called()
        self.assertEqual(self.bot.next_poll, 0)
        self.assertEqual([u.cursor for u in self.bot.updates('73:90')], ['73:91'])
        self.client.call.assert_called_once_with('GET', '/channels/73/messages?after=90&limit=100')
        self.bot.next_poll = 0
        self.client.call.side_effect = RateLimited(5)
        self.assertEqual(self.bot.updates('73:91'), [])


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.gateway = DiscordGateway({'user_id': '42'}, '73')
        self.gateway.client = SimpleNamespace(user=SimpleNamespace(id=7))
        self.interaction = SimpleNamespace(
            type=SimpleNamespace(value=3), guild_id=None, channel_id=73,
            user=SimpleNamespace(id=42, bot=False),
            message=SimpleNamespace(id=100, author=SimpleNamespace(id=7)),
            data={'component_type': 2, 'custom_id': 'approval:34'},
            response=SimpleNamespace(defer=AsyncMock()))

    async def test_authorized_click_is_acknowledged_and_queued(self):
        await self.gateway.on_interaction(self.interaction)
        self.interaction.response.defer.assert_awaited_once()
        self.assertEqual(self.gateway.drain(), [Reply('100', '34')])
        self.assertEqual(self.gateway.drain(), [])

    async def test_unauthorized_or_invalid_interactions_are_ignored(self):
        for changes in ({'guild_id': 9}, {'channel_id': 99},
                        {'user': SimpleNamespace(id=99, bot=False)},
                        {'user': SimpleNamespace(id=42, bot=True)}, {'message': None},
                        {'message': SimpleNamespace(id=100, author=SimpleNamespace(id=9))},
                        {'data': {'component_type': 2, 'custom_id': 'approval:999'}}):
            interaction = copy.copy(self.interaction)
            interaction.__dict__.update(changes)
            await self.gateway.on_interaction(interaction)
            self.assertEqual(self.gateway.drain(), [])
        self.interaction.response.defer.assert_not_awaited()

    async def test_failed_ack_does_not_submit(self):
        self.interaction.response.defer.side_effect = RuntimeError('private upstream detail')
        await self.gateway.on_interaction(self.interaction)
        self.assertEqual(self.gateway.drain(), [])


if __name__ == '__main__':
    unittest.main()
