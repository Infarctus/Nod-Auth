"""Telegram Bot API transport, private-user authorization, and pairing."""
import getpass
import json
import secrets
import time
import urllib.request
from app.state import state_path, save_json
from app.bots.base import Reply, Update, valid_callback


class Telegram:
    def __init__(self, token):
        self.token = token

    def call(self, method, **data):
        req = urllib.request.Request(
            f'https://api.telegram.org/bot{self.token}/{method}',
            data=json.dumps(data).encode(), headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=35) as response:
                result = json.load(response)
            if not result.get('ok'):
                raise ValueError('Telegram rejected request')
            return result['result']
        except Exception:
            # HTTP exceptions contain the bot token in the URL.
            raise RuntimeError('Telegram request failed; check connectivity and bot configuration') from None

    def send(self, chat, text, **extra):
        return self.call('sendMessage', chat_id=chat, text=text, **extra)

    def updates(self, offset, timeout=1):
        return self.call('getUpdates', offset=offset, timeout=timeout,
                         allowed_updates=['message', 'callback_query'])


class TelegramBot:
    name = 'telegram'
    require_reply = True

    def __init__(self, client, credentials):
        self.client, self.credentials = client, credentials

    def check(self):
        if self.client.call('getWebhookInfo').get('url'):
            raise RuntimeError('Use a dedicated Telegram bot without a webhook.')

    def notify(self, text):
        self.client.send(self.credentials['chat_id'], text)

    def request(self, text, *, choices=None):
        extra = {}
        if choices:
            extra['reply_markup'] = {'inline_keyboard': [[
                {'text': value, 'callback_data': 'approval:' + value} for value in choices]]}
        elif self.require_reply:
            extra['reply_markup'] = {'force_reply': True, 'selective': True}
        message = self.client.send(self.credentials['chat_id'], text, **extra)
        return str(message['message_id'])

    def update_request(self, request_id, text, *, status):
        self.client.call('editMessageText', chat_id=self.credentials['chat_id'],
                         message_id=int(request_id), text='Microsoft sign-in\n' + text,
                         reply_markup={'inline_keyboard': []})

    def parse_update(self, update):
        callback = update.get('callback_query')
        if callback:
            msg = callback.get('message', {})
            sender = callback.get('from', {})
            value = callback.get('data', '')
            reply = None
            if (sender.get('id') == self.credentials['user_id'] and not sender.get('is_bot', False)
                    and msg.get('chat', {}).get('id') == self.credentials['chat_id']
                    and msg.get('chat', {}).get('type') == 'private'
                    and msg.get('message_id') is not None and valid_callback(value)):
                reply = Reply(str(msg['message_id']), value.removeprefix('approval:'))
            try:
                self.client.call('answerCallbackQuery', callback_query_id=callback['id'])
            except RuntimeError:
                pass
            return Update(str(update['update_id'] + 1), reply)
        msg = update.get('message', {})
        reply = None
        if (msg.get('from', {}).get('id') == self.credentials['user_id'] and
                not msg.get('from', {}).get('is_bot', False) and
                msg.get('chat', {}).get('id') == self.credentials['chat_id'] and
                msg.get('chat', {}).get('type') == 'private'):
            mid = msg.get('reply_to_message', {}).get('message_id')
            if isinstance(msg.get('text'), str) and (mid is not None or not self.require_reply):
                reply = (Reply(str(mid), msg['text']) if mid is not None else
                         Reply(None, msg['text'], str(msg['message_id'])))
        return Update(str(update['update_id'] + 1), reply)

    def updates(self, cursor):
        return [self.parse_update(item) for item in self.client.updates(int(cursor or 0))]


class TelegramProvider:
    @staticmethod
    def validate_options(options):
        from app.config import ConfigError
        if not isinstance(options, dict) or set(options) - {'chat_id', 'user_id'}:
            raise ConfigError('Unknown key or invalid table in [bots.telegram].')
        if options:
            chat, user = options.get('chat_id'), options.get('user_id')
            if type(chat) is not int or type(user) is not int or chat <= 0 or chat != user:
                raise ConfigError('Telegram chat_id and user_id must both identify the same private user (positive integers).')

    @staticmethod
    def setup(options):
        TelegramProvider.validate_options(options)
        pair()

    @staticmethod
    def load(options):
        TelegramProvider.validate_options(options)
        credentials = json.loads(state_path('telegram.json').read_text())
        credentials.update(options)
        TelegramProvider.validate_options({key: credentials[key] for key in ('chat_id', 'user_id')})
        return TelegramBot(Telegram(credentials['bot_token']), credentials)


def pair():
    if not state_path('telegram.json').exists():
        token = getpass.getpass('Telegram bot token from @BotFather: ').strip()
        tg = Telegram(token)
        bot = tg.call('getMe')
        if tg.call('getWebhookInfo').get('url'):
            raise SystemExit('Use a dedicated Telegram bot without a webhook.')
        pairing = secrets.token_urlsafe(18)
        print(f"Open https://t.me/{bot['username']} and send this exact message in a private chat:\n{pairing}", flush=True)
        deadline, offset = time.monotonic() + 300, 0
        while time.monotonic() < deadline:
            for update in tg.updates(offset, timeout=10):
                offset = update['update_id'] + 1
                msg = update.get('message', {})
                if (msg.get('text') == pairing and msg.get('chat', {}).get('type') == 'private'
                        and not msg.get('from', {}).get('is_bot', True)):
                    credentials = {'bot_token': token, 'chat_id': msg['chat']['id'], 'user_id': msg['from']['id']}
                    save_json('telegram.json', credentials)
                    tg.send(credentials['chat_id'], 'Telegram pairing saved.')
                    break
            if state_path('telegram.json').exists():
                break
        else:
            raise SystemExit('Telegram pairing timed out; rerun setup.')
