"""Discord REST transport with approvals restricted to one user's direct messages."""
import getpass
import json
import socket
import ssl
import time
import urllib.error
import urllib.request

from app.bots.base import BotError, Reply, Update
from app.state import save_json, state_path


class DiscordAPIError(BotError):
    def __init__(self, message, status, code):
        super().__init__(message)
        self.status = status
        self.code = code


class RateLimited(BotError):
    def __init__(self, retry_after):
        super().__init__('Discord rate limited the request; try again later.')
        self.retry_after = retry_after


class Discord:
    def __init__(self, token):
        self.token = token

    def call(self, method, path, **data):
        request = urllib.request.Request(
            'https://discord.com/api/v10' + path,
            method=method, data=json.dumps(data).encode() if data else None,
            headers={'Authorization': 'Bot ' + self.token,
                     'Content-Type': 'application/json',
                     'User-Agent': 'DiscordBot (https://github.com/discord/discord-api-docs, 1.0)'})
        if path == '/users/@me':
            operation = 'checking the bot token'
        elif path == '/users/@me/channels':
            operation = 'opening your DM channel'
        elif method == 'GET':
            operation = 'reading DM replies'
        else:
            operation = 'sending a DM'
        prefix = f'Discord failed while {operation}: '
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                result = json.load(exc)
                if not isinstance(result, dict):
                    result = {}
            except (ValueError, OSError):
                result = {}
            if exc.code == 429:
                try:
                    delay = max(1, float(result['retry_after']))
                except (ValueError, TypeError, KeyError):
                    delay = 5
                raise RateLimited(delay) from None
            code = result.get('code')
            code = code if type(code) is int and 0 <= code <= 999999 else None
            status = f'HTTP {exc.code}'
            if code is not None:
                status += f', Discord code {code}'
            if exc.code == 401:
                hint = 'The bot token was rejected. Use the token from the Developer Portal Bot page, not the application ID or client secret.'
            elif code == 50278:
                hint = 'The bot and configured user share no server. Install the bot in a server you belong to using the bot scope (Server Install), then allow DMs from that server. No privileged intents or extra app ID configuration are needed.'
            elif code == 50007:
                hint = 'Discord cannot deliver a DM to this user. Check your user ID, install the bot in a shared server, allow DMs from that server, and unblock the bot.'
            elif code == 10013:
                hint = 'Discord could not find the user. Set user_id to your own Discord user ID.'
            elif code in (50001, 50013):
                hint = 'The bot lacks access. Check its server installation and your DM privacy settings.'
            elif exc.code == 403:
                hint = 'Discord denied access. Check bot access and whether the Docker host or proxy is blocking Discord.'
            else:
                hint = 'Check Discord availability and the bot configuration, then retry setup.'
            raise DiscordAPIError(prefix + status + '. ' + hint, exc.code, code) from None
        except Exception as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            if isinstance(reason, ssl.SSLCertVerificationError):
                hint = 'TLS certificate verification failed. Check the container CA certificates and any HTTPS-inspecting proxy.'
            elif isinstance(reason, socket.gaierror):
                hint = 'DNS lookup failed. Check DNS and outbound connectivity inside the Docker container.'
            elif isinstance(reason, (TimeoutError, socket.timeout)):
                hint = 'The connection timed out. Check outbound HTTPS connectivity inside the Docker container and retry.'
            elif isinstance(reason, ssl.SSLError):
                hint = 'The TLS connection failed. Check the container network and HTTPS proxy settings.'
            elif isinstance(reason, (ValueError, UnicodeError)):
                hint = 'Discord returned an invalid response. Check whether a proxy is intercepting requests.'
            else:
                hint = 'A network request failed. Check outbound HTTPS connectivity and proxy settings inside the Docker container.'
            raise BotError(prefix + hint) from None



class DiscordBot:
    name = 'discord'
    require_reply = True

    def __init__(self, client, credentials):
        self.client = client
        self.credentials = credentials
        self.channel_id = None
        self.initial_cursor = '0'
        self.next_poll = 0
        self.bot_id = None
        self.gateway = None

    def check(self):
        identity = self.client.call('GET', '/users/@me')
        if not identity.get('bot'):
            raise BotError('Discord requires a bot token.')
        self.bot_id = str(identity['id'])
        channel = self.client.call('POST', '/users/@me/channels',
                                   recipient_id=str(self.credentials['user_id']))
        if channel.get('type') != 1 or [str(u['id']) for u in channel.get('recipients', [])] != [str(self.credentials['user_id'])]:
            raise BotError('Discord did not return the authorized private DM channel.')
        self.channel_id = str(channel['id'])
        # Ignore history predating this process, even when switching bot/user.
        messages = self.client.call('GET', f'/channels/{self.channel_id}/messages?limit=1')
        self.initial_cursor = str(messages[0]['id']) if messages else '0'

    def notify(self, text):
        self.request(text)

    def request(self, text, *, choices=None):
        data = {'embeds': [{'title': 'Microsoft sign-in', 'description': text,
                            'color': 0x0078D4}],
                'allowed_mentions': {'parse': []}}
        if choices:
            if self.gateway is None:
                from app.bots.discord_gateway import DiscordGateway
                self.gateway = DiscordGateway(self.credentials, self.channel_id)
                self.gateway.start()
            data['components'] = [{'type': 1, 'components': [
                {'type': 2, 'style': 4 if value == 'DENY' else 1,
                 'label': value.title() if value in ('DENY', 'APPROVE') else value,
                 'custom_id': 'approval:' + value} for value in choices]}]
        message = self.client.call('POST', f'/channels/{self.channel_id}/messages', **data)
        return str(message['id'])

    def update_request(self, request_id, text, *, status):
        colors = {'sending': 0xF1C40F, 'succeeded': 0x2ECC71,
                  'denied': 0x95A5A6, 'failed': 0xE74C3C, 'expired': 0x95A5A6,
                  'cancelled': 0x95A5A6}
        self.client.call('PATCH', f'/channels/{self.channel_id}/messages/{request_id}',
                         content='', components=[], allowed_mentions={'parse': []},
                         embeds=[{'title': 'Microsoft sign-in', 'description': text,
                                  'color': colors[status]}])

    def parse_update(self, message):
        reference = message.get('message_reference') or {}
        author = message.get('author') or {}
        reply = None
        if (str(author.get('id')) == str(self.credentials['user_id'])
                and not author.get('bot', False) and not message.get('webhook_id')
                and str(message.get('channel_id')) == self.channel_id
                and not message.get('guild_id') and isinstance(message.get('content'), str)):
            if (message.get('type') == 19 and reference.get('type', 0) == 0
                    and not reference.get('guild_id')
                    and str(reference.get('channel_id')) == self.channel_id
                    and reference.get('message_id')):
                reply = Reply(str(reference['message_id']), message['content'])
            elif not self.require_reply and message.get('type') == 0 and not reference:
                reply = Reply(None, message['content'], str(message['id']))
        return Update(f"{self.channel_id}:{message['id']}", reply)

    def close(self):
        if self.gateway is not None:
            self.gateway.close()

    def updates(self, cursor):
        # Button events are transient and must not advance the REST message cursor.
        buttons = [Update(cursor, reply) for reply in self.gateway.drain()] if self.gateway else []
        # Deliver clicks before any fallible or slow REST request. Once drained,
        # they cannot be recovered if polling fails. Poll messages next time,
        # using the unchanged cursor and poll deadline.
        if buttons or time.monotonic() < self.next_poll:
            return buttons
        self.next_poll = time.monotonic() + 2
        channel, separator, last = cursor.partition(':')
        after = max(int(last) if separator and channel == self.channel_id else 0,
                    int(self.initial_cursor))
        try:
            messages = self.client.call('GET', f'/channels/{self.channel_id}/messages?after={after}&limit=100')
        except RateLimited as exc:
            self.next_poll = time.monotonic() + exc.retry_after
            return buttons
        return buttons + [self.parse_update(message) for message in sorted(messages, key=lambda m: int(m['id']))
                if int(message['id']) > after]


class DiscordProvider:
    @staticmethod
    def validate_options(options):
        from app.config import ConfigError
        if not isinstance(options, dict) or set(options) - {'bot_token', 'user_id'}:
            raise ConfigError('Unknown key or invalid table in [bots.discord].')
        if 'bot_token' in options:
            token = options['bot_token']
            if not isinstance(token, str) or not token or any(c.isspace() for c in token):
                raise ConfigError('Discord bot_token must be a nonempty token without whitespace.')
        if 'user_id' in options:
            user = options['user_id']
            if (type(user) not in (int, str) or not str(user).isascii()
                    or len(str(user)) > 20 or not str(user).isdigit() or not 0 < int(user) < 2**64):
                raise ConfigError('Discord user_id must be a positive numeric Discord user ID.')

    @staticmethod
    def credentials(options):
        DiscordProvider.validate_options(options)
        path = state_path('discord.json')
        credentials = json.loads(path.read_text()) if path.exists() else {}
        credentials.update(options)
        DiscordProvider.validate_options(credentials)
        return credentials

    @staticmethod
    def setup(options):
        credentials = DiscordProvider.credentials(options)
        if 'bot_token' not in credentials:
            credentials['bot_token'] = getpass.getpass('Discord bot token: ').strip()
        if 'user_id' not in credentials:
            credentials['user_id'] = input('Your Discord user ID: ').strip()
        DiscordProvider.validate_options(credentials)
        bot = DiscordBot(Discord(credentials['bot_token']), credentials)
        bot.check()
        try:
            bot.notify('Discord setup connected.')
        except DiscordAPIError as exc:
            if exc.code != 50278:
                raise
            invite = (f'https://discord.com/oauth2/authorize?client_id={bot.bot_id}'
                      '&scope=bot&permissions=0')
            print('Discord requires the bot and your account to share a server.', flush=True)
            print('Add the bot to your dummy server with this invite (no server permissions requested):', flush=True)
            print(invite, flush=True)
            input('After Discord confirms the bot joined the server, press Enter to verify DM delivery: ')
            bot.check()
            bot.notify('Discord setup connected.')
        save_json('discord.json', credentials)
        print('Discord credentials saved; DM delivery verified.', flush=True)

    @staticmethod
    def load(options):
        from app.config import ConfigError
        credentials = DiscordProvider.credentials(options)
        if not {'bot_token', 'user_id'} <= credentials.keys():
            raise ConfigError('Run setup or set bot_token and user_id in [bots.discord].')
        return DiscordBot(Discord(credentials['bot_token']), credentials)
