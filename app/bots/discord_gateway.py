"""Discord's SDK maintains the Gateway connection used by DM buttons.

REST polling still owns the durable message cursor. Button replies are queued in
memory; the bridge's pending map enforces expiry and one-time consumption.
"""
import asyncio
import queue
import threading

from app.bots.base import BotError, Reply, valid_callback


class DiscordGateway:
    def __init__(self, credentials, channel_id):
        self.credentials = credentials
        self.channel_id = channel_id
        self.replies = queue.Queue(maxsize=100)
        self.ready = threading.Event()
        self.failed = threading.Event()
        self.loop = None
        self.client = None
        self.thread = None

    async def on_interaction(self, interaction):
        data = interaction.data or {}
        message = interaction.message
        value = data.get('custom_id')
        if (interaction.type.value != 3 or interaction.guild_id is not None
                or str(interaction.channel_id) != self.channel_id
                or str(interaction.user.id) != str(self.credentials['user_id'])
                or interaction.user.bot or message is None
                or message.author.id != self.client.user.id
                or data.get('component_type') != 2 or not valid_callback(value)):
            return
        try:
            # This acknowledges the click, not the sign-in result.
            await interaction.response.defer()
        except Exception:
            return
        try:
            self.replies.put_nowait(Reply(str(message.id), value.removeprefix('approval:')))
        except queue.Full:
            pass

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True, name='discord-buttons')
        self.thread.start()
        if not self.ready.wait(30) or self.failed.is_set():
            self.close()
            raise BotError('Discord button connection failed. Check connectivity and bot credentials, or disable show_number_buttons.')

    def _run(self):
        async def connect():
            import discord
            self.loop = asyncio.get_running_loop()
            self.client = discord.Client(intents=discord.Intents.none())
            self.client.event(self.on_interaction)

            @self.client.event
            async def on_ready():
                self.ready.set()

            async with self.client:
                await self.client.start(self.credentials['bot_token'])

        try:
            asyncio.run(connect())
        except Exception:
            # SDK exceptions can contain credentials or upstream response data.
            self.failed.set()
        finally:
            self.ready.set()

    def drain(self):
        if self.failed.is_set():
            raise BotError('Discord button connection stopped. Restart the bridge or disable show_number_buttons.')
        replies = []
        while True:
            try:
                replies.append(self.replies.get_nowait())
            except queue.Empty:
                return replies

    def close(self):
        if self.loop and self.loop.is_running() and self.client:
            future = asyncio.run_coroutine_threadsafe(self.client.close(), self.loop)
            try:
                future.result(timeout=5)
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=5)
