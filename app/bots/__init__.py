"""Explicit provider registry; add reviewed adapters here to enable new bots."""
from app.bots.base import BotProvider
from app.bots.telegram import TelegramProvider
from app.bots.discord import DiscordProvider

PROVIDERS: dict[str, type[BotProvider]] = {'telegram': TelegramProvider, 'discord': DiscordProvider}


def setup_bot(config):
    if config.enabled:
        PROVIDERS[config.provider].setup(config.bot_options)


def load_bot(config):
    if not config.enabled:
        return None
    bot = PROVIDERS[config.provider].load(config.bot_options)
    bot.require_reply = config.require_reply
    bot.check()
    return bot
