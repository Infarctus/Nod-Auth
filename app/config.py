"""Validated runtime configuration (Python 3.11+ TOML)."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib


@dataclass(frozen=True)
class Config:
    enabled: bool = True
    provider: str = 'telegram'
    startup_message: bool = True
    timeout_seconds: int = 90
    require_reply: bool = True
    show_number_buttons: bool = False
    max_pending: int = 20
    bot_options: dict = field(default_factory=dict)
    device_name: str = 'Pixel 8'


class ConfigError(ValueError):
    """Contains only safe, user-facing configuration diagnostics."""


def load_config(path=None):
    path = Path(path or os.environ.get('AUTH_CONFIG', Path(__file__).resolve().parent.parent / 'config.toml'))
    try:
        with path.open('rb') as stream:
            raw = tomllib.load(stream)
    except FileNotFoundError:
        raise ConfigError('Configuration file is missing; create config.toml or set AUTH_CONFIG.') from None
    except tomllib.TOMLDecodeError:
        raise ConfigError('Invalid TOML in configuration file.') from None
    allowed = {'enrollment': {'device_name'},
               'notifications': {'enabled', 'provider', 'startup_message'},
               'approval': {'timeout_seconds', 'max_pending', 'require_reply', 'show_number_buttons'}}
    if set(raw) - {'enrollment', 'notifications', 'approval', 'bots'}:
        raise ConfigError('Unknown configuration section.')
    for section, keys in allowed.items():
        value = raw.get(section, {})
        if not isinstance(value, dict) or set(value) - keys:
            raise ConfigError(f'Unknown key or invalid table in [{section}].')
    notifications, approval = raw.get('notifications', {}), raw.get('approval', {})
    device_name = raw.get('enrollment', {}).get('device_name', 'Pixel 8')
    if not isinstance(device_name, str):
        raise ConfigError('enrollment.device_name must be a string.')
    for key in ('enabled', 'startup_message'):
        if type(notifications.get(key, True)) is not bool:
            raise ConfigError(f'notifications.{key} must be true or false.')
    for key, default in (('require_reply', True), ('show_number_buttons', False)):
        if type(approval.get(key, default)) is not bool:
            raise ConfigError(f'approval.{key} must be true or false.')
    provider = notifications.get('provider', 'telegram')
    from app.bots import PROVIDERS
    if not isinstance(provider, str) or provider not in PROVIDERS:
        raise ConfigError('Unsupported bot provider; installed providers: ' + ', '.join(PROVIDERS))
    for key, default, maximum in [('timeout_seconds', 90, 300), ('max_pending', 20, 100)]:
        value = approval.get(key, default)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ConfigError(f'approval.{key} must be an integer between 1 and {maximum}.')
    bots = raw.get('bots', {})
    if not isinstance(bots, dict) or set(bots) - set(PROVIDERS):
        raise ConfigError('Unknown bot configuration table.')
    for name, options in bots.items():
        PROVIDERS[name].validate_options(options)
    return Config(**notifications, **approval, bot_options=bots.get(provider, {}),
                  device_name=device_name)
