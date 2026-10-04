#!/usr/bin/env python3
"""Interactive one-time setup; all generated state lives in AUTH_STATE_DIR."""
import getpass
import os

from app.state import exclusive_lock
from app.service import run
from app.config import ConfigError, load_config
from app.bots import setup_bot
from app.bots.base import BotError
from app.enrollment import prepare_registration, failure_detail


def main():
    os.umask(0o077)
    config = load_config()
    with exclusive_lock():
        saved = prepare_registration(os.environ.get('AUTH_APK_PATH', '/apk/msauth.apk'))
        from app.registration import RegistrationState
        setup_bot(config)
        stage = saved.get('staged')
        prompt = ('Resume staged Microsoft activation? [Y/n]: ' if stage else
                  'Reuse saved Microsoft activation? [Y/n]: ')
        reuse = bool(stage or saved['account']) and input(prompt).strip().lower() != 'n'
        if reuse:
            registration = RegistrationState()
            try:
                registration.verification_material(testing=True)
            finally:
                registration.close()
            if (not stage and saved['confirmed_at'] and saved['binding_verified']
                    and saved['phase'] == 'bound'):
                print('Previously verified Microsoft activation reused. Start the runtime with: docker compose up -d bot')
                return
        else:
            link = input('Fresh Microsoft activatev2 URL: ').strip()
            code = getpass.getpass('One-time Microsoft activation code: ').strip()
            from app import activation
            activation.activate(link, code, device_name=config.device_name)
        if not config.enabled:
            print('Enrollment retained; setup is not verified. Enable notifications and rerun setup for the sign-in test.')
            return
        print('Start a Microsoft sign-in for this Entra account and answer the bot request. Waiting up to 5 minutes.', flush=True)
        run(once=True, config=config)
        print('Setup complete: the Entra sign-in test was confirmed. Start the runtime with: docker compose up -d bot')


def failure_message(exc):
    if isinstance(exc, BotError):
        return f'Setup failed: {exc} Existing state has been preserved. Fix the reported error and rerun setup.'
    return (f'Setup failed: {failure_detail(exc)}. '
            'Existing state has been preserved. Fix the reported error and rerun setup.')


if __name__ == '__main__':
    try:
        main()
    except ConfigError as exc:
        raise SystemExit(str(exc)) from None
    except Exception as exc:
        raise SystemExit(failure_message(exc)) from None
