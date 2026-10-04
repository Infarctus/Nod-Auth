#!/usr/bin/env python3
"""Nod Auth approval service with pluggable bot transports."""
import argparse
import json
import os
import re
import signal
import sqlite3
import time

from app.state import state_path, exclusive_lock
from app.config import Config, ConfigError, load_config
from app.bots import load_bot
from app.bots.base import ApprovalBot, BotError, Reply
from app.mcs import McsListener
from app.activation import read_tag
from app.approval import (classify_push, KIND_LABELS, payload_summary,
                          K_ENTROPY, build_pin_validation,
                          build_auth_result, send_pad, pad_url_of)


class Bridge:
    def __init__(self, bot: ApprovalBot | None, config: Config, submit=send_pad, registration=None):
        self.bot, self.config, self.submit = bot if config.enabled else None, config, submit
        self.registration = registration
        self.db = sqlite3.connect(state_path('requests.sqlite3'))
        state_path('requests.sqlite3')  # Repair permissions before creating journals.
        self.db.execute('CREATE TABLE IF NOT EXISTS seen (guid TEXT PRIMARY KEY)')
        self.db.execute('CREATE TABLE IF NOT EXISTS cursor (id INTEGER PRIMARY KEY, value INTEGER)')
        self.db.execute('CREATE TABLE IF NOT EXISTS bot_cursor (provider TEXT PRIMARY KEY, value TEXT)')
        # Preserve the existing Telegram cursor while allowing new providers
        # to use independent, opaque cursor formats.
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO bot_cursor SELECT 'telegram', CAST(value AS TEXT) FROM cursor WHERE id=1")
        row = self.db.execute('SELECT value FROM bot_cursor WHERE provider=?', (config.provider,)).fetchone()
        self.offset = str(row[0]) if row else '0'
        self.pending = {}
        self.request_contexts = {}
        self.button_requests = set()
        self.token = state_path('fcm_token.txt').read_text().strip()
        self.approved = False
        self.poll_retry_at = 0
        self.poll_backoff = 1

    def report_unsupported(self, kind, ad):
        """Report unsupported traffic without interrupting supported approvals."""
        label = KIND_LABELS.get(kind, KIND_LABELS['unknown'])
        print(f'[bridge] unsupported push ({kind}); no approval sent', flush=True)
        if self.bot is None:
            return
        summary = payload_summary(ad, kind)
        self.notify(f'{label} received. This flow is not supported by this '
                    'bridge; no approval was sent. The service remains available '
                    'for Entra MFA requests. Start a '
                    'Microsoft sign-in with the supported Entra MFA method.'
                    + (f'\n{summary}' if summary else ''))

    def capture(self, ad, context=None):
        kind = classify_push(ad)
        if kind == 'aad_validate' and self.registration is not None:
            self.registration.on_push(ad)
            return
        if kind != 'aad_mfa':
            self.report_unsupported(kind, ad)
            return
        if self.registration is not None:
            if context is None:
                self.registration.on_mfa_push(ad)
                return
            if not self.registration.context_is_current(context):
                return
        # Persist before notification: a restart must never resurrect an old approval.
        with self.db:
            added = self.db.execute('INSERT OR IGNORE INTO seen VALUES (?)', (ad['guid'],)).rowcount
        if not added:
            print('[bridge] ignored duplicate sign-in request', flush=True)
            return
        if self.bot is None:
            print('[bridge] notifications disabled; no approval requested', flush=True)
            return
        self.expire_requests()
        # One activation: a fresh GUID supersedes the previous pending prompt.
        # Consume before I/O, even when message editing or delivery fails.
        for mid in list(self.pending):
            del self.pending[mid]
            self.finish_request(mid, 'Request cancelled due to receiving another sign-in request.', 'cancelled')
        numbered = any(k in ad for k in K_ENTROPY)
        # isAppLockRequired is noted but never enforced (see docs/PUSH_FLOWS.md):
        # the reply is sent as if local device authentication had succeeded.
        self.app_lock_required = str(ad.get('isAppLockRequired', 'false')).lower() in ('true', 'yes', '1')
        if self.app_lock_required:
            print('[bridge] sign-in requires app lock; replying as if local auth succeeded', flush=True)
        print(f'[bridge] sign-in push received; number_matching={numbered}; sending bot request', flush=True)
        action = 'Reply to THIS message' if self.config.require_reply else 'Send a message'
        instruction = (f'{action} with the number on the Microsoft sign-in page, or DENY.'
                       if numbered else f'{action} with APPROVE or DENY.')
        choices = None
        if self.config.show_number_buttons:
            numbers = [str(ad.get(key, '')) for key in K_ENTROPY]
            if numbered and all(re.fullmatch(r'[0-9]{1,2}', n) for n in numbers) and len(set(map(int, numbers))) == 3:
                choices = numbers + ['DENY']
                instruction = 'Click the number shown on the Microsoft sign-in page, or DENY. You can also reply with the number.'
            elif not numbered:
                choices = ['APPROVE', 'DENY']
                instruction = 'Click APPROVE or DENY, or reply with your choice.'
            else:
                instruction += '\nThree valid number choices were not supplied; enter the number manually.'
        text = ('Microsoft sign-in requested.\n' + instruction +
                f'\nExpires here in {self.config.timeout_seconds} seconds.')
        deadline = time.monotonic() + self.config.timeout_seconds
        try:
            request_id = self.bot.request(text, choices=choices) if choices else self.bot.request(text)
        except Exception as exc:
            # Delivery may have succeeded remotely; never retry an ambiguous send.
            print(f'[bridge] request notification failed: {type(exc).__name__}; start a new sign-in', flush=True)
            return
        if choices:
            self.button_requests.add(request_id)
        self.pending[request_id] = (ad, deadline, numbered)
        if context is not None:
            self.request_contexts[request_id] = context
        print('[bridge] Bot request sent; waiting for reply', flush=True)

    def notify(self, text):
        try:
            self.bot.notify(text)
        except Exception as exc:
            print(f'[bridge] notification failed: {type(exc).__name__}', flush=True)

    def expire_requests(self):
        for mid, (_, deadline, _) in list(self.pending.items()):
            if time.monotonic() >= deadline:
                del self.pending[mid]
                self.finish_request(mid, 'Request expired; no approval was sent. Start a new sign-in.', 'expired')

    def update_request(self, request_id, text, status):
        try:
            self.bot.update_request(request_id, text, status=status)
            return True
        except Exception as exc:
            # A presentation failure must not cancel or retry Microsoft's request.
            print(f'[bridge] message update failed: {type(exc).__name__}', flush=True)
            return False

    def finish_request(self, request_id, text, status):
        self.request_contexts.pop(request_id, None)
        edited = self.update_request(request_id, text, status)
        self.button_requests.discard(request_id)
        if not edited:
            self.notify(text)

    def handle(self, reply: Reply | None):
        if reply is None or self.bot is None:
            return
        mid = reply.request_id
        if mid is None:
            if self.config.require_reply:
                return
            live = [key for key, (_, deadline, _) in self.pending.items() if time.monotonic() < deadline]
            if len(live) != 1:
                if live:
                    self.notify('Several sign-ins are pending. Reply to the specific request or use its buttons.')
                return
            mid = live[0]
            # Both transports use increasing message IDs in a private chat.
            # A queued ordinary message predating this prompt cannot approve it.
            if reply.source_id is None or int(reply.source_id) <= int(mid):
                return
        pending = self.pending.get(mid)
        if not pending:
            return
        ad, deadline, numbered = pending
        if time.monotonic() >= deadline:
            del self.pending[mid]
            self.finish_request(mid, 'Request expired; start a new sign-in.', 'expired')
            return
        answer = reply.text.strip().upper()
        deny = answer == 'DENY'
        if numbered and not deny and re.fullmatch(r'[0-9]+', answer):
            choices = {int(value) for key in K_ENTROPY
                       if re.fullmatch(r'[0-9]{1,2}', value := str(ad.get(key, '')))}
            if len(answer) > 2 or int(answer) not in choices:
                return
        context = self.request_contexts.get(mid)
        if self.registration is not None and (context is None or not self.registration.context_is_current(context)):
            return
        if not deny and not (re.fullmatch(r'[0-9]{1,2}', answer) if numbered else answer == 'APPROVE'):
            self.notify('Reply to the original request with ' +
                         ('the sign-in number or DENY.' if numbered else 'APPROVE or DENY.'))
            return
        # Consume before network I/O; ambiguous network failures must not retry approval.
        del self.pending[mid]
        self.update_request(mid, 'Sending…', 'sending')
        counter = int(time.time() // 30)
        token = context['token'] if context is not None else self.token
        # App-lock requests are answered as if local device authentication had
        # succeeded (isAppLockUsed=yes); everything else reports honestly.
        app_lock_used = self.app_lock_required
        if numbered and not deny:
            body = build_pin_validation(ad['guid'], token, answer, counter,
                                        app_lock_used=app_lock_used)
            action = 'phoneAppPinValidationRequest'
        else:
            body = build_auth_result(ad['guid'], token, 2 if deny else 1, counter,
                                     app_lock_used=app_lock_used)
            action = 'phoneAppAuthenticationResultRequest'
        result_status = 'failed'
        try:
            status, xml = self.submit(pad_url_of(ad), body, token, ad, action, 'chrome131_android')
            code = read_tag(xml, 'validationResult' if numbered and not deny else 'result')
            success = 200 <= status < 300 and code in (('1', '6') if numbered and not deny else ('1',))
            safe_code = code if re.fullmatch(r'[0-9]{1,3}', code) else 'missing/invalid'
            print(f'[bridge] Microsoft response: HTTP={status} result={safe_code} success={success}', flush=True)
            if success and not deny and self.registration is not None and self.registration.verification_only:
                self.registration.confirm_test(context)
            self.approved = self.approved or (success and not deny)
            result_status = ('denied' if deny else 'succeeded') if success else 'failed'
            outcome = ('Denial sent.' if deny else 'Sign-in approved.') if success else 'Microsoft did not confirm success; check the sign-in page.'
        except (Exception, SystemExit) as exc:
            print(f'[bridge] submission failed: {type(exc).__name__}', flush=True)
            outcome = 'Could not confirm the result. Check the sign-in page before starting another request.'
        self.finish_request(mid, outcome, result_status)

    def poll(self):
        if self.registration is not None:
            for ad, context in self.registration.take_auth_results():
                self.capture(ad, context)
        if self.bot is None:
            return
        self.expire_requests()
        if time.monotonic() < self.poll_retry_at:
            return
        try:
            updates = self.bot.updates(self.offset)
        except Exception as exc:
            print(f'[bridge] bot polling failed: {type(exc).__name__}; retrying', flush=True)
            self.poll_retry_at = time.monotonic() + self.poll_backoff
            self.poll_backoff = min(self.poll_backoff * 2, 30)
            self.expire_requests()
            return
        self.poll_backoff = 1
        self.expire_requests()
        for update in updates:
            # Acknowledge durably before execution, to prevent replay after a crash.
            self.offset = update.cursor
            with self.db:
                self.db.execute('INSERT OR REPLACE INTO bot_cursor VALUES (?, ?)', (self.config.provider, self.offset))
            self.handle(update.reply)
        self.expire_requests()


def run(once=False, config=None):
    config = config or load_config()
    if once and not config.enabled:
        raise ConfigError('Enable notifications before running the approval test.')
    from app.registration_runtime import RegistrationCoordinator
    coordinator = RegistrationCoordinator(verification_only=once)
    bot = bridge = listener = None
    try:
        coordinator.registry.verification_material(testing=once)
        bot = load_bot(config)
        bridge = Bridge(bot, config, registration=coordinator)
        state = json.loads(state_path('checkin_info.json').read_text())
        stopping = False

        def stop(*_):
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        listener = None
        announced_ready = False
        retry_at, backoff = 0, 1
        end = time.monotonic() + 300 if once else float('inf')
        print('[bridge] starting; connecting to MCS', flush=True)
        coordinator.start()
        while not stopping and time.monotonic() < end:
            coordinator.set_transport_ready(bool(listener and listener.ready.is_set()))
            if listener:
                if listener.ready.is_set():
                    backoff = 1
                if listener.ready.is_set() and not announced_ready:
                    print('[bridge] MCS ready; waiting for sign-in pushes', flush=True)
                    if bot is not None and config.startup_message:
                        bridge.notify('Nod Auth connected.' +
                                   (' Start a Microsoft sign-in now to complete setup.' if once else ' Waiting for sign-in requests.'))
                    announced_ready = True
                while listener.pushes:
                    bridge.capture(listener.pushes.pop(0)["app_data"])
                    backoff = 1
            if listener is None or not listener.is_alive():
                if time.monotonic() >= retry_at:
                    if listener:
                        if coordinator is not None and type(getattr(listener, 'login_error_code', None)) is int:
                            coordinator.request_recheckin()
                        listener.stop()
                        listener.join(timeout=2)
                        # It can enqueue a final push between the drain above
                        # and is_alive(); preserve that push before replacing it.
                        while listener.pushes:
                            bridge.capture(listener.pushes.pop(0)['app_data'])
                    state = json.loads(state_path('checkin_info.json').read_text())
                    listener = McsListener(int(state['androidId']), int(state['securityToken']))
                    print('[bridge] opening MCS connection', flush=True)
                    announced_ready = False
                    listener.start()
                    retry_at = time.monotonic() + backoff
                    backoff = min(backoff * 2, 60)
            bridge.poll()
            if once and bridge.approved:
                bridge.notify('Setup complete: Microsoft confirmed your test sign-in.')
                return
            time.sleep(0.1)
    finally:
        if listener:
            listener.stop()
            listener.join(timeout=3)
        if bot is not None and hasattr(bot, 'close'):
            bot.close()
        if bridge is not None:
            bridge.db.close()
        if coordinator is not None:
            coordinator.stop()
    if once:
        raise SystemExit('Setup test did not complete; saved enrollment and staged credentials are retained. Rerun setup to test again.')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()
    config = load_config()
    with exclusive_lock():
        if config.enabled and not args.test:
            from app.registration import RegistrationState
            registry = RegistrationState()
            try:
                saved = registry.snapshot()
            finally:
                registry.close()
            if not saved['confirmed_at'] or not saved['binding_verified']:
                raise SystemExit('Run setup and complete a confirmed Entra sign-in test first.')
        try:
            run(args.test, config)
        except (ConfigError, BotError) as exc:
            raise SystemExit(str(exc)) from None
        except Exception as exc:
            raise SystemExit(f'Bridge stopped: {type(exc).__name__}; check connectivity and saved configuration. Pending requests will not be replayed.') from None


if __name__ == '__main__':
    try:
        main()
    except ConfigError as exc:
        raise SystemExit(str(exc)) from None
