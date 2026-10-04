"""Entra renewal and account-verified push handling on bounded worker queues."""
from __future__ import annotations

import hashlib
import json
import queue
import threading
import time

from app import fcm_lifecycle, entra_registration as entra
from app.state import state_path
from app.registration import RegistrationState


class RegistrationCoordinator:
    def __init__(self, registry=None, now=None, verification_only=False):
        self.registry = registry or RegistrationState()
        self.now = now or time.time
        self.verification_only = verification_only
        self.stopping = threading.Event()
        self.wake = threading.Event()
        self.transport_ready = threading.Event()
        self.challenges = queue.Queue(maxsize=16)
        self.events = queue.Queue(maxsize=32)
        self.auth_ready = queue.Queue(maxsize=16)
        self.thread = threading.Thread(target=self._run, name='entra-registration', daemon=True)
        self.auth_thread = threading.Thread(target=self._events_loop, name='entra-push-validation', daemon=True)
        self.binding_in_progress = False
        self.recheckin_requested = False

    @property
    def active_token(self):
        return self.registry.active_token

    def start(self):
        state = self.registry.snapshot()
        if not self.verification_only:
            try:
                version = str(fcm_lifecycle.load_apk_config().get('version_code', ''))
                stale = (not state['google_checked_at'] or
                         int(self.now()) - state['google_checked_at'] >= 7 * 86400 or
                         state.get('google_app_version', '') != version)
                if stale and state['google_due_at'] > int(self.now()):
                    with self.registry.lock:
                        self.registry.state['google_due_at'] = int(self.now())
                        self.registry._save()
            except (Exception, SystemExit):
                pass
            self.thread.start()
        self.auth_thread.start()

    def stop(self):
        self.stopping.set()
        self.wake.set()
        for worker in (self.thread, self.auth_thread):
            if worker.ident is not None:
                worker.join(timeout=35)
        if not self.thread.is_alive() and not self.auth_thread.is_alive():
            self.registry.close()

    def set_transport_ready(self, ready):
        if ready:
            if not self.transport_ready.is_set():
                self.transport_ready.set()
                self.wake.set()
        else:
            self.transport_ready.clear()

    def _enqueue(self, kind, data, context):
        try:
            self.events.put_nowait((kind, dict(data), context))
        except queue.Full:
            print('[registration] push work queue full; request not processed', flush=True)

    def on_mfa_push(self, data):
        try:
            context = self.registry.verification_material(self.verification_only)
        except ValueError:
            print('[registration] account needs enrollment verification', flush=True)
            return
        if entra.push_matches_account(data, context['account']):
            self._enqueue('authentication', data, context)

    def on_push(self, data):
        from app.activation import is_valid_challenge
        if not is_valid_challenge(data):
            return
        if data.get('deviceTokenChangeVersion', '').upper() == 'V2':
            attempt = self.registry.snapshot()['attempt']
            if (not self.binding_in_progress or not attempt or attempt['protocol'] != 'V2'
                    or attempt['phase'] not in {'v2_start', 'v2_waiting_validation'}):
                return
            try:
                # The APK selects accounts by all four combination fields.
                entra.v2_challenge(data, attempt['account'])
                self.challenges.put_nowait((attempt['id'], dict(data)))
            except (entra.BindingError, queue.Full):
                pass
            return
        try:
            context = self.registry.verification_material(self.verification_only)
        except ValueError:
            return
        if not entra.push_matches_account(data, context['account']):
            return
        # V1 validation is independent in the APK. It uses the current Google
        # registration, including when no local change request is in flight.
        if not self.verification_only:
            context['token'] = self.registry.snapshot()['google'] or context['token']
        self._enqueue('validation', data, context)

    def take_auth_results(self):
        result = []
        while True:
            try:
                result.append(self.auth_ready.get_nowait())
            except queue.Empty:
                return result

    def context_is_current(self, context):
        state = self.registry.snapshot()
        if context['revision'] != state['revision']:
            return False
        candidate = context.get('candidate_id')
        if (not candidate and context.get('binding_stamp') is not None and
                context['binding_stamp'] != [state['binding_attempts'], len(state['token_history'])]):
            return False
        return not candidate or bool(state['staged'] and state['staged']['id'] == candidate)

    def _authentication(self, data, context):
        if not self.context_is_current(context):
            return
        # MfaNotification uses notification details directly when its account
        # lookup succeeds. Do not make a redundant HTTP fetch a prerequisite.
        if entra.push_identifies_account(data, context['account']):
            entra.pad_url_of_push(data)
            if not data.get('guid'):
                raise entra.BindingError('unmatched_authentication_push')
            self._queue_authentication(dict(data), context)
            print('[registration] authentication ready: source=push account=matched', flush=True)
            return
        details = entra.fetch_authentication(data, context['account'], context['token'])
        reported = details['server_token']
        if context.get('candidate_id') and reported and reported != context['token']:
            raise entra.BindingError('staged_token_not_bound')
        if not self.registry.learn(context, details['fields'], reported):
            return
        self.wake.set()
        state = self.registry.snapshot()
        if not context.get('candidate_id'):
            # The APK treats a missing response token as 'no token-change
            # hint', not a failed authentication. Retain the saved request
            # token without promoting it to a confirmed registration.
            token = reported or self.registry.active_token or context['token']
            context['token'] = token
            context['binding_stamp'] = [state['binding_attempts'], len(state['token_history'])]
        context['account'] = {**context['account'], **details['fields']}
        self._queue_authentication(details['push'], context)

    def _queue_authentication(self, data, context):
        try:
            self.auth_ready.put_nowait((data, context))
        except queue.Full:
            print('[registration] verified request queue full; start a fresh sign-in', flush=True)

    @staticmethod
    def _fingerprint(data, context, *, affirmative=None):
        parts = {key: data.get(key, '') for key in ('guid', 'url', 'deviceTokenChangeVersion',
                 'oathCounter', 'tenantId', 'replicationScope', 'routingHint', 'countryCode')}
        parts['revision'] = context.get('candidate_id') or context['revision']
        parts['attempt_id'] = context.get('attempt_id', '')
        if affirmative is not None:
            parts['affirmative'] = affirmative
        return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()

    def _validation(self, data, context):
        if not data.get('guid') or not self.context_is_current(context):
            return
        entra.pad_url_of_push(data)
        from app.activation import answer_challenge
        attempt = self.registry.snapshot()['attempt']
        allowed = bool(self.binding_in_progress and attempt and attempt['revision'] == context['revision'])
        fingerprint = self._fingerprint(data, {**context, 'attempt_id': attempt['id'] if allowed else ''},
                                        affirmative=allowed)
        if not self.registry.claim_validation(fingerprint):
            return
        try:
            outcome = answer_challenge(data, context['token'],
                                       need_dos_preventer=not bool(context['account'].get('DosPreventer')),
                                       account=context['account'], validation_result=allowed)
            if outcome.get('action') != 'validated' or not 200 <= outcome.get('status', 0) < 300:
                return
            fields, confirmed = entra.validation_metadata(outcome['text'], context['account'])
            self.registry.learn(context, fields, context['token'] if confirmed and allowed else '')
            self.registry.complete_validation(fingerprint)
            self.wake.set()
        finally:
            # A failed send or unusable response remains retryable on redelivery.
            self.registry.release_validation(fingerprint)

    def _learn_responses(self):
        """Process queued, provenance-carrying events (also used by offline tests)."""
        while not self.stopping.is_set():
            try:
                kind, data, context = self.events.get_nowait()
            except queue.Empty:
                return
            try:
                if kind == 'authentication':
                    self._authentication(data, context)
                else:
                    self._validation(data, context)
            except (Exception, SystemExit) as exc:
                # BindingError reasons are local protocol labels, never response
                # bodies, URLs, credentials, or arbitrary exception messages.
                reason = f' reason={exc.kind}' if isinstance(exc, entra.BindingError) else ''
                print(f'[registration] {kind} not verified: {type(exc).__name__}{reason}', flush=True)
                if isinstance(exc, entra.BindingError) and exc.diagnostic:
                    print(f'[registration] diagnostic: {exc.diagnostic}', flush=True)

    def _events_loop(self):
        while not self.stopping.wait(0.1):
            self._learn_responses()

    def confirm_test(self, context):
        if not self.verification_only:
            raise ValueError('enrollment can only be confirmed during setup test')
        self.registry.commit_test(context)

    def request_recheckin(self):
        now = int(self.now())
        last = self.registry.snapshot().get('recheckin_attempt_at', 0)
        if not self.recheckin_requested and (not last or now - last >= 86400):
            self.recheckin_requested = True
            self.wake.set()

    def _google(self):
        self.registry.record_google_attempt()
        device = json.loads(state_path('checkin_info.json').read_text())
        cfg = fcm_lifecycle.load_apk_config()
        token = fcm_lifecycle.acquire(device, cfg)
        self.registry.google_success(token, cfg.get('version_code', ''))
        print('[registration] Google token checked', flush=True)

    def _v1(self, account, old, target):
        if not all(account.get(key) for key in ('PadUrl', 'ReplicationScopes', 'DosPreventer')):
            raise entra.BindingError('metadata_required')
        entra.pad_url(account['PadUrl'])
        attempt = self.registry.binding_started('v1_sent', expected={'pending': target, 'bound': old, 'account': account})
        self.binding_in_progress = True
        try:
            try:
                entra.change_v1(account, old, target)
            except entra.BindingError as exc:
                if exc.kind == 'invalid_dos_preventer':
                    self.registry.invalidate_dos_preventer(account['DosPreventer'])
                raise
            self.registry.binding_success(target, attempt['id'])
        finally:
            self.binding_in_progress = False

    def _v2(self, account, target):
        required = ('PadUrl', 'PhoneAppDetailId', 'OathTokenSecretKey',
                    'AzureObjectId', 'TenantId', 'ReplicationScope')
        if not all(account.get(key) for key in required):
            raise entra.BindingError('metadata_required')
        entra.pad_url(account['PadUrl'])
        # Reset before Start, as MfaSdkState.initValidationResult does.
        while not self.challenges.empty():
            self.challenges.get_nowait()
        attempt = self.registry.binding_started('v2_start', expected={'pending': target, 'account': account})
        self.binding_in_progress = True
        try:
            try:
                response = entra.post(account['PadUrl'], entra.build_start_v2(target), target,
                                      'phoneAppStartDeviceTokenChangeV2Request', account)
            except entra.BindingError as exc:
                # Start does not change the bound token; an uncertain Complete does.
                raise entra.BindingError(exc.kind) from exc
            if entra.result_code(response) != 1:
                raise entra.BindingError('v2_start_rejected')
            self.registry.binding_started('v2_waiting_validation')
            deadline = time.monotonic() + 120
            challenge = None
            while not self.stopping.is_set() and time.monotonic() < deadline:
                try:
                    attempt_id, data = self.challenges.get(timeout=0.2)
                except queue.Empty:
                    continue
                if attempt_id != attempt['id']:
                    continue
                try:
                    candidate = entra.v2_challenge(data, account)
                    fingerprint = self._fingerprint(data, {'revision': attempt['revision'],
                                                           'attempt_id': attempt['id']})
                    if not self.registry.claim_validation(fingerprint):
                        continue
                    challenge = candidate
                    break
                except entra.BindingError:
                    continue
            if challenge is None:
                raise entra.BindingError('v2_validation_timeout')
            body = entra.build_complete_v2(target, account, challenge['counter'])
            self.registry.binding_started('v2_complete_sent')
            complete = entra.post(challenge['url'], body, target,
                                  'phoneAppCompleteDeviceTokenChangeV2Request', {**account, **challenge})
            if not entra.complete_success(complete, account):
                raise entra.BindingError('v2_complete_unconfirmed', uncertain=True)
            self.registry.complete_validation(fingerprint)
            self.registry.binding_success(target, attempt['id'])
        finally:
            self.binding_in_progress = False

    def _binding(self):
        state = self.registry.snapshot()
        if not state['pending'] or state['phase'] == 'uncertain' or not state['binding_verified']:
            return
        if state['account'].get('BindingProtocol') == 'V2':
            self._v2(state['account'], state['pending'])
        else:
            self._v1(state['account'], state['bound'], state['pending'])
        print('[registration] Entra token binding confirmed', flush=True)

    def tick(self):
        now = int(self.now())
        if self.recheckin_requested:
            self.recheckin_requested = False
            with self.registry.lock:
                self.registry.state['recheckin_attempt_at'] = now
                self.registry._save()
            try:
                from app.fcm import do_checkin
                do_checkin(force=True)
                with self.registry.lock:
                    self.registry.state['google_due_at'] = now
                    self.registry._save()
            except (Exception, SystemExit) as exc:
                self.registry.google_failure(type(exc).__name__, 30)
        state = self.registry.snapshot()
        if now >= state['google_due_at']:
            try:
                self._google()
            except fcm_lifecycle.FcmError as exc:
                if exc.kind in ('fis_auth_invalid', 'fis_bad_state'):
                    fcm_lifecycle.invalidate_installation(exc.kind)
                retry = 86400 if exc.kind in ('fis_bad_config', 'fis_identity_mismatch') else 30
                self.registry.google_failure(exc.kind, retry)
                print(f'[registration] Google check failed: {exc.kind}', flush=True)
            except (Exception, SystemExit) as exc:
                self.registry.google_failure(type(exc).__name__, 30)
                print(f'[registration] Google check failed: {type(exc).__name__}', flush=True)
        if self.transport_ready.is_set():
            self.registry.retry_uncertain()
        state = self.registry.snapshot()
        if (self.transport_ready.is_set() and state['pending'] and state['binding_verified']
                and state['phase'] != 'uncertain' and now >= state['binding_due_at']
                and (not state['binding_attempt_at'] or now - state['binding_attempt_at'] >= 86400)):
            try:
                self._binding()
            except entra.BindingError as exc:
                self.registry.binding_failure(exc.kind, uncertain=exc.uncertain or self.registry.snapshot()['phase'] == 'v2_complete_sent')
                print(f'[registration] Entra binding failed: {exc.kind}', flush=True)
            except Exception as exc:
                if self.registry.snapshot()['attempt']:
                    self.registry.binding_failure(type(exc).__name__)
                print(f'[registration] Entra binding outcome unresolved: {type(exc).__name__}', flush=True)

    def _run(self):
        while not self.stopping.is_set():
            try:
                self.tick()
            except Exception as exc:
                print(f'[registration] reconciliation paused: {type(exc).__name__}', flush=True)
            self.wake.wait(1 if self.transport_ready.is_set() else 5)
            self.wake.clear()
