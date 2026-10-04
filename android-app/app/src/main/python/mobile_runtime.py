"""Android's local approval session. No bot configuration or transport is loaded."""
import json
import os
from pathlib import Path
import queue
import re
import shutil
import sqlite3
import threading
import time
import uuid
import base64
from contextlib import contextmanager

from app.state_bundle import BundleError, extract_bundle, export_bundle, validate_state


def choices_for(data):
    from app.approval import K_ENTROPY
    if not any(k in data for k in K_ENTROPY):
        return ['APPROVE']
    numbers = [str(data.get(k, '')) for k in K_ENTROPY]
    if (not all(re.fullmatch(r'[0-9]{1,2}', n) for n in numbers)
            or len(set(map(int, numbers))) != 3):
        return []
    return numbers


class PendingRequest:
    def __init__(self, data, context, timeout=90):
        self.id = uuid.uuid4().hex
        self.data = dict(data)
        self.context = context
        self.choices = choices_for(data)
        self.deadline = time.monotonic() + timeout
        self.lock_required = str(data.get('isAppLockRequired', 'false')).lower() in ('true', 'yes', '1')
        self.consumed = False

    def consume(self, request_id, answer, unlocked, now=None):
        if (self.consumed or request_id != self.id or
                (time.monotonic() if now is None else now) >= self.deadline):
            return False
        if answer != 'DENY' and (answer not in self.choices or self.lock_required and not unlocked):
            return False
        self.consumed = True
        return True

    def public(self):
        from app.approval import payload_summary
        return {'id': self.id, 'choices': self.choices, 'lock_required': self.lock_required,
                'seconds': max(0, int(self.deadline - time.monotonic())),
                'details': payload_summary(self.data, 'aad_mfa')}


class MobileRuntime:
    def __init__(self, private_dir):
        self.root = Path(private_dir)
        self.state_dir = self.root / 'enrollment'
        os.environ['AUTH_STATE_DIR'] = str(self.state_dir)
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.answers = queue.Queue(maxsize=8)
        self.worker = None
        self.pending = None
        self.operating = False
        self.view = {'status': 'No setup imported', 'connected': False, 'listening': False,
                     'has_setup': self.state_dir.is_dir(), 'message': '', 'diagnostics': '', 'enrolling': False}
        self._recover_import()
        self._refresh_setup_details()

    def _config_path(self):
        saved = self.root / 'source-apk-config.json'
        return saved if saved.exists() else self.state_dir / 'apk_config.json'

    def _refresh_setup_details(self):
        try:
            cfg = json.loads(self._config_path().read_text())
            ready = cfg.get('package') == 'com.azure.authenticator' and bool(cfg.get('firebase'))
        except (OSError, ValueError, AttributeError):
            cfg, ready = {}, False
        draft = self.root / 'setup-draft'
        try:
            validate_state(draft)
            draft_ready = draft.is_dir()
        except BundleError:
            draft_ready = False
        self._set(apk_ready=ready, apk_version=cfg.get('version_name', '') if ready else '', draft_ready=draft_ready)

    @contextmanager
    def _operation(self):
        with self.lock:
            if self.operating or self.worker and self.worker.is_alive():
                raise BundleError('Disconnect before changing or exporting setup.')
            self.operating = True
        try:
            yield
        finally:
            with self.lock:
                self.operating = False

    def prepare_apk(self, apk, certificates_json):
        from app.extract_apk_config import extract_config
        from app.state import sync_directory
        with self._operation():
            certificates = json.loads(certificates_json)
            if not isinstance(certificates, list) or not certificates:
                raise BundleError('Could not read the APK signing certificate.')
            cfg = extract_config(apk, signing_cert_sha1=certificates)
            if cfg.get('package') != 'com.azure.authenticator':
                raise BundleError('Choose the Microsoft Authenticator APK.')
            temporary = self.root / ('apk-config-' + uuid.uuid4().hex)
            try:
                with temporary.open('x') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    json.dump(cfg, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.replace(self.root / 'source-apk-config.json')
                sync_directory(self.root)
            finally:
                temporary.unlink(missing_ok=True)
            self._refresh_setup_details()
            return cfg['version_name']

    def inspect_qr(self, raw):
        from enrollment_qr import qr_summary
        return qr_summary(raw)

    @staticmethod
    def _android_google(url, data, headers):
        from java import jclass
        transport = jclass('io.github.infarctus.nodauth.AndroidHttpTransport')
        result = json.loads(str(transport.googlePost(url, base64.b64encode(data).decode('ascii'), json.dumps(headers))))
        return result['status'], base64.b64decode(result['body'], validate=True)

    def use_android_transport(self):
        from java import jclass
        from app.fcm import configure_http_transport
        jclass('io.github.infarctus.nodauth.AndroidHttpTransport')
        configure_http_transport(self._android_google)

    @staticmethod
    def _android_soap(url, body, action, timeout=90):
        from java import jclass
        from app.activation import UA
        transport = jclass('io.github.infarctus.nodauth.AndroidHttpTransport')
        result = json.loads(str(transport.post(url, body, action, UA, timeout)))
        return result['status'], result['text']

    def enroll(self, raw):
        from enrollment_qr import parse_qr
        from app import fcm, activation
        from app.state import exclusive_lock, save_json, sync_directory
        from app.registration import RegistrationState
        from app.fcm_lifecycle import FcmError
        link, code = parse_qr(raw)  # Validate before any network request or state change.
        with self._operation():
            cfg = json.loads(self._config_path().read_text())
            draft = self.root / 'setup-draft'
            self._set(enrolling=True, connected=False, status='Preparing setup…', message='Keep the app open while your account is activated.')
            ownership = None
            try:
                if draft.exists():
                    try:
                        saved_cfg = json.loads((draft / 'apk_config.json').read_text())
                    except (OSError, ValueError):
                        saved_cfg = None
                    if (draft / 'activation.pending.json').exists() or saved_cfg != cfg:
                        recovery = self.root / ('setup-recovery-' + uuid.uuid4().hex)
                        draft.rename(recovery)
                        sync_directory(self.root)
                os.environ['AUTH_STATE_DIR'] = str(draft)
                ownership = exclusive_lock()
                save_json('apk_config.json', cfg)
                self._set(status='Registering Google push…')
                device = fcm.do_checkin()
                registry = RegistrationState()
                try:
                    saved = registry.snapshot()
                    if not (saved['active'] or saved['legacy_token'] or saved['google']):
                        registry.google_success(fcm.do_register(device))
                finally:
                    registry.close()
                self._set(status='Activating Microsoft account…', message='Answer the verification sign-in after activation completes.')
                activation.activate(link, code, soap_transport=self._android_soap)
                confirmed = validate_state(draft)
                ownership.close()
                ownership = None
                self._commit_directory(draft, confirmed)
                self._set(status='Account activated', message='Connect, then finish the Microsoft verification sign-in.')
                return True
            except (Exception, SystemExit) as exc:
                detail = exc.diagnostic if isinstance(exc, FcmError) else type(exc).__name__
                self._set(status='Setup stopped', message=f'Setup could not finish ({detail}). Recovery state was retained. Use a fresh QR code if activation was attempted.')
                return False
            finally:
                if ownership:
                    ownership.close()
                os.environ['AUTH_STATE_DIR'] = str(self.state_dir)
                self._set(enrolling=False)
                self._refresh_setup_details()

    def resume_setup(self):
        with self._operation():
            draft = self.root / 'setup-draft'
            confirmed = validate_state(draft)
            self._commit_directory(draft, confirmed)
            self._refresh_setup_details()

    def export_setup(self, output):
        with self._operation():
            export_bundle(self.state_dir, output)

    def _recover_import(self):
        backup = self.root / 'enrollment.previous'
        if not self.state_dir.exists() and backup.exists():
            backup.rename(self.state_dir)
        self.view['has_setup'] = self.state_dir.is_dir()

    def _set(self, **fields):
        with self.lock:
            self.view.update(fields)

    def snapshot(self):
        with self.lock:
            result = dict(self.view)
            result['request'] = self.pending.public() if self.pending and not self.pending.consumed else None
        return json.dumps(result)

    def diagnostics(self):
        checks = {}
        stage = 'loading native libraries'
        try:
            import sys
            import curl_cffi
            import cffi
            from curl_cffi import requests
            checks.update(python=sys.version.split()[0], curl_cffi=curl_cffi.__version__, cffi=cffi.__version__)
            stage = 'loading protocol modules'
            from app import approval, registration_runtime, mcs, state, fcm_lifecycle
            checks['protocol_modules'] = True
            try:
                from java import jclass
                native_status = jclass('io.github.infarctus.nodauth.AndroidHttpTransport').publicCheck()
                checks.update(native_https=native_status == 200, native_http_status=native_status)
            except ImportError:
                pass
            stage = 'checking Microsoft HTTPS'
            result = requests.get(
                'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
                impersonate='chrome131_android', timeout=20, allow_redirects=False)
            ok = result.status_code == 200 and 'authorization_endpoint' in result.json()
            checks.update(microsoft_https=ok, http_status=result.status_code, impersonation='chrome131_android')
            message = (f'Python {sys.version.split()[0]} · curl-cffi {curl_cffi.__version__} · '
                       f'CFFI {cffi.__version__} · Microsoft TLS {"OK" if ok else "failed"} '
                       f'(HTTP {result.status_code})')
        except Exception as exc:
            checks.update(failed_stage=stage, error_type=type(exc).__name__)
            message = f'Runtime check failed while {stage} ({type(exc).__name__}).'
        # Only public runtime facts. This file never contains account/token data.
        (self.root / 'runtime-check.json').write_text(json.dumps(checks))
        print('[android-runtime] ' + message, flush=True)
        self._set(diagnostics=message)
        return message

    def import_setup(self, archive):
        with self._operation():
            stage = self.root / ('import-' + uuid.uuid4().hex)
            try:
                confirmed = extract_bundle(archive, stage)
                self._commit_directory(stage, confirmed)
                self._refresh_setup_details()
            finally:
                if stage.exists():
                    shutil.rmtree(stage)

    def _commit_directory(self, stage, confirmed):
        backup = self.root / 'enrollment.previous'
        if backup.exists():
            shutil.rmtree(backup)
        if self.state_dir.exists():
            self.state_dir.rename(backup)
        try:
            stage.rename(self.state_dir)
            from app.state import sync_directory
            sync_directory(self.root)
        except OSError:
            if self.state_dir.exists():
                self.state_dir.rename(stage)
            if backup.exists():
                backup.rename(self.state_dir)
            raise
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
        self._set(has_setup=True, status='Setup imported',
                  message='Ready to connect.' if confirmed else 'Connect, then complete a fresh sign-in to verify this setup.')

    def start(self):
        with self.lock:
            if self.operating:
                return
            if self.worker and self.worker.is_alive():
                return
            if not self.state_dir.is_dir():
                self.view.update(status='Import your setup ZIP first', has_setup=False)
                return
            self.stop_event = threading.Event()
            self.pending = None
            self.answers = queue.Queue(maxsize=8)
            self.view.update(listening=True, connected=False, status='Connecting…', message='')
            self.worker = threading.Thread(target=self._run, name='android-approval', daemon=True)
            self.worker.start()

    def stop(self):
        self.stop_event.set()
        with self.lock:
            self.pending = None
            self.view.update(connected=False, status='Disconnecting…' if self.worker and self.worker.is_alive() else 'Disconnected')

    def answer(self, request_id, answer, unlocked=False):
        with self.lock:
            if self.stop_event.is_set() or not self.pending or self.pending.consumed:
                return False
            try:
                self.answers.put_nowait((request_id, answer, bool(unlocked)))
                return True
            except queue.Full:
                return False

    def _capture(self, data, context, db):
        from app.approval import payload_summary
        # Account/URL verification was done by RegistrationCoordinator.
        with db:
            added = db.execute('INSERT OR IGNORE INTO seen VALUES (?)', (data['guid'],)).rowcount
        if not added:
            return
        pending = PendingRequest(data, context)
        if not pending.choices:
            self._set(message='Request has invalid number choices; start a fresh sign-in.')
            return
        with self.lock:
            self.pending = pending
            self.view.update(message='Choose the number shown on your sign-in page.' if pending.choices != ['APPROVE'] else 'Approve only a sign-in you started.')

    def _submit(self, coordinator):
        from app.approval import build_auth_result, build_pin_validation, pad_url_of, send_pad
        from app.activation import read_tag
        while not self.stop_event.is_set():
            try:
                request_id, answer, unlocked = self.answers.get_nowait()
            except queue.Empty:
                return
            with self.lock:
                pending = self.pending
                if (not pending or not coordinator.context_is_current(pending.context)
                        or not pending.consume(request_id, answer, unlocked)):
                    continue
                self.view['message'] = 'Sending your response…'
            token = pending.context['token']
            app_lock = bool(unlocked)
            numbered = answer not in ('APPROVE', 'DENY')
            if numbered:
                body = build_pin_validation(pending.data['guid'], token, answer, int(time.time() // 30), app_lock_used=app_lock)
                action = 'phoneAppPinValidationRequest'
            else:
                body = build_auth_result(pending.data['guid'], token, 2 if answer == 'DENY' else 1,
                                         int(time.time() // 30), app_lock_used=app_lock)
                action = 'phoneAppAuthenticationResultRequest'
            try:
                status, xml = send_pad(pad_url_of(pending.data), body, token, pending.data, action, 'chrome131_android')
                code = read_tag(xml, 'validationResult' if numbered else 'result')
                success = 200 <= status < 300 and code in (('1', '6') if numbered else ('1',))
                if success and answer != 'DENY' and coordinator.verification_only:
                    coordinator.confirm_test(pending.context)
                message = ('Denial sent.' if answer == 'DENY' else 'Sign-in approved.') if success else 'Microsoft did not confirm success. Check your sign-in page.'
            except (Exception, SystemExit):
                # Consumed before I/O: never retry an uncertain approval.
                message = 'Could not confirm the result. Check your sign-in page before trying again.'
            with self.lock:
                self.pending = None
                self.view['message'] = message

    def _run(self):
        from app.state import exclusive_lock, state_path
        from app.registration_runtime import RegistrationCoordinator
        from app.mcs import McsListener
        from app.approval import classify_push, KIND_LABELS
        coordinator = listener = db = ownership = None
        try:
            ownership = exclusive_lock()
            coordinator = RegistrationCoordinator()
            saved = coordinator.registry.snapshot()
            coordinator.verification_only = not bool(saved['confirmed_at'] and saved['binding_verified'] and not saved['staged'])
            coordinator.registry.verification_material(coordinator.verification_only)
            db = sqlite3.connect(state_path('requests.sqlite3'))
            db.execute('CREATE TABLE IF NOT EXISTS seen (guid TEXT PRIMARY KEY)')
            coordinator.start()
            retry_at, backoff = 0, 1
            while not self.stop_event.is_set():
                ready = bool(listener and listener.ready.is_set())
                coordinator.set_transport_ready(ready)
                self._set(connected=ready, status=('Connected · verification sign-in needed' if coordinator.verification_only else 'Connected · waiting for sign-in') if ready else 'Connecting…')
                if ready:
                    backoff = 1
                if listener:
                    while listener.pushes:
                        data = listener.pushes.pop(0)['app_data']
                        kind = classify_push(data)
                        if kind == 'aad_mfa':
                            coordinator.on_mfa_push(data)
                        elif kind == 'aad_validate':
                            coordinator.on_push(data)
                        else:
                            self._set(message=f'{KIND_LABELS.get(kind, "Unsupported request")} is not supported by this app.')
                if (listener is None or not listener.is_alive()) and time.monotonic() >= retry_at:
                    if listener:
                        if type(getattr(listener, 'login_error_code', None)) is int:
                            coordinator.request_recheckin()
                        listener.stop()
                        listener.join(timeout=2)
                    device = json.loads(state_path('checkin_info.json').read_text())
                    listener = McsListener(int(device['androidId']), int(device['securityToken']))
                    listener.start()
                    retry_at = time.monotonic() + backoff
                    backoff = min(60, backoff * 2)
                for data, context in coordinator.take_auth_results():
                    if coordinator.context_is_current(context):
                        self._capture(data, context, db)
                with self.lock:
                    if self.pending and time.monotonic() >= self.pending.deadline:
                        self.pending = None
                        self.view['message'] = 'Request expired. Start a new sign-in.'
                self._submit(coordinator)
                # Promote a successful first test into normal token maintenance.
                saved = coordinator.registry.snapshot()
                if (coordinator.verification_only and saved['confirmed_at']
                        and saved['binding_verified'] and not saved['staged']):
                    coordinator.stop()
                    coordinator = RegistrationCoordinator()
                    coordinator.start()
                    self._set(message='Setup verified. Sign-in approved.')
                self.stop_event.wait(0.15)
        except (Exception, SystemExit) as exc:
            self._set(message=f'Connection stopped ({type(exc).__name__}). Check your setup and reconnect.')
        finally:
            if listener:
                listener.stop()
                listener.join(timeout=3)
            if coordinator:
                coordinator.stop()
                # Keep ownership until every renewal request has actually finished.
                # Import/reconnect must never race an old network worker.
                for worker in (coordinator.thread, coordinator.auth_thread):
                    if worker.ident is not None:
                        worker.join()
                coordinator.registry.close()
            if db:
                db.close()
            if ownership:
                ownership.close()
            with self.lock:
                self.pending = None
                self.view.update(listening=False, connected=False, status='Disconnected')
