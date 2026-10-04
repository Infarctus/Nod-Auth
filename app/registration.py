"""Durable single-account enrollment, token binding and recovery records.

SQLite is authoritative. JSON/text files are repairable exports; history is
written and fsynced before any enrollment or credential replacement.
"""
from __future__ import annotations

import copy
import functools
import json
import os
import random
import sqlite3
import threading
import time
import uuid

from app.state import state_path, save_json, save_text, remove_state, exclusive_lock

SENT_PHASES = {'v1_sent', 'v2_complete_sent'}


def locked(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return call


def valid_token(token):
    return isinstance(token, str) and bool(token) and not any(c.isspace() for c in token)


def valid_account(account):
    return (isinstance(account, dict) and account.get('ActivateNewResult') is True
            and all(isinstance(account.get(k), str) and account[k].strip()
                    for k in ('TenantId', 'AzureObjectId'))
            and (not account.get('OathTokenEnabled') or bool(account.get('OathTokenSecretKey'))))


class RegistrationState:
    def __init__(self, now=None, spread_hours=None):
        self.lock = threading.RLock()
        self.now = now or time.time
        self.spread_hours = spread_hours or (lambda: random.randrange(120))
        path = state_path('registration.sqlite3')
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS lifecycle (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS validation_seen (fingerprint TEXT PRIMARY KEY)')
        columns = {row[1] for row in self.db.execute('PRAGMA table_info(validation_seen)')}
        if 'completed' not in columns:
            # Existing rows represent challenges previously treated as delivered.
            self.db.execute('ALTER TABLE validation_seen ADD COLUMN completed INTEGER NOT NULL DEFAULT 1')
        if 'lease_until' not in columns:
            self.db.execute('ALTER TABLE validation_seen ADD COLUMN lease_until INTEGER NOT NULL DEFAULT 0')
        if 'completed_at' not in columns:
            self.db.execute('ALTER TABLE validation_seen ADD COLUMN completed_at INTEGER NOT NULL DEFAULT 0')
            self.db.execute('UPDATE validation_seen SET completed_at=? WHERE completed=1',
                            (int(self.now()),))
        self.db.execute('CREATE INDEX IF NOT EXISTS validation_seen_age ON validation_seen(completed,completed_at)')
        row = self.db.execute('SELECT state FROM lifecycle WHERE id=1').fetchone()
        self.state = json.loads(row[0]) if row else self._import_legacy()
        self._upgrade()
        self._save()
        export = state_path('activation.json')
        if export.exists():
            try:
                differs = json.loads(export.read_text()) != self.state['account']
            except ValueError:
                differs = True
            if differs:
                self._archive('before_export_repair')
        self._export()

    def _import_legacy(self):
        token_path = state_path('fcm_token.txt')
        account_path = state_path('activation.json')
        token = token_path.read_text().strip() if token_path.exists() else ''
        account = json.loads(account_path.read_text()) if account_path.exists() else {}
        if token and not valid_token(token):
            raise ValueError('malformed saved token; original files retained')
        return {'schema': 2, 'active': token if not account else '', 'google': token,
                'bound': '', 'legacy_token': token if account else '',
                'binding_verified': False, 'pending': '', 'generation': int(bool(token)),
                'pending_generation': 0, 'phase': 'legacy_binding_unverified' if account else 'initial',
                'google_checked_at': 0, 'google_attempt_at': 0, 'google_due_at': 0,
                'binding_due_at': 0, 'binding_attempt_at': 0, 'binding_attempts': 0,
                'binding_failed': False, 'last_error': '', 'account': account,
                'revision': uuid.uuid4().hex, 'confirmed_at': 0, 'staged': None,
                'attempt': None, 'attempt_history': [], 'token_history': []}

    def _upgrade(self):
        s = self.state
        s.setdefault('revision', uuid.uuid4().hex)
        s.setdefault('confirmed_at', 0)
        s.setdefault('staged', None)
        s.setdefault('attempt', None)
        s.setdefault('attempt_history', [])
        s.setdefault('token_history', [])
        s.setdefault('legacy_token', '')
        if s.get('schema', 1) < 2:
            self._archive('schema_upgrade')
            if not s.get('binding_verified') and s.get('account'):
                s['legacy_token'] = s['active'] or s['bound']
                s['active'] = s['bound'] = ''
                if s['phase'] not in SENT_PHASES | {'uncertain'}:
                    s['phase'] = 'legacy_binding_unverified'
            # Old state did not retain an immutable attempt. Do not replay it.
            if s['phase'] in SENT_PHASES | {'uncertain'}:
                s['attempt'] = {'id': uuid.uuid4().hex, 'old': s['bound'],
                                'target': s['pending'], 'generation': s['pending_generation'],
                                'phase': s['phase'], 'revision': s['revision'],
                                'started_at': s['binding_attempt_at'], 'protocol': 'unknown'}
            s['schema'] = 2
        if s['phase'] in SENT_PHASES:
            s['phase'] = 'uncertain'
            s['last_error'] = 'process_stopped_after_send'
            s['binding_failed'] = True
            s['binding_due_at'] = max(int(self.now()), s['binding_attempt_at'] + 86400)
        elif s['phase'] == 'uncertain' and s['attempt'] and s['attempt'].get('protocol') in {'V1', 'V2'}:
            # Older bridge versions parked these attempts at NEVER. Resume the
            # APK's daily retry cadence without sending immediately on restart.
            s['binding_due_at'] = max(int(self.now()), s['binding_attempt_at'] + 86400)
        elif s['phase'] in {'v2_start', 'v2_waiting_validation'}:
            self._finish_attempt('interrupted_before_complete')
            s['phase'] = 'retry'
            s['binding_due_at'] = max(int(self.now()), s['binding_attempt_at'] + 86400)

    @locked
    def _save(self):
        try:
            with self.db:
                self.db.execute('INSERT OR REPLACE INTO lifecycle(id,state) VALUES(1,?)',
                                (json.dumps(self.state, separators=(',', ':')),))
        except BaseException:
            row = self.db.execute('SELECT state FROM lifecycle WHERE id=1').fetchone()
            if row:
                self.state = json.loads(row[0])
            raise

    def _archive(self, reason):
        path = state_path('entra_history.json')
        history = json.loads(path.read_text()) if path.exists() else []
        entry = {'id': uuid.uuid4().hex, 'created_at': int(self.now()), 'reason': reason,
                 'state': copy.deepcopy(self.state)}
        # Preserve an out-of-sync legacy export too, without trusting it.
        activation = state_path('activation.json')
        if activation.exists():
            entry['activation_file'] = activation.read_text()
        token_file = state_path('fcm_token.txt')
        if token_file.exists():
            entry['token_file'] = token_file.read_text()
        history.append(entry)
        save_json('entra_history.json', history)
        return entry['id']

    @locked
    def archive(self, reason):
        return self._archive(reason)

    def _export(self):
        s = self.state
        if s['account']:
            save_json('activation.json', s['account'])
        token = s['active'] or s['legacy_token']
        if token:
            save_text('fcm_token.txt', token + '\n')
        if s['staged']:
            save_json('activation.pending.json', s['staged'])
        else:
            remove_state('activation.pending.json')
        if s['confirmed_at'] and s['binding_verified']:
            save_json('setup_complete.json', {'confirmed_at': s['confirmed_at'], 'revision': s['revision']})
        else:
            remove_state('setup_complete.json')

    @locked
    def close(self):
        self.db.close()

    @locked
    def snapshot(self):
        return copy.deepcopy(self.state)

    @property
    def active_token(self):
        with self.lock:
            return self.state['active'] if self.state['binding_verified'] or not self.state['account'] else ''

    @locked
    def begin_enrollment(self, token):
        if not valid_token(token) or token not in {self.state['google'], self.state['active'], self.state['legacy_token']}:
            raise ValueError('enrollment token is not in saved state')
        self._archive('before_enrollment')
        candidate = {'id': uuid.uuid4().hex, 'token': token, 'account': {},
                     'created_at': int(self.now()), 'status': 'awaiting_response',
                     'base_revision': self.state['revision']}
        self.state['staged'] = candidate
        self._save()
        self._export()
        return candidate['id']

    @locked
    def retain_activation_response(self, candidate_id, raw_response, status, confirmation=False):
        stage = self.state['staged']
        if not stage or stage['id'] != candidate_id:
            raise ValueError('stale activation response')
        if confirmation:
            stage.update(confirmation_response_xml=raw_response, confirmation_http_status=status)
        else:
            stage.update(response_xml=raw_response, http_status=status, status='response_received')
        self._save()
        self._export()

    @locked
    def stage_activation(self, candidate_id, account, raw_response='', evidence=None):
        stage = self.state['staged']
        if not stage or stage['id'] != candidate_id:
            raise ValueError('stale enrollment response')
        # Persist even incomplete responses: an OATH secret must not be lost.
        stage.update(account=copy.deepcopy(account), response_xml=raw_response,
                     status='confirmation_required')
        if evidence is not None:
            stage['validation_evidence'] = copy.deepcopy(evidence)
        self._save()
        self._export()
        if not valid_account(account):
            raise ValueError('incomplete Entra activation; response preserved in staging')

    @locked
    def confirm_staged(self, candidate_id):
        stage = self.state['staged']
        if not stage or stage['id'] != candidate_id or not valid_account(stage['account']):
            raise ValueError('invalid staged activation')
        stage['status'] = 'test_required'
        self._save()
        self._export()

    @locked
    def verification_material(self, testing=False):
        s = self.state
        stage = s['staged'] if testing else None
        if stage:
            if stage['status'] != 'test_required' or not valid_account(stage['account']):
                raise ValueError('staged activation is not ready for a sign-in test')
            return {'revision': s['revision'], 'candidate_id': stage['id'],
                    'account': copy.deepcopy(stage['account']), 'token': stage['token']}
        if not valid_account(s['account']):
            raise ValueError('saved Entra account is incomplete; enroll again')
        token = s['active'] or s['legacy_token'] or s['google']
        if not valid_token(token):
            raise ValueError('saved Entra token is missing')
        return {'revision': s['revision'], 'candidate_id': None,
                'account': copy.deepcopy(s['account']), 'token': token,
                'binding_stamp': [s['binding_attempts'], len(s['token_history'])]}

    @locked
    def commit_test(self, context):
        s = self.state
        if context['revision'] != s['revision']:
            raise ValueError('approval belongs to a previous enrollment')
        if (not context.get('candidate_id') and context.get('binding_stamp') is not None
                and context['binding_stamp'] != [s['binding_attempts'], len(s['token_history'])]):
            raise ValueError('approval belongs to a previous token binding')
        candidate_id = context.get('candidate_id')
        if candidate_id:
            stage = s['staged']
            if not stage or stage['id'] != candidate_id or stage['status'] != 'test_required' or stage['token'] != context['token']:
                raise ValueError('approval does not verify the staged enrollment')
            self._archive('before_enrollment_commit')
            s['account'] = copy.deepcopy(stage['account'])
            s['revision'] = uuid.uuid4().hex
            s['staged'] = None
            self._finish_attempt('replaced_by_enrollment')
        elif s['phase'] == 'uncertain':
            # Approval of the old token alone does not disprove a remote change.
            s['confirmed_at'] = int(self.now())
            self._save()
            self._export()
            return
        self._set_bound(context['token'], 'confirmed_sign_in')
        s['confirmed_at'] = int(self.now())
        self._save()
        self._export()

    @locked
    def mark_activation(self, token, account):
        """Record an already verified enrollment (used by offline fixtures)."""
        if not valid_token(token) or token != self.state['active']:
            raise ValueError('activation token differs from active token')
        self._archive('before_verified_activation')
        self.state['account'] = copy.deepcopy(account)
        self._set_bound(token, 'activation')
        self._save()
        self._export()

    def _set_bound(self, token, reason):
        s = self.state
        if not valid_token(token):
            raise ValueError('invalid binding token')
        s['token_history'].append({'token': token, 'previous': s['bound'],
                                   'at': int(self.now()), 'reason': reason})
        s.update(active=token, bound=token, legacy_token='', binding_verified=True,
                 binding_failed=False, last_error='')
        target = s['google'] if s['google'] and s['google'] != token else ''
        s['pending'] = target
        s['pending_generation'] = s['generation'] if target else 0
        s['phase'] = 'pending' if target else 'bound'
        s['binding_due_at'] = int(self.now()) + self.spread_hours() * 3600 if target else 0

    @locked
    def update_account(self, fields):
        changes = {k: v for k, v in fields.items() if self.state['account'].get(k) != v}
        if changes:
            self._archive('before_account_metadata_update')
            self.state['account'].update(changes)
            self._resume_after_metadata_recovery()
            self._save()
            self._export()

    def _resume_after_metadata_recovery(self):
        s = self.state
        account = s['account']
        if (s['pending'] and s['binding_verified'] and not s['attempt']
                and s['phase'] in {'retry', 'metadata_required'}
                and s['last_error'] in {'invalid_dos_preventer', 'metadata_required'}
                and account.get('BindingProtocol') != 'V2'
                and all(account.get(k) for k in ('PadUrl', 'ReplicationScopes', 'DosPreventer'))):
            # Recover the blocked job without bypassing the APK's daily gate.
            earliest = s['binding_attempt_at'] + 86400 if s['binding_attempt_at'] else 0
            s.update(phase='pending', binding_failed=False, last_error='',
                     binding_due_at=max(int(self.now()), earliest))

    @locked
    def invalidate_dos_preventer(self, rejected):
        # An authentication response can deliver a replacement while V1 runs.
        # Only clear the credential that the failed operation actually sent.
        if rejected and self.state['account'].get('DosPreventer') == rejected:
            self.update_account({'DosPreventer': ''})

    @locked
    def learn(self, context, fields, server_token=''):
        """Called only with a typed, account-matched Entra response."""
        if context['revision'] != self.state['revision']:
            return False
        if context.get('candidate_id'):
            stage = self.state['staged']
            if not stage or stage['id'] != context['candidate_id']:
                return False
            if ('DosPreventer' in fields and context['account'].get('DosPreventer')
                    != stage['account'].get('DosPreventer')):
                return False
            stage['account'].update(fields)
            self._save()
            self._export()
            return True
        if (context.get('binding_stamp') is not None and context['binding_stamp'] !=
                [self.state['binding_attempts'], len(self.state['token_history'])]):
            return False
        if ('DosPreventer' in fields and context['account'].get('DosPreventer')
                != self.state['account'].get('DosPreventer')):
            return False
        self.update_account(fields)
        if server_token:
            if self.state['attempt']:
                attempt = self.state['attempt']
                if self.state['phase'] == 'uncertain' and server_token == attempt['target']:
                    self.binding_success(server_token, attempt['id'])
                else:
                    # Keep the attempt phase stable while its HTTP request runs.
                    attempt['observed_token'] = server_token
                    attempt['observed_at'] = int(self.now())
                    self._save()
            elif server_token != self.state['bound'] or not self.state['binding_verified']:
                self._set_bound(server_token, 'account_matched_authentication_response')
                self._save()
                self._export()
        return True

    @locked
    def record_google_attempt(self):
        self.state['google_attempt_at'] = int(self.now())
        self._save()

    @locked
    def google_success(self, token, app_version=''):
        if not valid_token(token):
            raise ValueError('empty or malformed Google registration')
        s = self.state
        now = int(self.now())
        changed = token != s['google']
        s.update(google=token, google_checked_at=now, google_due_at=now + 30 * 86400,
                 google_error='', google_app_version=str(app_version))
        if changed:
            s['generation'] += 1
            if s['phase'] == 'uncertain' or s['attempt']:
                s['pending'] = token
                s['pending_generation'] = s['generation']
            elif not s['account']:
                s.update(active=token, pending='', phase='initial')
            elif not s['binding_verified']:
                s.update(pending=token, pending_generation=s['generation'], phase='legacy_binding_unverified')
            elif token == s['bound']:
                s.update(pending='', pending_generation=0, phase='bound', binding_failed=False)
            else:
                s.update(pending=token, pending_generation=s['generation'], phase='pending',
                         binding_due_at=now + self.spread_hours() * 3600, binding_failed=False)
        self._save()
        self._export()
        return changed

    @locked
    def google_failure(self, kind, retry_seconds=30):
        self.state.update(google_error=kind, google_due_at=int(self.now()) + retry_seconds)
        self._save()

    @locked
    def force_rebind(self, server_token):
        if not valid_token(server_token) or self.state['phase'] == 'uncertain':
            return False
        self._set_bound(server_token, 'verified_server_mismatch')
        self.state['binding_due_at'] = int(self.now())
        self._save()
        self._export()
        return bool(self.state['pending'])

    @locked
    def binding_started(self, phase, expected=None):
        s = self.state
        if expected and any(s[key] != value for key, value in expected.items()):
            raise ValueError('binding context changed before send')
        if not s['pending'] or s['phase'] == 'uncertain':
            raise ValueError('no safe pending Entra binding')
        if not s['attempt']:
            s['attempt'] = {'id': uuid.uuid4().hex, 'old': s['bound'], 'target': s['pending'],
                            'generation': s['pending_generation'], 'revision': s['revision'],
                            'started_at': int(self.now()), 'protocol': 'V1' if phase == 'v1_sent' else 'V2',
                            'account': copy.deepcopy(s['account'])}
            s['binding_attempt_at'] = int(self.now())
            s['binding_attempts'] += 1
        s['attempt']['phase'] = phase
        s['phase'] = phase
        self._save()
        return copy.deepcopy(s['attempt'])

    def _finish_attempt(self, result):
        if self.state.get('attempt'):
            self.state['attempt']['outcome'] = result
            self.state['attempt_history'].append(copy.deepcopy(self.state['attempt']))
            self.state['attempt'] = None

    @locked
    def binding_failure(self, kind, retry_seconds=86400, uncertain=None):
        s = self.state
        if uncertain is None:
            uncertain = s['phase'] in SENT_PHASES
        if uncertain:
            attempt = s['attempt']
            if attempt and attempt.get('observed_token') == attempt['target']:
                self.binding_success(attempt['target'], attempt['id'])
                return
            s.update(phase='uncertain',
                     binding_due_at=max(int(self.now()), s['binding_attempt_at'] + 86400))
        else:
            self._finish_attempt(kind)
            s.update(phase='metadata_required' if kind == 'metadata_required' else 'retry',
                     binding_due_at=int(self.now()) + retry_seconds)
        s.update(binding_failed=True, last_error=kind)
        self._resume_after_metadata_recovery()
        self._save()

    @locked
    def retry_uncertain(self):
        """Retry a lost-result change after the APK's daily gate.

        Keep the last confirmed binding until a new response or an account-
        matched server observation confirms the target. If Google has issued
        another token, archive the unresolved attempt before trying that token.
        """
        s = self.state
        attempt = s['attempt']
        if (s['phase'] != 'uncertain' or not attempt
                or attempt.get('protocol') not in {'V1', 'V2'}
                or attempt.get('revision') != s['revision']
                or not s['pending'] or s['google'] != s['pending']
                or s['pending'] == s['bound']
                or not s['binding_verified']
                or int(self.now()) < s['binding_due_at']
                or int(self.now()) - s['binding_attempt_at'] < 86400):
            return False
        if (s['account'].get('BindingProtocol') == 'V2') != (attempt['protocol'] == 'V2'):
            return False
        self._finish_attempt('retry_after_ambiguous_response')
        s.update(phase='retry', binding_due_at=int(self.now()))
        self._save()
        return True

    @locked
    def binding_success(self, target, attempt_id=None):
        s = self.state
        attempt = s['attempt']
        expected = attempt['target'] if attempt else s['pending']
        if (target != expected or not target or
                (attempt_id and (not attempt or attempt['id'] != attempt_id))):
            raise ValueError('stale binding response')
        self._finish_attempt('confirmed')
        self._set_bound(target, 'binding_confirmed')
        self._save()
        self._export()

    @locked
    def claim_validation(self, fingerprint):
        now = int(self.now())
        with self.db:
            # Validation GUIDs expire remotely; retain local replay protection for 30 days.
            self.db.execute('DELETE FROM validation_seen WHERE completed=1 AND completed_at>0 AND completed_at<?',
                            (now - 30 * 86400,))
            added = self.db.execute(
                'INSERT OR IGNORE INTO validation_seen(fingerprint,completed,lease_until) VALUES (?,0,?)',
                (fingerprint, now + 60)).rowcount
            if added:
                return True
            return bool(self.db.execute(
                'UPDATE validation_seen SET lease_until=? WHERE fingerprint=? AND completed=0 AND lease_until<=?',
                (now + 60, fingerprint, now)).rowcount)

    @locked
    def complete_validation(self, fingerprint):
        with self.db:
            self.db.execute('UPDATE validation_seen SET completed=1, lease_until=0, completed_at=? WHERE fingerprint=?',
                            (int(self.now()), fingerprint))

    @locked
    def release_validation(self, fingerprint):
        with self.db:
            self.db.execute('DELETE FROM validation_seen WHERE fingerprint=? AND completed=0',
                            (fingerprint,))

    @locked
    def restore(self, entry_id):
        entries = json.loads(state_path('entra_history.json').read_text())
        matches = [e for e in entries if e['id'] == entry_id]
        if len(matches) != 1 or not valid_account(matches[0]['state']['account']):
            raise ValueError('history entry has no complete Entra account')
        saved = matches[0]['state']
        token = saved['active'] or saved['bound'] or saved.get('legacy_token', '')
        if not valid_token(token):
            raise ValueError('history entry has no enrollment token')
        self._archive('before_restore')
        self._finish_attempt('restored_enrollment')
        self.state.update(account=copy.deepcopy(saved['account']), active='', bound='',
                          legacy_token=token, binding_verified=False, pending='', staged=None,
                          confirmed_at=0, revision=uuid.uuid4().hex, phase='legacy_binding_unverified',
                          binding_failed=False, last_error='', binding_due_at=0)
        self._save()
        self._export()

    @locked
    def status(self):
        return public_status(self.state)


def public_status(s):
    # Allow-list: future secret-bearing fields cannot accidentally reach logs.
    names = ('schema', 'phase', 'generation', 'pending_generation', 'binding_verified',
             'google_checked_at', 'google_due_at', 'google_attempt_at', 'binding_due_at',
             'binding_attempt_at', 'binding_attempts', 'binding_failed', 'last_error',
             'google_error', 'confirmed_at')
    result = {k: s[k] for k in names if k in s}
    account = s.get('account') or {}
    result.update(has_dos_preventer=bool(account.get('DosPreventer')),
                  dos_recovery_needed=bool(account) and not bool(account.get('DosPreventer')),
                  has_pending_token=bool(s.get('pending')),
                  google_matches_bound=bool(s.get('bound')) and s.get('bound') == s.get('google'),
                  has_staged_activation=bool(s.get('staged')),
                  staged_status=(s.get('staged') or {}).get('status', ''),
                  has_unresolved_attempt=bool(s.get('attempt')))
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Private Entra enrollment recovery and redacted status')
    parser.add_argument('command', choices=['status', 'history', 'restore'])
    parser.add_argument('entry_id', nargs='?')
    args = parser.parse_args()
    if args.command == 'history':
        path = state_path('entra_history.json')
        entries = json.loads(path.read_text()) if path.exists() else []
        print(json.dumps([{k: e[k] for k in ('id', 'created_at', 'reason')} for e in entries]))
    elif args.command == 'restore':
        if not args.entry_id:
            parser.error('restore requires an entry ID from history')
        with exclusive_lock():
            registry = RegistrationState()
            try:
                registry.restore(args.entry_id)
            finally:
                registry.close()
        print('Saved enrollment restored locally. Run setup and verify it with a new sign-in; remote registrations are unchanged.')
    else:
        path = state_path('registration.sqlite3')
        if not path.exists():
            print(json.dumps({'phase': 'uninitialized'}))
            return
        with sqlite3.connect(f'file:{path}?mode=ro', uri=True) as db:
            row = db.execute('SELECT state FROM lifecycle WHERE id=1').fetchone()
        print(json.dumps(public_status(json.loads(row[0])) if row else {'phase': 'uninitialized'}, sort_keys=True))


if __name__ == '__main__':
    main()
