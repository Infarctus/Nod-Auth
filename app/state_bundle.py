"""Portable snapshots of data/: shared by the desktop tools and Android app."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
import zipfile

FILES = frozenset({
    'registration.sqlite3', 'requests.sqlite3', 'checkin_info.json', 'apk_config.json',
    'firebase_installation.json', 'firebase_installation.invalid.json', 'fcm_token.txt',
    'activation.json', 'activation.pending.json', 'credential_history.json', 'entra_history.json',
    'setup_complete.json',
    'telegram.json', 'discord.json',
})
REQUIRED = {'registration.sqlite3', 'checkin_info.json', 'apk_config.json', 'fcm_token.txt'}
MAX_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 256
DATABASES = {'registration.sqlite3', 'requests.sqlite3'}


def _ignored(name):
    return (name in {'service.lock', '.DS_Store', 'Thumbs.db'}
            or name.endswith(('.log', '.md')) or name.startswith('.state-')
            or name in {db + suffix for db in DATABASES
                        for suffix in ('-wal', '-shm', '-journal')})


class BundleError(ValueError):
    """Fixed diagnostics safe to display without disclosing setup material."""


def _json(path):
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError, OSError):
        raise BundleError('Setup contains invalid JSON.') from None


def validate_state(root):
    root = Path(root)
    if any(not (root / name).is_file() or (root / name).is_symlink() for name in REQUIRED):
        raise BundleError('Setup is missing required state files.')
    cfg = _json(root / 'apk_config.json')
    if cfg.get('package') != 'com.azure.authenticator' or not cfg.get('version_name'):
        raise BundleError('Setup has no valid Authenticator APK identity.')
    firebase = cfg.get('firebase', {})
    if not isinstance(firebase, dict) or not all(firebase.get(k) for k in ('app_id', 'project', 'api_key', 'sender_id')):
        raise BundleError('Setup has no complete Firebase configuration.')
    device = _json(root / 'checkin_info.json')
    try:
        if not all(0 < int(device[k]) < 2**64 for k in ('androidId', 'securityToken')):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise BundleError('Setup has invalid Google device credentials.') from None
    try:
        request_db = root / 'requests.sqlite3'
        if request_db.exists():
            with sqlite3.connect(request_db.resolve().as_uri() + '?mode=ro', uri=True) as db:
                if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                    raise ValueError()
        with sqlite3.connect((root / 'registration.sqlite3').resolve().as_uri() + '?mode=ro', uri=True) as db:
            if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise ValueError()
            row = db.execute('SELECT state FROM lifecycle WHERE id=1').fetchone()
            saved = json.loads(row[0])
        stage = saved.get('staged')
        account = stage['account'] if stage and stage.get('status') == 'test_required' else saved.get('account', {})
        token = stage['token'] if stage and stage.get('status') == 'test_required' else (
            saved.get('active') or saved.get('legacy_token') or saved.get('google'))
        if (not isinstance(account, dict) or account.get('ActivateNewResult') is not True
                or not all(isinstance(account.get(k), str) and account[k].strip()
                           for k in ('TenantId', 'AzureObjectId'))
                or not isinstance(token, str) or not token or any(c.isspace() for c in token)):
            raise ValueError()
        exported_token = saved.get('active') or saved.get('legacy_token') or saved.get('google')
        if (root / 'fcm_token.txt').read_text().strip() != exported_token:
            raise ValueError()
    except (sqlite3.Error, ValueError, KeyError, TypeError, IndexError, AttributeError, OSError):
        raise BundleError('Setup has no usable enrollment; complete activation first.') from None
    return bool(saved.get('confirmed_at') and saved.get('binding_verified') and not stage)


def export_bundle(source, output):
    """Take a consistent snapshot with the same data/ layout on both platforms."""
    source, output = Path(source).resolve(), Path(output).resolve()
    if not source.is_dir():
        raise BundleError('State directory does not exist.')
    if output.is_relative_to(source):
        raise BundleError('Save the ZIP outside the state directory.')
    try:
        lock_fd = os.open(source / 'service.lock', os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise BundleError('Could not acquire the state ownership lock.') from None
    with os.fdopen(lock_fd, 'a') as ownership:
        os.fchmod(ownership.fileno(), 0o600)
        try:
            fcntl.flock(ownership, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BundleError('Disconnect before exporting the enrollment.') from None
        with tempfile.TemporaryDirectory() as temp:
            snapshot = Path(temp)
            for name in sorted(FILES):
                path = source / name
                if not path.exists():
                    continue
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
                    raise BundleError('State contains an unsupported or oversized file.')
                target = snapshot / name
                if name.endswith('.sqlite3'):
                    try:
                        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as original:
                            with sqlite3.connect(target) as backup:
                                original.backup(backup)
                    except sqlite3.Error:
                        raise BundleError('State contains an unreadable SQLite database.') from None
                else:
                    target.write_bytes(path.read_bytes())
                target.chmod(0o600)
            validate_state(snapshot)
            if sum(p.stat().st_size for p in snapshot.iterdir()) > MAX_BYTES:
                raise BundleError('State snapshot exceeds the size limit.')
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                    for path in sorted(snapshot.iterdir()):
                        archive.writestr('data/' + path.name, path.read_bytes())
                stream.flush()
                os.fsync(stream.fileno())


def extract_bundle(archive, destination):
    """Extract into a NEW private staging directory; caller commits after validation."""
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    try:
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            names = [i.filename.removeprefix('./') for i in infos]
            if (len(names) != len(set(names)) or len(names) > MAX_ENTRIES
                    or sum(i.file_size for i in infos) > MAX_BYTES):
                raise BundleError('Setup ZIP contains unexpected files or exceeds the size limit.')
            prefixed = any(name.startswith('data/') for name in names)
            entries = {}
            for info in infos:
                mode = info.external_attr >> 16
                kind = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
                if info.flag_bits & 1 or stat.S_IFMT(mode) not in (0, kind):
                    raise BundleError('Setup ZIP contains unsupported file entries.')
                name = info.filename.removeprefix('./')
                if info.is_dir() and name in {'', 'data/'}:
                    continue
                if prefixed:
                    if not name.startswith('data/'):
                        raise BundleError('Setup ZIP mixes data/ with files at the ZIP root.')
                    name = name[5:]
                if (not name or '/' in name or '\\' in name or ':' in name
                        or name in {'.', '..'} or info.is_dir()):
                    raise BundleError('Setup ZIP contains an unsupported path.')
                if name not in FILES:
                    if not _ignored(name):
                        raise BundleError('Setup ZIP contains an unsupported state file.')
                    if name.endswith(('-wal', '-journal')) and info.file_size:
                        raise BundleError('Stop the listener and recreate the ZIP; it contains an active SQLite journal.')
                    continue
                entries[name] = info
            if not REQUIRED <= entries.keys():
                raise BundleError('Setup ZIP is missing required state files.')
            for name, info in entries.items():
                data = z.read(info)
                path = destination / name
                with path.open('xb') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
        confirmed = validate_state(destination)
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return confirmed
    except BundleError:
        shutil.rmtree(destination)
        raise
    except (ValueError, TypeError, KeyError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
        shutil.rmtree(destination)
        raise BundleError('Could not read the setup ZIP.') from None


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    export = commands.add_parser('export', help='Snapshot a stopped data directory.')
    export.add_argument('--state-dir', type=Path, default=Path('data'))
    export.add_argument('--output', type=Path, required=True)
    restore = commands.add_parser('import', help='Validate and extract a ZIP into a new data directory.')
    restore.add_argument('--archive', type=Path, required=True)
    restore.add_argument('--state-dir', type=Path, default=Path('data'))
    args = parser.parse_args()
    try:
        if args.command == 'export':
            export_bundle(args.state_dir, args.output)
            print('Data ZIP created.')
        else:
            if args.state_dir.exists():
                raise BundleError('Destination already exists; choose a new state directory or move the old data/ aside first.')
            confirmed = extract_bundle(args.archive, args.state_dir)
            print('Data ZIP imported.' + ('' if confirmed else ' Complete a fresh sign-in to verify enrollment.'))
    except (BundleError, OSError) as exc:
        parser.exit(1, str(exc) + '\n' if isinstance(exc, BundleError) else 'Could not access the data ZIP or directory.\n')


if __name__ == '__main__':
    main()
