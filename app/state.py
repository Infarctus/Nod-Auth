"""Private, durable state files and a single-process ownership lock."""
import base64
import fcntl
import json
import os
import tempfile
import time
import uuid
from pathlib import Path


def state_path(name):
    root = Path(os.environ.get('AUTH_STATE_DIR', Path(__file__).resolve().parent.parent / 'data'))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink():
        raise ValueError('state directory must not be a symlink')
    root.chmod(0o700)
    path = root / name
    if path.parent != root or path.is_symlink():
        raise ValueError('invalid state path')
    if path.exists():
        path.chmod(0o600)
    return path


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_text(name, value):
    path = state_path(name)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.state-')
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save_json(name, value):
    save_text(name, json.dumps(value, indent=2))


def remove_state(name):
    path = state_path(name)
    path.unlink(missing_ok=True)
    sync_directory(path.parent)


def archive_file(name, reason):
    """Preserve exact bytes before replacing a Google credential record."""
    path = state_path(name)
    if not path.exists():
        return
    history_path = state_path('credential_history.json')
    history = json.loads(history_path.read_text()) if history_path.exists() else []
    history.append({'id': uuid.uuid4().hex, 'created_at': int(time.time()),
                    'file': name, 'reason': reason,
                    'content_base64': base64.b64encode(path.read_bytes()).decode('ascii')})
    save_json('credential_history.json', history)


def exclusive_lock():
    lock = open(state_path('service.lock'), 'a')
    os.fchmod(lock.fileno(), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        raise SystemExit('Another setup/runtime is using this state directory')
    return lock
