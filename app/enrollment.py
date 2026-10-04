"""Shared PC enrollment preparation for Docker and Android ZIP setup.

Callers own the state-directory lock and choose where verification happens.
"""
from pathlib import Path
import subprocess
import sys

from app.state import state_path


def prepare_registration(apk):
    from app import fcm
    from app.registration import RegistrationState

    if not state_path('apk_config.json').exists():
        subprocess.run([sys.executable, '-m', 'app.extract_apk_config',
                        '--apk', str(apk), '--out', str(state_path('apk_config.json'))],
                       cwd=Path(__file__).resolve().parent.parent, check=True)
    device = fcm.do_checkin()
    registration = RegistrationState()
    try:
        saved = registration.snapshot()
        if not (saved['active'] or saved['legacy_token'] or saved['google']):
            if saved['account']:
                raise ValueError('activated account has no confirmed local FCM token')
            registration.google_success(fcm.do_register(device))
        return registration.snapshot()
    finally:
        registration.close()


def failure_detail(exc):
    """Report code locations and fixed FCM labels, never exception text."""
    from app.fcm_lifecycle import FcmError

    detail = type(exc).__name__
    if isinstance(exc, FcmError):
        detail += f' [{exc.diagnostic}]'
    trace = exc.__traceback__
    while trace and trace.tb_next:
        trace = trace.tb_next
    if trace:
        code = trace.tb_frame.f_code
        detail += f' at {Path(code.co_filename).name}:{trace.tb_lineno} ({code.co_name})'
    return detail
