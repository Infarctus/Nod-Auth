#!/usr/bin/env python3
"""PC-only enrollment with phone-side verification, without any bot setup."""
import argparse
import getpass
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
sys.path.insert(0, str(ROOT / 'tools'))


def create_setup(apk, state_dir, output):
    from export_setup import export_setup, BundleError
    if output.exists():
        raise BundleError('Choose a new output ZIP filename before starting setup.')
    if output.resolve().is_relative_to(state_dir.resolve()):
        raise BundleError('Save the ZIP outside the state directory.')
    if not apk.is_file() and not (state_dir / 'apk_config.json').is_file():
        raise BundleError('Provide the original Microsoft Authenticator APK with --apk.')
    from app.state import exclusive_lock
    from app.enrollment import prepare_registration
    from app.registration import RegistrationState
    from app import activation
    os.umask(0o077)
    os.environ['AUTH_STATE_DIR'] = str(state_dir.resolve())
    ownership = exclusive_lock()
    try:
        saved = prepare_registration(apk.resolve())
        registry = RegistrationState()
        try:
            stage = saved.get('staged')
            usable = stage and stage.get('status') == 'test_required' or saved.get('account')
            if usable: registry.verification_material(testing=True)
        finally:
            registry.close()
        if not usable:
            print('Use a fresh activation URL and one-time code from your Microsoft security setup.')
            link = getpass.getpass('Microsoft activatev2 URL (hidden): ').strip()
            code = getpass.getpass('One-time activation code: ').strip()
            activation.activate(link, code)
    finally:
        ownership.close()
    export_setup(state_dir, output)
    print('Setup ZIP created. Import on the phone, connect, then complete a fresh Microsoft sign-in there.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        create_setup(args.apk, args.state_dir, args.output)
    except (Exception, SystemExit) as exc:
        from export_setup import BundleError
        if isinstance(exc, BundleError): parser.exit(1, str(exc) + '\n')
        from app.enrollment import failure_detail
        parser.exit(1, f'PC setup stopped: {failure_detail(exc)}. Saved state is retained. Rerun setup; share this diagnostic if it fails again.\n')
