#!/usr/bin/env python3
"""Locate ADB without a machine-specific username, or run an ADB command."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WINDOWS_USERS = Path('/mnt/c/Users')


def find_adb():
    configured = os.environ.get('ANDROID_ADB')
    if configured:
        return configured
    for command in ('adb', 'adb.exe'):
        executable = shutil.which(command)
        if executable:
            return executable
    # Windows ADB can use Windows USB devices from WSL without USB passthrough.
    windows = sorted(WINDOWS_USERS.glob(
        '*/Downloads/platform-tools-latest-windows/platform-tools/adb.exe'))
    if len(windows) == 1:
        return str(windows[0])
    if len(windows) > 1:
        raise FileNotFoundError('Multiple Windows ADB installations found. Set ANDROID_ADB to the one to use.')
    sdk_roots = [Path(os.environ[name]) for name in ('ANDROID_HOME', 'ANDROID_SDK_ROOT')
                 if os.environ.get(name)]
    sdk_roots.append(ROOT / '.toolchain/sdk')
    for sdk in sdk_roots:
        for name in ('adb', 'adb.exe'):
            executable = sdk / 'platform-tools' / name
            if executable.is_file():
                return str(executable)
    raise FileNotFoundError('Set ANDROID_ADB to your adb or adb.exe executable.')


def main():
    try:
        return subprocess.call([find_adb(), *sys.argv[1:]])
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
