#!/usr/bin/env python3
"""Install the debug APK using Linux ADB or Windows ADB from WSL."""
import argparse
from pathlib import Path
import subprocess

from adb import find_adb

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', help='ADB device serial; required if several devices are connected')
    parser.add_argument('--apk', type=Path, default=ROOT / 'app/build/outputs/apk/debug/app-debug.apk')
    args = parser.parse_args()
    try:
        adb = find_adb()
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if not args.apk.is_file(): parser.error('Build the APK first with tools/build.sh.')
    if not args.serial:
        result = subprocess.check_output([adb, 'devices'], text=True)
        devices = [line.split()[0] for line in result.splitlines() if len(line.split()) >= 2 and line.split()[1] == 'device']
        if len(devices) != 1: parser.error('Authorize exactly one device or specify --serial.')
        args.serial = devices[0]
    apk = str(args.apk.resolve())
    if adb.lower().endswith('.exe'): apk = subprocess.check_output(['wslpath', '-w', apk], text=True).strip()
    subprocess.run([adb, '-s', args.serial, 'install', '-r', apk], check=True)
    subprocess.run([adb, '-s', args.serial, 'shell', 'am', 'start', '-n',
                    'io.github.infarctus.nodauth/.MainActivity'], check=True)


if __name__ == '__main__': main()
