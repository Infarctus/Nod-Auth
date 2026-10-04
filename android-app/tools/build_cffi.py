#!/usr/bin/env python3
"""Build CFFI 2.0 for Chaquopy Python 3.13/ARM64 from verified upstream inputs."""
import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / '.toolchain/native'
WHEELS = ROOT / '.toolchain/wheels'
NDK_VERSION = '28.2.13676358'
INPUTS = {
    'cffi-2.0.0.tar.gz': (
        'https://files.pythonhosted.org/packages/source/c/cffi/cffi-2.0.0.tar.gz',
        '44d1b5909021139fe36001ae048dbdde8214afa20200eda0f64c068cac5d5529'),
    'python-target.zip': (
        'https://repo.maven.apache.org/maven2/com/chaquo/python/target/3.13.9-0/target-3.13.9-0-arm64-v8a.zip',
        'c19f39fecada0b3932ab7a61b0f214c1212068cbbae0dc22c2afa38a4f354b8e'),
    'libffi.whl': (
        'https://chaquo.com/pypi-13.1/chaquopy-libffi/chaquopy_libffi-3.3-3-py3-none-android_24_arm64_v8a.whl',
        '86873c2f8e5e43b07b72233bf35e06ad8dae41ba98e0556202d61d00d7ad952f'),
}


def main():
    NATIVE.mkdir(parents=True, exist_ok=True)
    WHEELS.mkdir(parents=True, exist_ok=True)
    sdk = Path(os.environ.get('ANDROID_HOME', ROOT / '.toolchain/sdk'))
    ndk = Path(os.environ.get('ANDROID_NDK_HOME', sdk / 'ndk' / NDK_VERSION))
    clang = ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang'
    if not clang.is_file():
        raise SystemExit(f'Install Android NDK {NDK_VERSION} first; see README.md.')
    for name, (url, expected) in INPUTS.items():
        path = NATIVE / name
        if not path.exists():
            path.write_bytes(urllib.request.urlopen(url, timeout=120).read())
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f'Checksum failed for {name}; remove it and retry.')
    with tarfile.open(NATIVE / 'cffi-2.0.0.tar.gz') as archive:
        archive.extractall(NATIVE, filter='data')
    for name, directory in [('python-target.zip', 'python-target'), ('libffi.whl', 'libffi')]:
        with zipfile.ZipFile(NATIVE / name) as archive:
            archive.extractall(NATIVE / directory)
    source = NATIVE / 'cffi-2.0.0'
    python = NATIVE / 'python-target'
    ffi = NATIVE / 'libffi/chaquopy'
    backend = NATIVE / '_cffi_backend.so'
    subprocess.run([
        str(clang), '-shared', '-fPIC', '-O2', '-DFFI_BUILDING=1', '-DUSE__THREAD',
        '-DHAVE_SYNC_SYNCHRONIZE', '-I' + str(python / 'include/python3.13'),
        '-I' + str(ffi / 'include'), str(source / 'src/c/_cffi_backend.c'),
        '-L' + str(ffi / 'lib'), '-lffi', '-L' + str(python / 'jniLibs/arm64-v8a'),
        '-lpython3.13', '-ldl', '-Wl,-z,max-page-size=16384',
        '-Wl,-rpath,$ORIGIN/chaquopy/lib', '-o', str(backend),
    ], check=True)
    files = {str(p.relative_to(source / 'src')): p.read_bytes()
             for p in (source / 'src/cffi').rglob('*') if p.is_file() and p.suffix in ('.py', '.h')}
    files['_cffi_backend.so'] = backend.read_bytes()
    info = 'cffi-2.0.0.dist-info/'
    files[info + 'METADATA'] = (
        'Metadata-Version: 2.1\nName: cffi\nVersion: 2.0.0\n'
        'Summary: CFFI Android build for Chaquopy\nLicense: MIT\n'
        'Requires-Dist: pycparser\nRequires-Dist: chaquopy-libffi (==3.3)\n').encode()
    files[info + 'WHEEL'] = (
        'Wheel-Version: 1.0\nGenerator: android-app/tools/build_cffi.py\n'
        'Root-Is-Purelib: false\nTag: cp313-cp313-android_24_arm64_v8a\n').encode()
    files[info + 'LICENSE'] = (source / 'LICENSE').read_bytes()
    rows = [[name, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='), str(len(data))]
            for name, data in sorted(files.items())]
    rows.append([info + 'RECORD', '', ''])
    record = io.StringIO()
    csv.writer(record).writerows(rows)
    files[info + 'RECORD'] = record.getvalue().encode()
    wheel = WHEELS / 'cffi-2.0.0-cp313-cp313-android_24_arm64_v8a.whl'
    with zipfile.ZipFile(wheel, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(2026, 9, 30, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    print('Built CFFI 2.0.0 for Android ARM64 / Python 3.13.')


if __name__ == '__main__':
    main()
