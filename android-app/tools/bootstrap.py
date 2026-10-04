#!/usr/bin/env python3
"""Install project-local Linux/WSL Android build prerequisites. Requires JDK 17/21 and uv."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / '.toolchain'
SDK = TOOLS / 'sdk'
URL = 'https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip'
SHA = '4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583'


def main():
    TOOLS.mkdir(exist_ok=True)
    env = dict(os.environ)
    jdk = Path('/usr/lib/jvm/java-21-openjdk-amd64')
    if jdk.exists(): env['JAVA_HOME'] = str(jdk)
    manager = SDK / 'cmdline-tools/latest/bin/sdkmanager'
    if not manager.exists():
        archive = TOOLS / 'cmdline-tools.zip'
        if not archive.exists(): archive.write_bytes(urllib.request.urlopen(URL, timeout=120).read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA:
            raise SystemExit('Android tools checksum failed.')
        temp = TOOLS / 'sdk-temp'
        with zipfile.ZipFile(archive) as z: z.extractall(temp)
        manager.parent.parent.parent.mkdir(parents=True, exist_ok=True)
        (temp / 'cmdline-tools').rename(manager.parent.parent)
        for binary in manager.parent.iterdir(): binary.chmod(0o755)
    with (TOOLS / 'sdk-bootstrap.log').open('w') as log:
        subprocess.run([str(manager), '--sdk_root=' + str(SDK), '--licenses'],
                       input='y\n' * 30, text=True, env=env, stdout=log, stderr=log, check=True)
        subprocess.run([str(manager), '--sdk_root=' + str(SDK), 'platforms;android-36',
                        'build-tools;35.0.0', 'platform-tools', 'ndk;28.2.13676358'],
                       env=env, stdout=log, stderr=log, check=True)
    uv = shutil.which('uv')
    if not uv: raise SystemExit('Install uv or provide Python 3.13; see README.md.')
    env.update(UV_PYTHON_INSTALL_DIR=str(TOOLS / 'python'), UV_CACHE_DIR=str(TOOLS / 'uv-cache'))
    subprocess.run([uv, 'python', 'install', '3.13', '--no-bin'], env=env, check=True)
    (ROOT / 'local.properties').write_text('sdk.dir=' + str(SDK) + '\n')
    subprocess.run(['python3', str(ROOT / 'tools/build_cffi.py')], env=env, check=True)
    print('Android build prerequisites ready.')


if __name__ == '__main__': main()
