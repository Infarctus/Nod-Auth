#!/usr/bin/env bash
set -euo pipefail
setup_root="$(cd "$(dirname "$0")" && pwd)"
setup_python="${ANDROID_SETUP_PYTHON:-python3}"
setup_venv="$setup_root/.venv"
umask 077

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<'EOF'
Usage: ./android-app/setup.sh [--apk PATH] [--state-dir PATH] [--output PATH]
       ./android-app/setup.sh --prepare-only

Creates android-app/.venv, installs pinned setup dependencies, then prompts for
fresh Microsoft activation details and exports android-app/setup.zip.
Verification happens in the Android app after importing the ZIP.

Defaults:
  APK:       apk/msauth.apk
  State:     android-app/.setup-state
  ZIP:       android-app/setup.zip

--prepare-only installs and checks the dependencies without enrolling an account.
Set ANDROID_SETUP_PYTHON to choose the Python 3.11+ interpreter for a new venv.
EOF
    exit 0
fi

if [[ ! -x "$setup_venv/bin/python" ]]; then
    "$setup_python" -c 'import sys; sys.exit("Python 3.11+ is required.") if sys.version_info < (3, 11) else None'
    "$setup_python" -m venv "$setup_venv"
fi
export PIP_CACHE_DIR="$setup_root/.toolchain/setup-pip-cache"
"$setup_venv/bin/python" -m pip install --disable-pip-version-check -r "$setup_root/requirements-setup.txt"
"$setup_venv/bin/python" -m pip check
"$setup_venv/bin/python" - <<'PY'
import curl_cffi, cffi, tls_client
tls_client.Session(client_identifier="okhttp4_android_13")
print(f"PC setup dependencies ready: curl-cffi {curl_cffi.__version__}, CFFI {cffi.__version__}.")
PY

if [[ "${1:-}" == "--prepare-only" ]]; then
    if [[ $# != 1 ]]; then
        echo '--prepare-only must be used on its own.' >&2
        exit 2
    fi
    exit 0
fi
exec "$setup_venv/bin/python" "$setup_root/tools/create_setup.py" \
    --apk "$setup_root/../apk/msauth.apk" \
    --state-dir "$setup_root/.setup-state" \
    --output "$setup_root/setup.zip" "$@"
