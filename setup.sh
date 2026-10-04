#!/usr/bin/env bash
# Prepare host bind mounts and run the interactive registration wizard.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
umask 077

fail() { printf 'Setup: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null || fail 'Install Docker with Compose v2 first.'
docker compose version >/dev/null
docker info >/dev/null

# Use the invoking account even if this script was launched through sudo.
export LOCAL_UID="${SUDO_UID:-$(id -u)}"
export LOCAL_GID="${SUDO_GID:-$(id -g)}"
[[ "$LOCAL_UID" != 0 ]] || fail 'Run ./setup.sh as your normal host user (sudo ./setup.sh also preserves that user).'

as_owner_admin() {
    if [[ $(id -u) == 0 ]]; then
        "$@"
    else
        command -v sudo >/dev/null || fail 'Existing files need ownership repair; install sudo or have an administrator repair data/ and apk/.'
        sudo -- "$@"
    fi
}

for directory in data apk; do
    [[ ! -L "$directory" ]] || fail "$directory must be a real directory, not a symlink."
    mkdir -p -- "$directory"
    # Do not follow links out of the directories when fixing permissions.
    scanner=(find)
    if ! entries=$(find "$directory" -type l -print -quit 2>/dev/null); then
        scanner=(as_owner_admin find)
        entries=$("${scanner[@]}" "$directory" -type l -print -quit)
    fi
    [[ -z "$entries" ]] || fail "Remove symlinks from $directory before running setup."
    mismatched=$("${scanner[@]}" "$directory" \( ! -uid "$LOCAL_UID" -o ! -gid "$LOCAL_GID" \) -print -quit)
    if [[ -n "$mismatched" ]]; then
        printf 'Repairing ownership of %s for %s:%s (may require sudo).\n' "$directory" "$LOCAL_UID" "$LOCAL_GID"
        as_owner_admin chown -R -P -- "$LOCAL_UID:$LOCAL_GID" "$directory"
    fi
done
find data -type d -exec chmod 700 {} +
find data -type f -exec chmod 600 {} +
find apk -type d -exec chmod u+rwx {} +
find apk -type f -exec chmod u+r {} +

# Preserve other Compose settings, including AUTH_CONFIG_FILE. Never source .env.
[[ ! -L .env ]] || fail '.env must be a regular file, not a symlink.'
[[ ! -e .env || -f .env ]] || fail '.env must be a regular file.'
env_tmp=$(mktemp .env.setup.XXXXXX)
trap 'rm -f -- "$env_tmp"' EXIT
if [[ -f .env ]]; then
    awk '!/^[[:space:]]*(export[[:space:]]+)?LOCAL_(UID|GID)[[:space:]]*=/' .env > "$env_tmp"
fi
printf 'LOCAL_UID=%s\nLOCAL_GID=%s\n' "$LOCAL_UID" "$LOCAL_GID" >> "$env_tmp"
if [[ $(id -u) == 0 ]]; then
    chown "$LOCAL_UID:$LOCAL_GID" "$env_tmp"
fi
mv -- "$env_tmp" .env

apk_files=()
while IFS= read -r -d '' path; do
    apk_files+=("$path")
done < <(find apk -maxdepth 1 -type f -iname '*.apk' -print0)

apk_container_path=''
if [[ ! -s data/apk_config.json ]]; then
    ((${#apk_files[@]} > 0)) || fail 'Folders and permissions are ready. Place the Microsoft Authenticator APK in apk/, then rerun ./setup.sh.'
    ((${#apk_files[@]} == 1)) || fail 'More than one APK was found in apk/. Leave only the Microsoft Authenticator APK there, then rerun ./setup.sh.'
    apk_container_path="/apk/${apk_files[0]##*/}"
fi

docker compose build
# Check permissions from inside the container, including SELinux and UID mapping.
# The real state lock also catches another running setup/listener before enrollment.
docker compose run --rm --no-deps -T -e "AUTH_APK_PATH=$apk_container_path" setup python -c '
import tempfile
import os
from pathlib import Path
from app.state import exclusive_lock
try:
    with exclusive_lock(), tempfile.TemporaryFile(dir="/data"):
        with open("/config/config.toml", "rb"):
            pass
        if not Path("/data/apk_config.json").exists():
            with open(os.environ["AUTH_APK_PATH"], "rb"):
                pass
except PermissionError:
    raise SystemExit("Container cannot access the mounted state, config, or APK. Check host ownership, SELinux labels, and Docker user-namespace mappings.") from None
'
docker compose run --rm --no-deps -e "AUTH_APK_PATH=$apk_container_path" setup
printf '\nSetup finished. Start the service with: docker compose up -d bot\n'
