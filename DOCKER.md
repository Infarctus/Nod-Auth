# Nod Auth bot approval bridge

One image provides an interactive `setup` container and a long-running `bot`
container. Both bind-mount **`./data` on the host to `/data`**. No ports are
published: Telegram uses long polling and Discord uses REST DM polling (plus an outbound Gateway connection for optional buttons); MCS connects outbound to Google on TCP
5228. HTTPS access to the selected bot provider, Microsoft and Google is also required.

## Configuration

Edit [config.toml](config.toml) to choose notification enablement, startup
announcements, the provider, private destination, reply timeout, and request limit.
For optional plain-message approvals and clickable number buttons, see the
[approval controls](README.md#approval-controls).
Telegram and Discord are supported; see [Discord setup](README.md#discord-approvals)
for token/user-ID configuration and [the bot transport interface](app/bots/base.py).
Compose mounts the config read-only at `/config/config.toml`. Setup saves secrets in `/data`; optional Discord token overrides belong in a
private `config.local.toml`.
After editing, apply it with `docker compose up -d --force-recreate bot`.

If you add personal routing IDs, first copy `config.toml` to the ignored
`config.local.toml` and edit that copy. Put `AUTH_CONFIG_FILE=./config.local.toml`
in the ignored `.env` file so both setup and bot mount your private config.
Recreate the bot after changing the selected file.

With notifications disabled, the service listens but sends no messages or approvals.
Setup can save activation without pairing a bot, but cannot mark the final sign-in
test complete. Enable notifications and rerun setup to configure a bot and reuse
the saved activation.

## First setup

Run from the repository root. Docker Engine/Desktop with Compose v2 must be
available (on WSL, enable Docker Desktop integration for your distribution).
Choose Telegram or Discord in `config.toml` and create the corresponding bot.

```bash
./setup.sh
```

The script creates `data/` and `apk/`, repairs ownership to match your host user
(using `sudo` only when needed), and sets state directories to mode 700 and state
files to mode 600. Existing credentials are preserved. It saves `LOCAL_UID` and
`LOCAL_GID` in `.env`, preserving other settings such as `AUTH_CONFIG_FILE`.
Run it as your normal account; `sudo ./setup.sh` also uses the invoking account.
Symlinks in these directories are rejected before changing ownership.

If requested, place the Microsoft Authenticator APK in `apk/`, then rerun
`./setup.sh`. Keep only one `.apk` file in that directory. The script builds the image and checks state write access and
config/APK read access inside the container before starting the wizard. A saved
`data/apk_config.json` allows setup to proceed without the original APK.

Compose uses shared SELinux labels (`z`) for the bind mounts so both setup and
runtime can access them on enforcing hosts such as Oracle Linux. A directory
owned by `opc` with mode 700 still fails if the container uses another UID, or
SELinux denies access; changing directory permissions alone does not fix both.
The script persists the user IDs and Compose applies the mount labels.

If the container access check still fails, check the selected config file is
readable by your host user and whether Docker uses rootless/user-namespace UID
mapping. Such mappings may require host-specific ownership configuration.
Shell exports of `LOCAL_UID`/`LOCAL_GID` override `.env` for later manual Compose
commands; unset stale exports if necessary.

The wizard:

1. Extracts `apk_config.json` from the mounted APK using `extract_apk_config.py`.
2. Performs Google check-in and FCM registration; reuses saved identity/token on
   subsequent runs.
3. Prompts privately for the bot token. Displays a random pairing phrase to send
   to the bot in a private chat. Only that Telegram user and chat are authorized.
4. Prompts for a fresh Microsoft `activatev2` URL and activation code, then runs
   the existing activation protocol, including its device-validation push and
   any `ConfirmActivation` step. Archives the previous enrollment and stages the returned credentials until the test succeeds.
5. Waits up to five minutes for a real Microsoft sign-in or registration test.
   Trigger it, then **reply to the Telegram request with the number displayed on
   Microsoft's sign-in page**. Setup completes only after Microsoft confirms
   successful approval, and sends a Telegram confirmation.

Get the Microsoft activation URL/code when prompted: they are short-lived.
On subsequent runs, answer **Y** (or press Enter) to reuse saved Microsoft
activation. A previously verified enrollment can finish immediately; imported,
restored, or staged enrollments require a confirmed sign-in test. Staging ready
for testing can be resumed without repeating activation.
If setup is interrupted, rerun it; completed local steps are reused. If Microsoft
activation was incomplete, choose **n** when asked to reuse activation and supply
a fresh URL/code. A failed test does not discard the device identity.

Then start the persistent service:

```bash
docker compose up -d bot
docker compose logs -f bot
```

When notifications are enabled, the daemon requires completed setup, either by a
successful test approval or by accepting saved activation. To rerun setup:

```bash
docker compose stop bot
./setup.sh
docker compose up -d bot
```

A file lock prevents setup and the daemon from sharing the identity concurrently.
Use one instance and one authorized bot user per state directory. This is not a
multi-user account router.

## Bot interaction

The setup walkthrough above uses Telegram. For Discord, set
`notifications.provider = "discord"` and supply the bot token and your user ID
when setup prompts (or in `[bots.discord]` in private config). Use Discord's
**Reply** action on each request; the same approval rules apply.

For number matching, reply to the **specific request message** with the number
from Microsoft's sign-in page, or `DENY`. For a plain approval, reply `APPROVE`
or `DENY`. There is no automatic approval. The local response window defaults to 90 seconds (configurable);
Microsoft can expire the request sooner. Requests requiring Authenticator's app
lock cannot be approved by this bridge.

Unknown users, group messages, unrelated replies, stale replies and duplicate
pushes cannot trigger approval. The service stores seen request IDs and per-provider
update cursors in SQLite. Existing Telegram cursors are migrated automatically. Pending approvals are intentionally abandoned
on restart. If delivery or submission fails, check Microsoft's sign-in page and
start a fresh request; an ambiguous approval is never retried automatically.

MCS reconnects with backoff, responds to heartbeats, sends an idle heartbeat and
reconnects if no response arrives. It checks login errors and acknowledges each
data frame using RMQ2 stream acknowledgments. Docker restarts the service on other errors.
This remains the repository's reverse-engineered Microsoft protocol; a successful
live setup test is necessary to verify compatibility with your tenant.

## Sign-in troubleshooting

The setup container exits when finished. Ordinary sign-ins require the `bot`
service to be running:

```bash
docker compose up -d --build bot
docker compose ps -a
docker compose logs --tail=100 -f bot
```

Wait for `[mcs] LOGIN OK` and `[bridge] MCS ready` (also announced in Telegram),
then start a fresh sign-in. The logs distinguish the stages:

- No `MCS ready`: inspect connection/login errors or a setup/state-directory error.
- Ready but no `PUSH`: no push reached this listener; check the selected Microsoft
  authentication method and make sure no other listener uses this device identity.
- `unsupported push`: a push arrived for a flow this bridge cannot answer
  (personal Microsoft account, passwordless/NGC, registration, or unrecognized).
  No approval is sent; the service continues handling Entra MFA requests.
  Start a sign-in with the supported Entra MFA method (`type=auth`, including
  number matching). See [compatibility and current limits](README.md#compatibility-and-current-limits).
- `Bot request sent`: the request reached Telegram; reply to that message.
- `Microsoft response`: HTTP status and numeric result show whether Microsoft
  accepted the response. The browser may still fail for a separate reason.

Diagnostics omit credentials, approval numbers and raw payloads. MCS delivery
acknowledgments only acknowledge transport receipt; they never approve a sign-in.

## Persistent files and backup

| Host file under `data/` | Purpose |
| --- | --- |
| `apk_config.json` | Extracted application/Firebase configuration |
| `checkin_info.json` | Google device identity and security token |
| `firebase_installation.json` | Firebase installation ID, refresh/auth tokens |
| `fcm_token.txt` | Registered push token |
| `activation.json` | Export of the selected Microsoft activation, including OATH secret |
| `registration.sqlite3` | Authoritative account, staging, token generations, and binding attempts |
| `activation.pending.json` | New activation response awaiting confirmation/test; contains secrets |
| `entra_history.json` | Private previous enrollments and preserved responses for restoration |
| `credential_history.json` | Private copies of replaced Google credential records |
| `firebase_installation.invalid.json` | Invalidation marker; original FIS credentials remain until replacement |
| `telegram.json` | Bot token and paired Telegram user/chat IDs |
| `discord.json` | Bot token and authorized Discord user ID |
| `requests.sqlite3` | Seen request IDs and per-provider update cursors |
| `setup_complete.json` | Export of the confirmed test timestamp and enrollment revision |
| `service.lock` | Exclusive process lock; contains no credential |

The whole `data/` directory is sensitive. Back it up securely while the bot is
stopped, preserve permissions, and restore it before starting the same image.
Rebuilding/removing containers or running `docker compose down` leaves the host
bind mount intact. Losing `data/` requires pairing and registration again.
Do not run two restored copies simultaneously. For selection of an older saved Entra
enrollment, use the [history and restore commands](README.md#service-commands);
restoration requires a new sign-in test. See [DOS-preventer recovery and its limits](data/DOS_PREVENTER.md)
when a token change is stuck at `metadata_required`.

Desktop and Android share the same portable state files. With the bot stopped,
`zip -r transfer.zip data/` creates a ZIP the Android app can import directly;
a ZIP of the directory's contents also works. No manifest is required. To take
a consistent snapshot with private archive permissions, use:

```bash
python3 -m app.state_bundle export --state-dir data --output transfer.zip
```

Disconnect on the phone and export without a password to move back. Move the
old desktop `data/` aside, then validate and restore the phone ZIP:

```bash
python3 -m app.state_bundle import --archive /path/to/phone-backup.zip --state-dir data
```

Restore refuses an existing destination. It preserves enrollment, token renewal
state, history, request deduplication, and any desktop Telegram/Discord credentials.
Logs, locks, and temporary files are excluded. The desktop `config.toml` stays on
the desktop. A phone-created enrollment needs desktop bot pairing via `./setup.sh`;
reuse the imported enrollment. See [desktop/phone transfers](README.md#move-between-desktop-and-phone)
for the app steps and manual ZIP requirements.

Secrets are entered interactively and stored in private files; they are not
passed as Compose environment variables or baked into image layers. The Docker
build context uses an allowlist and excludes existing credentials, the APK,
decompiled sources and local dependencies. The runtime uses a non-root UID,
read-only root filesystem and a writable `/data` mount.

To use a previously registered identity, stop all old MCS listeners and copy
`apk_config.json`, `checkin_info.json`, and `fcm_token.txt` together into `data/`
with mode 600 before setup. Copy `activation.json` as well if you have it. Without
saved activation details, setup asks for fresh Microsoft activation; it never
silently imports credentials from the source directory.

To rotate the Telegram token or change the paired user, stop the bot, securely
remove `data/telegram.json`, then rerun setup. Device identity stays intact.

## Offline verification

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s test -v
```

Tests use mocked Microsoft/Telegram endpoints and temporary state directories;
they do not approve real sign-ins.
