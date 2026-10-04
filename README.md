# Nod Auth

An unofficial app and desktop service for approving Microsoft Entra work or school MFA sign-ins, including number matching. Use Nod Auth directly on an Android phone, or run the service on a computer or server and approve requests through a private Telegram or Discord bot.

The Android app runs on the phone without a computer, Docker, Termux, or a bot. The computer setup uses Docker and keeps a bot listener running. Choose your setup below.

This project is not affiliated with or endorsed by Microsoft, Google, Telegram, or Discord. Compatibility depends on your account and tenant. Use it only with accounts you are authorized to manage and where your organization permits this authentication method.

Read the [privacy and data flow](PRIVACY.md). Enrollment and service connections require user action; applicable service terms govern that use.

## Contents

- [Android setup](#android-setup): [install](#install-on-android), [account setup](#set-up-your-account-on-the-phone), [approvals](#approve-sign-ins), [backups](#back-up-and-restore), [updates](#updating-the-app)
- [Computer setup](#computer-setup): [requirements](#computer-requirements), [bot setup](#bot-setup), [registration and startup](#registration-and-startup), [bot approvals](#approve-sign-ins-through-your-bot), [service commands](#service-commands)
- [Computer configuration](#computer-configuration): [approval controls](#approval-controls), [private configuration](#private-configuration)
- [Move between desktop and phone](#move-between-desktop-and-phone)
- [Compatibility and current limits](#compatibility-and-current-limits)
- [Troubleshooting](#troubleshooting)
- [Development and releases](#development-and-releases): [desktop](#desktop-development), [Android](#android-development), [GitHub releases](#automatic-github-releases)
- [License and acknowledgments](#license-and-acknowledgments)

## Android setup

Install the release APK and enroll on the phone, or import an existing setup. A computer is only needed if you choose to build the app or prepare a setup ZIP yourself.

### Install on Android

#### Phone requirements

- An ARM64 Android phone running Android 7.0 or later (API 24+).
- A Microsoft work or school account with Authenticator MFA enrollment available.
- Internet access to Microsoft and Google services.
- For a new enrollment, a lawfully obtained original Microsoft Authenticator APK. It is not included with Nod Auth.

#### Download and install

The first release is **v0.1.0**, with an ARM64 APK available from [GitHub Releases](https://github.com/Infarctus/Nod-Auth/releases/tag/v0.1.0).

1. On your phone, open [GitHub Releases](https://github.com/Infarctus/Nod-Auth/releases) and choose a release containing **`nod-auth-arm64.apk`**.
2. Download the APK from the release's **Assets** section.
3. Open the downloaded file. If Android asks, allow your browser or file manager to **install unknown apps**, then return to the installer and choose **Install**. Settings names vary by device.
4. Open **Nod Auth** and follow the account setup below.

The release APK supports ARM64 devices only. Other CPU architectures are not included. For updates, read [Updating the app](#updating-the-app) before replacing an existing installation.

### Set up your account on the phone

#### New enrollment

1. Download the original Microsoft Authenticator APK onto your phone. Nod Auth reads its public configuration; you do not need to install that APK.
2. In Nod Auth, choose **Set up with QR code**, then **Choose Authenticator APK** and select the original Microsoft APK.
3. In your Microsoft work or school account's security settings, add an Authenticator app and obtain a fresh MFA setup QR code.
4. Choose **Scan setup QR code** to scan it from another screen, or **Choose QR image** to select a saved image. Allow camera access when using the scanner.
5. Choose **Activate account**. After activation, wait for the app to report **Connected**, then complete Microsoft's verification sign-in and approve its request in Nod Auth.

The first successful verification sign-in confirms enrollment. Setup QR codes expire; obtain a fresh one if activation fails. Personal Microsoft account QR codes and `otpauth` codes are unsupported.

New enrollment is staged separately from the current account. A failed attempt retains the existing enrollment and recovery state. If activation completed before setup was interrupted, use **Resume activated setup** when available instead of reusing the one-time code.

#### Import an existing setup

Choose **Import backup / setup ZIP**, select your Nod Auth backup or compatible setup ZIP, and enter its password if it is encrypted. Leave the password blank for an unencrypted ZIP. Disconnect first if the app is already listening.

Import validates the backup before replacing the phone's current setup. Stop any other phone or desktop listener using that enrollment; only one listener should use the same identity at a time. See [desktop/phone transfers](#move-between-desktop-and-phone) to move an existing desktop enrollment.

### Approve sign-ins

1. Open Nod Auth and wait for **Connected**. If disconnected, choose **Connect for 10 minutes**.
2. Start your Microsoft sign-in. Keep the listening session active while switching to your browser.
3. When the request appears, tap the number displayed on Microsoft's sign-in page, or **Approve** for a request without number matching. Choose **Deny** for a request you did not initiate.
4. Complete Android's biometric or device credential prompt if the request requires app lock.

Approvals require your selection in the app. The listening notification opens the approval screen; approval actions stay inside Nod Auth.

**A listening session lasts ten minutes.** Open the app again or choose **Connect for 10 minutes** for another session. **Disconnect** stops listening. The app does not start automatically after a reboot, and requests sent while offline may not arrive later. Connect first, then start a fresh sign-in. Android battery management can also interrupt a session.

### Back up and restore

Before changing phones, uninstalling, or replacing a build:

1. Choose **Disconnect**, then **Export backup**.
2. Enter and confirm a password to create an encrypted **`.nodbackup`** file, unlock the device when prompted, and choose where to save it.
3. Keep the backup and its password somewhere private. There is no password reset or recovery mechanism.

Leaving the password blank creates an **unencrypted `.zip` containing account credentials**. Keep that file private. To restore, use **Import backup / setup ZIP** on the destination phone. Disconnect the old listener before connecting the restored setup.

Uninstalling clears the app's private enrollment. Earlier encrypted `.aabackup` exports can still be imported. Wrong passwords, tampered encrypted files, and invalid ZIPs are rejected before the installed setup is replaced. Backups preserve desktop bot credentials when present, so you can move back to the computer without pairing again.

### Updating the app

The Android package is now `io.github.infarctus.nodauth`. Builds using the former `dev.nodauth.app` package install separately. Export a backup from the old app, disconnect it, and import the backup into the new app before removing the old installation.

GitHub release APKs currently use debug signing. Each fresh build runner generates a different signing key, so a new release generally cannot install over an earlier release or a locally built APK.

Export a backup before uninstalling the old build. Install the new APK, import the backup, and reconnect. Preserve your backup until you have verified a sign-in. Stable release signing is not configured yet.

## Computer setup

Run the desktop service on a computer or server that can stay online while you sign in. It receives Microsoft push requests through Google MCS and sends them to your private Telegram chat or Discord DM. The host and bot account become part of your authentication security boundary; keep both secure.

### Computer requirements

- Docker Engine or Docker Desktop with Compose v2, accessible to your normal host user.
- A Bash environment for `setup.sh`; use Linux, macOS, or WSL on Windows.
- A Microsoft work or school account with Authenticator MFA enrollment available.
- A lawfully obtained Microsoft Authenticator APK; the APK is not included.
- A dedicated [Telegram or Discord bot](#bot-setup).

The service needs outbound HTTPS to Microsoft, Google, and your bot provider, plus TCP port 5228 for Google MCS. No inbound ports are required. Run the following commands from the repository root.

### Bot setup

Before registration, edit [config.toml](config.toml) and choose your provider:

```toml
[notifications]
enabled = true
provider = "discord" # Change to "telegram" for Telegram.
startup_message = true
```

The supplied configuration selects Discord. Keep credentials out of this tracked file; the wizard stores them privately in `data/`.

#### Telegram approvals

Create a bot through [@BotFather](https://t.me/BotFather) and save its token. During setup, enter the token and send the generated pairing phrase to the bot in a private chat. Only the paired user can approve requests.

#### Discord approvals

Create a bot in the [Discord Developer Portal](https://discord.com/developers/applications), then install it in a server you belong to using the `bot` scope and **Server Install**. A private server works. Allow direct messages from that server and enable Developer Mode in Discord to copy your user ID.

Setup asks for the **bot token** and **your user ID**, then verifies DM delivery. No server ID, channel ID, privileged intents, or public endpoint are needed. Leave **Interactions Endpoint URL** empty for approval buttons. Text replies use REST polling; buttons use an outbound Gateway connection.

If delivery fails, check the token, shared server, and DM permissions.

### Registration and startup

1. Clone the repository and enter its directory:

   ```bash
   git clone https://github.com/Infarctus/Nod-Auth.git
   cd Nod-Auth
   ```

2. Place exactly one original Microsoft Authenticator `.apk` in `apk/`:

   ```bash
   mkdir -p apk
   cp /path/to/Microsoft-Authenticator.apk apk/msauth.apk
   ```

3. Choose your provider in [config.toml](config.toml), then run the setup script as your normal host user:

   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

   The script creates `data/` and `apk/`, repairs ownership using `sudo` when needed, sets private state permissions, and saves your UID/GID in `.env` for later Compose commands. It preserves existing state and other `.env` settings, builds the image, checks container access, and starts the wizard. If the APK is missing, place it in `apk/` and rerun the script. Once APK configuration has been extracted, subsequent runs can reuse it.

4. Follow the wizard to extract the APK configuration, register a Google push identity, and pair your Telegram bot or verify Discord DM delivery.
5. In your Microsoft work or school account's security settings, add an Authenticator app and obtain fresh setup details. Supply the Microsoft **`activatev2` URL** and **one-time activation code** when the wizard prompts for them. These are enrollment details, separate from the number displayed during a sign-in.
6. Start Microsoft's verification sign-in and answer the bot request with the number shown on Microsoft's sign-in page. Wait for the wizard to confirm that the test succeeded.
7. Start the service and check its logs:

   ```bash
   docker compose up -d bot
   docker compose logs -f bot
   ```

State persists in `data/` across container rebuilds. Run only one listener per enrollment. For manual Compose setup, activation recovery, and host permission details, see the [Docker guide](DOCKER.md#first-setup).

### Approve sign-ins through your bot

Keep the service running and initiate a Microsoft sign-in. Use the number buttons when shown, or answer the request by text:

| Request | Response |
| --- | --- |
| Number matching | The number displayed on Microsoft's sign-in page |
| Plain approval | `APPROVE` |
| Reject either request | `DENY` |

Only the configured user can respond. With `require_reply = true`, use Telegram or Discord's **Reply** action on the specific request message. With `require_reply = false`, an ordinary private message is accepted when exactly one unexpired request is pending.

The default response window is 90 seconds; Microsoft may expire requests sooner. Each new, distinct sign-in replaces the previous pending request locally without sending Microsoft a denial. Restarting abandons pending requests. Start a fresh sign-in after a restart or failed submission.

### Service commands

```bash
# Follow logs
docker compose logs -f bot

# Rebuild and restart after updating the source
docker compose up -d --build bot

# Stop the service
docker compose stop bot

# Rerun setup, then restart
./setup.sh
docker compose up -d bot
```

Stop the bot before rerunning setup. Saved device state is reused. A previously verified enrollment can skip another test; imported, restored, and staged enrollments require a confirmed sign-in test. To switch providers, stop the bot, change `[notifications].provider`, rerun setup, and restart.

## Computer configuration

Edit [config.toml](config.toml), then apply changes:

```bash
docker compose up -d --force-recreate bot
```

| Setting | Purpose |
| --- | --- |
| `enrollment.device_name` | Device name sent to Microsoft during fresh activation; defaults to `Pixel 8` |
| `notifications.provider` | `telegram` or `discord` |
| `notifications.enabled` | When `false`, listen for pushes but discard requests without messaging or approving |
| `notifications.startup_message` | Enable or suppress connection announcements |
| `approval.timeout_seconds` | Local response window, from 1 to 300 seconds |
| `approval.require_reply` | Require text replies to the specific request message |
| `approval.show_number_buttons` | Show approval and denial buttons |
| `approval.max_pending` | Compatibility setting; only the latest request is retained |

Changing `enrollment.device_name` does not rename an existing registration. For a new name, stop the bot, run `./setup.sh`, decline reuse/resume when prompted, and use fresh activation details. Microsoft decides whether to accept custom names. This configuration applies to the desktop service; Android does not read `config.toml`.

### Approval controls

The supplied configuration enables buttons and ordinary text responses:

```toml
[approval]
timeout_seconds = 90
max_pending = 20
show_number_buttons = true
require_reply = false
```

Set `require_reply = true` to require replies to specific messages for text responses. Set `show_number_buttons = false` to disable buttons. These settings are independent. If a push does not contain three valid number choices, type the number instead. A numeric reply outside the supplied valid choices is ignored and leaves the request pending. Expired or consumed requests cannot be submitted again.

### Private configuration

Setup stores credentials in `data/`. For token or recipient overrides, copy `config.toml` to `config.local.toml`, run `chmod 600 config.local.toml`, and put `AUTH_CONFIG_FILE=./config.local.toml` in your local `.env` file. Keep these files out of Git. Recreate the bot after changing the selected config.

Use `[bots.discord]` for `bot_token` and `user_id` overrides. For Telegram, optional `chat_id` and `user_id` under `[bots.telegram]` must both equal the recipient's positive numeric user ID; that user must start the bot first. Omitted values use credentials saved during setup.

The state directory contains device credentials, bot tokens, activation secrets, and request history. See [persistent files and backup](DOCKER.md#persistent-files-and-backup) for backup and credential rotation.

## Move between desktop and phone

Both platforms use the same enrollment files. Stop the desktop bot before exporting its setup:

```bash
docker compose stop bot
python3 android-app/tools/export_setup.py --state-dir data --output transfer.zip
```

Run the exporter in a Python environment prepared with the [desktop dependencies](#desktop-development). It acquires the ownership lock and takes consistent SQLite snapshots. Transfer `transfer.zip` privately and import it on the phone with **Import backup / setup ZIP**, leaving the password blank. Only connect the phone after the desktop listener has stopped.

To return to the computer, disconnect on the phone and export a backup without a password. Stop the desktop bot and move any existing `data/` directory aside, then restore into a new directory:

```bash
python3 -m app.state_bundle import --archive /path/to/phone-backup.zip --state-dir data
./setup.sh
docker compose up -d bot
```

The import command validates the archive and refuses to overwrite an existing state directory. Setup pairs a bot if the enrollment was created on the phone and verifies the imported account before startup. Keep desktop `config.toml` on the computer; it is outside `data/`.

Unencrypted ZIPs contain credentials, including preserved bot tokens. Transfer them privately and remove transfer copies afterward. Encrypted `.nodbackup` files restore through the Android app. Use only one listener for an enrollment at a time.

## Compatibility and current limits

The app supports Entra MFA push approvals, including number matching, for a single account. Personal Microsoft accounts, passwordless sign-in, passkeys, broker/SSO integration, device compliance, and TOTP display are not implemented. Reliable always-on notification delivery is also outside the current build's scope.

The desktop service also supports Entra MFA push approvals only. Unsupported push types are reported without submitting an approval. Android enforces a native biometric/device credential prompt for requests requiring app lock; the desktop service answers such requests as if local device authentication had succeeded.

Android 7.0 is the configured minimum version; this does not establish testing on every supported device or tenant.

## Troubleshooting

- **APK will not install:** check that the phone supports ARM64 and Android 7.0+, and that installation is allowed for the app opening the file. An existing Nod Auth installation with another signing key requires the [backup and update steps](#updating-the-app).
- **No sign-in request appears:** wait for **Connected**, check that the ten-minute session is active, stop any other listener using the enrollment, then start a fresh sign-in.
- **QR code is rejected or expired:** obtain a fresh work or school Authenticator MFA setup QR. Use **Choose QR image** if scanning another screen is inconvenient.
- **Setup or connection fails:** open **Runtime check** for runtime and HTTPS diagnostics. Keep enrollment files, backups, and private logs out of public issue reports.
- **Computer setup cannot access Docker or mounted files:** check Docker is running and your host user can access it, then rerun `./setup.sh`. See [Docker permissions](DOCKER.md) for ownership, SELinux, and user namespace details.
- **Bot messages or buttons do not work:** check the selected provider and paired user. For Discord, check the bot token, shared server, and DM permissions; leave the Interactions Endpoint URL empty. See [sign-in troubleshooting](DOCKER.md#sign-in-troubleshooting).

## Development and releases

### Desktop development

Use Python 3.12 and OpenSSL:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s test -v
```

Tests use temporary credentials and local or mocked endpoints; they do not approve real sign-ins. Local commands include `python -m app.extract_apk_config --apk apk/msauth.apk` and `python -m app.service --help`. State defaults to `./data`; override it with `AUTH_STATE_DIR`, or select a private TOML file with `AUTH_CONFIG`. Run only one listener against an enrollment.

Additional bot transports implement the interface in [app/bots/base.py](app/bots/base.py).

### Android development

Build from Linux or WSL with JDK 17 or 21, Python 3.12+ for tooling, and `uv`. From the repository root:

```bash
python3 android-app/tools/bootstrap.py
android-app/tools/build.sh
python3 android-app/tools/install.py
```

Bootstrap downloads the pinned Android SDK, NDK, Python 3.13 runtime, and CFFI build dependencies into the ignored `android-app/.toolchain` directory and accepts the standard Android SDK licenses. Allow several GB of disk space. The debug APK is written to `android-app/app/build/outputs/apk/debug/app-debug.apk`. Windows-native builds are not implemented; use WSL. Set `ANDROID_ADB` to select an ADB executable, or use the installer's `--serial` option when several devices are connected.

Run mobile and shared protocol checks with:

```bash
python3 -m unittest discover -s android-app/tests -v
android-app/tools/build.sh :app:assembleDebug :app:testDebugUnitTest :app:assembleDebugAndroidTest :app:lintDebug
.venv/bin/python -m unittest discover -s test -q
```

To prepare a fresh phone setup ZIP on a computer without pairing a bot, place the original APK at `apk/msauth.apk` and run `./android-app/setup.sh`. It creates a separate Python environment and enrollment state, prompts for fresh Microsoft activation details, and writes `android-app/setup.zip`. Import that ZIP on the phone and complete the verification sign-in there. Use `./android-app/setup.sh --prepare-only` to prepare the environment without enrolling.

### Automatic GitHub releases

The [Android release workflow](.github/workflows/android-release.yml) builds `nod-auth-arm64.apk` and publishes it on a GitHub release whenever a tag is pushed. To release a committed build, push the branch and then a new tag:

```bash
git push origin main
git tag v0.3.0
git push origin v0.3.0
```

Choose an unused version tag. Rerunning the workflow replaces the APK asset on an existing release. Release APKs currently use debug signing; follow the [backup and update steps](#updating-the-app) when changing builds.

## License and acknowledgments

This project is licensed under the [Apache License 2.0](LICENSE).

See [third-party notices](THIRD_PARTY_NOTICES.md) for dependencies, retained upstream licenses, and the remaining binary distribution review.

The FCM and MCS implementations reimplement processes described by [microG GmsCore](https://github.com/microg/GmsCore), an Apache-2.0 project. The MCS implementation also references [Chromium's protocol definitions](https://github.com/chromium/chromium/blob/main/google_apis/gcm/protocol/mcs.proto). Third-party software retains its own licenses; this project's license does not cover Microsoft Authenticator or the locally supplied APK.
