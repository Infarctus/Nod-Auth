# Privacy and data flow

Nod Auth has no project-operated backend, advertising, or analytics integration
in this repository. It contacts the services needed for enrollment, push
delivery, and sign-in approval. Those services receive network metadata, such as
your IP address, and are governed by their own terms and privacy policies.

- **Microsoft:** activation and approval requests contain account, tenant,
  registration, and device information and your approval/denial choice.
- **Google:** device check-in, Firebase installation/registration, and the MCS
  connection send device/app identifiers and registration credentials. Google
  provides the push transport.
- **Telegram or Discord, when enabled on desktop:** the chosen bot provider
  receives sign-in details, number choices, and your replies or button selections.
  These messages are not end-to-end encrypted. Chat history may remain with the
  provider after local enrollment files are deleted. Android operation does not
  require a bot.

The desktop stores credentials in `data/` by default (`AUTH_STATE_DIR` can
override it), including device security tokens, account identifiers, OATH
secrets, push registration state, and bot credentials. A private configuration
file can also contain bot tokens and user/chat IDs. The phone keeps enrollment
in app-private storage, disables Android backup, and blocks screenshots of its
main activity. Local access to the host, phone, or its backups remains sensitive.

Encrypted `.nodbackup` exports are protected with the password you choose.
Unencrypted setup ZIPs contain reusable authentication credentials; treat them
as secrets. Stop other listeners before moving an enrollment. Remove local
state, backups, bot messages, and the registration in Microsoft's security
settings when retiring a setup. Deleting the local copy alone does not revoke a
server registration or erase copies held by a bot provider.

The project does not receive data automatically from your installation. If you
share a GitHub issue, logs, screenshots, a setup QR, or a backup yourself, that
information goes to the recipients or hosting service you select. Redact account
names, tenant IDs, tokens, IP addresses, and machine paths before sharing.

The repository's ignore rules reduce accidental publication
of known credential files. They do not protect files added with `git add -f`,
secrets already in Git history, arbitrary custom state/config paths, or every
possible secret embedded in source code.
