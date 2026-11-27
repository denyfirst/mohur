# Mohur architecture

Mohur lets two organizations that each run their own server talk privately.
People exchange end-to-end encrypted one-to-one messages and files. Servers
carry ciphertext only. There is no central Denyfirst service.

The design goal is the strongest protection that a person never has to think
about. Every check below runs automatically. A person sees a question only
when something real happens, such as a partner's key changing.

## Parts

| Part | What it is | Holds |
|---|---|---|
| `mohurd` | One Go binary per organization: admin web pages, client API, federation API | Organization signing key, employee list, partner list, queued ciphertext |
| Mohur desktop app | Electron app with the official libsignal library | The person's message keys, sessions and history, sealed by the operating system |

The admin pages are served by `mohurd`. Messages are never read or written in a
browser: code that a server can change must not see plaintext, so the desktop
app is a separately signed program and talks only to its own organization's
server.

## Trust in four facts

1. **Domain.** One DNS TXT record proves the organization controls its domain
   and publishes its signing key and server address:

   ```
   _mohur.example.com  TXT  "v=mohur1 server=mohur.example.com key=<base64url Ed25519 public key>"
   ```

   The admin adds it once and presses **Check**. The server name must be the
   domain itself or a name under it, so a spoofed answer that points elsewhere
   is refused.

2. **Organization.** `https://<server>/.well-known/mohur` returns the domain,
   display name, server and key, signed by that key, over verified TLS. Mohur
   trusts a partner only when the TXT record, the TLS certificate and the signed
   document all name the same key. An attacker needs both the domain's DNS and a
   valid certificate for a name under it.

3. **Connection.** An admin types the partner's domain and presses **Connect**.
   The partner's admin sees the request, already verified the same way, and
   presses **Accept**. Each side pins the other's key. That is the whole
   procedure: one click on each side, no codes to read aloud. A security code is
   available under Details for anyone who wants to compare it.

4. **Person.** An admin invites an employee. The invite is the domain plus a
   one-time code, valid for 72 hours. The desktop app verifies the domain as in
   2, creates the person's keys on the device and redeems the code. The server
   signs a device certificate with the organization key. Partners accept a
   device only with a valid certificate from the pinned organization key.

## Who can write to whom

Colleagues in one organization always see and can write to each other; that
needs nothing beyond their invites. With a partner, no one may write until an
admin chooses who on their own side may, so a new person is never shown to a
partner by surprise. The admin chooses in the same list from two places: per
partner (asked right after Connect or Accept, changeable any time) and per
person (on the People page, or in the invite itself). Each side decides only
for its own people, so two people can write to each other only when both
admins allow it.

The server enforces the choice, not the app. A partner receives only the
chosen people in its directory; this server refuses keys, messages and files
for anyone else here, and refuses to forward anything from them. Removing a
person also takes them off every chosen list, so a later person with the same
user name does not inherit it.

Apps learn about changes at once. Each mail check carries a directory version;
it changes when people join or leave, a partner connects, disconnects or
changes its key, or an admin changes who may write. A change wakes every
waiting app, which then reads its contacts again. A server also sends its
connected partners a signed `POST /fed/v1/changed` when its own people change,
so their apps update too; without it, a partner's people are read again every
minute. The app also reads its contacts when its window comes to the front and
they are older than 15 seconds, and its Refresh button asks the server to read
partners' lists afresh. A server honours that for one person six times a
minute; beyond that the cached lists answer, so no app can make its server call
partners without limit.

The app keeps, in its encrypted vault, how far each conversation was read and
shows the rest as unread, in the list and in the window title. Messages that
were in a vault before the app counted them are taken as read.

## Changed keys

A partner's key change pauses the connection until an admin accepts the new,
again verified, key. A person's new device is shown in their conversations as a
notice; a device without a valid certificate is refused outright.

## Messages

- Sessions use libsignal unchanged: PQXDH for the first message (X25519 with
  ML-KEM-1024) and the Double Ratchet with its post-quantum extension after.
  Mohur adds no cryptography of its own.
- The app encrypts for each recipient device and sends the result to its own
  server. A server forwards to the partner's server with a request signed by
  its organization key. The partner's server checks the signature against the
  pinned key, the connection, the sender's domain and the recipient.
- The recipient's app decrypts, then returns an encrypted delivery receipt the
  same way.
- Servers drop ciphertext that nobody fetched after 30 days.

## Files

- The app encrypts each file with a fresh random 256-bit key, AES-256-GCM, a
  single pass, up to 100 MB.
- The encrypted file goes to the sender's server and on to the recipient's
  server. The key, the file name, its type and the SHA-256 of the ciphertext
  travel inside the encrypted message.
- The recipient's app checks the hash and the GCM tag before it offers to save.

## Signatures

Every signed value is the Ed25519 signature of a context label followed by the
fields, each written as a 4-byte big-endian length and its bytes. Go and the app
build the same bytes; there is no JSON canonicalization.

| Context | Fields | Signed by |
|---|---|---|
| `mohur/org/v1` | domain, name, server, key | organization key |
| `mohur/device/v1` | address, name, device id, identity key, auth key, issued | organization key |
| `mohur/fed/v1` | method, path, from, to, time, nonce, SHA-256 of body | organization key |
| `mohur/session/v1` | domain, address, device id, nonce | device auth key |

Federation requests older than five minutes, or with a nonce already seen, are
refused.

## Blocking and reports

A person can block someone from the conversation menu. Blocking happens on
their own computer:
- Messages from a blocked person are still opened, so the conversation keys
  stay in step, but they are not kept and get no delivery receipt.
- The blocked person is not told.
- Unblocking picks the conversation up where the keys are.

A person can also report someone to their own organization's admin. A report
holds:
- who sent it and whom it is about;
- one of four reasons;
- an optional note of up to 1,000 characters in their own words.

A report never holds a message. Messages stay encrypted between the two
people. The note is sealed at rest with the instance key and is never logged.
Partners hear nothing of reports. An admin sees open reports on the Reports
page and marks them handled. The admin can act from the People page (remove
the person) or the Partners page (choose who writes with that partner, or
disconnect). A person can send five reports a minute. A server keeps at most
1,000 open reports, and handled ones go after 90 days.

## What servers learn

Servers see who writes to whom, when, and how large the ciphertext is. They do
not see message text, file contents, file names or keys. A report that a
person sends to their own admin is the one place where their own words, not a
message, reach the server. An organization's
admin can add a device for their own employee; the employee's partners then see
the new-device notice, so it cannot happen silently.

## Privacy page, terms and crashes

What each part keeps, Mohur's promises and the terms of use are in
[docs/policies](policies/README.md). The app ships both pages and shows them
itself from the join screen and the empty conversation view, so it holds no
address of denyfirst's and never connects anywhere to show them. Joining
accepts the terms.

The app starts Electron's crash reporter with uploading off, so a crash is
caught before Windows Error Reporting can send it. A crash dump can hold parts
of open messages; it stays on the computer and is deleted at the next start.

## Updates

denyfirst signs each release's `SHA256SUMS` with its release key, as
`ssh-keygen -Y sign` does; the key is in `.allowed_signers` and compiled
into `mohurd`. `internal/sshsig` reads the signature format strictly and
verifies with `crypto/ed25519`.

The admin's Server page shows the running version. The server asks GitHub for
the latest release list only when an admin presses **Check now**, or once a
day, at a random hour, after an admin turns that on; it is off by default. A
check reaches only public addresses on port 443 and follows redirects only
within GitHub, carries nothing about the organization, and believes a list
only when the signature verifies. A newer version is shown on every admin
page and installed by nothing but the operator's `sudo mohurd upgrade`. That
command installs only a newer release whose hash is on the verified list,
keeps the running binary as `mohurd.previous`, renames the new one into
place, restarts every running `mohurd` unit, and puts the previous binary
back if one does not come up. The desktop app is updated by the Microsoft
Store and has no update code.

The app gives its version, such as `0.1.0`, in a `Mohur-App` header when it
joins and each time it signs in, and only to its own server. The server
records it with the device once the device has proved its key, shows it to
admins on the People page, and never puts it in what colleagues or partners
receive. A server works with apps from `OldestApp` on
(`internal/server/apps.go`); an older app, or one that gives no version, is
answered `426` with a request to update, which the app shows until it is new
enough. The version is what the app says about itself: it decides whom to ask
to update, never whom to trust.

## Admin access

An admin signs in with a password (Argon2id) and an authenticator code, or a
one-time recovery code instead of the authenticator. When both are lost, the
server's operator runs `mohurd reset-admin`. It reads only the instance key
and prints a code: six random bytes and a 72-bit HMAC-SHA256 tag over them and
the current minute, keyed from the instance key. The running server accepts it
for an hour, once, at ten tries a minute, and only to set a new password,
authenticator and recovery codes. Whoever can read the instance key can
already open every sealed secret, so the code gives the operator nothing new.

## Out of scope for the first version

Groups, calls, guests, reactions, previews, history transfer, cloud backup,
mobile apps and more than one device per person. The data model already keeps
device ids so that more devices can come later without a new protocol.

## Storage

- `mohurd` keeps one bbolt file. The organization key and the TOTP seeds are
  sealed with an instance key that lives in a separate root-only file.
- The app keeps one encrypted vault per profile. Its key is protected with the
  operating system's user store (DPAPI on Windows, Keychain on macOS, libsecret
  on Linux) through Electron `safeStorage`. Writes go to a temporary file and
  are renamed into place.
