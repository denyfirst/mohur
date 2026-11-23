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

## What servers learn

Servers see who writes to whom, when, and how large the ciphertext is. They do
not see message text, file contents, file names or keys. An organization's
admin can add a device for their own employee; the employee's partners then see
the new-device notice, so it cannot happen silently.

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
