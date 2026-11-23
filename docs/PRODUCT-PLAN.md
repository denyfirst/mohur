# Product plan

Goal: the most secure way for two organizations to talk, that nobody has to
learn. One DNS record, one invite per person, one click per partner.

## Removed from the first design

The research phase built 26 separate synthetic studies. They are in history
(`research/client-and-design-2026-10-29`) and gone from the tree, along with:

- hardware (TPM) anti-rollback, organization-key custodians and quorum, and
  expiring authorization leases: heavy to run, with no protection a small
  organization would notice;
- comparing a code for every new employee: the organization signs its people's
  devices instead, and partners verify that signature automatically;
- a separate personal mode: a person is a user on some Mohur server;
- 15-minute invites (now 72 hours, one use) and mandatory WebAuthn.

## Added

- Discovery and trust from one TXT record, checked against TLS and a signed
  document; partners pinned after one click each.
- Device certificates signed by the organization; new devices shown as a notice.
- Post-quantum sessions from libsignal, files with a fresh key each, and padded
  messages.

## Next, in order

1. Install on Linux: `install.sh`, systemd, automatic certificates, upgrade
   and backup, then two separate test machines with real domains.
2. Windows installer for the app, signed, with signed updates.
3. Offboarding in one click with a notice to partners, and retention settings.
4. Signed prekey rotation and a server-side delivery queue.
5. Several devices per person, then a mobile app.
