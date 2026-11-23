# Status

23 November 2026. First working version; not released, no users.

## Works, with tests

- **Server (`mohurd`)**: first-run setup with a one-time code, admin sign-in
  with password and authenticator code, the domain record and its **Check**,
  people and one-time invites, partners by domain (connect, accept, remove,
  accept a changed key), the app API and signed federation between servers.
- **Desktop app**: join with an invite after verifying the organization, a
  contact list of colleagues and partners, one-to-one messages with delivery
  receipts, files up to 100 MB, an encrypted local vault protected by the
  operating system, retry when a partner's server is away.
- **Tests**: Go end-to-end tests run three organizations over real TLS and DNS
  and check refusals: an unconnected organization, a replayed or altered
  request, an old request, a forged device certificate, a sender outside the
  partner's domain, a DNS-only key change, a rebuilt partner, records that do
  not agree, private addresses, untrusted certificates, reused invites, a
  removed person, a wrong device key, cross-site admin calls and a partner's
  request that is accepted after its key changed. The app's end-to-end test
  runs two real servers and two engines with libsignal: joining, contacts,
  messages and receipts, a 3 MB file, a restart, the vault on disk, and a
  certificate from the wrong organization; further tests check the
  organization check, invite parsing and that sessions are post-quantum.
- **Sabotage**: each of those checks was switched off in turn and a test
  failed every time, except the sender-domain check on delivery, which the
  device-certificate check already covers.

## Not yet

- A test on two separate machines (the install script and its Linux lab are
  done; see [INSTALL.md](INSTALL.md)), automatic certificates, and real domains.
- Signed app installers and updates.
- New signed prekeys over time (the first ones are kept), and a server-side
  retry queue for an unreachable partner (the app retries today).
- More than one device per person, mobile apps, groups.
- Independent security review.
