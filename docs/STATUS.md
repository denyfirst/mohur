# Status

27 November 2026. First working version; not released, no users.

## Works, with tests

- **Server (`mohurd`)**: first-run setup with a one-time code, admin sign-in
  with password and authenticator code, an admin reset by the server's
  operator (`mohurd reset-admin`) for a forgotten password, the domain record and its **Check**,
  people and one-time invites, partners by domain (connect, accept, remove,
  accept a changed key), per-partner choice of who may write (no one until
  chosen, per partner or per person and in the invite, enforced by the server), the app API and signed federation
  between servers. Apps hear of changes to people and partners at once.
  A Server page shows the running version and, on Check now or a daily
  check an admin turns on, whether a newer signed release is out;
  `sudo mohurd upgrade` installs it. The People page shows which app version
  each person runs, and an app too old for the server is asked to update.
- **Desktop app**: join with an invite after verifying the organization, a
  contact list of colleagues and partners, one-to-one messages with delivery
  receipts, files up to 100 MB, an encrypted local vault protected by the
  operating system, retry when a partner's server is away, unread counts that
  survive a restart, a Refresh button for the contact list, blocking a
  person on this computer and reporting someone to one's own admin, the
  privacy page and terms of use shown in the app (joining accepts them),
  and crash reports that stay on the computer and go at the next start.
- **Tests**: Go end-to-end tests run three organizations over real TLS and DNS
  and check refusals: an unconnected organization, a replayed or altered
  request, an old request, a forged device certificate, a sender outside the
  partner's domain, a DNS-only key change, a rebuilt partner, records that do
  not agree, private addresses, untrusted certificates, reused invites, a
  removed person, a wrong device key, cross-site admin calls and a partner's
  request that is accepted after its key changed. Partner access is tested
  end to end: no one crosses until both sides choose; a person who was not
  chosen cannot list, fetch keys of, send to or upload for the partner; a new
  person is shown to no partner unless their invite or the People page
  chooses one; the partner sees only chosen people and its
  server's direct attempts are refused; bad and cross-site access changes are
  refused; a removed person's access is not inherited by a new one with the
  same user name; a waiting app is woken by a new partner, and a partner's new
  person reaches another organization's app without the one-minute wait.
  Refresh reads partners afresh at most six times a minute per person, and
  never on any value but `fresh=1`.
  Reports reach only the reporter's own admin; the partner hears nothing.
  Malformed addresses, reports about oneself, unknown reasons, long notes,
  control characters, a sixth report in a minute and cross-site admin calls
  are refused. A note is sealed at rest and does not open if it is moved to
  another report. Open reports are capped, and handled ones are pruned.
  The admin reset is tested the same way: a code from the instance key lets the
  admin set a new password and authenticator once, within the hour; expired,
  altered, malformed, foreign, reused and cross-site attempts are refused, as
  are a wrong authenticator code and an eleventh try in a minute; the old
  password, recovery codes and sessions stop working. The Linux install lab
  runs the command with sudo against the sandboxed service.
  Tests use `*.e2e.test` names, so lab entries in a hosts file cannot collide.
  The app's end-to-end test
  runs two real servers and two engines with libsignal: joining, contacts,
  messages and receipts, a 3 MB file, a restart, unread counts and their
  read marks (kept across a restart, odd addresses refused), blocking (nothing
  kept or answered, sending refused, kept across a restart, keys still in step
  after unblocking, no request sent), reports, the vault on disk, a
  search of both servers' databases, files and log for a message, a file
  and a report note, a
  certificate from the wrong organization, and an app too old for its server,
  which is asked to update without spending its invite; further tests check the
  organization check, invite parsing and that sessions are post-quantum.
  The store deletes collected mail at once and mail and files after 30 days.
  The policies use only what the app can show, every promise names a test
  that exists, and the app holds no address of denyfirst's.
  Updates: a release list is believed only with denyfirst's signature
  (checked against a real `ssh-keygen` signature, and refused when altered,
  signed by another key or for another namespace, or malformed); checks
  reach only GitHub on public addresses and port 443, are spaced a minute
  apart, and run daily only once an admin turns that on; `mohurd upgrade`
  installs only a newer release whose hash is on the list, restarts only
  mohurd units, keeps the previous binary and puts it back when a service
  does not come up; the admin calls refuse other sites, signed-out browsers
  and malformed choices.
  App versions: an app gives its version on joining and signing in; it is
  recorded only after the device proves its key and only for its current
  device, compared as numbers, and never shown to colleagues or partners; a
  missing or older version is asked to update, and a malformed or repeated
  one is refused.
  Releases: CI builds the release on Linux and on Windows and requires the
  same bytes, also with a machine's own Go settings in the way. The release
  check accepts a signed release
  that its tag builds and refuses one with no signature, signed by another
  key or for something other than files, with a file changed after signing,
  with an unlisted or a missing file, or whose signed list is not what the
  tag builds.
- **Sabotage**: each of those checks was switched off in turn and a test
  failed every time, except the sender-domain check on delivery, which the
  device-certificate check already covers. The 17 partner-access and
  change-notice checks, the 13 admin-reset checks, the 10 chosen-only checks,
  the 9 refresh-limit and read-mark checks, the 21 blocking and report checks,
  the 16 checks behind the privacy page's promises, the 27 update checks, the
  20 app-version checks and the 8 release-build and release-check checks were
  switched off the same way; each was caught. For a newer Go than `go.mod`
  names, `go.mod` was lowered in a throwaway copy with a newer Go on the path.
  A sabotage that no longer builds is not counted.

## Not yet

- A test on two separate machines (the install script and its Linux lab are
  done; see [INSTALL.md](INSTALL.md)), automatic certificates, and real domains.
- A Microsoft Store listing. The Windows package (MSIX) builds and installs;
  see [packaging/windows](../packaging/windows/README.md). Updates will come
  from the Store. Still needed: the privacy page and terms on denyfirst's
  website, a test organization for Microsoft's testers, and published hashes
  of each release's files, so the Store build can be compared with a rebuild.
- The first release. The server's update check, `mohurd upgrade` and the
  public Reproduce workflow, which rebuilds each release from its tag and
  checks it, are built; see [RELEASING.md](RELEASING.md).
- New signed prekeys over time (the first ones are kept), and a server-side
  retry queue for an unreachable partner (the app retries today).
- More than one device per person, mobile apps, groups.
- Independent security review.
