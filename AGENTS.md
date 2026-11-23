# Working on Mohur

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/STATUS.md](docs/STATUS.md)
before changing code.

Mohur is self-hosted. Security comes first, and it must stay simple to use:
every check runs automatically, and a person is asked something only when a
real change happened. Prefer removing a feature to adding a step.

- No cryptography of our own. Messages use libsignal unchanged; signatures are
  Ed25519 over the length-prefixed format in `internal/proto`; files use
  AES-256-GCM with a fresh key each.
- Servers never hold plaintext, message keys or file keys, in storage, logs or
  tests' output. A device without a certificate from its pinned organization
  key is refused, and a partner's key never changes without an admin's accept.
- Security changes need success, refusal, malformed-input and abuse tests.
  Break the code on purpose and show the tests catch it, then restore it.
- Everything in the repository is in English.

Branches are `topic/mohur-<purpose>-<YYYY-MM-DD>` from `main`. Stage explicit
paths, inspect the index, and sign every commit with the Denyfirst identity.
No attribution trailers. Merge commits only; never `git add -A`, squash,
rebase, auto-merge or an admin bypass. Run `scripts/check.ps1` before a commit.

Porch, Keybash and Rootwell are read-only references: never edit their files,
branches or settings. Keep caches, downloads, lab state and builds in `.work/`.
