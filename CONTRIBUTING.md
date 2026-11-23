# Contributing

1. Branch from `main` as `topic/mohur-<purpose>-<YYYY-MM-DD>`.
2. Make the change with its tests. For a security change, also break the code
   on purpose and confirm a test fails, then restore it.
3. Run `scripts/check.ps1` (add `-Analysis` when staticcheck, gosec and
   govulncheck are installed).
4. Stage exact paths, read `git diff --cached`, and commit signed. The subject
   says why, in the imperative, in at most 72 characters.
5. Open a PR with the template's sections: Why, Evidence, Limits and recovery.

Dependencies stay few: bbolt and the Go x/ modules on the server; Electron and
libsignal in the app. A new one needs a reason, an exact version and its
licence in `docs/third-party/`.

Never commit keys, databases, `.env` files, lab state or real messages.
