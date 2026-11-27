# Releasing

A release is the server for Linux (`mohurd`, amd64 and arm64), the list of
its SHA-256 hashes, and denyfirst's signature of that list, published on
GitHub. The desktop app reaches people through the Microsoft Store, built from
the same tag. Nothing is released without the maintainers' agreement, and the
tag is never moved.

## What a server trusts

`mohurd` believes a release list only when `SHA256SUMS.sig` verifies with
denyfirst's release key, which it carries compiled in. The same key is in
[.allowed_signers](../.allowed_signers), so anyone can check a release with
`ssh-keygen` alone. The key lives on the maintainer's release machine, not in
GitHub: whoever takes the GitHub account cannot sign a release.

`sudo mohurd upgrade` installs a file only if its hash is on a verified list,
and only a version newer than the one running.

## Steps

1. Everything for the release is merged and `main` is green.
2. Tag the merge commit, signed, and push the tag:

   ```powershell
   git tag -s v0.1.0 -m "Mohur v0.1.0"
   git push origin v0.1.0
   ```

3. Build from the tag. Building twice, or on another machine, gives the same
   hashes:

   ```powershell
   git checkout v0.1.0
   ./scripts/release-build.ps1 -Version v0.1.0
   ```

4. Sign the list on the release machine and check the signature:

   ```powershell
   ssh-keygen -Y sign -f $HOME\.ssh\id_ed25519_denyfirst_release -n file .work\release\v0.1.0\SHA256SUMS
   cmd /c "ssh-keygen -Y verify -f .allowed_signers -I releases@denyfirst.dev -n file -s .work\release\v0.1.0\SHA256SUMS.sig < .work\release\v0.1.0\SHA256SUMS"
   ```

5. Publish the four files with notes that say what changed and what an admin
   has to do, if anything:

   ```powershell
   gh release create v0.1.0 --title "Mohur v0.1.0" --notes-file notes.md `
     .work\release\v0.1.0\mohurd_v0.1.0_linux_amd64 .work\release\v0.1.0\mohurd_v0.1.0_linux_arm64 `
     .work\release\v0.1.0\SHA256SUMS .work\release\v0.1.0\SHA256SUMS.sig
   ```

6. On a test server: the Server page's **Check now** shows the release, and
   `sudo mohurd upgrade` installs it and restarts the service.
7. Build the Store package from the same tag with
   [packaging/windows](../packaging/windows/README.md), version `0.1.0.0`, and
   submit it in Partner Center.

## The app and the server together

The Store can take a few days to certify an app update. A server release must
therefore keep working with the app version before it, and a release that
needs a newer app says so in its notes.

The app's version is `version` in `client/package.json`; the app gives it to
its server when it joins and signs in. A server refuses apps older than
`OldestApp` in `internal/server/apps.go`, and asks them to update. Raise it
only in a server release that needs the newer app, and only once that app is
in the Store.
