# Windows package

This folder builds the Mohur desktop app (`../../client`) into an MSIX package
(`.appx`) for the Microsoft Store. It is a separate npm project, so the app and
its tests never depend on the packaging tools.

```powershell
.\build.ps1
```

The package lands in `.work/dist/windows`. It is unsigned on purpose. The
Microsoft Store signs what it publishes, so users see no SmartScreen warning
and nobody has to buy a certificate. For a Store build, pass the identity that
Partner Center shows for the app:

```powershell
.\build.ps1 -IdentityName '<Package/Identity/Name>' -Publisher 'CN=<publisher id>'
```

## What goes in

- `src`, `assets` and `package.json` from the app, and the app's production
  dependencies.
- Only the x64 libsignal library.
- Only English Chromium resources, because the window is English only.
- Tile and taskbar images from `build/appx`. They are made from
  `client/assets/mohur.svg` at each scale and target size, so Windows never
  stretches a small image.

The package declares `runFullTrust`, as every Electron app must, and needs
Windows 10 1809 or later. electron-builder uses its current Windows SDK tools
(`toolsets.winCodeSign: 1.1.0`, SDK 10.0.26100, checksums pinned inside
electron-builder). The default older bundle cannot sign MSIX on Windows 11.

## Trying a build before the Store

Windows installs only signed packages. To test locally:

1. Sign the build with a short-lived test certificate whose subject matches
   `Publisher`.
2. Trust that one certificate in the machine's Trusted People store. This
   needs an admin.
3. Install the package with `Add-AppxPackage`.
4. Afterwards, remove the package with `Remove-AppxPackage` and take the
   certificate out of the store again.

On 24 November 2026 this was done on Windows 11 (26200) with the lab:

- The package installed and appeared in Start as Mohur, published by Denyfirst.
- It started from its package and sealed its key with the operating system.
- The same build, outside the package, joined a lab organization and
  exchanged messages both ways.

## What the Store asks of Mohur

From the Microsoft Store Policies, version 7.20:

- **10.5.1:** a privacy policy URL. Win32 and Desktop Bridge apps always need
  one.
- **10.2.4:** the start of the description must say that Mohur needs the
  organization's Mohur server.
- **10.3.1 and 10.3.2:** a working demo account and a working server for the
  certification testers. Each submission needs fresh invites to a test
  organization.
- **11.12 (user-generated content):** terms of use in the app and on the web,
  an in-app way to report content, and removal on Microsoft's request.
  Messages are end-to-end encrypted and servers are self-hosted, so the answer
  has to be a report that goes to the person's own organization, plus
  blocking. Whether the Store accepts that is not yet known.
- **10.14:** organizations must use a company account. Denyfirst is a team,
  not a company, so the account will be an individual one.
