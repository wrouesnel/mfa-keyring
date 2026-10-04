# mfa-keyring

PAM module (`pam_mfa_keyring.so`) and CLI (`mfa-keyring`) that unlock the GNOME login keyring and
per-user encrypted ZFS homes after PIV smartcard, FIDO2 or password login. See README.md for the
design.

## Repositories

- GitHub: `wrouesnel/mfa-keyring` (remote `github`). Local backup: `~/git/will/mfa-keyring.git`
  (remote `origin`).
- Ubuntu packages: `ppa:w-rouesnel/mfa-keyring`, built by Launchpad for noble and resolute.

## Building and testing locally

- This machine has a stale libsodium 1.0.1 in `/usr/local` that shadows the system one. Build with
  `CFLAGS=-I<dir with symlinks to /usr/include/sodium{,.h}>`,
  `LDFLAGS=-L/usr/lib/x86_64-linux-gnu` and
  `PKG_CONFIG_LIBDIR=/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig`.
- `~/.local/bin/ninja` (pip) fails under dpkg-buildpackage; put `/usr/bin` first in `PATH`.
- The integration tests need softhsm2, libpam-wrapper and libfido2-dev. If they aren't installed,
  unpack them with `apt-get download` + `dpkg -x` into the scratchpad and point `SOFTHSM_MODULE`,
  `PAM_WRAPPER_LIB` and `PAM_WRAPPER_MODULES` at them.
- VM tests: `tests/vm/run.sh DEB_DIR ~/opt/iso/noble-server-cloudimg-amd64.img`
  (libvirt `qemu:///session`).

## Releasing

1. Bump the version in `meson.build` and `debian/changelog` (`X.Y.Z-1`).
2. Push to `main` and wait for CI to pass.
3. Tag `vX.Y.Z` and push the tag to `github`. The `ppa` workflow uploads the source packages; the
   `release` workflow makes the GitHub release.

A manual run of the `ppa` workflow builds and signs without uploading, unless `upload` is ticked.

## Approved GPG key exception

PPA uploads are signed in CI with the user's shared Launchpad signing key, which the global
instructions approve exporting to CI secrets.

- Key: `2A12 8435 A6FE 8BD7 51AA 5787 2095 9AB8 0709 6ADB`, "Will Rouesnel (GPG key for launchpad
  signing)", registered on Launchpad as `~w-rouesnel`.
- It is exported only to the GitHub repository secrets `PACKAGE_SIGNING_KEY` and
  `PACKAGE_SIGNING_KEY_PASSPHRASE` of `wrouesnel/mfa-keyring`, with the fingerprint in the
  repository variable `PACKAGE_SIGNING_KEY_FINGERPRINT`.
- The passphrase is looked up only as
  `secret-tool lookup service gpg-passphrase fingerprint 2A128435A6FE8BD751AA578720959AB807096ADB`.
  Never print it.
