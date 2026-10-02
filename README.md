# mfa-keyring

Unlock the GNOME login keyring, and optionally mount an encrypted ZFS home, on
Ubuntu when you log in with a **PIV smartcard** (via SSSD), **passwordlessly
with a FIDO2 security key** (via pam_u2f), or with your **password**.

## The problem

`pam_gnome_keyring` unlocks the login keyring with whatever is in
`PAM_AUTHTOK`, which is normally the login password. `pam_zfs_key` does the
same with the passphrase of a per-user encrypted ZFS home. A smartcard or
security-key login has no password, so the keyring stays locked and the home
can't be mounted at all.

The common workarounds are weak:

- **Empty keyring password:** secrets are stored unencrypted on disk.
- **Keyring password = card PIN:** the keyring file can be brute-forced offline
  in seconds, because the PIN is 6–8 digits and the card's retry counter
  doesn't apply to a file.

## Design

The keyring password, and optionally the ZFS home's passphrase, is replaced by
a **random 256-bit secret**. The secret is kept in a wrap file, sealed
(XChaCha20-Poly1305) once per enrolled unlock method ("slot"), much like LUKS
keyslots:

| Slot       | Key-encryption key | Needs at unlock |
|------------|-------------------|-----------------|
| `piv-ec`   | HKDF(ECDH(ephemeral, card key)), with the ECDH done **on the card** | card + PIN |
| `piv-rsa`  | HKDF(seed), seed RSA-decrypted **on the card** (PKCS#1 v1.5, which PIV cards support) | card + PIN |
| `fido2`    | HKDF(hmac-secret(credential, salt)) from the authenticator | key + touch (+ key PIN with `--uv`) |
| `password` | Argon2id(login password), 256 MiB, 3 passes | login password |

The header (including the user name) and each slot's parameters are
authenticated as AEAD associated data. Card keys are identified by the SHA-256
of their SubjectPublicKeyInfo, and that keyid is also bound into the KDF.

At login, `pam_mfa_keyring.so` recovers the secret and replaces `PAM_AUTHTOK`
with it, ahead of the modules that consume it. Neither gnome-keyring nor
pam_zfs_key needs changing.

### Where the wrap file lives

The module and the CLI look in two places, in this order:

1. `/var/lib/mfa-keyring/<user>/login.wrap`. This is needed when the home is
   encrypted, because it isn't mounted yet during authentication.
   `mfa-keyring zfs-enroll` moves the file here.
2. `~/.local/share/mfa-keyring/login.wrap`, the default for ordinary homes.

The file is read with the user's filesystem credentials. It is refused if it's
a symlink, not owned by the user, group or world writable, larger than 64 KiB,
or written for another user.

### Login flows

**Smartcard (gdm-smartcard).** The package installs
`/etc/pam.d/gdm-smartcard-sssd-mfa-keyring` as the highest-priority
`gdm-smartcard` alternative. It is Ubuntu's `gdm-smartcard-sssd-exclusive`
with these changes:

1. `pam_sss ... forward_pass`, so that the PIN SSSD just verified is put in
   `PAM_AUTHTOK`.
2. `pam_mfa_keyring.so mode=piv` runs **straight after pam_sss** and uses that
   PIN to unwrap the secret on the card.
3. `pam_zfs_key.so` runs only if the secret was recovered, and picks it up for
   the session. Linux-PAM clears `PAM_AUTHTOK` when authentication ends, so it
   has to happen here. Running it only on success means it can't prompt for a
   password.

The PIN is never allowed to reach `pam_gnome_keyring`. If that happened,
gnome-keyring would create a *new* login keyring protected only by the PIN. So
on any failure the module clears `PAM_AUTHTOK`.

A password must never be sent to the card as a PIN, because that would burn a
retry. Two things prevent it:

- **Stack layout.** If SSSD isn't installed, `module_unknown=3` skips all three
  lines, and on success a `pam_permit` jump skips the password fallback.
- **Module checks.** The module only tries a PIN on a token that holds an
  enrolled key. It never tries one when the token reports the PIN locked or on
  its final try, or when the value's length is outside the token's PIN length
  range. A wrong PIN is tried at most once.

**Password, and passwordless FIDO2.** Two pam-auth-update profiles add the
module to `common-auth` and `common-password`:

- **`mfa-keyring-early`** (priority 129, just ahead of pam_zfs_key's 128):
  - In auth (`mode=login zfs_only`), it acts **only for ZFS-enrolled users**.
    It turns the password into the secret before pam_zfs_key sees it. With no
    password, after passwordless pam_u2f, it asks for a touch instead.
  - In the password stack, it re-wraps the password slot when the password
    changes. For ZFS-enrolled users it then passes the secret on as the new
    password, so pam_zfs_key keeps the dataset on the secret.
- **`mfa-keyring`** (priority −128, last): for the GNOME keyring on
  `gdm-password` and `gdm-smartcard` (its password fallback). It does nothing if
  the early instance already applied the secret, so there's no second FIDO2
  touch. It runs last so that, for users without a ZFS home, every other module
  still sees the real password.

*pam_u2f:* with pam_u2f as a primary auth method (Ubuntu's `pam-u2f` profile,
`[success=end]`), there's no `PAM_AUTHTOK`, so the module asks for a touch and
uses the key's hmac-secret. pam_u2f doesn't request hmac-secret or expose its
assertion, so this costs a **second touch**. With pam_u2f as a second factor
alongside the password, the password slot is used and there's no extra touch.

*Password resets:* if an administrator resets the password, there's no old
password to re-wrap with, so the slot goes stale. The module logs it, and
`mfa-keyring set-password`, run with a card or key, fixes it.

### ZFS encrypted homes

`sudo mfa-keyring zfs-enroll` changes the passphrase of the user's home dataset
to the secret and moves the wrap file to `/var/lib/mfa-keyring/`. Requirements:

- the home must be its own encryption root with `keyformat=passphrase`, i.e. a
  per-user encrypted home;
- `pam_zfs_key` must be enabled (`libpam-zfs`).

After that:
- **Smartcard and FIDO2 logins** mount the home.
- **Password logins** (GDM, console, SSH) mount it through the password slot.
- **Password changes** never move the dataset off the secret. In fact
  pam_zfs_key refuses to re-key it at all, because the old password no longer
  matches.

`zfs-disenroll` gives the dataset an ordinary passphrase again.

Each password login of a ZFS-enrolled user costs one Argon2id derivation
(256 MiB, about half a second). `sudo` and `polkit-1` are skipped, because they
don't mount homes.

### Security properties

- **Stolen laptop, no card or key:** the attacker must guess the login password
  against Argon2id. That is stronger than gnome-keyring's own password hashing
  or ZFS's PBKDF2. Enrol with `--no-password-slot` to remove even that, at the
  cost of password logins.
- **Card or key without its PIN:** the PIV slot is useless without the PIN, and
  the PIN is rate-limited by the card. A FIDO2 slot without `--uv` needs only
  the key and a touch, so **use `--uv` if the key may be lost with the
  laptop.**
- **Card cloning or key extraction:** private keys never leave the card. The
  secret is only ever in memory, in PAM, gnome-keyring and the ZFS keystore.
- **Wrap file tampering:** only the user (and root) can write the file, and
  anyone who can do that can already replace the keyring. Argon2 parameters in
  the file are bounded.
- **Enrolment** passes keyring passwords to gnome-keyring over the user's
  session bus, using the Secret Service "plain" algorithm. The bus is private
  to the user.

## Packages

- `libpam-mfa-keyring`: the PAM module, the gdm-smartcard stack (an alternative,
  priority 60), the two pam-auth-update profiles, and `/var/lib/mfa-keyring`.
  Purging it keeps users' wrap files, because ZFS homes may depend on them, and
  removing it warns about ZFS-enrolled users.
- `mfa-keyring`: the enrolment tool.

Build with `dpkg-buildpackage -us -uc -b`. Tests:

- **Unit and integration** (run during the build): SoftHSM as the card,
  pam_wrapper to run PAM stacks unprivileged, and a real gnome-keyring-daemon
  on a private D-Bus.
- **`tests/vm/run.sh DEB_DIR noble-server-cloudimg-amd64.img`:** installs the
  packages in a throwaway VM (libvirt `qemu:///session`). It runs real
  `gdm-password` logins against gnome-keyring, and smartcard and password
  logins that mount a passphrase-encrypted ZFS home through the real
  `common-auth`/`common-session`, including a password change while the home is
  mounted.

## Setup

1. Configure SSSD smartcard login for GDM (certificate mapping for your
   users). See the Ubuntu Server guide, "Smart card authentication".
2. Install `libpam-mfa-keyring` and `mfa-keyring`.
3. As the user, with the card inserted:

   ```
   mfa-keyring list-keys
   mfa-keyring enroll                 # uses the PIV key-management key (9d / id 03)
   mfa-keyring add-piv --key <keyid>  # optional: backup card
   mfa-keyring add-fido2 --uv         # optional: FIDO2 key for pam_u2f logins
   mfa-keyring status
   ```

4. Optionally, for a per-user encrypted ZFS home:
   `sudo mfa-keyring zfs-enroll`.

The key-management slot (9d) must hold an EC (P-256/P-384) or RSA key. For
example, with a YubiKey:
`ykman piv keys generate -a ECCP256 9d pub.pem`, then
`ykman piv certificates generate -s "CN=you" 9d pub.pem`.

## Limitations and notes

- Passwordless pam_u2f logins need a second touch. Unlocking the screen this
  way asks for one each time too.
- Only ZFS homes are handled among encrypted homes. Homes unlocked by other
  modules, or mounted only in the session stage, can't use a wrap file inside
  the home. They can use `/var/lib/mfa-keyring/<user>/`, which an administrator
  creates.
- With `libpam-zfs` enabled, `chpasswd` (as root) fails on stock Ubuntu.
  pam_zfs_key prompts for an "old password", chpasswd answers with the new
  one, and pam_unix then rejects it as unchanged. This is not specific to
  mfa-keyring; use `usermod -p` or `passwd`.
- The PIV card path has been tested with SoftHSM, not yet with a physical card
  through SSSD in a real GDM session. FIDO2 support builds and is wired up, but
  hasn't been tested with a physical key.
