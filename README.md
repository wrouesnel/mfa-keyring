# mfa-keyring

Unlock the GNOME login keyring on Ubuntu when you log in to GDM with a **PIV
smartcard** (via SSSD), **passwordlessly with a FIDO2 security key** (via
pam_u2f) or with your **password**.

## The problem

`pam_gnome_keyring` unlocks the login keyring with whatever is in
`PAM_AUTHTOK`, which is normally the login password. A smartcard or
security-key login has no password, so the keyring stays locked and GNOME
prompts for it after login. The common workarounds are weak:

- **Empty keyring password:** secrets are stored unencrypted on disk.
- **Keyring password = card PIN:** the keyring file can be brute-forced offline
  in seconds, because the PIN is 6–8 digits and the card's retry counter
  doesn't apply to a file.

## Design

The login keyring password is replaced by a **random 256-bit secret**. The
secret is stored in `~/.local/share/mfa-keyring/login.wrap`, sealed
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
with it, just before `pam_gnome_keyring.so`, which then unlocks the keyring as
usual. No changes to gnome-keyring are needed.

### Login flows

**Smartcard (gdm-smartcard).** The package installs
`/etc/pam.d/gdm-smartcard-sssd-mfa-keyring` as the highest-priority
`gdm-smartcard` alternative. It is Ubuntu's `gdm-smartcard-sssd-exclusive`
with two changes:

1. `pam_sss ... forward_pass`, so that the PIN SSSD just verified is put in
   `PAM_AUTHTOK`.
2. `pam_mfa_keyring.so mode=piv` runs **straight after pam_sss** and uses that
   PIN to unwrap the secret on the card.

The PIN is never allowed to reach `pam_gnome_keyring`. If that happened,
gnome-keyring would create a *new* login keyring protected only by the PIN. So
on any failure the module clears `PAM_AUTHTOK`.

A password must never be sent to the card as a PIN, because that would burn a
retry. Two things prevent it:

- **Stack layout.** If SSSD isn't installed, `module_unknown=1` skips our
  module, and on success `[default=2]` jumps over the password fallback.
- **Module checks.** The module only tries a PIN on a token that holds an
  enrolled key. It never tries one when the token reports the PIN locked or on
  its final try, or when the value's length is outside the token's PIN length
  range. A wrong PIN is tried at most once.

**Password (gdm-password, and the gdm-smartcard fallback).** A pam-auth-update
profile adds `pam_mfa_keyring.so mode=login` as the **last** module in
`common-auth`, limited to GDM with `only_if`. Running last means modules that
need the real password, such as `pam_zfs_key`, still see it. The module turns
the password into the secret through the password slot.

**Passwordless FIDO2 (pam_u2f).** With pam_u2f as a primary auth method
(Ubuntu's `pam-u2f` pam-auth-update profile, `[success=end]`), there is no
`PAM_AUTHTOK` when the module runs, so it asks for a touch and uses the
key's hmac-secret.

*Limitation:* pam_u2f doesn't request hmac-secret or expose its assertion, so
this costs a **second touch**. When pam_u2f is a *second factor* alongside the
password, the password slot is used and there is no extra touch.

**Password changes.** In the password stack the module re-wraps the password
slot with the new password, using `PAM_OLDAUTHTOK` and `PAM_AUTHTOK` from
pam_unix. If an administrator resets the password, there is no old password,
so the slot goes stale. The module logs this, and the user runs
`mfa-keyring set-password` with their card.

### Security properties

- **Stolen laptop, no card or key:** the attacker must guess the login password
  (Argon2id-hardened), the same as an ordinary password-protected keyring. To
  remove even that, enrol with `--no-password-slot`.
- **Card or key without its PIN:** the PIV slot is useless without the PIN, and
  the PIN is rate-limited by the card. A FIDO2 slot without `--uv` needs only
  the key and a touch, so **use `--uv` if the key may be lost with the
  laptop.**
- **Card cloning or key extraction:** private keys never leave the card. The
  secret is only ever in memory, in PAM and in gnome-keyring.
- **Wrap file tampering:** the file is read with the user's filesystem
  credentials and refused if it's a symlink, not owned by the user, group or
  world writable, larger than 64 KiB, or for a different user. Argon2
  parameters in the file are bounded. Anyone who can write the user's home
  can already replace their keyring, so the file is not a new attack surface.
- **Enrolment** passes the old and new keyring passwords to gnome-keyring over
  the user's session bus, using the Secret Service "plain" algorithm. The bus is
  private to the user.

## Packages

- `libpam-mfa-keyring`: the PAM module, the gdm-smartcard stack (an alternative,
  priority 60) and the pam-auth-update profile.
- `mfa-keyring`: the enrolment tool.

Build with `dpkg-buildpackage -us -uc -b`. The tests use SoftHSM as the card,
pam_wrapper to run PAM stacks unprivileged, and a real gnome-keyring-daemon
on a private D-Bus.

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

The key-management slot (9d) must hold an EC (P-256/P-384) or RSA key. For
example, with a YubiKey:
`ykman piv keys generate -a ECCP256 9d pub.pem`, then
`ykman piv certificates generate -s "CN=you" 9d pub.pem`.

## Limitations

- The home directory must be readable at authentication time. That covers
  ordinary homes, and ZFS homes unlocked by `pam_zfs_key`, which runs earlier
  in `common-auth`. It does not cover homes that are only mounted in the
  session stage.
- Passwordless pam_u2f logins need a second touch. Unlocking the screen this
  way asks for one each time too.
- The PIV card path has been tested with SoftHSM, not yet with a physical card
  through SSSD in a real GDM session. FIDO2 support builds and is wired up, but
  hasn't been tested with a physical key.
