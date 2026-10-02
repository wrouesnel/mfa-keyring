#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# End-to-end test: SoftHSM stands in for the PIV card, pam_wrapper runs PAM
# stacks unprivileged, and a real gnome-keyring-daemon runs on a private bus.
#
#   integration.sh BUILD_DIR SOURCE_DIR
#
# Optional environment: SOFTHSM_MODULE, PAM_WRAPPER_LIB, PAM_WRAPPER_MODULES.
# Exits 77 (skip) when a dependency is missing.
set -euo pipefail

BUILD=$(realpath "$1")
SRC=$(realpath "$2")

find_first() { for f in "$@"; do [ -e "$f" ] && { echo "$f"; return 0; }; done; return 1; }
skip() { echo "SKIP: $*"; exit 77; }

SOFTHSM_MODULE=${SOFTHSM_MODULE:-$(find_first /usr/lib/softhsm/libsofthsm2.so \
	/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so || true)}
PAM_WRAPPER_LIB=${PAM_WRAPPER_LIB:-$(find_first /usr/lib/x86_64-linux-gnu/libpam_wrapper.so || true)}
PAM_WRAPPER_MODULES=${PAM_WRAPPER_MODULES:-/usr/lib/x86_64-linux-gnu/pam_wrapper}
PAM_MODULES=/usr/lib/x86_64-linux-gnu/security

[ -n "$SOFTHSM_MODULE" ] || skip "softhsm2 not installed"
[ -n "$PAM_WRAPPER_LIB" ] || skip "libpam-wrapper not installed"
for t in softhsm2-util pkcs11-tool openssl gnome-keyring-daemon dbus-run-session python3; do
	command -v "$t" >/dev/null || skip "$t not installed"
done

if [ -z "${PIVKR_IN_BUS:-}" ]; then
	export PIVKR_IN_BUS=1
	exec dbus-run-session -- "$0" "$@"
fi

T=$(mktemp -d)
cleanup() {
	[ -n "${GKR_PID:-}" ] && kill "$GKR_PID" 2>/dev/null || true
	rm -rf "$T"
}
trap cleanup EXIT

PASS=0
ok() { PASS=$((PASS + 1)); echo "ok $PASS - $*"; }
fail() { echo "FAIL - $*"; exit 1; }

PIN=123456
LOGINPW=correct-horse
CLI="$BUILD/piv-keyring --module $SOFTHSM_MODULE --file $T/login.wrap"
GKR="python3 $SRC/tests/gkr-helper.py"
USER_NAME=$(id -un)

# ---------------------------------------------------------------- SoftHSM ---
export SOFTHSM2_CONF=$T/softhsm2.conf
mkdir -p "$T/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$T" > "$SOFTHSM2_CONF"
P11="pkcs11-tool --module $SOFTHSM_MODULE"

softhsm2-util --module "$SOFTHSM_MODULE" --init-token --free --label piv-card --pin $PIN --so-pin 12345678 >/dev/null

# Key management key (id 03): EC P-256 generated on the token (public key object only).
$P11 --token-label piv-card --login --pin $PIN --keypairgen --key-type EC:prime256v1 \
	--id 03 --label "KEY MAN key" --usage-derive >/dev/null 2>&1
# Authentication key (id 01): RSA-2048 imported together with a certificate.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/rsa.key" -out "$T/rsa.crt" \
	-subj "/CN=$USER_NAME" -days 30 2>/dev/null
openssl x509 -in "$T/rsa.crt" -outform DER -out "$T/rsa.der"
openssl pkcs8 -topk8 -nocrypt -in "$T/rsa.key" -outform DER -out "$T/rsa.p8"
$P11 --token-label piv-card --login --pin $PIN --write-object "$T/rsa.p8" --type privkey \
	--id 01 --label "PIV AUTH key" --usage-decrypt >/dev/null 2>&1
$P11 --token-label piv-card --login --pin $PIN --write-object "$T/rsa.der" --type cert \
	--id 01 --label "Certificate for PIV Authentication" >/dev/null 2>&1

$CLI list-keys > "$T/keys.txt"
grep -q 'id 03' "$T/keys.txt" && grep -q 'id 01' "$T/keys.txt" || { cat "$T/keys.txt"; fail "list-keys"; }
grep -q 'RSA' "$T/keys.txt" || fail "list-keys did not parse the RSA certificate"
ok "list-keys sees the EC public key and the RSA certificate"

# ---------------------------------------------------------- gnome-keyring ---
export XDG_RUNTIME_DIR=$T/run XDG_DATA_HOME=$T/data HOME=$T/home
mkdir -p -m 700 "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME" "$HOME"
printf '%s' "$LOGINPW" | gnome-keyring-daemon --foreground --unlock --components=secrets \
	>"$T/gkr.log" 2>&1 &
GKR_PID=$!
for _ in $(seq 100); do
	gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
		--method org.freedesktop.DBus.NameHasOwner org.freedesktop.secrets 2>/dev/null |
		grep -q true && break
	sleep 0.1
done
$GKR unlock "$LOGINPW" || fail "test keyring not created with the login password"
ok "gnome-keyring running with login keyring"

# ----------------------------------------------------------------- enrol ---
printf '%s\n%s\n\n' "$LOGINPW" "$PIN" | $CLI enroll >"$T/enroll.log" 2>&1 ||
	{ cat "$T/enroll.log"; fail "enroll"; }
[ "$(stat -c %a "$T/login.wrap")" = 600 ] || fail "wrap file mode"
grep -q '^piv-ec ' "$T/login.wrap" && grep -q '^password argon2id ' "$T/login.wrap" ||
	fail "wrap file slots"
$GKR lock
$GKR unlock "$LOGINPW" 2>/dev/null && fail "keyring still opens with the old password"
ok "enroll re-keys the keyring (default key 03, password slot reusing keyring password)"

printf '%s\n%s\n\n' "$LOGINPW" "$PIN" | $CLI enroll >/dev/null 2>&1 &&
	fail "second enroll without --force should refuse"
ok "enroll refuses to overwrite an existing enrolment"

$GKR lock
$GKR locked || fail "lock"
printf '%s\n' "$PIN" | $CLI unlock >/dev/null 2>&1 || fail "unlock with card"
$GKR locked && fail "still locked after unlock"
ok "piv-keyring unlock opens the keyring with the card"

$GKR lock
printf '%s\n' 000000 | $CLI unlock >"$T/out" 2>&1 && fail "wrong PIN unlocked"
grep -q 'PIN incorrect' "$T/out" || { cat "$T/out"; fail "wrong PIN message"; }
ok "wrong PIN is rejected once without falling back to the password prompt"

# ---------------------------------------------------------------- PAM ---
SVC=$T/pam.d
mkdir -p "$SVC"
MOD=$BUILD/pam_piv_keyring.so
OPTS="file=$T/login.wrap module=$SOFTHSM_MODULE debug"
SET=$PAM_WRAPPER_MODULES/pam_set_items.so
GET=$PAM_WRAPPER_MODULES/pam_get_items.so

pamrun() { # pamrun auth|chauthtok SERVICE [env...]
	local op=$1 svc=$2
	shift 2
	env "$@" LD_PRELOAD="$PAM_WRAPPER_LIB" PAM_WRAPPER=1 PAM_WRAPPER_SERVICE_DIR="$SVC" \
		"$BUILD/tests/pamtest" "$op" "$svc" "$USER_NAME"
}
authtok_of() { sed -n 's/.*authtok=//p'; }

cat > "$SVC/piv" <<EOF
auth required $SET
auth optional $MOD mode=piv $OPTS
auth required $GET
EOF
cat > "$SVC/login" <<EOF
auth required $SET
auth optional $MOD mode=login $OPTS
auth required $GET
EOF

TOK=$(pamrun auth piv PAM_AUTHTOK=$PIN 2>"$T/err" | authtok_of)
[ ${#TOK} -eq 43 ] || { cat "$T/err"; fail "mode=piv did not produce the secret (got '$TOK')"; }
$GKR lock
$GKR unlock "$TOK" || fail "PAM-recovered secret does not unlock the keyring"
SECRET=$TOK
ok "mode=piv turns the forwarded PIN into the keyring secret"

TOK=$(pamrun auth piv PAM_AUTHTOK=999999 2>/dev/null | authtok_of)
[ "$TOK" = "(null)" ] || fail "mode=piv with a wrong PIN must clear PAM_AUTHTOK (got '$TOK')"
ok "mode=piv clears PAM_AUTHTOK when the PIN is wrong"

TOK=$(pamrun auth piv PAM_AUTHTOK=12 2>/dev/null | authtok_of)
[ "$TOK" = "(null)" ] || fail "short PIN"
ok "mode=piv clears PAM_AUTHTOK for a value that can't be a PIN"

TOK=$(pamrun auth login PAM_AUTHTOK=$LOGINPW 2>/dev/null | authtok_of)
[ "$TOK" = "$SECRET" ] || fail "mode=login with the password"
ok "mode=login turns the login password into the keyring secret"

TOK=$(pamrun auth login PAM_AUTHTOK=wrong-password 2>/dev/null | authtok_of)
[ "$TOK" = wrong-password ] || fail "mode=login must leave a non-matching password alone"
ok "mode=login leaves PAM_AUTHTOK alone when the password slot doesn't match"

TOK=$(pamrun auth login PAMTEST_ANSWERS= 2>"$T/err" | authtok_of)
[ "$TOK" = "(null)" ] && ! grep -q PROMPT "$T/err" || fail "mode=login without fido2 slots"
ok "mode=login with no password and no FIDO2 slot does nothing and doesn't prompt"

cat > "$SVC/onlyif" <<EOF
auth required $SET
auth optional $MOD mode=login only_if=gdm-password $OPTS
auth required $GET
EOF
TOK=$(pamrun auth onlyif PAM_AUTHTOK=$LOGINPW 2>/dev/null | authtok_of)
[ "$TOK" = "$LOGINPW" ] || fail "only_if"
ok "only_if limits the module to the listed services"

cat > "$SVC/pivprompt" <<EOF
auth optional $MOD mode=piv prompt_pin $OPTS
auth required $GET
EOF
TOK=$(pamrun auth pivprompt PAMTEST_ANSWERS=$PIN 2>/dev/null | authtok_of)
[ "$TOK" = "$SECRET" ] || fail "prompt_pin"
ok "mode=piv prompt_pin asks for the PIN when none was forwarded"

# ----------------------------------------- shipped gdm-smartcard stack ---
# Replace pam_sss with pam_set_items (success + forwarded PIN), or with a
# module that doesn't exist (SSSD not installed), and pam_gnome_keyring with
# pam_get_items; keep everything else as shipped.
mkstack() { # mkstack NAME SSS_REPLACEMENT
	sed -e "s|pam_sss.so|$2|" \
	    -e "s|pam_piv_keyring.so mode=piv|$MOD mode=piv $OPTS|" \
	    -e "s|pam_gnome_keyring.so|$GET|" \
	    -e "s|substack        common-auth|substack        $1-common|" \
	    -e '/^@include/d' -e '/^session/d' -e '/^account/d' -e '/^password/d' \
	    "$SRC/pam/gdm-smartcard-sssd-piv-keyring" > "$SVC/$1"
	printf 'auth required %s\n' "$SET" > "$SVC/$1-common"
	sed -i "s|pam_nologin.so|$PAM_MODULES/pam_nologin.so|; s|pam_succeed_if.so|$PAM_MODULES/pam_succeed_if.so|; s|pam_echo.so|$PAM_MODULES/pam_echo.so|" "$SVC/$1"
}
mkstack gdm-sc "$SET"
mkstack gdm-sc-nosss "$T/no-such-module/pam_sss.so"

OUT=$(pamrun auth gdm-sc PAM_AUTHTOK=$PIN 2>"$T/err")
[ "$(authtok_of <<<"$OUT")" = "$SECRET" ] && grep -q 'rc=0 ' <<<"$OUT" ||
	{ cat "$SVC/gdm-sc" "$T/err"; echo "$OUT"; fail "shipped stack, sss success"; }
ok "shipped gdm-smartcard stack: smartcard login yields the keyring secret"

# The fallback password must not reach mode=piv (it would be tried as a PIN).
# Use the PIN as the "password": if the module ran, PAM_AUTHTOK would change.
OUT=$(pamrun auth gdm-sc-nosss PAM_AUTHTOK=$PIN 2>"$T/err")
[ "$(authtok_of <<<"$OUT")" = "$PIN" ] && grep -q 'rc=0 ' <<<"$OUT" ||
	{ cat "$T/err"; echo "$OUT"; fail "shipped stack, sss missing: module must be skipped"; }
ok "shipped gdm-smartcard stack: password fallback never reaches mode=piv"

# ------------------------------------------------------------ chauthtok ---
cat > "$SVC/passwd" <<EOF
password required $SET
password optional $MOD $OPTS
password required $GET
EOF
pamrun chauthtok passwd PAM_OLDAUTHTOK=$LOGINPW PAM_AUTHTOK=new-password >/dev/null 2>&1
TOK=$(pamrun auth login PAM_AUTHTOK=new-password 2>/dev/null | authtok_of)
[ "$TOK" = "$SECRET" ] || fail "new password after chauthtok"
TOK=$(pamrun auth login PAM_AUTHTOK=$LOGINPW 2>/dev/null | authtok_of)
[ "$TOK" = "$LOGINPW" ] || fail "old password still works after chauthtok"
ok "password change re-wraps the password slot"

pamrun chauthtok passwd PAM_AUTHTOK=admin-reset >/dev/null 2>&1
TOK=$(pamrun auth login PAM_AUTHTOK=new-password 2>/dev/null | authtok_of)
[ "$TOK" = "$SECRET" ] || fail "reset without old password must leave the slot alone"
ok "password reset without the old password leaves the slot untouched"

printf '%s\nrecovered-pw\n' "$PIN" | $CLI set-password >/dev/null 2>&1 || fail "set-password"
TOK=$(pamrun auth login PAM_AUTHTOK=recovered-pw 2>/dev/null | authtok_of)
[ "$TOK" = "$SECRET" ] || fail "set-password"
ok "set-password re-creates the password slot using the card"

# -------------------------------------------------------- multiple keys ---
printf '%s\n%s\n' "$PIN" "$PIN" | $CLI add-piv --key 01 >"$T/out" 2>&1 || { cat "$T/out"; fail "add-piv rsa"; }
grep -q '^piv-rsa ' "$T/login.wrap" || fail "no piv-rsa slot"
$CLI remove 0 >/dev/null
grep -q '^piv-ec ' "$T/login.wrap" && fail "remove"
TOK=$(pamrun auth piv PAM_AUTHTOK=$PIN 2>"$T/err" | authtok_of)
[ "$TOK" = "$SECRET" ] || { cat "$T/err"; fail "RSA slot via PAM"; }
ok "RSA key slot (certificate-backed) unlocks via PAM"

# Plug in a second card with its own key-management key.
softhsm2-util --module "$SOFTHSM_MODULE" --init-token --free --label other-card --pin 654321 --so-pin 12345678 >/dev/null
$P11 --token-label other-card --login --pin 654321 --keypairgen --key-type EC:prime256v1 \
	--id 03 --label "KEY MAN key" --usage-derive >/dev/null 2>&1
$CLI list-keys > "$T/keys.txt"
printf '%s\n654321\n' "$PIN" | $CLI add-piv --key "$(grep -A1 other-card "$T/keys.txt" | sed -n 's/.*keyid //p' | head -c 16)" \
	>"$T/out" 2>&1 || { cat "$T/out"; fail "add-piv second card"; }
ok "a second card can be added as a backup"

# ------------------------------------------------------------ hardening ---
cp "$T/login.wrap" "$T/good.wrap"
chmod 666 "$T/login.wrap"
TOK=$(pamrun auth login PAM_AUTHTOK=recovered-pw 2>/dev/null | authtok_of)
[ "$TOK" = recovered-pw ] || fail "world-writable wrap file was used"
cp "$T/good.wrap" "$T/login.wrap"; chmod 600 "$T/login.wrap"
ok "world-writable wrap file is refused"

sed -i "1s/ $USER_NAME\$/ someone-else/" "$T/login.wrap"
TOK=$(pamrun auth piv PAM_AUTHTOK=$PIN 2>/dev/null | authtok_of)
[ "$TOK" = "(null)" ] || fail "wrap file for another user was used"
cp "$T/good.wrap" "$T/login.wrap"
ok "wrap file naming another user is refused (and the PIN is still cleared)"

ln -sf "$T/good.wrap" "$T/link.wrap"
cat > "$SVC/symlink" <<EOF
auth required $SET
auth optional $MOD mode=login file=$T/link.wrap module=$SOFTHSM_MODULE
auth required $GET
EOF
TOK=$(pamrun auth symlink PAM_AUTHTOK=recovered-pw 2>/dev/null | authtok_of)
[ "$TOK" = recovered-pw ] || fail "symlinked wrap file was followed"
ok "symlinked wrap file is not followed"

# ------------------------------------------------------------ disenroll ---
printf '%s\nplain-again\nplain-again\n' "$PIN" | $CLI disenroll >/dev/null 2>&1 || fail "disenroll"
[ -e "$T/login.wrap" ] && fail "wrap file left behind"
$GKR lock
$GKR unlock plain-again || fail "keyring password after disenroll"
ok "disenroll restores an ordinary keyring password"

echo "All $PASS integration tests passed."
