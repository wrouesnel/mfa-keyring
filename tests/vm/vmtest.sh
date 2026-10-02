#!/bin/bash
# Runs inside the throwaway VM as root (cloud-init runcmd).
set -u
exec > >(tee /var/log/mfakr-vmtest.log) 2>&1
PASS=0; FAILS=0
ok()   { PASS=$((PASS+1)); echo "VMTEST ok $PASS - $*"; }
bad()  { FAILS=$((FAILS+1)); echo "VMTEST FAIL - $*"; }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

export DEBIAN_FRONTEND=noninteractive
echo "VMTEST installing prerequisites"
apt-get update -q >/dev/null
apt-get install -y -q --no-install-recommends gdm3 gnome-keyring libpam-gnome-keyring \
	opensc-pkcs11 opensc softhsm2 pamtester dbus-user-session libglib2.0-bin >/dev/null 2>&1 ||
	{ bad "prerequisites"; }
cp /etc/pam.d/common-auth /root/common-auth.orig
cp /etc/pam.d/common-password /root/common-password.orig
ALT_BEFORE=$(readlink -f /etc/pam.d/gdm-smartcard)

echo "VMTEST installing packages"
apt-get install -y -q /mnt/libpam-mfa-keyring_*.deb /mnt/mfa-keyring_*.deb >/dev/null 2>&1
check "packages installed" dpkg -s libpam-mfa-keyring mfa-keyring >/dev/null
check "gdm-smartcard alternative points at our stack" \
	test "$(readlink -f /etc/pam.d/gdm-smartcard)" = /etc/pam.d/gdm-smartcard-sssd-mfa-keyring
check "common-auth has mode=login as the last auth module" \
	test "$(grep -E '^auth' /etc/pam.d/common-auth | tail -1 | tr -s ' \t' ' ')" = \
	"auth optional pam_mfa_keyring.so mode=login only_if=gdm-password,gdm-smartcard"
check "common-password has the password hook" grep -q 'pam_mfa_keyring.so' /etc/pam.d/common-password
echo "--- common-auth:"; grep -v '^#' /etc/pam.d/common-auth | grep .
echo "--- common-password:"; grep -v '^#' /etc/pam.d/common-password | grep .

# ---- end to end: real gdm-password stack, real pam_unix and pam_gnome_keyring
useradd -m -s /bin/bash tester
echo 'tester:Login-Pass-1' | chpasswd
loginctl enable-linger tester
UIDN=$(id -u tester)
for _ in $(seq 60); do [ -S /run/user/$UIDN/bus ] && break; sleep 1; done
asuser() { sudo -u tester XDG_RUNTIME_DIR=/run/user/$UIDN DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$UIDN/bus "$@"; }
# One daemon, started the way a PAM login would, with its control socket in
# /run/user/UID/keyring where pam_gnome_keyring looks for it.
asuser systemctl --user mask --now gnome-keyring-daemon.socket gnome-keyring-daemon.service >/dev/null 2>&1
printf 'Login-Pass-1' | asuser gnome-keyring-daemon --daemonize --login --components=secrets >/dev/null
sleep 1
asuser gnome-keyring-daemon --start --components=secrets >/dev/null
sleep 1
ls -la /run/user/$UIDN/keyring/ || true
LOCKED() { asuser gdbus call --session --dest org.freedesktop.secrets \
	--object-path /org/freedesktop/secrets/collection/login \
	--method org.freedesktop.DBus.Properties.Get org.freedesktop.Secret.Collection Locked; }
LOCK() { asuser gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
	--method org.freedesktop.Secret.Service.Lock "['/org/freedesktop/secrets/collection/login']" >/dev/null; }
check "test user's login keyring exists and is unlocked" bash -c "$(declare -f asuser LOCKED); UIDN=$UIDN; LOCKED | grep -q false"

# A software token stands in for the PIV card.
SOFTHSM=/usr/lib/softhsm/libsofthsm2.so
asuser mkdir -p /home/tester/.softhsm/tokens
printf 'directories.tokendir = /home/tester/.softhsm/tokens\n' | asuser tee /home/tester/.softhsm/softhsm2.conf >/dev/null
export SOFTHSM2_CONF=/home/tester/.softhsm/softhsm2.conf
asuser env SOFTHSM2_CONF=$SOFTHSM2_CONF softhsm2-util --init-token --free --label piv --pin 123456 --so-pin 12345678 >/dev/null
asuser env SOFTHSM2_CONF=$SOFTHSM2_CONF pkcs11-tool --module $SOFTHSM --login --pin 123456 --keypairgen \
	--key-type EC:prime256v1 --id 03 --label "KEY MAN key" --usage-derive >/dev/null 2>&1
printf 'Login-Pass-1\n123456\n\n' | asuser env SOFTHSM2_CONF=$SOFTHSM2_CONF mfa-keyring --module $SOFTHSM enroll
check "enrolled with the default wrap file" test -f /home/tester/.local/share/mfa-keyring/login.wrap

LOCK
check "keyring locked before login" bash -c "$(declare -f asuser LOCKED); UIDN=$UIDN; LOCKED | grep -q true"
journalctl --rotate >/dev/null 2>&1; SINCE=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
echo 'Login-Pass-1' | XDG_RUNTIME_DIR=/run/user/$UIDN pamtester gdm-password tester authenticate
check "real gdm-password login unlocked the re-keyed keyring" bash -c "$(declare -f asuser LOCKED); UIDN=$UIDN; LOCKED | grep -q false"
journalctl --since "$SINCE" --no-pager | grep -E 'gkr-pam|pam_mfa_keyring' | tail -5

# A password change through the real password stack re-wraps the slot.
# Drive the real setuid passwd as the user, so pam_unix asks for the old password.
cat > /root/pw.py <<'PY'
import os, pty, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp("sudo", ["sudo", "-u", "tester", "passwd"])
answers = {b"current": sys.argv[1], b"new password": sys.argv[2], b"retype": sys.argv[2]}
buf = b""
while True:
    try:
        d = os.read(fd, 1024)
    except OSError:
        break
    if not d:
        break
    buf += d
    low = buf.lower()
    for k in (b"retype", b"new password", b"current"):
        if low.rstrip().endswith(b":") and k in low.splitlines()[-1]:
            os.write(fd, answers[k].encode() + b"\n")
            buf = b""
            break
sys.stdout.write(buf.decode(errors="replace"))
_, st = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(st))
PY
python3 /root/pw.py Login-Pass-1 'Tr0ub4dor&3-Horse' || echo "(passwd returned non-zero)"
check "password change logged a re-wrap" bash -c "journalctl --since '$SINCE' --no-pager | grep -q 'updated keyring password slot for tester'"
LOCK
echo 'Tr0ub4dor&3-Horse' | XDG_RUNTIME_DIR=/run/user/$UIDN pamtester gdm-password tester authenticate
check "new password unlocks the keyring at login" bash -c "$(declare -f asuser LOCKED); UIDN=$UIDN; LOCKED | grep -q false"

# The PIN must never reach pam_gnome_keyring through the smartcard stack when
# SSSD isn't installed: that path falls back to common-auth (password).
if ls /usr/lib/x86_64-linux-gnu/security/pam_sss.so >/dev/null 2>&1; then
	echo "VMTEST skip - pam_sss is installed here, so the no-sssd fallback path can't be exercised"
	echo foo | pamtester gdm-smartcard tester authenticate
	check "smartcard stack with unconfigured sssd refuses (default=die), no keyring unlock attempted" \
		bash -c "! journalctl --since '$SINCE' --no-pager | grep -q 'pam_mfa_keyring.*smartcard'"
fi

# ---- removal restores the original PAM configuration
apt-get remove -y -q libpam-mfa-keyring >/dev/null 2>&1
check "alternative restored on remove" test "$(readlink -f /etc/pam.d/gdm-smartcard)" = "$ALT_BEFORE"
diff /root/common-auth.orig /etc/pam.d/common-auth; diff /root/common-password.orig /etc/pam.d/common-password
check "common-auth restored on remove" bash -c '! grep -q pam_mfa_keyring /etc/pam.d/common-auth'
check "common-password restored on remove" bash -c '! grep -q pam_mfa_keyring /etc/pam.d/common-password'
apt-get purge -y -q libpam-mfa-keyring >/dev/null 2>&1
check "conffile removed on purge" test ! -e /etc/pam.d/gdm-smartcard-sssd-mfa-keyring
LOCK
echo 'Tr0ub4dor&3-Horse' | XDG_RUNTIME_DIR=/run/user/$UIDN pamtester gdm-password tester authenticate
check "negative control: without the module, login does not unlock the re-keyed keyring" \
	bash -c "$(declare -f asuser LOCKED); UIDN=$UIDN; LOCKED | grep -q true"
check "password login still works after removal" bash -c "echo 'Tr0ub4dor&3-Horse' | pamtester login tester authenticate"

echo "VMTEST DONE pass=$PASS fail=$FAILS"
