#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Runs inside the throwaway VM as root (cloud-init runcmd), see run.sh.
set -u
exec > >(tee /var/log/mfakr-vmtest.log) 2>&1
PASS=0; FAILS=0
ok()   { PASS=$((PASS+1)); echo "VMTEST ok $PASS - $*"; }
bad()  { FAILS=$((FAILS+1)); echo "VMTEST FAIL - $*"; }
info() { echo "VMTEST info - $*"; }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

export DEBIAN_FRONTEND=noninteractive
SOFTHSM=/usr/lib/softhsm/libsofthsm2.so
SETITEMS=/usr/lib/x86_64-linux-gnu/pam_wrapper/pam_set_items.so
PIN=123456

echo "VMTEST installing prerequisites"
apt-get update -q >/dev/null
apt-get install -y -q --no-install-recommends gdm3 gnome-keyring libpam-gnome-keyring \
	opensc-pkcs11 opensc softhsm2 pamtester dbus-user-session libglib2.0-bin \
	zfsutils-linux libpam-zfs libpam-wrapper >/dev/null 2>&1 || bad "prerequisites"
modprobe zfs || bad "zfs kernel module"
ALT_BEFORE=$(readlink -f /etc/pam.d/gdm-smartcard)

echo "VMTEST installing packages"
apt-get install -y -q /mnt/libpam-mfa-keyring_*.deb /mnt/mfa-keyring_*.deb >/dev/null 2>&1
check "packages installed" dpkg -s libpam-mfa-keyring mfa-keyring >/dev/null
check "gdm-smartcard alternative points at our stack" \
	test "$(readlink -f /etc/pam.d/gdm-smartcard)" = /etc/pam.d/gdm-smartcard-sssd-mfa-keyring
check "keyring instance is the last auth module" \
	test "$(grep -E '^auth' /etc/pam.d/common-auth | tail -1 | tr -s ' \t' ' ')" = \
	"auth optional pam_mfa_keyring.so mode=login only_if=gdm-password,gdm-smartcard"
order() { grep -nE "^$1.*($2)" "/etc/pam.d/common-$3" | head -1 | cut -d: -f1; }
check "early instance runs before pam_zfs_key in auth" \
	test "$(order auth 'zfs_only' auth)" -lt "$(order auth pam_zfs_key auth)"
check "password hook runs before pam_zfs_key and after pam_unix" bash -c \
	"[ $(order password pam_unix password) -lt $(order password pam_mfa_keyring password) ] &&
	 [ $(order password pam_mfa_keyring password) -lt $(order password pam_zfs_key password) ]"
echo "--- common-auth:"; grep -v '^#' /etc/pam.d/common-auth | grep .
echo "--- common-password:"; grep -v '^#' /etc/pam.d/common-password | grep .

# Helpers for a user's systemd/D-Bus session.
as() { local u=$1; shift; local i; i=$(id -u "$u")
	sudo -u "$u" XDG_RUNTIME_DIR=/run/user/$i DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$i/bus \
		SOFTHSM2_CONF="$SOFTHSM2_CONF" "$@"; }
locked() { as "$1" gdbus call --session --dest org.freedesktop.secrets \
	--object-path /org/freedesktop/secrets/collection/login \
	--method org.freedesktop.DBus.Properties.Get org.freedesktop.Secret.Collection Locked; }
lock() { as "$1" gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
	--method org.freedesktop.Secret.Service.Lock "['/org/freedesktop/secrets/collection/login']" >/dev/null; }
start_keyring() { # start_keyring USER PASSWORD
	local i; i=$(id -u "$1")
	loginctl enable-linger "$1"
	for _ in $(seq 60); do [ -S /run/user/$i/bus ] && break; sleep 1; done
	as "$1" systemctl --user mask --now gnome-keyring-daemon.socket gnome-keyring-daemon.service >/dev/null 2>&1
	printf '%s' "$2" | as "$1" gnome-keyring-daemon --daemonize --login --components=secrets >/dev/null
	sleep 1
	as "$1" gnome-keyring-daemon --start --components=secrets >/dev/null
	sleep 1
}
stop_user() { loginctl disable-linger "$1"; loginctl terminate-user "$1" 2>/dev/null; pkill -u "$1"; sleep 2; }
# Drives the real setuid passwd as the user, so pam_unix asks for the old password.
cat > /root/pw.py <<'PY'
import os, pty, sys
pid, fd = pty.fork()
if pid == 0:
    os.execvp("sudo", ["sudo", "-u", sys.argv[1], "passwd"])
answers = {b"current": sys.argv[2], b"new password": sys.argv[3], b"retype": sys.argv[3]}
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

# Software tokens stand in for the PIV cards; kept outside the (encrypted) homes.
export SOFTHSM2_CONF=/var/lib/softhsm-test/softhsm2.conf
mkdir -p /var/lib/softhsm-test/tokens && chmod 1777 /var/lib/softhsm-test/tokens
printf 'directories.tokendir = /var/lib/softhsm-test/tokens\n' > $SOFTHSM2_CONF
mkcard() { # mkcard USER LABEL
	as "$1" softhsm2-util --init-token --free --label "$2" --pin $PIN --so-pin 12345678 >/dev/null
	as "$1" pkcs11-tool --module $SOFTHSM --token-label "$2" --login --pin $PIN --keypairgen \
		--key-type EC:prime256v1 --id 03 --label "KEY MAN key" --usage-derive >/dev/null 2>&1
}

# ======================================================= GNOME keyring ===
useradd -m -s /bin/bash tester
usermod -p "$(openssl passwd -6 Login-Pass-1)" tester   # chpasswd trips over pam_zfs_key
mkcard tester tester-card
start_keyring tester Login-Pass-1
check "tester's login keyring exists and is unlocked" bash -c "$(declare -f as locked); SOFTHSM2_CONF=$SOFTHSM2_CONF; locked tester | grep -q false"
printf 'Login-Pass-1\n%s\n\n' $PIN | as tester mfa-keyring --module $SOFTHSM --key "$(as tester mfa-keyring --module $SOFTHSM list-keys | grep -A1 tester-card | sed -n 's/.*keyid //p' | head -c 16)" enroll
check "enrolled with the wrap file in the home" test -f /home/tester/.local/share/mfa-keyring/login.wrap

lock tester
SINCE=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
echo 'Login-Pass-1' | XDG_RUNTIME_DIR=/run/user/$(id -u tester) pamtester gdm-password tester authenticate
check "real gdm-password login unlocks the re-keyed keyring" bash -c "$(declare -f as locked); SOFTHSM2_CONF=$SOFTHSM2_CONF; locked tester | grep -q false"
journalctl --since "$SINCE" --no-pager | grep -E 'gkr-pam|pam_mfa_keyring' | tail -3

python3 /root/pw.py tester Login-Pass-1 'Tr0ub4dor&3-Horse' || info "passwd returned non-zero"
check "password change re-wrapped the slot" bash -c "journalctl --since '$SINCE' --no-pager | grep -q 'updated password slot for tester'"
lock tester
echo 'Tr0ub4dor&3-Horse' | XDG_RUNTIME_DIR=/run/user/$(id -u tester) pamtester gdm-password tester authenticate
check "new password unlocks the keyring at login" bash -c "$(declare -f as locked); SOFTHSM2_CONF=$SOFTHSM2_CONF; locked tester | grep -q false"

# ===================================================== ZFS encrypted home ===
truncate -s 2G /var/tmp/pool.img
zpool create -m none rpool /var/tmp/pool.img           # pam_zfs_key default: homes=rpool/home
zfs create -o mountpoint=none rpool/home
useradd -M -d /home/zuser -s /bin/bash zuser
usermod -p "$(openssl passwd -6 Zfs-Pass-1)" zuser
printf 'Zfs-Pass-1' | zfs create -o encryption=on -o keyformat=passphrase -o keylocation=prompt \
	-o mountpoint=/home/zuser rpool/home/zuser
chown zuser:zuser /home/zuser
DS=rpool/home/zuser
keystatus() { zfs get -H -o value keystatus $DS; }
# Log the user out completely (the session's gnome-keyring keeps the home busy).
reset_home() {
	pkill -u zuser; sleep 1
	zfs unmount $DS 2>/dev/null; zfs unload-key $DS 2>/dev/null
	[ "$(keystatus)" = unavailable ]
}
mounted() { zfs get -H -o value mounted $DS; }
grep -q pam_zfs_key /etc/pam.d/common-session || pam-auth-update --enable zfs_key
check "pam_zfs_key is active" grep -q pam_zfs_key /etc/pam.d/common-session

mkcard zuser zuser-card
start_keyring zuser Zfs-Pass-1
ZKEY=$(as zuser mfa-keyring --module $SOFTHSM list-keys | grep -A1 zuser-card | sed -n 's/.*keyid //p' | head -c 16)
printf 'Zfs-Pass-1\n%s\n\n' $PIN | as zuser mfa-keyring --module $SOFTHSM --key "$ZKEY" enroll
check "zuser enrolled" test -f /home/zuser/.local/share/mfa-keyring/login.wrap

printf '%s\n' $PIN | mfa-keyring --module $SOFTHSM --user zuser zfs-enroll
check "zfs-enroll moved the wrap file to /var/lib" grep -q "^zfs $DS\$" /var/lib/mfa-keyring/zuser/login.wrap
check "old wrap file in the home removed" test ! -e /home/zuser/.local/share/mfa-keyring/login.wrap
check "dataset no longer opens with the login password" bash -c "! echo Zfs-Pass-1 | zfs load-key -n $DS 2>/dev/null"
info "load-key -n with a wrong passphrase while loaded: $(echo wrong-pass | zfs load-key -n $DS 2>&1)"

stop_user zuser
zfs unmount $DS; zfs unload-key $DS
check "home unmounted and key unloaded" test "$(keystatus)" = unavailable

# The shipped smartcard stack, with pam_set_items standing in for pam_sss
# forward_pass (the VM has no SSSD smartcard setup).
sed -e "s|pam_sss.so|$SETITEMS|" -e "s|pam_mfa_keyring.so mode=piv|pam_mfa_keyring.so mode=piv module=$SOFTHSM|" \
	/etc/pam.d/gdm-smartcard-sssd-mfa-keyring > /etc/pam.d/mfa-zfs-sc
cat > /etc/pam.d/mfa-zfs-pw <<EOF
@include common-auth
@include common-account
@include common-session
EOF
PAM_AUTHTOK=$PIN pamtester mfa-zfs-sc zuser authenticate open_session
check "smartcard login mounts the encrypted home (secret reaches pam_zfs_key)" test "$(mounted)" = yes
pamtester mfa-zfs-sc zuser close_session
check "logged out: home unmounted and key unloaded" reset_home

PAM_AUTHTOK=000000 pamtester mfa-zfs-sc zuser authenticate open_session 2>/dev/null
check "wrong PIN does not mount the home" test "$(keystatus)" = unavailable
pamtester mfa-zfs-sc zuser close_session 2>/dev/null
reset_home

echo 'Zfs-Pass-1' | pamtester mfa-zfs-pw zuser authenticate open_session
check "password login (common-auth/common-session) mounts the encrypted home" test "$(mounted)" = yes

# Password change while the key is loaded: the case where pam_zfs_key could
# re-key the dataset to the new password.
python3 /root/pw.py zuser Zfs-Pass-1 'Zfs-New-Pass-2x!' || info "passwd returned non-zero"
pamtester mfa-zfs-pw zuser close_session
check "logged out after the password change" reset_home
check "dataset was not re-keyed to the new login password" bash -c "! echo 'Zfs-New-Pass-2x!' | zfs load-key -n $DS 2>/dev/null"
PAM_AUTHTOK=$PIN pamtester mfa-zfs-sc zuser authenticate open_session
check "smartcard login still mounts the home after the password change" test "$(mounted)" = yes
pamtester mfa-zfs-sc zuser close_session
reset_home
echo 'Zfs-New-Pass-2x!' | pamtester mfa-zfs-pw zuser authenticate open_session
check "new password mounts the home" test "$(mounted)" = yes
pamtester mfa-zfs-pw zuser close_session
reset_home

printf '%s\nPlain-Zfs-3\nPlain-Zfs-3\n' $PIN | mfa-keyring --module $SOFTHSM --user zuser zfs-disenroll
check "zfs-disenroll gives the dataset an ordinary passphrase" bash -c "echo Plain-Zfs-3 | zfs load-key -n $DS"
check "zfs-disenroll clears the zfs line" bash -c "! grep -q '^zfs ' /var/lib/mfa-keyring/zuser/login.wrap"
rm -f /etc/pam.d/mfa-zfs-sc /etc/pam.d/mfa-zfs-pw

# ========================================================= removal ===
apt-get remove -y -q libpam-mfa-keyring >/dev/null 2>&1
check "alternative restored on remove" test "$(readlink -f /etc/pam.d/gdm-smartcard)" = "$ALT_BEFORE"
check "common-auth cleaned on remove" bash -c '! grep -q pam_mfa_keyring /etc/pam.d/common-auth'
check "common-password cleaned on remove" bash -c '! grep -q pam_mfa_keyring /etc/pam.d/common-password'
apt-get purge -y -q libpam-mfa-keyring >/dev/null 2>&1
check "conffile removed on purge" test ! -e /etc/pam.d/gdm-smartcard-sssd-mfa-keyring
check "users' wrap files kept on purge" test -f /var/lib/mfa-keyring/zuser/login.wrap
lock tester
echo 'Tr0ub4dor&3-Horse' | XDG_RUNTIME_DIR=/run/user/$(id -u tester) pamtester gdm-password tester authenticate
check "negative control: without the module, login does not unlock the re-keyed keyring" \
	bash -c "$(declare -f as locked); SOFTHSM2_CONF=$SOFTHSM2_CONF; locked tester | grep -q true"
check "password login still works after removal" bash -c "echo 'Tr0ub4dor&3-Horse' | pamtester gdm-password tester authenticate"

if [ $FAILS -gt 0 ]; then
	journalctl --no-pager -o short-monotonic | grep -E 'pam_mfa_keyring|gkr-pam|pam_zfs_key|pamtester|passwd' |
		tail -80 | sed 's/^/VMLOG /'
fi
echo "VMTEST DONE pass=$PASS fail=$FAILS"
