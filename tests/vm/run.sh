#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Install-and-login test of the built .debs in a throwaway Ubuntu VM
# (libvirt qemu:///session, user-mode networking, no root needed).
#
#   tests/vm/run.sh DEB_DIR [CLOUD_IMAGE]
#
# CLOUD_IMAGE defaults to noble-server-cloudimg-amd64.img in the current
# directory.  Prints the VMTEST lines and exits non-zero on any failure.
set -euo pipefail

DEBS=$(realpath "$1")
IMAGE=$(realpath "${2:-noble-server-cloudimg-amd64.img}")
HERE=$(dirname "$(realpath "$0")")
NAME=mfakr-vmtest-$$
VIRSH="virsh -c qemu:///session"
W=$(mktemp -d)
trap '$VIRSH destroy $NAME >/dev/null 2>&1 || true; $VIRSH undefine $NAME >/dev/null 2>&1 || true; rm -rf "$W"' EXIT

mkdir "$W/payload"
cp "$DEBS"/libpam-mfa-keyring_*.deb "$DEBS"/mfa-keyring_*.deb "$HERE/vmtest.sh" "$W/payload/"
cp "$HERE/user-data" "$W/user-data"
printf 'instance-id: %s\nlocal-hostname: mfakr-test\n' "$NAME" > "$W/meta-data"
cloud-localds "$W/seed.iso" "$W/user-data" "$W/meta-data"
genisoimage -quiet -V PIVTEST -r -J -o "$W/payload.iso" "$W/payload"
qemu-img create -q -f qcow2 -F qcow2 -b "$IMAGE" "$W/disk.qcow2" 12G

virt-install --connect qemu:///session --name "$NAME" --memory 2048 --vcpus 2 \
	--osinfo ubuntu24.04 --import \
	--disk path="$W/disk.qcow2",format=qcow2,bus=virtio \
	--disk path="$W/seed.iso",device=cdrom --disk path="$W/payload.iso",device=cdrom \
	--network user,model=virtio --graphics none \
	--serial file,path="$W/console.log" --noautoconsole >/dev/null

deadline=$((SECONDS + 1200))
until grep -aq "VMTEST DONE" "$W/console.log" 2>/dev/null; do
	$VIRSH domstate "$NAME" 2>/dev/null | grep -q running || break
	[ $SECONDS -lt $deadline ] || { echo "timed out"; exit 1; }
	sleep 5
done
grep -a "VMTEST" "$W/console.log" | sed 's/^\[ *[0-9.]*\] cloud-init\[[0-9]*\]: //' | grep -a '^VMTEST'
grep -aq "VMTEST DONE pass=[0-9]* fail=0" "$W/console.log"
