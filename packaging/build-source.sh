#!/bin/bash
# Source uploads for Launchpad: one orig tarball from git (without debian/),
# then a source package per Ubuntu series, versioned <upstream>-<rev>~<series>1
# so each series gets its own build of the same code.
#   packaging/build-source.sh [-k KEYID] [-r REF] OUTDIR [SERIES...]
# Without -k the packages are left unsigned (to check them locally).
# SIGN_COMMAND, if set, replaces gpg for signing (e.g. a wrapper that supplies
# the passphrase non-interactively).
# REF (default HEAD) is the commit or tag to package.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=mfa-keyring
KEY='' REF=HEAD
while getopts k:r: o; do
	case $o in
	k) KEY=$OPTARG ;;
	r) REF=$OPTARG ;;
	*) exit 2 ;;
	esac
done
shift $((OPTIND - 1))
[ $# -gt 0 ] || { echo "usage: $0 [-k KEYID] [-r REF] OUTDIR [SERIES...]" >&2; exit 2; }
mkdir -p "$1"
OUT=$(cd "$1" && pwd)
shift
[ $# -gt 0 ] || set -- noble resolute

CHANGELOG=$(git -C "$ROOT" show "$REF:debian/changelog")
VERSION=$(dpkg-parsechangelog -l- -S Version <<<"$CHANGELOG")
UPVER=${VERSION%-*} REV=${VERSION##*-}
MESONVER=$(git -C "$ROOT" show "$REF:meson.build" | sed -n "s/^  version : '\(.*\)',/\1/p")
[ "$MESONVER" = "$UPVER" ] ||
	{ echo "meson.build says $MESONVER but debian/changelog $UPVER" >&2; exit 1; }

# The same orig tarball for every series (Launchpad insists on that).
ORIG=$OUT/${NAME}_$UPVER.orig.tar.gz
git -C "$ROOT" archive --format=tar --prefix="$NAME-$UPVER/" "$REF" -- . ':(exclude)debian' |
	gzip -n9 >"$ORIG"

export DEBFULLNAME DEBEMAIL
DEBFULLNAME=$(sed -n 's/^Maintainer: \(.*\) <.*/\1/p' "$ROOT/debian/control")
DEBEMAIL=$(sed -n 's/^Maintainer: .*<\(.*\)>/\1/p' "$ROOT/debian/control")
sign=(-us -uc)
[ -n "$KEY" ] && sign=("--sign-key=$KEY")
[ -n "$KEY" ] && [ -n "${SIGN_COMMAND:-}" ] && sign+=("--sign-command=$SIGN_COMMAND")

for series; do
	work=$(mktemp -d)
	tar -xzf "$ORIG" -C "$work"
	git -C "$ROOT" archive --format=tar "$REF" debian | tar -x -C "$work/$NAME-$UPVER"
	cp "$ORIG" "$work/"
	(
		cd "$work/$NAME-$UPVER"
		# ~ sorts below the plain version on purpose (-b allows it).
		dch -b --newversion "$UPVER-$REV~${series}1" --distribution "$series" \
			--force-distribution "Build for $series." >/dev/null
		# -d: the build dependencies are Launchpad's business.
		dpkg-buildpackage -S -sa -d "${sign[@]}" >/dev/null
	)
	mv "$work"/*.dsc "$work"/*.debian.tar.* "$work"/*_source.changes \
		"$work"/*_source.buildinfo "$OUT/"
	rm -rf "$work"
	echo "$OUT/${NAME}_$UPVER-$REV~${series}1_source.changes"
done
