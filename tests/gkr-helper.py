#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Test helper for the login keyring on a private session bus.

  gkr-helper.py lock
  gkr-helper.py locked            exit 0 if locked, 1 if unlocked
  gkr-helper.py unlock PASSWORD   exit 0 if PASSWORD unlocks the login keyring
"""
import sys

import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

NAME = "org.freedesktop.secrets"
PATH = "/org/freedesktop/secrets"
LOGIN = "/org/freedesktop/secrets/collection/login"
INTERNAL = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"

bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)


def call(path, iface, method, args, ret=None):
    return bus.call_sync(NAME, path, iface, method, args,
                         GLib.VariantType(ret) if ret else None,
                         Gio.DBusCallFlags.NONE, 10000, None)


def main():
    cmd = sys.argv[1]
    if cmd == "lock":
        call(PATH, "org.freedesktop.Secret.Service", "Lock",
             GLib.Variant("(ao)", ([LOGIN],)), "(aoo)")
        return 0
    if cmd == "locked":
        v = call(LOGIN, "org.freedesktop.DBus.Properties", "Get",
                 GLib.Variant("(ss)", ("org.freedesktop.Secret.Collection", "Locked")), "(v)")
        return 0 if v.unpack()[0] else 1
    if cmd == "unlock":
        _, session = call(PATH, "org.freedesktop.Secret.Service", "OpenSession",
                          GLib.Variant("(sv)", ("plain", GLib.Variant("s", ""))),
                          "(vo)").unpack()
        secret = (session, b"", sys.argv[2].encode(), "text/plain")
        try:
            call(PATH, INTERNAL, "UnlockWithMasterPassword",
                 GLib.Variant("(o(oayays))", (LOGIN, secret)))
        except GLib.Error as e:
            print(e.message, file=sys.stderr)
            return 1
        return 0
    return 2


sys.exit(main())
