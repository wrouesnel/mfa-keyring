/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "gkr.h"

#include <string.h>

#include <gio/gio.h>

#define SECRETS_NAME "org.freedesktop.secrets"
#define SECRETS_PATH "/org/freedesktop/secrets"
#define SERVICE_IFACE "org.freedesktop.Secret.Service"
#define INTERNAL_IFACE "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
#define LOGIN_COLLECTION "/org/freedesktop/secrets/collection/login"
#define TIMEOUT_MS 30000

static int fail(char **err, GError *e, const char *what)
{
	*err = g_strdup_printf("%s: %s", what, e ? e->message : "unknown error");
	g_clear_error(&e);
	return -1;
}

/*
 * The "plain" algorithm sends the secret unencrypted over the session bus,
 * which is only reachable by this user.  It's what gnome-keyring's own
 * tools use for these internal calls.
 */
static char *open_session(GDBusConnection *bus, GError **e)
{
	GVariant *ret;
	char *path = NULL;

	ret = g_dbus_connection_call_sync(bus, SECRETS_NAME, SECRETS_PATH, SERVICE_IFACE,
	                                  "OpenSession",
	                                  g_variant_new("(sv)", "plain", g_variant_new_string("")),
	                                  G_VARIANT_TYPE("(vo)"), G_DBUS_CALL_FLAGS_NONE,
	                                  TIMEOUT_MS, NULL, e);
	if (!ret)
		return NULL;
	g_variant_get(ret, "(vo)", NULL, &path);
	g_variant_unref(ret);
	return path;
}

static void close_session(GDBusConnection *bus, const char *session)
{
	GVariant *ret = g_dbus_connection_call_sync(bus, SECRETS_NAME, session,
	                                            "org.freedesktop.Secret.Session", "Close",
	                                            NULL, NULL, G_DBUS_CALL_FLAGS_NONE,
	                                            TIMEOUT_MS, NULL, NULL);
	if (ret)
		g_variant_unref(ret);
}

static GVariant *secret_variant(const char *session, const char *password)
{
	GVariant *params = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, "", 0, 1);
	GVariant *val = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, password,
	                                          strlen(password), 1);

	return g_variant_new("(o@ay@ays)", session, params, val, "text/plain");
}

static GDBusConnection *get_bus(char **err)
{
	GError *e = NULL;
	GDBusConnection *bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &e);

	if (!bus)
		fail(err, e, "cannot connect to session bus");
	return bus;
}

/* Calls method on the login collection with one (unlock) or two (change) secrets. */
static int call_internal(const char *method, const char *pw1, const char *pw2, char **err)
{
	GDBusConnection *bus;
	GError *e = NULL;
	GVariant *args, *ret;
	char *session;
	int r = 0;

	*err = NULL;
	bus = get_bus(err);
	if (!bus)
		return -1;
	session = open_session(bus, &e);
	if (!session) {
		r = fail(err, e, "cannot open secret service session (is gnome-keyring running?)");
		goto out;
	}

	if (pw2)
		args = g_variant_new("(o@(oayays)@(oayays))", LOGIN_COLLECTION,
		                     secret_variant(session, pw1), secret_variant(session, pw2));
	else
		args = g_variant_new("(o@(oayays))", LOGIN_COLLECTION, secret_variant(session, pw1));
	ret = g_dbus_connection_call_sync(bus, SECRETS_NAME, SECRETS_PATH, INTERNAL_IFACE,
	                                  method, args, NULL, G_DBUS_CALL_FLAGS_NONE,
	                                  TIMEOUT_MS, NULL, &e);
	if (!ret)
		r = fail(err, e, method);
	else
		g_variant_unref(ret);
	close_session(bus, session);
	g_free(session);
out:
	g_object_unref(bus);
	return r;
}

int pivkr_gkr_change_password(const char *oldpw, const char *newpw, char **err)
{
	return call_internal("ChangeWithMasterPassword", oldpw, newpw, err);
}

int pivkr_gkr_unlock(const char *password, char **err)
{
	return call_internal("UnlockWithMasterPassword", password, NULL, err);
}

int pivkr_gkr_is_locked(char **err)
{
	GDBusConnection *bus;
	GError *e = NULL;
	GVariant *ret, *v;
	int locked;

	*err = NULL;
	bus = get_bus(err);
	if (!bus)
		return -1;
	ret = g_dbus_connection_call_sync(bus, SECRETS_NAME, LOGIN_COLLECTION,
	                                  "org.freedesktop.DBus.Properties", "Get",
	                                  g_variant_new("(ss)", "org.freedesktop.Secret.Collection",
	                                                "Locked"),
	                                  G_VARIANT_TYPE("(v)"), G_DBUS_CALL_FLAGS_NONE,
	                                  TIMEOUT_MS, NULL, &e);
	g_object_unref(bus);
	if (!ret)
		return fail(err, e, "cannot query login keyring");
	g_variant_get(ret, "(v)", &v);
	locked = g_variant_get_boolean(v);
	g_variant_unref(v);
	g_variant_unref(ret);
	return locked;
}
