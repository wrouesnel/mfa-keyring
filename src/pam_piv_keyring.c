/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * pam_piv_keyring: recover the GNOME login keyring password from a wrap file
 * using a PIV smartcard, FIDO2 security key or the login password, and hand it
 * to pam_gnome_keyring as PAM_AUTHTOK.
 *
 *   auth     optional pam_piv_keyring.so mode=piv       (after pam_sss forward_pass)
 *   auth     optional pam_piv_keyring.so mode=login     (after pam_unix / pam_u2f)
 *   password optional pam_piv_keyring.so                (re-wraps the password slot)
 *
 * The module must run before pam_gnome_keyring in the auth stack.
 */
#include "config.h"

#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sodium.h>

#include "crypt.h"
#include "fido2.h"
#include "p11.h"
#include "slots.h"
#include "util.h"
#include "wrapfile.h"

#define PUBLIC __attribute__((visibility("default")))

enum mode { MODE_LOGIN, MODE_PIV };

struct opts {
	enum mode mode;
	const char *file;
	const char *module;
	const char *only_if;
	int prompt_pin;
	int fido2;
	int debug;
};

static void log_cb(int prio, const char *msg, void *ctx)
{
	pam_syslog((pam_handle_t *) ctx, prio, "%s", msg);
}

static int parse_opts(pam_handle_t *pamh, int argc, const char **argv, struct opts *o)
{
	o->mode = MODE_LOGIN;
	o->file = DEFAULT_WRAP_FILE;
	o->module = DEFAULT_PKCS11_MODULE;
	o->only_if = NULL;
	o->prompt_pin = 0;
	o->fido2 = 1;
	o->debug = 0;

	for (int i = 0; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "mode=piv") == 0)
			o->mode = MODE_PIV;
		else if (strcmp(a, "mode=login") == 0)
			o->mode = MODE_LOGIN;
		else if (strncmp(a, "file=", 5) == 0)
			o->file = a + 5;
		else if (strncmp(a, "module=", 7) == 0)
			o->module = a + 7;
		else if (strncmp(a, "only_if=", 8) == 0)
			o->only_if = a + 8;
		else if (strcmp(a, "prompt_pin") == 0)
			o->prompt_pin = 1;
		else if (strcmp(a, "nofido2") == 0)
			o->fido2 = 0;
		else if (strcmp(a, "debug") == 0)
			o->debug = 1;
		else {
			pam_syslog(pamh, LOG_ERR, "unknown option: %s", a);
			return -1;
		}
	}
	return 0;
}

static int service_matches(pam_handle_t *pamh, const char *only_if)
{
	const char *svc = NULL;
	size_t len;

	if (!only_if)
		return 1;
	if (pam_get_item(pamh, PAM_SERVICE, (const void **) &svc) != PAM_SUCCESS || !svc)
		return 0;
	len = strlen(svc);
	for (const char *p = only_if; *p;) {
		const char *end = strchrnul(p, ',');
		if ((size_t) (end - p) == len && strncmp(p, svc, len) == 0)
			return 1;
		p = *end ? end + 1 : end;
	}
	return 0;
}

static char *ui_get_pin(const char *prompt, void *ctx)
{
	char *resp = NULL;

	if (pam_prompt((pam_handle_t *) ctx, PAM_PROMPT_ECHO_OFF, &resp, "%s", prompt) != PAM_SUCCESS)
		return NULL;
	if (resp && !*resp) {
		free(resp);
		return NULL;
	}
	return resp;
}

static void ui_notify(const char *msg, void *ctx)
{
	pam_info((pam_handle_t *) ctx, "%s", msg);
}

struct userinfo {
	char *name;
	uid_t uid;
	gid_t gid;
	char *path;
};

static void userinfo_free(struct userinfo *u)
{
	free(u->name);
	free(u->path);
	memset(u, 0, sizeof(*u));
}

static int lookup_user(pam_handle_t *pamh, const struct opts *o, struct userinfo *u)
{
	const char *user = NULL;
	struct passwd pw, *res = NULL;
	char buf[4096];

	memset(u, 0, sizeof(*u));
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !*user)
		return -1;
	if (getpwnam_r(user, &pw, buf, sizeof(buf), &res) != 0 || !res)
		return -1;
	u->name = strdup(pw.pw_name);
	u->uid = pw.pw_uid;
	u->gid = pw.pw_gid;
	u->path = pivkr_expand_path(o->file, pw.pw_name, pw.pw_dir);
	if (!u->name || !u->path) {
		userinfo_free(u);
		return -1;
	}
	return 0;
}

/* 0 on success, 1 if the user has no wrap file, -1 on error. */
static int load_wrapfile(pam_handle_t *pamh, const struct userinfo *u,
                         struct pivkr_wrapfile *wf)
{
	char *data = NULL;
	size_t len;
	int r;

	r = pivkr_read_user_file(u->path, u->uid, u->gid, &data, &len);
	if (r == -ENOENT || r == -ENOTDIR)
		return 1;
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "cannot read %s: %s", u->path, strerror(-r));
		return -1;
	}
	r = pivkr_wf_parse(data, len, wf);
	free(data);
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "%s: malformed wrap file", u->path);
		return -1;
	}
	if (strcmp(wf->user, u->name) != 0) {
		pam_syslog(pamh, LOG_ERR, "%s: wrap file belongs to user %s, not %s",
		           u->path, wf->user, u->name);
		pivkr_wf_free(wf);
		return -1;
	}
	return 0;
}

static int set_keyring_authtok(pam_handle_t *pamh, const uint8_t secret[PIVKR_SECRET_LEN])
{
	char pw[PIVKR_PASSWORD_LEN + 1];
	int r;

	pivkr_secret_to_password(secret, pw);
	r = pam_set_item(pamh, PAM_AUTHTOK, pw);
	sodium_memzero(pw, sizeof(pw));
	return r;
}

PUBLIC int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct opts o;
	struct userinfo u;
	struct pivkr_wrapfile wf;
	struct pivkr_ui ui = { ui_get_pin, ui_notify, pamh };
	uint8_t secret[PIVKR_SECRET_LEN];
	const char *authtok = NULL;
	int r, ret = PAM_IGNORE;

	if (parse_opts(pamh, argc, argv, &o) < 0)
		return PAM_SERVICE_ERR;
	if (!service_matches(pamh, o.only_if))
		return PAM_IGNORE;
	if (pivkr_crypto_init() < 0)
		return PAM_SYSTEM_ERR;
	pivkr_set_logger(log_cb, pamh);

	if (lookup_user(pamh, &o, &u) < 0) {
		pivkr_set_logger(NULL, NULL);
		return PAM_USER_UNKNOWN;
	}
	pam_get_item(pamh, PAM_AUTHTOK, (const void **) &authtok);

	r = load_wrapfile(pamh, &u, &wf);
	if (r != 0) {
		if (o.debug && r > 0)
			pam_syslog(pamh, LOG_DEBUG, "no wrap file at %s", u.path);
		/* Never let a PIN reach pam_gnome_keyring, which would create a
		 * new login keyring protected only by the PIN. */
		if (o.mode == MODE_PIV && authtok)
			pam_set_item(pamh, PAM_AUTHTOK, NULL);
		goto out_user;
	}

	if (o.mode == MODE_PIV) {
		struct pivkr_p11 p11;
		char *pin = NULL;

		if (!authtok && o.prompt_pin)
			pin = ui_get_pin("PIN to unlock keyring: ", pamh);
		if (authtok || pin) {
			if (pivkr_p11_open(o.module, &p11) == 0) {
				r = pivkr_open_piv(&wf, &p11, authtok ? authtok : pin, &ui, secret);
				pivkr_p11_close(&p11);
			} else {
				r = -EIO;
			}
		} else {
			r = -ENOKEY;
		}
		pivkr_free_secret_str(pin);

		if (r == 0) {
			ret = set_keyring_authtok(pamh, secret) == PAM_SUCCESS ? PAM_SUCCESS : PAM_IGNORE;
		} else {
			pam_syslog(pamh, LOG_NOTICE, "could not unlock keyring secret with smartcard "
			           "for %s: %s", u.name, strerror(-r));
			if (authtok)
				pam_set_item(pamh, PAM_AUTHTOK, NULL);
		}
	} else {
		r = -ENOKEY;
		if (authtok && pivkr_wf_count(&wf, PIVKR_SLOT_PASSWORD) > 0) {
			r = pivkr_open_password(&wf, authtok, secret);
			if (r < 0)
				pam_syslog(pamh, LOG_NOTICE, "password slot did not unlock for %s; "
				           "run 'piv-keyring set-password'", u.name);
		} else if (!authtok && o.fido2 && pivkr_wf_count(&wf, PIVKR_SLOT_FIDO2) > 0) {
			r = pivkr_open_fido2(&wf, &ui, secret);
			if (r < 0)
				pam_syslog(pamh, LOG_NOTICE, "could not unlock keyring secret with "
				           "security key for %s: %s", u.name, strerror(-r));
		}
		if (r == 0)
			ret = set_keyring_authtok(pamh, secret) == PAM_SUCCESS ? PAM_SUCCESS : PAM_IGNORE;
	}

	if (ret == PAM_SUCCESS && o.debug)
		pam_syslog(pamh, LOG_DEBUG, "keyring secret recovered for %s", u.name);
	sodium_memzero(secret, sizeof(secret));
	pivkr_wf_free(&wf);
out_user:
	userinfo_free(&u);
	pivkr_set_logger(NULL, NULL);
	return ret;
}

PUBLIC int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

/*
 * After pam_unix has changed the password, re-wrap the password slot so that
 * password logins keep unlocking the keyring.
 */
PUBLIC int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct opts o;
	struct userinfo u;
	struct pivkr_wrapfile wf;
	uint8_t secret[PIVKR_SECRET_LEN];
	const char *oldtok = NULL, *newtok = NULL;
	char *data = NULL;
	int r, ret = PAM_IGNORE;

	if (!(flags & PAM_UPDATE_AUTHTOK))
		return PAM_IGNORE;
	if (parse_opts(pamh, argc, argv, &o) < 0)
		return PAM_SERVICE_ERR;
	if (!service_matches(pamh, o.only_if))
		return PAM_IGNORE;
	if (pivkr_crypto_init() < 0)
		return PAM_IGNORE;
	pivkr_set_logger(log_cb, pamh);

	if (lookup_user(pamh, &o, &u) < 0) {
		pivkr_set_logger(NULL, NULL);
		return PAM_IGNORE;
	}
	if (load_wrapfile(pamh, &u, &wf) != 0)
		goto out_user;
	if (pivkr_wf_count(&wf, PIVKR_SLOT_PASSWORD) == 0)
		goto out_wf;

	pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &oldtok);
	pam_get_item(pamh, PAM_AUTHTOK, (const void **) &newtok);
	if (!oldtok || !newtok) {
		pam_syslog(pamh, LOG_WARNING, "password for %s changed without the old password; "
		           "keyring password slot is stale until 'piv-keyring set-password' is run",
		           u.name);
		goto out_wf;
	}

	r = pivkr_open_password(&wf, oldtok, secret);
	if (r < 0) {
		pam_syslog(pamh, LOG_WARNING, "keyring password slot for %s did not match the old "
		           "password; leaving it unchanged", u.name);
		goto out_wf;
	}
	r = pivkr_set_password_slot(&wf, newtok, secret);
	sodium_memzero(secret, sizeof(secret));
	if (r >= 0) {
		data = pivkr_wf_serialize(&wf);
		r = data ? pivkr_write_user_file(u.path, u.uid, u.gid, data, strlen(data)) : -ENOMEM;
		free(data);
	}
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "could not update keyring password slot for %s: %s",
		           u.name, strerror(-r));
	} else {
		pam_syslog(pamh, LOG_NOTICE, "updated keyring password slot for %s", u.name);
		ret = PAM_SUCCESS;
	}
out_wf:
	pivkr_wf_free(&wf);
out_user:
	userinfo_free(&u);
	pivkr_set_logger(NULL, NULL);
	return ret;
}
