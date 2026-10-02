/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * pam_mfa_keyring: recover the login secret from a wrap file using a PIV
 * smartcard, a FIDO2 security key or the login password, and hand it on as
 * PAM_AUTHTOK to pam_gnome_keyring (and, for ZFS-enrolled users, pam_zfs_key).
 *
 *   auth     optional pam_mfa_keyring.so mode=piv            (after pam_sss forward_pass)
 *   auth     optional pam_mfa_keyring.so mode=login zfs_only (before pam_zfs_key)
 *   auth     optional pam_mfa_keyring.so mode=login          (last, before pam_gnome_keyring)
 *   password optional pam_mfa_keyring.so                     (before pam_zfs_key)
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
#define MAX_FILES 4
/* Set once PAM_AUTHTOK holds the secret, so later instances leave it alone. */
#define APPLIED_DATA "pam_mfa_keyring:applied"

enum mode { MODE_LOGIN, MODE_PIV };

struct opts {
	enum mode mode;
	const char *files[MAX_FILES];
	int nfiles;
	const char *module;
	const char *only_if;
	const char *skip_if;
	int zfs_only;
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
	memset(o, 0, sizeof(*o));
	o->mode = MODE_LOGIN;
	o->module = DEFAULT_PKCS11_MODULE;
	o->fido2 = 1;

	for (int i = 0; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "mode=piv") == 0)
			o->mode = MODE_PIV;
		else if (strcmp(a, "mode=login") == 0)
			o->mode = MODE_LOGIN;
		else if (strncmp(a, "file=", 5) == 0) {
			if (o->nfiles == MAX_FILES) {
				pam_syslog(pamh, LOG_ERR, "too many file= options");
				return -1;
			}
			o->files[o->nfiles++] = a + 5;
		} else if (strncmp(a, "module=", 7) == 0)
			o->module = a + 7;
		else if (strncmp(a, "only_if=", 8) == 0)
			o->only_if = a + 8;
		else if (strncmp(a, "skip_if=", 8) == 0)
			o->skip_if = a + 8;
		else if (strcmp(a, "zfs_only") == 0)
			o->zfs_only = 1;
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
	if (o->nfiles == 0) {
		o->files[o->nfiles++] = DEFAULT_SYSTEM_WRAP_FILE;
		o->files[o->nfiles++] = DEFAULT_WRAP_FILE;
	}
	return 0;
}

static int in_list(const char *list, const char *item)
{
	size_t len = strlen(item);

	for (const char *p = list; *p;) {
		const char *end = strchrnul(p, ',');
		if ((size_t) (end - p) == len && strncmp(p, item, len) == 0)
			return 1;
		p = *end ? end + 1 : end;
	}
	return 0;
}

static int service_matches(pam_handle_t *pamh, const struct opts *o)
{
	const char *svc = NULL;

	if (!o->only_if && !o->skip_if)
		return 1;
	if (pam_get_item(pamh, PAM_SERVICE, (const void **) &svc) != PAM_SUCCESS || !svc)
		return 0;
	if (o->only_if && !in_list(o->only_if, svc))
		return 0;
	if (o->skip_if && in_list(o->skip_if, svc))
		return 0;
	return 1;
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
	char *home;
	char *path;     /* wrap file in use */
};

static void userinfo_free(struct userinfo *u)
{
	free(u->name);
	free(u->home);
	free(u->path);
	memset(u, 0, sizeof(*u));
}

static int lookup_user(pam_handle_t *pamh, struct userinfo *u)
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
	u->home = strdup(pw.pw_dir);
	u->uid = pw.pw_uid;
	u->gid = pw.pw_gid;
	if (!u->name || !u->home) {
		userinfo_free(u);
		return -1;
	}
	return 0;
}

/*
 * Loads the first wrap file that exists.  0 on success, 1 if the user has
 * none, -1 on error.
 */
static int load_wrapfile(pam_handle_t *pamh, const struct opts *o, struct userinfo *u,
                         struct mfakr_wrapfile *wf)
{
	char *data = NULL, *path = NULL;
	size_t len;
	int r = -ENOENT;

	for (int i = 0; i < o->nfiles && (r == -ENOENT || r == -ENOTDIR); i++) {
		free(path);
		path = mfakr_expand_path(o->files[i], u->name, u->home);
		if (!path) {
			pam_syslog(pamh, LOG_ERR, "invalid file= option: %s", o->files[i]);
			return -1;
		}
		r = mfakr_read_user_file(path, u->uid, u->gid, &data, &len);
	}
	if (r == -ENOENT || r == -ENOTDIR) {
		free(path);
		return 1;
	}
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "cannot read %s: %s", path, strerror(-r));
		free(path);
		return -1;
	}
	r = mfakr_wf_parse(data, len, wf);
	free(data);
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "%s: malformed wrap file", path);
		free(path);
		return -1;
	}
	if (strcmp(wf->user, u->name) != 0) {
		pam_syslog(pamh, LOG_ERR, "%s: wrap file belongs to user %s, not %s",
		           path, wf->user, u->name);
		mfakr_wf_free(wf);
		free(path);
		return -1;
	}
	u->path = path;
	return 0;
}

static int set_secret_item(pam_handle_t *pamh, int item,
                           const uint8_t secret[MFAKR_SECRET_LEN])
{
	char pw[MFAKR_PASSWORD_LEN + 1];
	int r;

	mfakr_secret_to_password(secret, pw);
	r = pam_set_item(pamh, item, pw);
	sodium_memzero(pw, sizeof(pw));
	return r;
}

static int already_applied(pam_handle_t *pamh)
{
	const void *d = NULL;

	return pam_get_data(pamh, APPLIED_DATA, &d) == PAM_SUCCESS && d;
}

static int apply_secret(pam_handle_t *pamh, const uint8_t secret[MFAKR_SECRET_LEN])
{
	if (set_secret_item(pamh, PAM_AUTHTOK, secret) != PAM_SUCCESS)
		return PAM_IGNORE;
	pam_set_data(pamh, APPLIED_DATA, (void *) 1, NULL);
	return PAM_SUCCESS;
}

static int auth_piv(pam_handle_t *pamh, const struct opts *o, const struct userinfo *u,
                    const struct mfakr_wrapfile *wf, const char *authtok)
{
	struct mfakr_ui ui = { ui_get_pin, ui_notify, pamh };
	struct mfakr_p11 p11;
	uint8_t secret[MFAKR_SECRET_LEN];
	char *pin = NULL;
	int r, ret = PAM_IGNORE;

	if (!authtok && o->prompt_pin)
		pin = ui_get_pin("PIN to unlock keyring: ", pamh);
	if (authtok || pin) {
		if (mfakr_p11_open(o->module, &p11) == 0) {
			r = mfakr_open_piv(wf, &p11, authtok ? authtok : pin, &ui, secret);
			mfakr_p11_close(&p11);
		} else {
			r = -EIO;
		}
	} else {
		r = -ENOKEY;
	}
	mfakr_free_secret_str(pin);

	if (r == 0) {
		ret = apply_secret(pamh, secret);
	} else {
		pam_syslog(pamh, LOG_NOTICE, "could not recover the secret with a smartcard "
		           "for %s: %s", u->name, strerror(-r));
		/* Never let the PIN reach pam_gnome_keyring (which would create a new
		 * keyring protected only by the PIN) or pam_zfs_key. */
		if (authtok)
			pam_set_item(pamh, PAM_AUTHTOK, NULL);
	}
	sodium_memzero(secret, sizeof(secret));
	return ret;
}

static int auth_login(pam_handle_t *pamh, const struct opts *o, const struct userinfo *u,
                      const struct mfakr_wrapfile *wf, const char *authtok)
{
	struct mfakr_ui ui = { ui_get_pin, ui_notify, pamh };
	uint8_t secret[MFAKR_SECRET_LEN];
	int r = -ENOKEY, ret = PAM_IGNORE;

	if (authtok && mfakr_wf_count(wf, MFAKR_SLOT_PASSWORD) > 0) {
		r = mfakr_open_password(wf, authtok, secret);
		if (r < 0)
			pam_syslog(pamh, LOG_NOTICE, "password slot did not unlock for %s; "
			           "run 'mfa-keyring set-password'", u->name);
	} else if (!authtok && o->fido2 && mfakr_wf_count(wf, MFAKR_SLOT_FIDO2) > 0) {
		r = mfakr_open_fido2(wf, &ui, secret);
		if (r < 0)
			pam_syslog(pamh, LOG_NOTICE, "could not recover the secret with a security "
			           "key for %s: %s", u->name, strerror(-r));
	}
	if (r == 0)
		ret = apply_secret(pamh, secret);
	sodium_memzero(secret, sizeof(secret));
	return ret;
}

PUBLIC int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct opts o;
	struct userinfo u;
	struct mfakr_wrapfile wf;
	const char *authtok = NULL;
	int r, ret = PAM_IGNORE;

	if (parse_opts(pamh, argc, argv, &o) < 0)
		return PAM_SERVICE_ERR;
	if (!service_matches(pamh, &o))
		return PAM_IGNORE;
	/* An earlier instance already put the secret in PAM_AUTHTOK. */
	if (o.mode == MODE_LOGIN && already_applied(pamh))
		return PAM_IGNORE;
	if (mfakr_crypto_init() < 0)
		return PAM_SYSTEM_ERR;
	mfakr_set_logger(log_cb, pamh);

	if (lookup_user(pamh, &u) < 0) {
		mfakr_set_logger(NULL, NULL);
		return PAM_USER_UNKNOWN;
	}
	pam_get_item(pamh, PAM_AUTHTOK, (const void **) &authtok);

	r = load_wrapfile(pamh, &o, &u, &wf);
	if (r != 0) {
		if (o.debug && r > 0)
			pam_syslog(pamh, LOG_DEBUG, "no wrap file for %s", u.name);
		if (o.mode == MODE_PIV && authtok)
			pam_set_item(pamh, PAM_AUTHTOK, NULL);
		goto out;
	}

	if (o.mode == MODE_PIV)
		ret = auth_piv(pamh, &o, &u, &wf, authtok);
	else if (!o.zfs_only || wf.zfs_dataset)
		ret = auth_login(pamh, &o, &u, &wf, authtok);

	if (ret == PAM_SUCCESS && o.debug)
		pam_syslog(pamh, LOG_DEBUG, "secret recovered for %s from %s", u.name, u.path);
	mfakr_wf_free(&wf);
out:
	userinfo_free(&u);
	mfakr_set_logger(NULL, NULL);
	return ret;
}

PUBLIC int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

/*
 * After pam_unix has changed the password, re-wrap the password slot so that
 * password logins keep working.  For ZFS-enrolled users, then hand the secret
 * on as the new password, so a following pam_zfs_key re-keys the dataset to
 * the secret again instead of to the login password.
 */
PUBLIC int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct opts o;
	struct userinfo u;
	struct mfakr_wrapfile wf;
	uint8_t secret[MFAKR_SECRET_LEN];
	const char *oldtok = NULL, *newtok = NULL;
	char *data = NULL;
	int r, ret = PAM_IGNORE;

	if (!(flags & PAM_UPDATE_AUTHTOK))
		return PAM_IGNORE;
	if (parse_opts(pamh, argc, argv, &o) < 0)
		return PAM_SERVICE_ERR;
	if (!service_matches(pamh, &o))
		return PAM_IGNORE;
	if (mfakr_crypto_init() < 0)
		return PAM_IGNORE;
	mfakr_set_logger(log_cb, pamh);

	if (lookup_user(pamh, &u) < 0) {
		mfakr_set_logger(NULL, NULL);
		return PAM_IGNORE;
	}
	if (load_wrapfile(pamh, &o, &u, &wf) != 0)
		goto out_user;
	if (mfakr_wf_count(&wf, MFAKR_SLOT_PASSWORD) == 0)
		goto out_wf;

	pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &oldtok);
	pam_get_item(pamh, PAM_AUTHTOK, (const void **) &newtok);
	if (!oldtok || !newtok) {
		pam_syslog(pamh, LOG_WARNING, "password for %s changed without the old password; "
		           "password slot is stale until 'mfa-keyring set-password' is run",
		           u.name);
		goto out_wf;
	}

	r = mfakr_open_password(&wf, oldtok, secret);
	if (r < 0) {
		pam_syslog(pamh, LOG_WARNING, "password slot for %s did not match the old "
		           "password; leaving it unchanged", u.name);
		goto out_wf;
	}
	r = mfakr_set_password_slot(&wf, newtok, secret);
	if (r >= 0) {
		data = mfakr_wf_serialize(&wf);
		r = data ? mfakr_write_user_file(u.path, u.uid, u.gid, data, strlen(data)) : -ENOMEM;
		free(data);
	}
	if (r < 0) {
		pam_syslog(pamh, LOG_ERR, "could not update password slot for %s: %s",
		           u.name, strerror(-r));
	} else {
		pam_syslog(pamh, LOG_NOTICE, "updated password slot for %s", u.name);
		ret = PAM_SUCCESS;
		if (wf.zfs_dataset && set_secret_item(pamh, PAM_AUTHTOK, secret) != PAM_SUCCESS)
			pam_syslog(pamh, LOG_ERR, "could not pass the secret on to pam_zfs_key");
	}
	sodium_memzero(secret, sizeof(secret));
out_wf:
	mfakr_wf_free(&wf);
out_user:
	userinfo_free(&u);
	mfakr_set_logger(NULL, NULL);
	return ret;
}
