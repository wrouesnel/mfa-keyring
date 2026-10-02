/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "config.h"
#include "fido2.h"

#include <errno.h>

#if HAVE_FIDO2

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <fido.h>

#include "crypt.h"
#include "util.h"

#define MAX_DEVS 8

int pivkr_fido2_supported(void)
{
	return 1;
}

static void notify(const struct pivkr_ui *ui, const char *msg)
{
	if (ui && ui->notify)
		ui->notify(msg, ui->ctx);
}

static char *ask_pin(const struct pivkr_ui *ui, const char *prompt)
{
	return ui && ui->get_pin ? ui->get_pin(prompt, ui->ctx) : NULL;
}

static fido_dev_t *open_dev(const fido_dev_info_t *di)
{
	fido_dev_t *dev = fido_dev_new();

	if (!dev)
		return NULL;
	if (fido_dev_open(dev, fido_dev_info_path(di)) != FIDO_OK || !fido_dev_is_fido2(dev)) {
		fido_dev_close(dev);
		fido_dev_free(&dev);
		return NULL;
	}
	fido_dev_set_timeout(dev, PIVKR_FIDO2_TIMEOUT_MS);
	return dev;
}

static int dev_supports_hmac_secret(fido_dev_t *dev)
{
	fido_cbor_info_t *ci = fido_cbor_info_new();
	int ok = 0;

	if (ci && fido_dev_get_cbor_info(dev, ci) == FIDO_OK) {
		char **ext = fido_cbor_info_extensions_ptr(ci);
		for (size_t i = 0; i < fido_cbor_info_extensions_len(ci); i++)
			if (strcmp(ext[i], "hmac-secret") == 0)
				ok = 1;
	}
	fido_cbor_info_free(&ci);
	return ok;
}

static int get_hmac(fido_dev_t *dev, const char *rpid, const uint8_t *credid,
                    size_t credlen, const uint8_t *salt, int uv, const char *pin,
                    uint8_t out[PIVKR_FIDO2_HMAC_LEN])
{
	fido_assert_t *a = fido_assert_new();
	uint8_t cdh[32];
	int r = -EIO, fr;

	if (!a)
		return -ENOMEM;
	pivkr_random(cdh, sizeof(cdh));
	if (fido_assert_set_clientdata_hash(a, cdh, sizeof(cdh)) != FIDO_OK ||
	    fido_assert_set_rp(a, rpid) != FIDO_OK ||
	    fido_assert_allow_cred(a, credid, credlen) != FIDO_OK ||
	    fido_assert_set_extensions(a, FIDO_EXT_HMAC_SECRET) != FIDO_OK ||
	    fido_assert_set_hmac_salt(a, salt, PIVKR_FIDO2_SALT_LEN) != FIDO_OK ||
	    fido_assert_set_up(a, FIDO_OPT_TRUE) != FIDO_OK)
		goto out;

	/* hmac-secret yields different outputs with and without UV, so the
	 * PIN must be used exactly when it was used at enrolment. */
	fr = fido_dev_get_assert(dev, a, uv ? pin : NULL);
	if (fr == FIDO_ERR_PIN_INVALID || fr == FIDO_ERR_PIN_AUTH_BLOCKED ||
	    fr == FIDO_ERR_PIN_BLOCKED) {
		r = -EACCES;
		goto out;
	}
	if (fr != FIDO_OK) {
		pivkr_log(LOG_ERR, "FIDO2 assertion failed: %s", fido_strerr(fr));
		r = fr == FIDO_ERR_ACTION_TIMEOUT ? -ETIMEDOUT : -EIO;
		goto out;
	}
	if (fido_assert_count(a) != 1 ||
	    fido_assert_hmac_secret_len(a, 0) != PIVKR_FIDO2_HMAC_LEN)
		goto out;
	memcpy(out, fido_assert_hmac_secret_ptr(a, 0), PIVKR_FIDO2_HMAC_LEN);
	r = 0;
out:
	fido_assert_free(&a);
	return r;
}

/* Silent (no user presence) assertion: does this device hold the credential? */
static int has_credential(fido_dev_t *dev, const char *rpid, const uint8_t *credid,
                          size_t credlen)
{
	fido_assert_t *a = fido_assert_new();
	uint8_t cdh[32];
	int fr = FIDO_ERR_INTERNAL;

	if (!a)
		return 0;
	pivkr_random(cdh, sizeof(cdh));
	if (fido_assert_set_clientdata_hash(a, cdh, sizeof(cdh)) == FIDO_OK &&
	    fido_assert_set_rp(a, rpid) == FIDO_OK &&
	    fido_assert_allow_cred(a, credid, credlen) == FIDO_OK &&
	    fido_assert_set_up(a, FIDO_OPT_FALSE) == FIDO_OK)
		fr = fido_dev_get_assert(dev, a, NULL);
	fido_assert_free(&a);
	return fr == FIDO_OK;
}

int pivkr_fido2_hmac(const char *rpid, const uint8_t *credid, size_t credlen,
                     const uint8_t salt[PIVKR_FIDO2_SALT_LEN], int uv,
                     const struct pivkr_ui *ui, uint8_t out[PIVKR_FIDO2_HMAC_LEN])
{
	fido_dev_info_t *devs;
	size_t ndevs = 0;
	int r = -ENODEV;

	fido_init(0);
	devs = fido_dev_info_new(MAX_DEVS);
	if (!devs)
		return -ENOMEM;
	if (fido_dev_info_manifest(devs, MAX_DEVS, &ndevs) != FIDO_OK)
		ndevs = 0;

	for (size_t i = 0; i < ndevs && r == -ENODEV; i++) {
		fido_dev_t *dev = open_dev(fido_dev_info_ptr(devs, i));
		char *pin = NULL;

		if (!dev)
			continue;
		if (has_credential(dev, rpid, credid, credlen)) {
			if (uv) {
				pin = ask_pin(ui, "Security key PIN: ");
				if (!pin)
					r = -ECANCELED;
			}
			if (r != -ECANCELED) {
				notify(ui, "Touch your security key to unlock the keyring.");
				r = get_hmac(dev, rpid, credid, credlen, salt, uv, pin, out);
			}
			pivkr_free_secret_str(pin);
		}
		fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	fido_dev_info_free(&devs, MAX_DEVS);
	return r;
}

int pivkr_fido2_enroll(const char *rpid, int uv, const struct pivkr_ui *ui,
                       uint8_t **credid, size_t *credlen)
{
	fido_dev_info_t *devs;
	fido_dev_t *dev = NULL;
	fido_cred_t *cred = NULL;
	size_t ndevs = 0;
	uint8_t cdh[32], uid[32];
	char *pin = NULL;
	int r = -ENODEV, fr;

	*credid = NULL;
	fido_init(0);
	devs = fido_dev_info_new(MAX_DEVS);
	if (!devs)
		return -ENOMEM;
	if (fido_dev_info_manifest(devs, MAX_DEVS, &ndevs) != FIDO_OK)
		ndevs = 0;
	for (size_t i = 0; i < ndevs && !dev; i++)
		dev = open_dev(fido_dev_info_ptr(devs, i));
	if (!dev)
		goto out;

	if (!dev_supports_hmac_secret(dev)) {
		pivkr_log(LOG_ERR, "security key does not support the hmac-secret extension");
		r = -ENOTSUP;
		goto out;
	}
	if (uv && !fido_dev_has_pin(dev)) {
		pivkr_log(LOG_ERR, "security key has no PIN set; set one first or enrol without --uv");
		r = -EINVAL;
		goto out;
	}
	if (fido_dev_has_pin(dev)) {
		pin = ask_pin(ui, "Security key PIN: ");
		if (!pin) {
			r = -ECANCELED;
			goto out;
		}
	}

	cred = fido_cred_new();
	pivkr_random(cdh, sizeof(cdh));
	pivkr_random(uid, sizeof(uid));
	if (!cred ||
	    fido_cred_set_type(cred, COSE_ES256) != FIDO_OK ||
	    fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh)) != FIDO_OK ||
	    fido_cred_set_rp(cred, rpid, "GNOME keyring unlock") != FIDO_OK ||
	    fido_cred_set_user(cred, uid, sizeof(uid), "keyring", "Login keyring", NULL) != FIDO_OK ||
	    fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET) != FIDO_OK ||
	    fido_cred_set_rk(cred, FIDO_OPT_FALSE) != FIDO_OK) {
		r = -EIO;
		goto out;
	}

	notify(ui, "Touch your security key to create the credential.");
	fr = fido_dev_make_cred(dev, cred, pin);
	if (fr != FIDO_OK) {
		pivkr_log(LOG_ERR, "creating FIDO2 credential failed: %s", fido_strerr(fr));
		r = fr == FIDO_ERR_PIN_INVALID ? -EACCES : -EIO;
		goto out;
	}
	if (fido_cred_id_len(cred) == 0) {
		r = -EIO;
		goto out;
	}

	*credlen = fido_cred_id_len(cred);
	*credid = malloc(*credlen);
	if (!*credid) {
		r = -ENOMEM;
		goto out;
	}
	memcpy(*credid, fido_cred_id_ptr(cred), *credlen);
	r = 0;
out:
	pivkr_free_secret_str(pin);
	fido_cred_free(&cred);
	if (dev) {
		fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	fido_dev_info_free(&devs, MAX_DEVS);
	return r;
}

#else /* !HAVE_FIDO2 */

int pivkr_fido2_supported(void)
{
	return 0;
}

int pivkr_fido2_enroll(const char *rpid, int uv, const struct pivkr_ui *ui,
                       uint8_t **credid, size_t *credlen)
{
	return -ENOTSUP;
}

int pivkr_fido2_hmac(const char *rpid, const uint8_t *credid, size_t credlen,
                     const uint8_t salt[PIVKR_FIDO2_SALT_LEN], int uv,
                     const struct pivkr_ui *ui, uint8_t out[PIVKR_FIDO2_HMAC_LEN])
{
	return -ENOTSUP;
}

#endif
