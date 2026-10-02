/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define MFAKR_FIDO2_RPID "mfa-keyring"
#define MFAKR_FIDO2_SALT_LEN 32
#define MFAKR_FIDO2_HMAC_LEN 32
#define MFAKR_FIDO2_TIMEOUT_MS 30000

/* Asks the user for a PIN.  Returns a malloc'd string, or NULL to cancel. */
typedef char *(*mfakr_pin_fn)(const char *prompt, void *ctx);
/* Shows an informational message (e.g. "touch your key"). */
typedef void (*mfakr_notify_fn)(const char *msg, void *ctx);

struct mfakr_ui {
	mfakr_pin_fn get_pin;
	mfakr_notify_fn notify;
	void *ctx;
};

int mfakr_fido2_supported(void);

/*
 * Creates a non-resident credential with the hmac-secret extension on the
 * first FIDO2 device found.  uv requires the device PIN on every unlock.
 */
int mfakr_fido2_enroll(const char *rpid, int uv, const struct mfakr_ui *ui,
                       uint8_t **credid, size_t *credlen);

/*
 * Evaluates hmac-secret for credid with salt on whichever connected device
 * holds the credential.  Requires a touch (and the PIN if uv).
 */
int mfakr_fido2_hmac(const char *rpid, const uint8_t *credid, size_t credlen,
                     const uint8_t salt[MFAKR_FIDO2_SALT_LEN], int uv,
                     const struct mfakr_ui *ui, uint8_t out[MFAKR_FIDO2_HMAC_LEN]);
