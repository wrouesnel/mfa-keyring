/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdint.h>

#include "fido2.h"
#include "p11.h"
#include "util.h"
#include "wrapfile.h"

/*
 * Slot types and their fields (the trailing nonce and ciphertext omitted):
 *
 *   piv-ec   <keyid> <ephemeral-point>
 *   piv-rsa  <keyid> <rsa-wrapped-seed>
 *   password argon2id <opslimit> <memlimit> <salt>
 *   fido2    <rpid> <uv:0|1> <credential-id> <hmac-salt>
 */
#define PIVKR_SLOT_PIV_EC "piv-ec"
#define PIVKR_SLOT_PIV_RSA "piv-rsa"
#define PIVKR_SLOT_PASSWORD "password"
#define PIVKR_SLOT_FIDO2 "fido2"

int pivkr_slot_is_piv(const struct pivkr_slot *s);

int pivkr_add_piv_slot(struct pivkr_wrapfile *wf, const struct pivkr_p11_key *k,
                       const uint8_t secret[PIVKR_SECRET_LEN]);
/* Replaces any existing password slot. */
int pivkr_set_password_slot(struct pivkr_wrapfile *wf, const char *password,
                            const uint8_t secret[PIVKR_SECRET_LEN]);
/* Enrols a FIDO2 credential (touches the key) and adds a slot for it. */
int pivkr_add_fido2_slot(struct pivkr_wrapfile *wf, int uv, const struct pivkr_ui *ui,
                         const uint8_t secret[PIVKR_SECRET_LEN]);

int pivkr_open_password(const struct pivkr_wrapfile *wf, const char *password,
                        uint8_t secret[PIVKR_SECRET_LEN]);

/*
 * Tries every PIV slot whose key is on a connected token.  If pin is NULL,
 * asks through ui (once per token).  Stops after the first PIN rejection
 * so a wrong PIN costs at most one retry.  Returns -ENOENT when no enrolled
 * key is present, -EACCES on a wrong PIN.
 */
int pivkr_open_piv(const struct pivkr_wrapfile *wf, struct pivkr_p11 *p11,
                   const char *pin, const struct pivkr_ui *ui,
                   uint8_t secret[PIVKR_SECRET_LEN]);

/* Returns -ENOENT when no fido2 slot exists or no device holds the credential. */
int pivkr_open_fido2(const struct pivkr_wrapfile *wf, const struct pivkr_ui *ui,
                     uint8_t secret[PIVKR_SECRET_LEN]);

/* Index of the PIV slot for a card key, or -1. */
int pivkr_slot_find_keyid(const struct pivkr_wrapfile *wf, const char *keyid);
