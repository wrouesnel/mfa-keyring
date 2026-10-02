/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>

/*
 * Wrap file format (text, one record per line, single-space separated):
 *
 *   mfa-keyring-wrap 1 <user>
 *   <type> <field>... <nonce> <ciphertext>
 *   ...
 *
 * Every slot seals the same 32-byte secret with XChaCha20-Poly1305 under a
 * slot-specific key-encryption key.  The last two fields of every slot are
 * always the AEAD nonce and ciphertext; everything before them (plus the
 * header line) is authenticated as associated data.
 */

#define MFAKR_WF_MAGIC "mfa-keyring-wrap"
#define MFAKR_WF_VERSION 1
#define MFAKR_MAX_SLOTS 32
#define MFAKR_MAX_FIELDS 12

struct mfakr_slot {
	char *type;
	int nf;
	char *f[MFAKR_MAX_FIELDS];
};

struct mfakr_wrapfile {
	char *user;
	int nslots;
	struct mfakr_slot slots[MFAKR_MAX_SLOTS];
};

int mfakr_wf_init(struct mfakr_wrapfile *wf, const char *user);
int mfakr_wf_parse(const char *data, size_t len, struct mfakr_wrapfile *wf);
char *mfakr_wf_serialize(const struct mfakr_wrapfile *wf);
void mfakr_wf_free(struct mfakr_wrapfile *wf);

/* Copies type and fields.  Returns slot index or negative errno. */
int mfakr_wf_add_slot(struct mfakr_wrapfile *wf, const char *type,
                      int nf, const char *const *fields);
int mfakr_wf_remove_slot(struct mfakr_wrapfile *wf, int idx);
int mfakr_wf_count(const struct mfakr_wrapfile *wf, const char *type);

/* Associated data for a slot's AEAD: header + slot fields minus nonce/ct. */
char *mfakr_wf_slot_aad(const char *user, const char *type, int nf, const char *const *fields);

int mfakr_wf_valid_token(const char *s);
