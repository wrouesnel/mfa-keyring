/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>

/*
 * Wrap file format (text, one record per line, single-space separated):
 *
 *   piv-keyring-wrap 1 <user>
 *   <type> <field>... <nonce> <ciphertext>
 *   ...
 *
 * Every slot seals the same 32-byte secret with XChaCha20-Poly1305 under a
 * slot-specific key-encryption key.  The last two fields of every slot are
 * always the AEAD nonce and ciphertext; everything before them (plus the
 * header line) is authenticated as associated data.
 */

#define PIVKR_WF_MAGIC "piv-keyring-wrap"
#define PIVKR_WF_VERSION 1
#define PIVKR_MAX_SLOTS 32
#define PIVKR_MAX_FIELDS 12

struct pivkr_slot {
	char *type;
	int nf;
	char *f[PIVKR_MAX_FIELDS];
};

struct pivkr_wrapfile {
	char *user;
	int nslots;
	struct pivkr_slot slots[PIVKR_MAX_SLOTS];
};

int pivkr_wf_init(struct pivkr_wrapfile *wf, const char *user);
int pivkr_wf_parse(const char *data, size_t len, struct pivkr_wrapfile *wf);
char *pivkr_wf_serialize(const struct pivkr_wrapfile *wf);
void pivkr_wf_free(struct pivkr_wrapfile *wf);

/* Copies type and fields.  Returns slot index or negative errno. */
int pivkr_wf_add_slot(struct pivkr_wrapfile *wf, const char *type,
                      int nf, const char *const *fields);
int pivkr_wf_remove_slot(struct pivkr_wrapfile *wf, int idx);
int pivkr_wf_count(const struct pivkr_wrapfile *wf, const char *type);

/* Associated data for a slot's AEAD: header + slot fields minus nonce/ct. */
char *pivkr_wf_slot_aad(const char *user, const char *type, int nf, const char *const *fields);

int pivkr_wf_valid_token(const char *s);
