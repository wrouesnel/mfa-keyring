/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <p11-kit/pkcs11.h>

struct mfakr_p11 {
	void *dl;
	CK_FUNCTION_LIST_PTR f;
	int finalize;
};

struct mfakr_p11_key {
	CK_SLOT_ID slot;
	uint8_t id[64];
	size_t idlen;
	char label[128];
	char token[33];
	char *keyid;           /* hex SHA-256 of SPKI */
	EVP_PKEY *pub;
	int is_ec;
};

int mfakr_p11_open(const char *module, struct mfakr_p11 *p);
void mfakr_p11_close(struct mfakr_p11 *p);

/* Lists keys whose public half is visible without login (certs or public keys). */
int mfakr_p11_list_keys(struct mfakr_p11 *p, struct mfakr_p11_key **keys, int *n);
void mfakr_p11_keys_free(struct mfakr_p11_key *keys, int n);

/*
 * Opens a session on slot and logs in with pin (NULL for a protected
 * authentication path).  Refuses to try the PIN when the token reports the
 * PIN is locked or on its final try, so a wrong PIN can never lock the card.
 * Returns -EACCES if the PIN was rejected, -ENOLCK if the PIN is locked or
 * at its final try.
 */
int mfakr_p11_login(struct mfakr_p11 *p, CK_SLOT_ID slot, const char *pin,
                    CK_SESSION_HANDLE *sess);
void mfakr_p11_logout(struct mfakr_p11 *p, CK_SESSION_HANDLE sess);

/* Whether the token in slot wants its PIN entered on a PIN pad. */
int mfakr_p11_protected_auth(struct mfakr_p11 *p, CK_SLOT_ID slot);

int mfakr_p11_ecdh(struct mfakr_p11 *p, CK_SESSION_HANDLE sess,
                   const uint8_t *id, size_t idlen,
                   const uint8_t *peer, size_t peerlen,
                   uint8_t *z, size_t *zlen);
int mfakr_p11_rsa_decrypt(struct mfakr_p11 *p, CK_SESSION_HANDLE sess,
                          const uint8_t *id, size_t idlen,
                          const uint8_t *in, size_t inlen,
                          uint8_t *out, size_t *outlen);
