/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <p11-kit/pkcs11.h>

struct pivkr_p11 {
	void *dl;
	CK_FUNCTION_LIST_PTR f;
	int finalize;
};

struct pivkr_p11_key {
	CK_SLOT_ID slot;
	uint8_t id[64];
	size_t idlen;
	char label[128];
	char token[33];
	char *keyid;           /* hex SHA-256 of SPKI */
	EVP_PKEY *pub;
	int is_ec;
};

int pivkr_p11_open(const char *module, struct pivkr_p11 *p);
void pivkr_p11_close(struct pivkr_p11 *p);

/* Lists keys whose public half is visible without login (certs or public keys). */
int pivkr_p11_list_keys(struct pivkr_p11 *p, struct pivkr_p11_key **keys, int *n);
void pivkr_p11_keys_free(struct pivkr_p11_key *keys, int n);

/*
 * Opens a session on slot and logs in with pin (NULL for a protected
 * authentication path).  Refuses to try the PIN when the token reports the
 * PIN is locked or on its final try, so a wrong PIN can never lock the card.
 * Returns -EACCES if the PIN was rejected, -ENOLCK if the PIN is locked or
 * at its final try.
 */
int pivkr_p11_login(struct pivkr_p11 *p, CK_SLOT_ID slot, const char *pin,
                    CK_SESSION_HANDLE *sess);
void pivkr_p11_logout(struct pivkr_p11 *p, CK_SESSION_HANDLE sess);

/* Whether the token in slot wants its PIN entered on a PIN pad. */
int pivkr_p11_protected_auth(struct pivkr_p11 *p, CK_SLOT_ID slot);

int pivkr_p11_ecdh(struct pivkr_p11 *p, CK_SESSION_HANDLE sess,
                   const uint8_t *id, size_t idlen,
                   const uint8_t *peer, size_t peerlen,
                   uint8_t *z, size_t *zlen);
int pivkr_p11_rsa_decrypt(struct pivkr_p11 *p, CK_SESSION_HANDLE sess,
                          const uint8_t *id, size_t idlen,
                          const uint8_t *in, size_t inlen,
                          uint8_t *out, size_t *outlen);
