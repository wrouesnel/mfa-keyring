/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#include "util.h"

#define MFAKR_ARGON2_SALT_LEN 16
#define MFAKR_ARGON2_OPS 3
#define MFAKR_ARGON2_MEM (256UL * 1024 * 1024)
/* Upper bounds accepted from a wrap file, so a crafted file can't exhaust memory. */
#define MFAKR_ARGON2_MAX_OPS 16
#define MFAKR_ARGON2_MAX_MEM (1024UL * 1024 * 1024)

int mfakr_crypto_init(void);
void mfakr_random(uint8_t *buf, size_t len);

/* Seal/open the secret under kek; nonce and ciphertext are base64url. */
int mfakr_aead_seal(const uint8_t kek[MFAKR_KEK_LEN], const char *aad,
                    const uint8_t secret[MFAKR_SECRET_LEN],
                    char **nonce_b64, char **ct_b64);
int mfakr_aead_open(const uint8_t kek[MFAKR_KEK_LEN], const char *aad,
                    const char *nonce_b64, const char *ct_b64,
                    uint8_t secret[MFAKR_SECRET_LEN]);

int mfakr_hkdf(const uint8_t *ikm, size_t ikmlen, const uint8_t *salt,
               size_t saltlen, const char *info, uint8_t out[MFAKR_KEK_LEN]);

int mfakr_argon2id(const char *password, const uint8_t salt[MFAKR_ARGON2_SALT_LEN],
                   unsigned long long ops, size_t mem, uint8_t out[MFAKR_KEK_LEN]);

/* Hex SHA-256 of the DER SubjectPublicKeyInfo: identifies a card key. */
char *mfakr_spki_keyid(EVP_PKEY *pk);

/* EC: ephemeral-static ECDH against the card's public key. */
int mfakr_ec_wrap(EVP_PKEY *card_pub, const char *keyid,
                  uint8_t kek[MFAKR_KEK_LEN], char **eph_b64);
int mfakr_ec_kek(const uint8_t *z, size_t zlen, const uint8_t *eph, size_t ephlen,
                 const char *keyid, uint8_t kek[MFAKR_KEK_LEN]);

/* RSA: random seed encrypted to the card (PKCS#1 v1.5, what PIV cards support). */
int mfakr_rsa_wrap(EVP_PKEY *card_pub, const char *keyid,
                   uint8_t kek[MFAKR_KEK_LEN], char **wrapped_b64);
int mfakr_rsa_kek(const uint8_t *seed, size_t seedlen, const char *keyid,
                  uint8_t kek[MFAKR_KEK_LEN]);

int mfakr_fido2_kek(const uint8_t *hmac_out, size_t len, uint8_t kek[MFAKR_KEK_LEN]);
