/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "crypt.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <sodium.h>

#define AEAD_NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define AEAD_TAG_LEN crypto_aead_xchacha20poly1305_ietf_ABYTES
#define RSA_SEED_LEN 32

int mfakr_crypto_init(void)
{
	return sodium_init() < 0 ? -EIO : 0;
}

void mfakr_random(uint8_t *buf, size_t len)
{
	randombytes_buf(buf, len);
}

int mfakr_aead_seal(const uint8_t kek[MFAKR_KEK_LEN], const char *aad,
                    const uint8_t secret[MFAKR_SECRET_LEN],
                    char **nonce_b64, char **ct_b64)
{
	uint8_t nonce[AEAD_NONCE_LEN];
	uint8_t ct[MFAKR_SECRET_LEN + AEAD_TAG_LEN];
	unsigned long long ctlen;

	randombytes_buf(nonce, sizeof(nonce));
	crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &ctlen, secret, MFAKR_SECRET_LEN,
	                                           (const uint8_t *) aad, strlen(aad),
	                                           NULL, nonce, kek);
	*nonce_b64 = mfakr_b64enc(nonce, sizeof(nonce));
	*ct_b64 = mfakr_b64enc(ct, ctlen);
	if (!*nonce_b64 || !*ct_b64) {
		free(*nonce_b64);
		free(*ct_b64);
		return -ENOMEM;
	}
	return 0;
}

int mfakr_aead_open(const uint8_t kek[MFAKR_KEK_LEN], const char *aad,
                    const char *nonce_b64, const char *ct_b64,
                    uint8_t secret[MFAKR_SECRET_LEN])
{
	uint8_t nonce[AEAD_NONCE_LEN];
	uint8_t ct[MFAKR_SECRET_LEN + AEAD_TAG_LEN];
	size_t nlen, clen;
	unsigned long long mlen;

	if (mfakr_b64dec(nonce_b64, nonce, sizeof(nonce), &nlen) < 0 || nlen != sizeof(nonce))
		return -EINVAL;
	if (mfakr_b64dec(ct_b64, ct, sizeof(ct), &clen) < 0 || clen != sizeof(ct))
		return -EINVAL;
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(secret, &mlen, NULL, ct, clen,
	                                               (const uint8_t *) aad, strlen(aad),
	                                               nonce, kek) != 0 ||
	    mlen != MFAKR_SECRET_LEN) {
		sodium_memzero(secret, MFAKR_SECRET_LEN);
		return -EBADMSG;
	}
	return 0;
}

int mfakr_hkdf(const uint8_t *ikm, size_t ikmlen, const uint8_t *salt,
               size_t saltlen, const char *info, uint8_t out[MFAKR_KEK_LEN])
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	size_t outlen = MFAKR_KEK_LEN;
	int ok;

	if (!ctx)
		return -ENOMEM;
	ok = EVP_PKEY_derive_init(ctx) > 0 &&
	     EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
	     EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, ikmlen) > 0 &&
	     (saltlen == 0 || EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, saltlen) > 0) &&
	     EVP_PKEY_CTX_add1_hkdf_info(ctx, (const uint8_t *) info, strlen(info)) > 0 &&
	     EVP_PKEY_derive(ctx, out, &outlen) > 0 && outlen == MFAKR_KEK_LEN;
	EVP_PKEY_CTX_free(ctx);
	return ok ? 0 : -EIO;
}

int mfakr_argon2id(const char *password, const uint8_t salt[MFAKR_ARGON2_SALT_LEN],
                   unsigned long long ops, size_t mem, uint8_t out[MFAKR_KEK_LEN])
{
	if (ops < crypto_pwhash_OPSLIMIT_MIN || ops > MFAKR_ARGON2_MAX_OPS ||
	    mem < crypto_pwhash_MEMLIMIT_MIN || mem > MFAKR_ARGON2_MAX_MEM)
		return -EINVAL;
	if (crypto_pwhash(out, MFAKR_KEK_LEN, password, strlen(password), salt, ops, mem,
	                  crypto_pwhash_ALG_ARGON2ID13) != 0)
		return -ENOMEM;
	return 0;
}

char *mfakr_spki_keyid(EVP_PKEY *pk)
{
	unsigned char *der = NULL;
	uint8_t md[SHA256_DIGEST_LENGTH];
	int len = i2d_PUBKEY(pk, &der);

	if (len <= 0)
		return NULL;
	SHA256(der, len, md);
	OPENSSL_free(der);
	return mfakr_hexenc(md, sizeof(md));
}

int mfakr_ec_kek(const uint8_t *z, size_t zlen, const uint8_t *eph, size_t ephlen,
                 const char *keyid, uint8_t kek[MFAKR_KEK_LEN])
{
	char info[128];

	snprintf(info, sizeof(info), "mfa-keyring v1 piv-ec %s", keyid);
	return mfakr_hkdf(z, zlen, eph, ephlen, info, kek);
}

int mfakr_ec_wrap(EVP_PKEY *card_pub, const char *keyid,
                  uint8_t kek[MFAKR_KEK_LEN], char **eph_b64)
{
	EVP_PKEY_CTX *kctx = NULL, *dctx = NULL;
	EVP_PKEY *eph = NULL;
	uint8_t point[256], z[128];
	size_t plen = 0, zlen = sizeof(z);
	int r = -EIO;

	*eph_b64 = NULL;
	/* Generate the ephemeral key on the same curve as the card key. */
	kctx = EVP_PKEY_CTX_new_from_pkey(NULL, card_pub, NULL);
	if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &eph) <= 0)
		goto out;
	if (!EVP_PKEY_get_octet_string_param(eph, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
	                                     point, sizeof(point), &plen))
		goto out;

	dctx = EVP_PKEY_CTX_new_from_pkey(NULL, eph, NULL);
	if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(dctx, card_pub) <= 0 ||
	    EVP_PKEY_derive(dctx, z, &zlen) <= 0)
		goto out;

	r = mfakr_ec_kek(z, zlen, point, plen, keyid, kek);
	if (r < 0)
		goto out;
	*eph_b64 = mfakr_b64enc(point, plen);
	r = *eph_b64 ? 0 : -ENOMEM;
out:
	sodium_memzero(z, sizeof(z));
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(eph);
	return r;
}

int mfakr_rsa_kek(const uint8_t *seed, size_t seedlen, const char *keyid,
                  uint8_t kek[MFAKR_KEK_LEN])
{
	char info[128];

	if (seedlen != RSA_SEED_LEN)
		return -EBADMSG;
	snprintf(info, sizeof(info), "mfa-keyring v1 piv-rsa %s", keyid);
	return mfakr_hkdf(seed, seedlen, NULL, 0, info, kek);
}

int mfakr_rsa_wrap(EVP_PKEY *card_pub, const char *keyid,
                   uint8_t kek[MFAKR_KEK_LEN], char **wrapped_b64)
{
	EVP_PKEY_CTX *ctx = NULL;
	uint8_t seed[RSA_SEED_LEN], out[1024];
	size_t outlen = sizeof(out);
	int r = -EIO;

	*wrapped_b64 = NULL;
	randombytes_buf(seed, sizeof(seed));
	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, card_pub, NULL);
	if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
	    EVP_PKEY_encrypt(ctx, out, &outlen, seed, sizeof(seed)) <= 0)
		goto out;
	r = mfakr_rsa_kek(seed, sizeof(seed), keyid, kek);
	if (r < 0)
		goto out;
	*wrapped_b64 = mfakr_b64enc(out, outlen);
	r = *wrapped_b64 ? 0 : -ENOMEM;
out:
	sodium_memzero(seed, sizeof(seed));
	EVP_PKEY_CTX_free(ctx);
	return r;
}

int mfakr_fido2_kek(const uint8_t *hmac_out, size_t len, uint8_t kek[MFAKR_KEK_LEN])
{
	return mfakr_hkdf(hmac_out, len, NULL, 0, "mfa-keyring v1 fido2", kek);
}
