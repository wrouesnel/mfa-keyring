/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "crypt.h"
#include "slots.h"
#include "util.h"
#include "wrapfile.h"

static const char *const sample =
	"mfa-keyring-wrap 1 alice\n"
	"piv-ec abcd AAAA nonce1 ct1\n"
	"password argon2id 3 268435456 salt nonce2 ct2\n";

static void test_wf_roundtrip(void **state)
{
	struct mfakr_wrapfile wf;
	char *out;

	assert_int_equal(mfakr_wf_parse(sample, strlen(sample), &wf), 0);
	assert_string_equal(wf.user, "alice");
	assert_int_equal(wf.nslots, 2);
	assert_string_equal(wf.slots[0].type, "piv-ec");
	assert_int_equal(wf.slots[0].nf, 4);
	assert_string_equal(wf.slots[1].f[3], "salt");
	assert_int_equal(mfakr_wf_count(&wf, "password"), 1);

	out = mfakr_wf_serialize(&wf);
	assert_non_null(out);
	assert_string_equal(out, sample);
	free(out);

	assert_int_equal(mfakr_wf_remove_slot(&wf, 0), 0);
	assert_int_equal(wf.nslots, 1);
	assert_string_equal(wf.slots[0].type, "password");
	mfakr_wf_free(&wf);
}

static void test_wf_zfs(void **state)
{
	static const char *const in =
		"mfa-keyring-wrap 1 alice\n"
		"zfs rpool/home/alice\n"
		"password argon2id 3 268435456 salt nonce ct\n";
	static const char *const dup = "mfa-keyring-wrap 1 alice\nzfs a\nzfs b\n";
	struct mfakr_wrapfile wf;
	char *out;

	assert_int_equal(mfakr_wf_parse(in, strlen(in), &wf), 0);
	assert_string_equal(wf.zfs_dataset, "rpool/home/alice");
	assert_int_equal(wf.nslots, 1);
	out = mfakr_wf_serialize(&wf);
	assert_string_equal(out, in);
	free(out);
	assert_int_equal(mfakr_wf_set_zfs(&wf, NULL), 0);
	out = mfakr_wf_serialize(&wf);
	assert_null(strstr(out, "zfs"));
	free(out);
	mfakr_wf_free(&wf);
	assert_int_not_equal(mfakr_wf_parse(dup, strlen(dup), &wf), 0);
}

static void test_wf_rejects(void **state)
{
	static const char *const bad[] = {
		"",
		"mfa-keyring-wrap 2 alice\n",
		"something-else 1 alice\n",
		"mfa-keyring-wrap 1\n",
		"mfa-keyring-wrap 1 alice extra\n",
		"mfa-keyring-wrap 1 alice\nlonely onefield\n",
		"mfa-keyring-wrap 1 alice\nt 1 2 3 4 5 6 7 8 9 10 11 12 13\n",
		"mfa-keyring-wrap 1 al\x01ice\n",
	};
	struct mfakr_wrapfile wf;
	const char nul[] = "mfa-keyring-wrap 1 alice\0\nx a b\n";

	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		assert_int_not_equal(mfakr_wf_parse(bad[i], strlen(bad[i]), &wf), 0);
	assert_int_not_equal(mfakr_wf_parse(nul, sizeof(nul) - 1, &wf), 0);
}

static void test_expand_path(void **state)
{
	char *p = mfakr_expand_path("%h/.local/%u.wrap", "bob", "/home/bob");

	assert_string_equal(p, "/home/bob/.local/bob.wrap");
	free(p);
	assert_null(mfakr_expand_path("%x", "bob", "/home/bob"));
	assert_null(mfakr_expand_path("relative/%u", "bob", "/home/bob"));
}

static void test_secret_password(void **state)
{
	uint8_t secret[MFAKR_SECRET_LEN];
	char pw[MFAKR_PASSWORD_LEN + 1];

	mfakr_random(secret, sizeof(secret));
	mfakr_secret_to_password(secret, pw);
	assert_int_equal(strlen(pw), MFAKR_PASSWORD_LEN);
}

static void test_password_slot(void **state)
{
	struct mfakr_wrapfile wf, wf2;
	uint8_t secret[MFAKR_SECRET_LEN], out[MFAKR_SECRET_LEN];
	char *ser;

	mfakr_random(secret, sizeof(secret));
	assert_int_equal(mfakr_wf_init(&wf, "alice"), 0);
	assert_true(mfakr_set_password_slot(&wf, "hunter2", secret) >= 0);
	/* Setting again replaces rather than adds. */
	assert_true(mfakr_set_password_slot(&wf, "hunter3", secret) >= 0);
	assert_int_equal(mfakr_wf_count(&wf, MFAKR_SLOT_PASSWORD), 1);

	assert_int_equal(mfakr_open_password(&wf, "hunter3", out), 0);
	assert_memory_equal(out, secret, sizeof(secret));
	assert_int_not_equal(mfakr_open_password(&wf, "hunter2", out), 0);

	/* The user name is authenticated: moving the file to another user fails. */
	ser = mfakr_wf_serialize(&wf);
	memcpy(strstr(ser, "alice"), "mal1c", 5);
	assert_int_equal(mfakr_wf_parse(ser, strlen(ser), &wf2), 0);
	assert_int_not_equal(mfakr_open_password(&wf2, "hunter3", out), 0);
	free(ser);
	mfakr_wf_free(&wf2);
	mfakr_wf_free(&wf);
}

static void test_argon2_bounds(void **state)
{
	uint8_t salt[MFAKR_ARGON2_SALT_LEN] = { 0 }, out[MFAKR_KEK_LEN];

	assert_int_not_equal(mfakr_argon2id("x", salt, 1000, MFAKR_ARGON2_MEM, out), 0);
	assert_int_not_equal(mfakr_argon2id("x", salt, 3, MFAKR_ARGON2_MAX_MEM * 2, out), 0);
}

static EVP_PKEY *gen_key(const char *type, const char *param)
{
	EVP_PKEY *k = NULL;

	if (strcmp(type, "EC") == 0)
		k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", param);
	else
		k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
	assert_non_null(k);
	return k;
}

/* What the card does for piv-ec, in software. */
static void test_ec_wrap(void **state)
{
	const char *curves[] = { "P-256", "P-384" };

	for (size_t c = 0; c < 2; c++) {
		EVP_PKEY *card = gen_key("EC", curves[c]), *peer = NULL;
		EVP_PKEY_CTX *ctx;
		uint8_t kek1[MFAKR_KEK_LEN], kek2[MFAKR_KEK_LEN], eph[256], z[128];
		size_t ephlen, zlen = sizeof(z);
		char *eph_b64, *keyid = mfakr_spki_keyid(card);
		OSSL_PARAM params[3];

		assert_int_equal(mfakr_ec_wrap(card, keyid, kek1, &eph_b64), 0);
		assert_int_equal(mfakr_b64dec(eph_b64, eph, sizeof(eph), &ephlen), 0);

		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
		                                             (char *) curves[c], 0);
		params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, eph, ephlen);
		params[2] = OSSL_PARAM_construct_end();
		ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		assert_true(EVP_PKEY_fromdata_init(ctx) > 0);
		assert_true(EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, params) > 0);
		EVP_PKEY_CTX_free(ctx);

		ctx = EVP_PKEY_CTX_new_from_pkey(NULL, card, NULL);
		assert_true(EVP_PKEY_derive_init(ctx) > 0);
		assert_true(EVP_PKEY_derive_set_peer(ctx, peer) > 0);
		assert_true(EVP_PKEY_derive(ctx, z, &zlen) > 0);
		EVP_PKEY_CTX_free(ctx);

		assert_int_equal(mfakr_ec_kek(z, zlen, eph, ephlen, keyid, kek2), 0);
		assert_memory_equal(kek1, kek2, MFAKR_KEK_LEN);

		/* The keyid is bound into the KDF. */
		assert_int_equal(mfakr_ec_kek(z, zlen, eph, ephlen, "other", kek2), 0);
		assert_memory_not_equal(kek1, kek2, MFAKR_KEK_LEN);

		free(eph_b64);
		free(keyid);
		EVP_PKEY_free(peer);
		EVP_PKEY_free(card);
	}
}

static void test_rsa_wrap(void **state)
{
	EVP_PKEY *card = gen_key("RSA", NULL);
	EVP_PKEY_CTX *ctx;
	uint8_t kek1[MFAKR_KEK_LEN], kek2[MFAKR_KEK_LEN], wrapped[512], seed[512];
	size_t wlen, slen = sizeof(seed);
	char *w_b64, *keyid = mfakr_spki_keyid(card);

	assert_int_equal(mfakr_rsa_wrap(card, keyid, kek1, &w_b64), 0);
	assert_int_equal(mfakr_b64dec(w_b64, wrapped, sizeof(wrapped), &wlen), 0);
	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, card, NULL);
	assert_true(EVP_PKEY_decrypt_init(ctx) > 0);
	assert_true(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0);
	assert_true(EVP_PKEY_decrypt(ctx, seed, &slen, wrapped, wlen) > 0);
	EVP_PKEY_CTX_free(ctx);
	assert_int_equal(mfakr_rsa_kek(seed, slen, keyid, kek2), 0);
	assert_memory_equal(kek1, kek2, MFAKR_KEK_LEN);
	free(w_b64);
	free(keyid);
	EVP_PKEY_free(card);
}

static void test_aead_tamper(void **state)
{
	uint8_t kek[MFAKR_KEK_LEN], secret[MFAKR_SECRET_LEN], out[MFAKR_SECRET_LEN];
	char *nonce, *ct;

	mfakr_random(kek, sizeof(kek));
	mfakr_random(secret, sizeof(secret));
	assert_int_equal(mfakr_aead_seal(kek, "aad", secret, &nonce, &ct), 0);
	assert_int_equal(mfakr_aead_open(kek, "aad", nonce, ct, out), 0);
	assert_memory_equal(out, secret, sizeof(secret));
	assert_int_not_equal(mfakr_aead_open(kek, "aaX", nonce, ct, out), 0);
	ct[3] = ct[3] == 'A' ? 'B' : 'A';
	assert_int_not_equal(mfakr_aead_open(kek, "aad", nonce, ct, out), 0);
	free(nonce);
	free(ct);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wf_roundtrip),
		cmocka_unit_test(test_wf_zfs),
		cmocka_unit_test(test_wf_rejects),
		cmocka_unit_test(test_expand_path),
		cmocka_unit_test(test_secret_password),
		cmocka_unit_test(test_password_slot),
		cmocka_unit_test(test_argon2_bounds),
		cmocka_unit_test(test_ec_wrap),
		cmocka_unit_test(test_rsa_wrap),
		cmocka_unit_test(test_aead_tamper),
	};

	if (mfakr_crypto_init() < 0)
		return 1;
	return cmocka_run_group_tests(tests, NULL, NULL);
}
