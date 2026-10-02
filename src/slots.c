/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "slots.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <sodium.h>

#include "crypt.h"

int pivkr_slot_is_piv(const struct pivkr_slot *s)
{
	return strcmp(s->type, PIVKR_SLOT_PIV_EC) == 0 ||
	       strcmp(s->type, PIVKR_SLOT_PIV_RSA) == 0;
}

/* Seal the secret under kek and append a slot with params + nonce + ct. */
static int seal_slot(struct pivkr_wrapfile *wf, const char *type, int np,
                     const char **params, const uint8_t kek[PIVKR_KEK_LEN],
                     const uint8_t secret[PIVKR_SECRET_LEN])
{
	const char *fields[PIVKR_MAX_FIELDS];
	char *aad, *nonce = NULL, *ct = NULL;
	int r;

	if (np + 2 > PIVKR_MAX_FIELDS)
		return -E2BIG;
	memcpy(fields, params, np * sizeof(*params));
	fields[np] = fields[np + 1] = "";
	aad = pivkr_wf_slot_aad(wf->user, type, np + 2, fields);
	if (!aad)
		return -ENOMEM;
	r = pivkr_aead_seal(kek, aad, secret, &nonce, &ct);
	free(aad);
	if (r < 0)
		return r;
	fields[np] = nonce;
	fields[np + 1] = ct;
	r = pivkr_wf_add_slot(wf, type, np + 2, fields);
	free(nonce);
	free(ct);
	return r;
}

static int open_slot(const struct pivkr_wrapfile *wf, const struct pivkr_slot *s,
                     const uint8_t kek[PIVKR_KEK_LEN], uint8_t secret[PIVKR_SECRET_LEN])
{
	char *aad = pivkr_wf_slot_aad(wf->user, s->type, s->nf,
	                              (const char *const *) s->f);
	int r;

	if (!aad)
		return -ENOMEM;
	r = pivkr_aead_open(kek, aad, s->f[s->nf - 2], s->f[s->nf - 1], secret);
	free(aad);
	return r;
}

int pivkr_slot_find_keyid(const struct pivkr_wrapfile *wf, const char *keyid)
{
	for (int i = 0; i < wf->nslots; i++)
		if (pivkr_slot_is_piv(&wf->slots[i]) && wf->slots[i].nf == 4 &&
		    strcmp(wf->slots[i].f[0], keyid) == 0)
			return i;
	return -1;
}

int pivkr_add_piv_slot(struct pivkr_wrapfile *wf, const struct pivkr_p11_key *k,
                       const uint8_t secret[PIVKR_SECRET_LEN])
{
	uint8_t kek[PIVKR_KEK_LEN];
	char *wrapped = NULL;
	const char *params[2];
	int r;

	if (pivkr_slot_find_keyid(wf, k->keyid) >= 0)
		return -EEXIST;
	if (k->is_ec)
		r = pivkr_ec_wrap(k->pub, k->keyid, kek, &wrapped);
	else
		r = pivkr_rsa_wrap(k->pub, k->keyid, kek, &wrapped);
	if (r < 0)
		return r;
	params[0] = k->keyid;
	params[1] = wrapped;
	r = seal_slot(wf, k->is_ec ? PIVKR_SLOT_PIV_EC : PIVKR_SLOT_PIV_RSA, 2, params,
	              kek, secret);
	sodium_memzero(kek, sizeof(kek));
	free(wrapped);
	return r;
}

int pivkr_set_password_slot(struct pivkr_wrapfile *wf, const char *password,
                            const uint8_t secret[PIVKR_SECRET_LEN])
{
	uint8_t salt[PIVKR_ARGON2_SALT_LEN], kek[PIVKR_KEK_LEN];
	char ops[32], mem[32], *salt_b64;
	const char *params[4];
	int r;

	pivkr_random(salt, sizeof(salt));
	r = pivkr_argon2id(password, salt, PIVKR_ARGON2_OPS, PIVKR_ARGON2_MEM, kek);
	if (r < 0)
		return r;
	salt_b64 = pivkr_b64enc(salt, sizeof(salt));
	if (!salt_b64) {
		sodium_memzero(kek, sizeof(kek));
		return -ENOMEM;
	}
	snprintf(ops, sizeof(ops), "%d", PIVKR_ARGON2_OPS);
	snprintf(mem, sizeof(mem), "%lu", PIVKR_ARGON2_MEM);
	params[0] = "argon2id";
	params[1] = ops;
	params[2] = mem;
	params[3] = salt_b64;

	for (int i = wf->nslots - 1; i >= 0; i--)
		if (strcmp(wf->slots[i].type, PIVKR_SLOT_PASSWORD) == 0)
			pivkr_wf_remove_slot(wf, i);
	r = seal_slot(wf, PIVKR_SLOT_PASSWORD, 4, params, kek, secret);
	sodium_memzero(kek, sizeof(kek));
	free(salt_b64);
	return r;
}

int pivkr_open_password(const struct pivkr_wrapfile *wf, const char *password,
                        uint8_t secret[PIVKR_SECRET_LEN])
{
	int r = -ENOENT;

	for (int i = 0; i < wf->nslots; i++) {
		const struct pivkr_slot *s = &wf->slots[i];
		uint8_t salt[PIVKR_ARGON2_SALT_LEN], kek[PIVKR_KEK_LEN];
		unsigned long long ops;
		unsigned long mem;
		size_t slen;
		char *end;

		if (strcmp(s->type, PIVKR_SLOT_PASSWORD) != 0 || s->nf != 6 ||
		    strcmp(s->f[0], "argon2id") != 0)
			continue;
		ops = strtoull(s->f[1], &end, 10);
		if (*end)
			continue;
		mem = strtoul(s->f[2], &end, 10);
		if (*end)
			continue;
		if (pivkr_b64dec(s->f[3], salt, sizeof(salt), &slen) < 0 || slen != sizeof(salt))
			continue;
		r = pivkr_argon2id(password, salt, ops, mem, kek);
		if (r < 0)
			continue;
		r = open_slot(wf, s, kek, secret);
		sodium_memzero(kek, sizeof(kek));
		if (r == 0)
			return 0;
	}
	return r;
}

static int unwrap_piv(const struct pivkr_wrapfile *wf, const struct pivkr_slot *s,
                      struct pivkr_p11 *p11, CK_SESSION_HANDLE sess,
                      const struct pivkr_p11_key *k, uint8_t secret[PIVKR_SECRET_LEN])
{
	uint8_t in[1024], out[1024], kek[PIVKR_KEK_LEN];
	size_t inlen, outlen = sizeof(out);
	int r;

	if (pivkr_b64dec(s->f[1], in, sizeof(in), &inlen) < 0)
		return -EINVAL;
	if (strcmp(s->type, PIVKR_SLOT_PIV_EC) == 0) {
		r = pivkr_p11_ecdh(p11, sess, k->id, k->idlen, in, inlen, out, &outlen);
		if (r == 0)
			r = pivkr_ec_kek(out, outlen, in, inlen, k->keyid, kek);
	} else {
		r = pivkr_p11_rsa_decrypt(p11, sess, k->id, k->idlen, in, inlen, out, &outlen);
		if (r == 0)
			r = pivkr_rsa_kek(out, outlen, k->keyid, kek);
	}
	sodium_memzero(out, sizeof(out));
	if (r == 0)
		r = open_slot(wf, s, kek, secret);
	sodium_memzero(kek, sizeof(kek));
	return r;
}

int pivkr_open_piv(const struct pivkr_wrapfile *wf, struct pivkr_p11 *p11,
                   const char *pin, const struct pivkr_ui *ui,
                   uint8_t secret[PIVKR_SECRET_LEN])
{
	struct pivkr_p11_key *keys = NULL;
	int nkeys = 0, r;

	r = pivkr_p11_list_keys(p11, &keys, &nkeys);
	if (r < 0)
		return r;
	r = -ENOENT;

	for (int i = 0; i < nkeys && r != 0 && r != -EACCES && r != -ECANCELED; i++) {
		const struct pivkr_p11_key *k = &keys[i];
		int si = pivkr_slot_find_keyid(wf, k->keyid);
		CK_SESSION_HANDLE sess;
		char *asked = NULL;
		const char *use_pin = pin;

		if (si < 0)
			continue;
		if (strcmp(wf->slots[si].type, k->is_ec ? PIVKR_SLOT_PIV_EC : PIVKR_SLOT_PIV_RSA) != 0)
			continue;

		if (pivkr_p11_protected_auth(p11, k->slot)) {
			if (ui && ui->notify)
				ui->notify("Enter your PIN on the card reader.", ui->ctx);
			use_pin = NULL;
		} else if (!use_pin) {
			char prompt[96];

			snprintf(prompt, sizeof(prompt), "PIN for %s: ", k->token);
			asked = ui && ui->get_pin ? ui->get_pin(prompt, ui->ctx) : NULL;
			if (!asked) {
				r = -ECANCELED;
				continue;
			}
			use_pin = asked;
		}

		r = pivkr_p11_login(p11, k->slot, use_pin, &sess);
		pivkr_free_secret_str(asked);
		if (r < 0) {
			if (r == -EACCES)
				pivkr_log(LOG_WARNING, "PIN rejected by %s", k->token);
			continue;
		}
		r = unwrap_piv(wf, &wf->slots[si], p11, sess, k, secret);
		pivkr_p11_logout(p11, sess);
		if (r < 0)
			pivkr_log(LOG_ERR, "unwrapping with key %.16s on %s failed (%d)",
			          k->keyid, k->token, r);
	}
	pivkr_p11_keys_free(keys, nkeys);
	return r;
}

int pivkr_add_fido2_slot(struct pivkr_wrapfile *wf, int uv, const struct pivkr_ui *ui,
                         const uint8_t secret[PIVKR_SECRET_LEN])
{
	uint8_t *credid = NULL, salt[PIVKR_FIDO2_SALT_LEN];
	uint8_t hmac[PIVKR_FIDO2_HMAC_LEN], kek[PIVKR_KEK_LEN];
	size_t credlen = 0;
	char *cred_b64 = NULL, *salt_b64 = NULL;
	const char *params[4];
	int r;

	r = pivkr_fido2_enroll(PIVKR_FIDO2_RPID, uv, ui, &credid, &credlen);
	if (r < 0)
		return r;
	pivkr_random(salt, sizeof(salt));
	r = pivkr_fido2_hmac(PIVKR_FIDO2_RPID, credid, credlen, salt, uv, ui, hmac);
	if (r < 0)
		goto out;
	r = pivkr_fido2_kek(hmac, sizeof(hmac), kek);
	if (r < 0)
		goto out;

	cred_b64 = pivkr_b64enc(credid, credlen);
	salt_b64 = pivkr_b64enc(salt, sizeof(salt));
	if (!cred_b64 || !salt_b64) {
		r = -ENOMEM;
		goto out;
	}
	params[0] = PIVKR_FIDO2_RPID;
	params[1] = uv ? "1" : "0";
	params[2] = cred_b64;
	params[3] = salt_b64;
	r = seal_slot(wf, PIVKR_SLOT_FIDO2, 4, params, kek, secret);
out:
	sodium_memzero(hmac, sizeof(hmac));
	sodium_memzero(kek, sizeof(kek));
	free(credid);
	free(cred_b64);
	free(salt_b64);
	return r;
}

int pivkr_open_fido2(const struct pivkr_wrapfile *wf, const struct pivkr_ui *ui,
                     uint8_t secret[PIVKR_SECRET_LEN])
{
	int r = -ENOENT;

	for (int i = 0; i < wf->nslots; i++) {
		const struct pivkr_slot *s = &wf->slots[i];
		uint8_t credid[1024], salt[PIVKR_FIDO2_SALT_LEN];
		uint8_t hmac[PIVKR_FIDO2_HMAC_LEN], kek[PIVKR_KEK_LEN];
		size_t credlen, slen;

		if (strcmp(s->type, PIVKR_SLOT_FIDO2) != 0 || s->nf != 6)
			continue;
		if (pivkr_b64dec(s->f[2], credid, sizeof(credid), &credlen) < 0 ||
		    pivkr_b64dec(s->f[3], salt, sizeof(salt), &slen) < 0 || slen != sizeof(salt))
			continue;

		r = pivkr_fido2_hmac(s->f[0], credid, credlen, salt,
		                     strcmp(s->f[1], "1") == 0, ui, hmac);
		if (r == -ENODEV) {
			r = -ENOENT;
			continue;
		}
		if (r < 0)
			return r;  /* timeout, cancel or PIN failure: don't prompt again */
		r = pivkr_fido2_kek(hmac, sizeof(hmac), kek);
		if (r == 0)
			r = open_slot(wf, s, kek, secret);
		sodium_memzero(hmac, sizeof(hmac));
		sodium_memzero(kek, sizeof(kek));
		if (r == 0)
			return 0;
	}
	return r;
}
