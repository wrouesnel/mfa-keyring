/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "p11.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include "crypt.h"
#include "util.h"

#define MAX_SLOTS 16
#define MAX_OBJECTS 64

int mfakr_p11_open(const char *module, struct mfakr_p11 *p)
{
	CK_C_GetFunctionList getfl;
	CK_C_INITIALIZE_ARGS args;
	CK_RV rv;

	memset(p, 0, sizeof(*p));
	p->dl = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	if (!p->dl) {
		mfakr_log(LOG_ERR, "cannot load PKCS#11 module %s: %s", module, dlerror());
		return -ENOENT;
	}
	getfl = (CK_C_GetFunctionList) dlsym(p->dl, "C_GetFunctionList");
	if (!getfl || getfl(&p->f) != CKR_OK) {
		mfakr_log(LOG_ERR, "%s is not a PKCS#11 module", module);
		dlclose(p->dl);
		p->dl = NULL;
		return -EINVAL;
	}

	memset(&args, 0, sizeof(args));
	args.flags = CKF_OS_LOCKING_OK;
	rv = p->f->C_Initialize(&args);
	if (rv == CKR_OK) {
		p->finalize = 1;
	} else if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		mfakr_log(LOG_ERR, "C_Initialize failed: 0x%lx", rv);
		dlclose(p->dl);
		p->dl = NULL;
		return -EIO;
	}
	return 0;
}

void mfakr_p11_close(struct mfakr_p11 *p)
{
	if (p->finalize)
		p->f->C_Finalize(NULL);
	if (p->dl)
		dlclose(p->dl);
	memset(p, 0, sizeof(*p));
}

/* Fetch a variable-length attribute into a malloc'd buffer. */
static int get_attr(struct mfakr_p11 *p, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                    CK_ATTRIBUTE_TYPE type, uint8_t **out, size_t *len)
{
	CK_ATTRIBUTE a = { type, NULL, 0 };

	if (p->f->C_GetAttributeValue(s, o, &a, 1) != CKR_OK ||
	    a.ulValueLen == CK_UNAVAILABLE_INFORMATION || a.ulValueLen == 0 ||
	    a.ulValueLen > 16384)
		return -ENOENT;
	a.pValue = malloc(a.ulValueLen);
	if (!a.pValue)
		return -ENOMEM;
	if (p->f->C_GetAttributeValue(s, o, &a, 1) != CKR_OK) {
		free(a.pValue);
		return -EIO;
	}
	*out = a.pValue;
	*len = a.ulValueLen;
	return 0;
}

static int find_objects(struct mfakr_p11 *p, CK_SESSION_HANDLE s,
                        CK_ATTRIBUTE *tmpl, CK_ULONG n,
                        CK_OBJECT_HANDLE *objs, CK_ULONG max, CK_ULONG *count)
{
	CK_RV rv;

	*count = 0;
	if (p->f->C_FindObjectsInit(s, tmpl, n) != CKR_OK)
		return -EIO;
	rv = p->f->C_FindObjects(s, objs, max, count);
	p->f->C_FindObjectsFinal(s);
	return rv == CKR_OK ? 0 : -EIO;
}

static EVP_PKEY *pkey_from_cert(const uint8_t *der, size_t len)
{
	const unsigned char *pp = der;
	X509 *x = d2i_X509(NULL, &pp, len);
	EVP_PKEY *pk;

	if (!x)
		return NULL;
	pk = X509_get_pubkey(x);
	X509_free(x);
	return pk;
}

static EVP_PKEY *pkey_from_params(OSSL_PARAM_BLD *bld, const char *type)
{
	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
	EVP_PKEY *pk = NULL;

	if (params && ctx && EVP_PKEY_fromdata_init(ctx) > 0)
		EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(ctx);
	return pk;
}

static EVP_PKEY *pkey_from_pubkey_object(struct mfakr_p11 *p, CK_SESSION_HANDLE s,
                                         CK_OBJECT_HANDLE o)
{
	CK_KEY_TYPE kt;
	CK_ATTRIBUTE a = { CKA_KEY_TYPE, &kt, sizeof(kt) };
	OSSL_PARAM_BLD *bld = NULL;
	EVP_PKEY *pk = NULL;
	uint8_t *b1 = NULL, *b2 = NULL;
	size_t l1, l2;
	BIGNUM *n = NULL, *e = NULL;

	/* PKCS#11 2.40 tokens can hand us the SPKI directly. */
	if (get_attr(p, s, o, CKA_PUBLIC_KEY_INFO, &b1, &l1) == 0) {
		const unsigned char *pp = b1;
		pk = d2i_PUBKEY(NULL, &pp, l1);
		free(b1);
		if (pk)
			return pk;
		b1 = NULL;
	}

	if (p->f->C_GetAttributeValue(s, o, &a, 1) != CKR_OK)
		return NULL;
	bld = OSSL_PARAM_BLD_new();
	if (!bld)
		return NULL;

	if (kt == CKK_RSA) {
		if (get_attr(p, s, o, CKA_MODULUS, &b1, &l1) < 0 ||
		    get_attr(p, s, o, CKA_PUBLIC_EXPONENT, &b2, &l2) < 0)
			goto out;
		n = BN_bin2bn(b1, l1, NULL);
		e = BN_bin2bn(b2, l2, NULL);
		if (n && e && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) &&
		    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
			pk = pkey_from_params(bld, "RSA");
	} else if (kt == CKK_EC) {
		const unsigned char *pp;
		ASN1_OBJECT *oid = NULL;
		ASN1_OCTET_STRING *pt = NULL;
		const char *curve;

		if (get_attr(p, s, o, CKA_EC_PARAMS, &b1, &l1) < 0 ||
		    get_attr(p, s, o, CKA_EC_POINT, &b2, &l2) < 0)
			goto out;
		pp = b1;
		oid = d2i_ASN1_OBJECT(NULL, &pp, l1);
		pp = b2;
		/* CKA_EC_POINT is meant to be DER-wrapped, but some tokens return it raw. */
		pt = d2i_ASN1_OCTET_STRING(NULL, &pp, l2);
		curve = oid ? OBJ_nid2sn(OBJ_obj2nid(oid)) : NULL;
		if (curve &&
		    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0) &&
		    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
		                                     pt ? ASN1_STRING_get0_data(pt) : b2,
		                                     pt ? (size_t) ASN1_STRING_length(pt) : l2))
			pk = pkey_from_params(bld, "EC");
		ASN1_OBJECT_free(oid);
		ASN1_OCTET_STRING_free(pt);
	}
out:
	BN_free(n);
	BN_free(e);
	free(b1);
	free(b2);
	OSSL_PARAM_BLD_free(bld);
	return pk;
}

static void copy_padded(char *dst, size_t dstlen, const unsigned char *src, size_t srclen)
{
	size_t n = srclen < dstlen - 1 ? srclen : dstlen - 1;

	memcpy(dst, src, n);
	while (n > 0 && dst[n - 1] == ' ')
		n--;
	dst[n] = '\0';
}

static int add_key(struct mfakr_p11_key **keys, int *n, CK_SLOT_ID slot,
                   const CK_TOKEN_INFO *ti, const uint8_t *id, size_t idlen,
                   const uint8_t *label, size_t labellen, EVP_PKEY *pk)
{
	struct mfakr_p11_key *k, *nk;
	char *keyid = mfakr_spki_keyid(pk);
	int type = EVP_PKEY_get_base_id(pk);

	if (!keyid || (type != EVP_PKEY_EC && type != EVP_PKEY_RSA) || idlen > sizeof(k->id)) {
		free(keyid);
		EVP_PKEY_free(pk);
		return 0;
	}
	for (int i = 0; i < *n; i++) {
		if ((*keys)[i].slot == slot && strcmp((*keys)[i].keyid, keyid) == 0) {
			free(keyid);
			EVP_PKEY_free(pk);
			return 0;
		}
	}
	nk = realloc(*keys, (*n + 1) * sizeof(**keys));
	if (!nk) {
		free(keyid);
		EVP_PKEY_free(pk);
		return -ENOMEM;
	}
	*keys = nk;
	k = &nk[(*n)++];
	memset(k, 0, sizeof(*k));
	k->slot = slot;
	memcpy(k->id, id, idlen);
	k->idlen = idlen;
	copy_padded(k->label, sizeof(k->label), label ? label : (const uint8_t *) "", label ? labellen : 0);
	copy_padded(k->token, sizeof(k->token), ti->label, sizeof(ti->label));
	k->keyid = keyid;
	k->pub = pk;
	k->is_ec = type == EVP_PKEY_EC;
	return 0;
}

static int list_slot_keys(struct mfakr_p11 *p, CK_SLOT_ID slot,
                          struct mfakr_p11_key **keys, int *n)
{
	static const CK_OBJECT_CLASS classes[] = { CKO_CERTIFICATE, CKO_PUBLIC_KEY };
	CK_TOKEN_INFO ti;
	CK_SESSION_HANDLE s;
	int r = 0;

	if (p->f->C_GetTokenInfo(slot, &ti) != CKR_OK)
		return 0;
	if (p->f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &s) != CKR_OK)
		return 0;

	for (size_t c = 0; c < sizeof(classes) / sizeof(classes[0]) && r == 0; c++) {
		CK_OBJECT_CLASS cls = classes[c];
		CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &cls, sizeof(cls) } };
		CK_OBJECT_HANDLE objs[MAX_OBJECTS];
		CK_ULONG count;

		if (find_objects(p, s, tmpl, 1, objs, MAX_OBJECTS, &count) < 0)
			continue;
		for (CK_ULONG i = 0; i < count && r == 0; i++) {
			uint8_t *id = NULL, *label = NULL, *der = NULL;
			size_t idlen, labellen = 0, derlen;
			EVP_PKEY *pk = NULL;

			if (get_attr(p, s, objs[i], CKA_ID, &id, &idlen) < 0)
				continue;
			get_attr(p, s, objs[i], CKA_LABEL, &label, &labellen);
			if (cls == CKO_CERTIFICATE) {
				if (get_attr(p, s, objs[i], CKA_VALUE, &der, &derlen) == 0)
					pk = pkey_from_cert(der, derlen);
			} else {
				pk = pkey_from_pubkey_object(p, s, objs[i]);
			}
			if (pk)
				r = add_key(keys, n, slot, &ti, id, idlen, label, labellen, pk);
			free(id);
			free(label);
			free(der);
		}
	}
	p->f->C_CloseSession(s);
	return r;
}

int mfakr_p11_list_keys(struct mfakr_p11 *p, struct mfakr_p11_key **keys, int *n)
{
	CK_SLOT_ID slots[MAX_SLOTS];
	CK_ULONG nslots = MAX_SLOTS;
	int r;

	*keys = NULL;
	*n = 0;
	if (p->f->C_GetSlotList(CK_TRUE, slots, &nslots) != CKR_OK)
		return -EIO;
	for (CK_ULONG i = 0; i < nslots; i++) {
		r = list_slot_keys(p, slots[i], keys, n);
		if (r < 0) {
			mfakr_p11_keys_free(*keys, *n);
			*keys = NULL;
			*n = 0;
			return r;
		}
	}
	return 0;
}

void mfakr_p11_keys_free(struct mfakr_p11_key *keys, int n)
{
	for (int i = 0; i < n; i++) {
		free(keys[i].keyid);
		EVP_PKEY_free(keys[i].pub);
	}
	free(keys);
}

int mfakr_p11_protected_auth(struct mfakr_p11 *p, CK_SLOT_ID slot)
{
	CK_TOKEN_INFO ti;

	return p->f->C_GetTokenInfo(slot, &ti) == CKR_OK &&
	       (ti.flags & CKF_PROTECTED_AUTHENTICATION_PATH);
}

int mfakr_p11_login(struct mfakr_p11 *p, CK_SLOT_ID slot, const char *pin,
                    CK_SESSION_HANDLE *sess)
{
	CK_TOKEN_INFO ti;
	CK_RV rv;

	if (p->f->C_GetTokenInfo(slot, &ti) != CKR_OK)
		return -EIO;
	if (ti.flags & (CKF_USER_PIN_LOCKED | CKF_USER_PIN_FINAL_TRY)) {
		mfakr_log(LOG_WARNING, "token PIN is locked or on its final try; not using it");
		return -ENOLCK;
	}
	if (!pin && !(ti.flags & CKF_PROTECTED_AUTHENTICATION_PATH))
		return -EINVAL;
	/* Don't spend a retry on something that can't be this token's PIN. */
	if (pin && (strlen(pin) < ti.ulMinPinLen ||
	            (ti.ulMaxPinLen && strlen(pin) > ti.ulMaxPinLen))) {
		mfakr_log(LOG_WARNING, "PIN length outside token's range %lu-%lu; not trying it",
		          ti.ulMinPinLen, ti.ulMaxPinLen);
		return -EINVAL;
	}

	if (p->f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, sess) != CKR_OK)
		return -EIO;
	rv = p->f->C_Login(*sess, CKU_USER, (CK_UTF8CHAR_PTR) pin, pin ? strlen(pin) : 0);
	if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN)
		return 0;

	p->f->C_CloseSession(*sess);
	if (rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LEN_RANGE)
		return -EACCES;
	if (rv == CKR_PIN_LOCKED)
		return -ENOLCK;
	mfakr_log(LOG_ERR, "C_Login failed: 0x%lx", rv);
	return -EIO;
}

void mfakr_p11_logout(struct mfakr_p11 *p, CK_SESSION_HANDLE sess)
{
	p->f->C_Logout(sess);
	p->f->C_CloseSession(sess);
}

static int find_private_key(struct mfakr_p11 *p, CK_SESSION_HANDLE s,
                            const uint8_t *id, size_t idlen, CK_OBJECT_HANDLE *key)
{
	CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_ID, (void *) id, idlen },
	};
	CK_ULONG count;

	if (find_objects(p, s, tmpl, 2, key, 1, &count) < 0 || count != 1)
		return -ENOENT;
	return 0;
}

int mfakr_p11_ecdh(struct mfakr_p11 *p, CK_SESSION_HANDLE sess,
                   const uint8_t *id, size_t idlen,
                   const uint8_t *peer, size_t peerlen,
                   uint8_t *z, size_t *zlen)
{
	CK_OBJECT_HANDLE key, derived = CK_INVALID_HANDLE;
	CK_ECDH1_DERIVE_PARAMS params = {
		.kdf = CKD_NULL,
		.ulPublicDataLen = peerlen,
		.pPublicData = (CK_BYTE_PTR) peer,
	};
	CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_SENSITIVE, &no, sizeof(no) },
		{ CKA_EXTRACTABLE, &yes, sizeof(yes) },
	};
	CK_ATTRIBUTE val = { CKA_VALUE, z, *zlen };
	CK_RV rv;

	if (find_private_key(p, sess, id, idlen, &key) < 0)
		return -ENOENT;
	rv = p->f->C_DeriveKey(sess, &mech, key, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), &derived);
	if (rv != CKR_OK) {
		mfakr_log(LOG_ERR, "C_DeriveKey(ECDH) failed: 0x%lx", rv);
		return -EIO;
	}
	rv = p->f->C_GetAttributeValue(sess, derived, &val, 1);
	p->f->C_DestroyObject(sess, derived);
	if (rv != CKR_OK)
		return -EIO;
	*zlen = val.ulValueLen;
	return 0;
}

int mfakr_p11_rsa_decrypt(struct mfakr_p11 *p, CK_SESSION_HANDLE sess,
                          const uint8_t *id, size_t idlen,
                          const uint8_t *in, size_t inlen,
                          uint8_t *out, size_t *outlen)
{
	CK_OBJECT_HANDLE key;
	CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
	CK_ULONG olen = *outlen;
	CK_RV rv;

	if (find_private_key(p, sess, id, idlen, &key) < 0)
		return -ENOENT;
	if (p->f->C_DecryptInit(sess, &mech, key) != CKR_OK)
		return -EIO;
	rv = p->f->C_Decrypt(sess, (CK_BYTE_PTR) in, inlen, out, &olen);
	if (rv != CKR_OK) {
		mfakr_log(LOG_ERR, "C_Decrypt failed: 0x%lx", rv);
		return -EIO;
	}
	*outlen = olen;
	return 0;
}
