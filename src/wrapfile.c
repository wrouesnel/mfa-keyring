/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "wrapfile.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mfakr_wf_valid_token(const char *s)
{
	if (!s || !*s || strlen(s) > 4096)
		return 0;
	for (; *s; s++)
		if (*s <= ' ' || *s > '~')
			return 0;
	return 1;
}

int mfakr_wf_init(struct mfakr_wrapfile *wf, const char *user)
{
	memset(wf, 0, sizeof(*wf));
	if (!mfakr_wf_valid_token(user))
		return -EINVAL;
	wf->user = strdup(user);
	return wf->user ? 0 : -ENOMEM;
}

static void slot_free(struct mfakr_slot *s)
{
	free(s->type);
	for (int i = 0; i < s->nf; i++)
		free(s->f[i]);
	memset(s, 0, sizeof(*s));
}

void mfakr_wf_free(struct mfakr_wrapfile *wf)
{
	for (int i = 0; i < wf->nslots; i++)
		slot_free(&wf->slots[i]);
	free(wf->user);
	memset(wf, 0, sizeof(*wf));
}

int mfakr_wf_add_slot(struct mfakr_wrapfile *wf, const char *type,
                      int nf, const char *const *fields)
{
	struct mfakr_slot *s;

	/* Every slot carries at least a nonce and a ciphertext. */
	if (wf->nslots >= MFAKR_MAX_SLOTS || nf < 2 || nf > MFAKR_MAX_FIELDS)
		return -E2BIG;
	if (!mfakr_wf_valid_token(type))
		return -EINVAL;
	for (int i = 0; i < nf; i++)
		if (!mfakr_wf_valid_token(fields[i]))
			return -EINVAL;

	s = &wf->slots[wf->nslots];
	memset(s, 0, sizeof(*s));
	s->type = strdup(type);
	if (!s->type)
		return -ENOMEM;
	for (int i = 0; i < nf; i++) {
		s->f[i] = strdup(fields[i]);
		if (!s->f[i]) {
			s->nf = i;
			slot_free(s);
			return -ENOMEM;
		}
	}
	s->nf = nf;
	return wf->nslots++;
}

int mfakr_wf_remove_slot(struct mfakr_wrapfile *wf, int idx)
{
	if (idx < 0 || idx >= wf->nslots)
		return -EINVAL;
	slot_free(&wf->slots[idx]);
	memmove(&wf->slots[idx], &wf->slots[idx + 1],
	        (wf->nslots - idx - 1) * sizeof(wf->slots[0]));
	wf->nslots--;
	memset(&wf->slots[wf->nslots], 0, sizeof(wf->slots[0]));
	return 0;
}

int mfakr_wf_count(const struct mfakr_wrapfile *wf, const char *type)
{
	int n = 0;

	for (int i = 0; i < wf->nslots; i++)
		if (strcmp(wf->slots[i].type, type) == 0)
			n++;
	return n;
}

/* Split a line in place on single spaces. */
static int split(char *line, char **tok, int max)
{
	int n = 0;
	char *save = NULL, *t;

	for (t = strtok_r(line, " ", &save); t; t = strtok_r(NULL, " ", &save)) {
		if (n == max)
			return -1;
		tok[n++] = t;
	}
	return n;
}

int mfakr_wf_parse(const char *data, size_t len, struct mfakr_wrapfile *wf)
{
	char *copy, *line, *save = NULL;
	char *tok[MFAKR_MAX_FIELDS + 1];
	int n, r = -EINVAL, first = 1;

	memset(wf, 0, sizeof(*wf));
	if (memchr(data, '\0', len))
		return -EINVAL;
	copy = strndup(data, len);
	if (!copy)
		return -ENOMEM;

	for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (line[0] == '#')
			continue;
		n = split(line, tok, MFAKR_MAX_FIELDS + 1);
		if (n < 0)
			goto fail;
		if (n == 0)
			continue;
		if (first) {
			if (n != 3 || strcmp(tok[0], MFAKR_WF_MAGIC) != 0 ||
			    strcmp(tok[1], "1") != 0)
				goto fail;
			if (mfakr_wf_init(wf, tok[2]) < 0)
				goto fail;
			first = 0;
			continue;
		}
		if (mfakr_wf_add_slot(wf, tok[0], n - 1, (const char *const *) &tok[1]) < 0)
			goto fail;
	}
	if (first)
		goto fail;
	free(copy);
	return 0;
fail:
	mfakr_wf_free(wf);
	free(copy);
	return r;
}

char *mfakr_wf_serialize(const struct mfakr_wrapfile *wf)
{
	char *buf = NULL;
	size_t sz = 0;
	FILE *f = open_memstream(&buf, &sz);

	if (!f)
		return NULL;
	fprintf(f, "%s %d %s\n", MFAKR_WF_MAGIC, MFAKR_WF_VERSION, wf->user);
	for (int i = 0; i < wf->nslots; i++) {
		const struct mfakr_slot *s = &wf->slots[i];
		fputs(s->type, f);
		for (int j = 0; j < s->nf; j++) {
			fputc(' ', f);
			fputs(s->f[j], f);
		}
		fputc('\n', f);
	}
	if (fclose(f) != 0) {
		free(buf);
		return NULL;
	}
	return buf;
}

char *mfakr_wf_slot_aad(const char *user, const char *type, int nf, const char *const *fields)
{
	char *buf = NULL;
	size_t sz = 0;
	FILE *f = open_memstream(&buf, &sz);

	if (!f)
		return NULL;
	fprintf(f, "%s %d %s\n%s", MFAKR_WF_MAGIC, MFAKR_WF_VERSION, user, type);
	/* The nonce and ciphertext (last two fields) are not part of the AAD. */
	for (int i = 0; i < nf - 2; i++)
		fprintf(f, " %s", fields[i]);
	if (fclose(f) != 0) {
		free(buf);
		return NULL;
	}
	return buf;
}
