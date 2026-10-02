/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

static mfakr_log_fn log_fn;
static void *log_ctx;

void mfakr_set_logger(mfakr_log_fn fn, void *ctx)
{
	log_fn = fn;
	log_ctx = ctx;
}

void mfakr_log(int prio, const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (log_fn)
		log_fn(prio, buf, log_ctx);
	else if (prio <= LOG_WARNING)
		fprintf(stderr, "mfa-keyring: %s\n", buf);
}

void mfakr_memzero(void *p, size_t len)
{
	if (p)
		sodium_memzero(p, len);
}

void mfakr_free_secret_str(char *s)
{
	if (s) {
		sodium_memzero(s, strlen(s));
		free(s);
	}
}

char *mfakr_b64enc(const uint8_t *data, size_t len)
{
	const int v = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
	size_t n = sodium_base64_ENCODED_LEN(len, v);
	char *s = malloc(n);

	if (!s)
		return NULL;
	sodium_bin2base64(s, n, data, len, v);
	return s;
}

int mfakr_b64dec(const char *s, uint8_t *out, size_t cap, size_t *outlen)
{
	const char *end;

	if (sodium_base642bin(out, cap, s, strlen(s), NULL, outlen, &end,
	                      sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
		return -1;
	if (*end != '\0')
		return -1;
	return 0;
}

char *mfakr_hexenc(const uint8_t *data, size_t len)
{
	char *s = malloc(len * 2 + 1);

	if (!s)
		return NULL;
	sodium_bin2hex(s, len * 2 + 1, data, len);
	return s;
}

int mfakr_hexdec(const char *s, uint8_t *out, size_t cap, size_t *outlen)
{
	const char *end;

	if (sodium_hex2bin(out, cap, s, strlen(s), NULL, outlen, &end) != 0)
		return -1;
	if (*end != '\0')
		return -1;
	return 0;
}

void mfakr_secret_to_password(const uint8_t secret[MFAKR_SECRET_LEN],
                              char out[MFAKR_PASSWORD_LEN + 1])
{
	sodium_bin2base64(out, MFAKR_PASSWORD_LEN + 1, secret, MFAKR_SECRET_LEN,
	                  sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

char *mfakr_expand_path(const char *tmpl, const char *user, const char *home)
{
	size_t cap = strlen(tmpl) + 1;
	const char *p;
	char *out, *o;

	for (p = tmpl; *p; p++)
		if (*p == '%')
			cap += strlen(home) + strlen(user);
	out = o = malloc(cap);
	if (!out)
		return NULL;

	for (p = tmpl; *p; p++) {
		if (*p != '%') {
			*o++ = *p;
			continue;
		}
		p++;
		if (*p == 'h') {
			o = stpcpy(o, home);
		} else if (*p == 'u') {
			o = stpcpy(o, user);
		} else if (*p == '%') {
			*o++ = '%';
		} else {
			free(out);
			return NULL;
		}
	}
	*o = '\0';

	if (out[0] != '/') {
		free(out);
		return NULL;
	}
	return out;
}

/* Switch filesystem credentials when running as root. */
struct fscreds {
	int switched;
	uid_t old_uid;
	gid_t old_gid;
};

static int creds_enter(struct fscreds *c, uid_t uid, gid_t gid)
{
	c->switched = 0;
	if (geteuid() != 0)
		return geteuid() == uid ? 0 : -EPERM;

	c->old_gid = setfsgid(gid);
	if ((gid_t) setfsgid(gid) != gid) {
		setfsgid(c->old_gid);
		return -EPERM;
	}
	c->old_uid = setfsuid(uid);
	if ((uid_t) setfsuid(uid) != uid) {
		setfsuid(c->old_uid);
		setfsgid(c->old_gid);
		return -EPERM;
	}
	c->switched = 1;
	return 0;
}

static void creds_leave(struct fscreds *c)
{
	if (!c->switched)
		return;
	setfsuid(c->old_uid);
	setfsgid(c->old_gid);
	c->switched = 0;
}

int mfakr_read_user_file(const char *path, uid_t uid, gid_t gid,
                         char **data, size_t *len)
{
	struct fscreds c;
	struct stat st;
	char *buf = NULL;
	size_t off = 0;
	int fd, r;

	r = creds_enter(&c, uid, gid);
	if (r < 0)
		return r;
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
	r = fd < 0 ? -errno : 0;
	creds_leave(&c);
	if (r < 0)
		return r;

	if (fstat(fd, &st) < 0) {
		r = -errno;
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_uid != uid || (st.st_mode & 022)) {
		mfakr_log(LOG_ERR, "%s: refusing to use: must be a regular file owned "
		          "by uid %u and not group/world writable", path, (unsigned) uid);
		r = -EPERM;
		goto out;
	}
	if (st.st_size > MFAKR_MAX_FILE) {
		r = -EFBIG;
		goto out;
	}

	buf = malloc(st.st_size + 1);
	if (!buf) {
		r = -ENOMEM;
		goto out;
	}
	while (off < (size_t) st.st_size) {
		ssize_t n = read(fd, buf + off, st.st_size - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			r = n < 0 ? -errno : -EIO;
			goto out;
		}
		off += n;
	}
	buf[off] = '\0';
	*data = buf;
	*len = off;
	buf = NULL;
	r = 0;
out:
	free(buf);
	close(fd);
	return r;
}

static int mkdir_parents(const char *path)
{
	char *copy = strdup(path), *p;
	int r = 0;

	if (!copy)
		return -ENOMEM;
	/* Create each missing ancestor of the file, skipping the file itself. */
	for (p = copy + 1; (p = strchr(p, '/')); p++) {
		*p = '\0';
		if (mkdir(copy, 0700) < 0 && errno != EEXIST) {
			r = -errno;
			break;
		}
		*p = '/';
	}
	free(copy);
	return r;
}

int mfakr_write_user_file(const char *path, uid_t uid, gid_t gid,
                          const char *data, size_t len)
{
	struct fscreds c;
	char *tmp = NULL, *dircopy = NULL;
	int fd = -1, dfd, r;
	size_t off = 0;

	r = creds_enter(&c, uid, gid);
	if (r < 0)
		return r;

	r = mkdir_parents(path);
	if (r < 0)
		goto out;

	if (asprintf(&tmp, "%s.tmp.XXXXXX", path) < 0) {
		tmp = NULL;
		r = -ENOMEM;
		goto out;
	}
	fd = mkostemp(tmp, O_CLOEXEC);
	if (fd < 0) {
		r = -errno;
		goto out;
	}
	if (fchmod(fd, 0600) < 0) {
		r = -errno;
		goto out_unlink;
	}
	while (off < len) {
		ssize_t n = write(fd, data + off, len - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			r = -errno;
			goto out_unlink;
		}
		off += n;
	}
	if (fsync(fd) < 0) {
		r = -errno;
		goto out_unlink;
	}
	close(fd);
	fd = -1;
	if (rename(tmp, path) < 0) {
		r = -errno;
		goto out_unlink;
	}

	dircopy = strdup(path);
	if (dircopy) {
		dfd = open(dirname(dircopy), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (dfd >= 0) {
			fsync(dfd);
			close(dfd);
		}
	}
	r = 0;
	goto out;

out_unlink:
	unlink(tmp);
out:
	if (fd >= 0)
		close(fd);
	creds_leave(&c);
	free(tmp);
	free(dircopy);
	return r;
}

int mfakr_unlink_user_file(const char *path, uid_t uid, gid_t gid)
{
	struct fscreds c;
	int r = creds_enter(&c, uid, gid);

	if (r < 0)
		return r;
	r = unlink(path) < 0 ? -errno : 0;
	creds_leave(&c);
	return r;
}
