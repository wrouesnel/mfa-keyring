/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>

#define PIVKR_SECRET_LEN 32
#define PIVKR_KEK_LEN 32
#define PIVKR_MAX_FILE (64 * 1024)
/* base64url(32 bytes) without padding is 43 chars */
#define PIVKR_PASSWORD_LEN 43

/* Logging callback so the same core code can log via syslog (PAM) or stderr (CLI). */
typedef void (*pivkr_log_fn)(int prio, const char *msg, void *ctx);
void pivkr_set_logger(pivkr_log_fn fn, void *ctx);
void pivkr_log(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* base64url, no padding.  Returns malloc'd string or NULL. */
char *pivkr_b64enc(const uint8_t *data, size_t len);
/* Decodes into out (capacity cap).  Returns 0 on success. */
int pivkr_b64dec(const char *s, uint8_t *out, size_t cap, size_t *outlen);

char *pivkr_hexenc(const uint8_t *data, size_t len);
int pivkr_hexdec(const char *s, uint8_t *out, size_t cap, size_t *outlen);

/* Turns the 32-byte secret into the string used as the keyring password. */
void pivkr_secret_to_password(const uint8_t secret[PIVKR_SECRET_LEN],
                              char out[PIVKR_PASSWORD_LEN + 1]);

/*
 * Expand %h (home) and %u (user) in a path template.  Returns malloc'd
 * string or NULL if the template is invalid.
 */
char *pivkr_expand_path(const char *tmpl, const char *user, const char *home);

/*
 * Read a small file owned by uid.  When running as root, the file is opened
 * with the filesystem credentials of uid/gid so that we never read anything
 * the user couldn't, and the file must be a regular file owned by uid that is
 * not group/world writable.  Returns 0 on success, -ENOENT if missing, other
 * negative errno on failure.
 */
int pivkr_read_user_file(const char *path, uid_t uid, gid_t gid,
                         char **data, size_t *len);

/*
 * Atomically replace path with data (mode 0600), creating missing parent
 * directories (mode 0700).  When running as root, all filesystem operations
 * use the filesystem credentials of uid/gid.
 */
int pivkr_write_user_file(const char *path, uid_t uid, gid_t gid,
                          const char *data, size_t len);

void pivkr_memzero(void *p, size_t len);
void pivkr_free_secret_str(char *s);
