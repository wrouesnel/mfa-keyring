/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * mfa-keyring: enrol PIV smartcards, FIDO2 security keys and the login
 * password as ways to unlock the GNOME login keyring.
 */
#include "config.h"

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

#include "crypt.h"
#include "fido2.h"
#include "gkr.h"
#include "p11.h"
#include "slots.h"
#include "util.h"
#include "wrapfile.h"

static const char *opt_module = DEFAULT_PKCS11_MODULE;
static const char *opt_file;
static const char *opt_key;
static const char *opt_user;
static const char *opt_dataset;
static int opt_fido2, opt_uv, opt_no_password, opt_force;

/* The user whose wrap file we work on (the caller, or --user/SUDO_USER for root). */
static struct passwd *me;
static char *wrap_path;
/* Candidate locations, in the order pam_mfa_keyring searches them. */
static char *system_path, *home_path;

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("mfa-keyring: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}

/* Reads a line with echo off from the terminal, or from stdin when not a tty. */
static char *read_secret(const char *prompt)
{
	struct termios old, noecho;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	int tty = isatty(STDIN_FILENO);

	fputs(prompt, stderr);
	fflush(stderr);
	if (tty) {
		tcgetattr(STDIN_FILENO, &old);
		noecho = old;
		noecho.c_lflag &= ~ECHO;
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho);
	}
	n = getline(&line, &cap, stdin);
	if (tty) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
		fputc('\n', stderr);
	}
	if (n < 0) {
		free(line);
		return NULL;
	}
	if (n > 0 && line[n - 1] == '\n')
		line[--n] = '\0';
	return line;
}

static char *ui_get_pin(const char *prompt, void *ctx)
{
	char *s = read_secret(prompt);

	if (s && !*s) {
		free(s);
		return NULL;
	}
	return s;
}

static void ui_notify(const char *msg, void *ctx)
{
	fprintf(stderr, "%s\n", msg);
}

static const struct mfakr_ui ui = { ui_get_pin, ui_notify, NULL };

static char *read_new_password(const char *what)
{
	char prompt[128], *a, *b;

	snprintf(prompt, sizeof(prompt), "New %s: ", what);
	a = read_secret(prompt);
	if (!a)
		die("no password given");
	snprintf(prompt, sizeof(prompt), "Repeat new %s: ", what);
	b = read_secret(prompt);
	if (!b || strcmp(a, b) != 0)
		die("passwords do not match");
	mfakr_free_secret_str(b);
	return a;
}

static int load(struct mfakr_wrapfile *wf)
{
	char *data;
	size_t len;
	int r = mfakr_read_user_file(wrap_path, me->pw_uid, me->pw_gid, &data, &len);

	if (r == -ENOENT)
		return r;
	if (r < 0)
		die("cannot read %s: %s", wrap_path, strerror(-r));
	r = mfakr_wf_parse(data, len, wf);
	free(data);
	if (r < 0)
		die("%s is malformed", wrap_path);
	if (strcmp(wf->user, me->pw_name) != 0)
		die("%s belongs to user %s", wrap_path, wf->user);
	return 0;
}

static void load_or_die(struct mfakr_wrapfile *wf)
{
	if (load(wf) == -ENOENT)
		die("not enrolled (%s does not exist); run 'mfa-keyring enroll'", wrap_path);
}

static void save(const struct mfakr_wrapfile *wf)
{
	char *data = mfakr_wf_serialize(wf);
	int r;

	if (!data)
		die("out of memory");
	r = mfakr_write_user_file(wrap_path, me->pw_uid, me->pw_gid, data, strlen(data));
	free(data);
	if (r < 0)
		die("cannot write %s: %s", wrap_path, strerror(-r));
}

static void open_p11(struct mfakr_p11 *p11)
{
	if (mfakr_p11_open(opt_module, p11) < 0)
		die("cannot load PKCS#11 module %s", opt_module);
}

static int key_is_selected(const struct mfakr_p11_key *k, const char *sel)
{
	char *idhex = mfakr_hexenc(k->id, k->idlen);
	int match = (idhex && strcasecmp(idhex, sel) == 0) ||
	            (strlen(sel) >= 8 && strncasecmp(k->keyid, sel, strlen(sel)) == 0);

	free(idhex);
	return match;
}

static void print_key(const struct mfakr_p11_key *k)
{
	char *idhex = mfakr_hexenc(k->id, k->idlen);

	printf("  token \"%s\"  id %s  %s  %s\n    keyid %s\n", k->token, idhex ? idhex : "?",
	       k->is_ec ? "EC " : "RSA", k->label, k->keyid);
	free(idhex);
}

/* Pick the card key to enrol: --key, else the PIV key-management key (id 03). */
static const struct mfakr_p11_key *select_key(struct mfakr_p11_key *keys, int n)
{
	const struct mfakr_p11_key *found = NULL;
	int matches = 0;

	if (n == 0)
		die("no keys found; is the card inserted?");
	for (int i = 0; i < n; i++) {
		int m = opt_key ? key_is_selected(&keys[i], opt_key)
		                : keys[i].idlen == 1 && keys[i].id[0] == 0x03;
		if (m) {
			found = &keys[i];
			matches++;
		}
	}
	if (!opt_key && matches == 0 && n == 1)
		return &keys[0];
	if (matches == 1)
		return found;

	fprintf(stderr, "Available keys:\n");
	for (int i = 0; i < n; i++)
		print_key(&keys[i]);
	if (matches && opt_key)
		die("--key matches more than one key");
	die(matches ? "more than one key-management key (id 03) found; choose one with --key" :
	    "choose a key with --key <id or keyid prefix>");
}

/* Recover the secret from an existing wrap file using whatever is at hand. */
static void recover_secret(const struct mfakr_wrapfile *wf, uint8_t secret[MFAKR_SECRET_LEN],
                           int allow_password)
{
	int has_piv = 0, r;

	for (int i = 0; i < wf->nslots; i++)
		has_piv |= mfakr_slot_is_piv(&wf->slots[i]);

	if (has_piv) {
		struct mfakr_p11 p11;

		if (mfakr_p11_open(opt_module, &p11) == 0) {
			r = mfakr_open_piv(wf, &p11, NULL, &ui, secret);
			mfakr_p11_close(&p11);
			if (r == 0)
				return;
			if (r == -EACCES)
				die("PIN incorrect");
		}
	}
	if (mfakr_wf_count(wf, MFAKR_SLOT_FIDO2) > 0) {
		r = mfakr_open_fido2(wf, &ui, secret);
		if (r == 0)
			return;
		if (r != -ENOENT)
			fprintf(stderr, "security key: %s\n", strerror(-r));
	}
	if (allow_password && mfakr_wf_count(wf, MFAKR_SLOT_PASSWORD) > 0) {
		char *pw = read_secret("Login password: ");
		r = pw ? mfakr_open_password(wf, pw, secret) : -ECANCELED;
		mfakr_free_secret_str(pw);
		if (r == 0)
			return;
	}
	die("could not unlock the keyring secret with any enrolled card, key or password");
}

static int cmd_list_keys(void)
{
	struct mfakr_p11 p11;
	struct mfakr_p11_key *keys;
	int n;

	open_p11(&p11);
	if (mfakr_p11_list_keys(&p11, &keys, &n) < 0)
		die("cannot list keys");
	if (n == 0)
		printf("No keys found.\n");
	for (int i = 0; i < n; i++)
		print_key(&keys[i]);
	mfakr_p11_keys_free(keys, n);
	mfakr_p11_close(&p11);
	return 0;
}

static int cmd_status(void)
{
	struct mfakr_wrapfile wf;
	char *err = NULL;
	int locked;

	if (load(&wf) == -ENOENT) {
		printf("Not enrolled (%s does not exist).\n", wrap_path);
		return 1;
	}
	printf("Wrap file: %s\nUser: %s\n", wrap_path, wf.user);
	if (wf.zfs_dataset)
		printf("ZFS home: %s (its key is the secret)\n", wf.zfs_dataset);
	for (int i = 0; i < wf.nslots; i++) {
		const struct mfakr_slot *s = &wf.slots[i];

		printf("  [%d] %-8s ", i, s->type);
		if (mfakr_slot_is_piv(s) && s->nf == 4)
			printf("keyid %.16s…\n", s->f[0]);
		else if (strcmp(s->type, MFAKR_SLOT_FIDO2) == 0 && s->nf == 6)
			printf("rp %s, %s\n", s->f[0], strcmp(s->f[1], "1") == 0 ?
			       "PIN required" : "touch only");
		else if (strcmp(s->type, MFAKR_SLOT_PASSWORD) == 0 && s->nf == 6)
			printf("%s ops=%s mem=%luMiB\n", s->f[0], s->f[1],
			       strtoul(s->f[2], NULL, 10) >> 20);
		else
			printf("(unrecognised slot)\n");
	}
	locked = mfakr_gkr_is_locked(&err);
	if (locked >= 0)
		printf("Login keyring: %s\n", locked ? "locked" : "unlocked");
	free(err);
	mfakr_wf_free(&wf);
	return 0;
}

static void add_password_slot(struct mfakr_wrapfile *wf, const uint8_t *secret,
                              const char *fallback)
{
	char *pw;
	int r;

	if (fallback) {
		pw = read_secret("Login password (Enter to reuse the keyring password): ");
		if (pw && !*pw) {
			mfakr_free_secret_str(pw);
			pw = strdup(fallback);
		}
	} else {
		pw = read_secret("Login password: ");
	}
	if (!pw || !*pw)
		die("no password given");
	fprintf(stderr, "Deriving key from password…\n");
	r = mfakr_set_password_slot(wf, pw, secret);
	mfakr_free_secret_str(pw);
	if (r < 0)
		die("cannot create password slot: %s", strerror(-r));
}

static void add_piv_slot(struct mfakr_wrapfile *wf, const uint8_t secret[MFAKR_SECRET_LEN])
{
	struct mfakr_p11 p11;
	struct mfakr_p11_key *keys;
	struct mfakr_wrapfile probe;
	uint8_t check[MFAKR_SECRET_LEN];
	const struct mfakr_p11_key *k;
	int n, r;

	open_p11(&p11);
	if (mfakr_p11_list_keys(&p11, &keys, &n) < 0)
		die("cannot list keys");
	k = select_key(keys, n);
	r = mfakr_add_piv_slot(wf, k, secret);
	if (r == -EEXIST)
		die("that key is already enrolled");
	if (r < 0)
		die("cannot wrap secret to card key: %s", strerror(-r));

	/* Prove the card can unwrap it before we rely on it. */
	if (mfakr_wf_init(&probe, wf->user) < 0 || mfakr_add_piv_slot(&probe, k, secret) < 0)
		die("out of memory");
	fprintf(stderr, "Checking that the card can unwrap the secret.\n");
	r = mfakr_open_piv(&probe, &p11, NULL, &ui, check);
	if (r < 0 || sodium_memcmp(check, secret, MFAKR_SECRET_LEN) != 0)
		die("card could not unwrap the secret (%s); nothing was changed",
		    r == -EACCES ? "wrong PIN" : strerror(-r));
	sodium_memzero(check, sizeof(check));
	mfakr_wf_free(&probe);
	mfakr_p11_keys_free(keys, n);
	mfakr_p11_close(&p11);
}

static void add_fido2_slot(struct mfakr_wrapfile *wf, const uint8_t secret[MFAKR_SECRET_LEN])
{
	int r;

	if (!mfakr_fido2_supported())
		die("built without FIDO2 support");
	r = mfakr_add_fido2_slot(wf, opt_uv, &ui, secret);
	if (r < 0)
		die("cannot enrol security key: %s", strerror(-r));
}

static int cmd_enroll(void)
{
	struct mfakr_wrapfile wf;
	uint8_t secret[MFAKR_SECRET_LEN];
	char newpw[MFAKR_PASSWORD_LEN + 1], *oldpw, *err = NULL;

	if (load(&wf) == 0) {
		if (!opt_force)
			die("already enrolled; use add-piv/add-fido2, or --force to start over "
			    "(the keyring password must then be the current secret)");
		mfakr_wf_free(&wf);
	}

	oldpw = read_secret("Current login keyring password: ");
	if (!oldpw)
		die("no password given");

	mfakr_random(secret, sizeof(secret));
	if (mfakr_wf_init(&wf, me->pw_name) < 0)
		die("invalid user name");
	if (opt_fido2)
		add_fido2_slot(&wf, secret);
	else
		add_piv_slot(&wf, secret);
	if (!opt_no_password)
		add_password_slot(&wf, secret, oldpw);

	/* Write the wrap file first: a wrap file for an unchanged keyring is
	 * harmless, but a re-keyed keyring without its wrap file is lost. */
	save(&wf);
	mfakr_secret_to_password(secret, newpw);
	if (mfakr_gkr_change_password(oldpw, newpw, &err) < 0) {
		unlink(wrap_path);
		die("could not change the login keyring password: %s\n"
		    "(is the current password right?)  Nothing was changed.", err);
	}
	sodium_memzero(newpw, sizeof(newpw));
	sodium_memzero(secret, sizeof(secret));
	mfakr_free_secret_str(oldpw);
	mfakr_wf_free(&wf);
	printf("Enrolled.  The login keyring is now protected by a random secret stored in\n"
	       "%s.\n", wrap_path);
	return 0;
}

static int cmd_add(int fido2)
{
	struct mfakr_wrapfile wf;
	uint8_t secret[MFAKR_SECRET_LEN];

	load_or_die(&wf);
	recover_secret(&wf, secret, 1);
	if (fido2)
		add_fido2_slot(&wf, secret);
	else
		add_piv_slot(&wf, secret);
	sodium_memzero(secret, sizeof(secret));
	save(&wf);
	mfakr_wf_free(&wf);
	printf("Added.\n");
	return 0;
}

static int cmd_set_password(void)
{
	struct mfakr_wrapfile wf;
	uint8_t secret[MFAKR_SECRET_LEN];

	load_or_die(&wf);
	/* The point is usually that the old password slot is stale, so use a card or key. */
	recover_secret(&wf, secret, 0);
	add_password_slot(&wf, secret, NULL);
	sodium_memzero(secret, sizeof(secret));
	save(&wf);
	mfakr_wf_free(&wf);
	printf("Password slot updated.\n");
	return 0;
}

static int cmd_remove(const char *arg)
{
	struct mfakr_wrapfile wf;
	char *end;
	long idx = strtol(arg, &end, 10);
	int hardware = 0;

	load_or_die(&wf);
	if (*end || idx < 0 || idx >= wf.nslots)
		die("no slot %s (see 'mfa-keyring status')", arg);
	if (wf.nslots == 1)
		die("refusing to remove the last slot; use disenroll");
	mfakr_wf_remove_slot(&wf, idx);
	for (int i = 0; i < wf.nslots; i++)
		hardware |= strcmp(wf.slots[i].type, MFAKR_SLOT_PASSWORD) != 0;
	if (!hardware)
		fprintf(stderr, "warning: no card or security key slots remain\n");
	save(&wf);
	mfakr_wf_free(&wf);
	printf("Removed slot %ld.\n", idx);
	return 0;
}

static int cmd_unlock(void)
{
	struct mfakr_wrapfile wf;
	uint8_t secret[MFAKR_SECRET_LEN];
	char pw[MFAKR_PASSWORD_LEN + 1], *err = NULL;

	load_or_die(&wf);
	recover_secret(&wf, secret, 1);
	mfakr_secret_to_password(secret, pw);
	sodium_memzero(secret, sizeof(secret));
	if (mfakr_gkr_unlock(pw, &err) < 0)
		die("%s", err);
	sodium_memzero(pw, sizeof(pw));
	mfakr_wf_free(&wf);
	printf("Login keyring unlocked.\n");
	return 0;
}

static int cmd_disenroll(void)
{
	struct mfakr_wrapfile wf;
	uint8_t secret[MFAKR_SECRET_LEN];
	char pw[MFAKR_PASSWORD_LEN + 1], *newpw, *err = NULL;

	load_or_die(&wf);
	if (wf.zfs_dataset)
		die("%s still uses the secret as its key; run 'sudo mfa-keyring zfs-disenroll' first",
		    wf.zfs_dataset);
	recover_secret(&wf, secret, 1);
	mfakr_secret_to_password(secret, pw);
	sodium_memzero(secret, sizeof(secret));
	newpw = read_new_password("keyring password (normally your login password)");
	if (mfakr_gkr_change_password(pw, newpw, &err) < 0)
		die("%s", err);
	sodium_memzero(pw, sizeof(pw));
	mfakr_free_secret_str(newpw);
	if (unlink(wrap_path) < 0)
		die("keyring password changed, but cannot remove %s: %s", wrap_path, strerror(errno));
	mfakr_wf_free(&wf);
	printf("Disenrolled.  The login keyring now uses the password you entered.\n");
	return 0;
}

/* ---------------------------------------------------------------- ZFS --- */

struct zds {
	char name[256];
	char mountpoint[4096];
	char encroot[256];
	char keyformat[32];
	char keystatus[32];
};

/* Find a filesystem by name, or (name NULL) by mountpoint. */
static int zfs_find(const char *name, const char *mountpoint, struct zds *out)
{
	FILE *f = popen("zfs list -H -o name,mountpoint,encryptionroot,keyformat,keystatus "
	                "-t filesystem", "r");
	char line[8192];
	int found = 0;

	if (!f)
		die("cannot run zfs");
	while (!found && fgets(line, sizeof(line), f)) {
		char *save = NULL, *fld[5];
		int n = 0;

		line[strcspn(line, "\n")] = '\0';
		for (char *t = strtok_r(line, "\t", &save); t && n < 5; t = strtok_r(NULL, "\t", &save))
			fld[n++] = t;
		if (n != 5)
			continue;
		if (name ? strcmp(fld[0], name) != 0 : strcmp(fld[1], mountpoint) != 0)
			continue;
		snprintf(out->name, sizeof(out->name), "%s", fld[0]);
		snprintf(out->mountpoint, sizeof(out->mountpoint), "%s", fld[1]);
		snprintf(out->encroot, sizeof(out->encroot), "%s", fld[2]);
		snprintf(out->keyformat, sizeof(out->keyformat), "%s", fld[3]);
		snprintf(out->keystatus, sizeof(out->keystatus), "%s", fld[4]);
		found = 1;
	}
	pclose(f);
	return found ? 0 : -ENOENT;
}

/* Runs zfs with argv, feeding input (a passphrase) on stdin.  Returns the exit status. */
static int run_zfs(const char *const *argv, const char *input)
{
	int fds[2], status;
	pid_t pid;

	if (pipe(fds) < 0)
		die("pipe: %s", strerror(errno));
	pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		dup2(fds[0], STDIN_FILENO);
		close(fds[0]);
		close(fds[1]);
		execvp("zfs", (char *const *) argv);
		_exit(127);
	}
	close(fds[0]);
	if (input) {
		size_t len = strlen(input);
		if (write(fds[1], input, len) != (ssize_t) len || write(fds[1], "\n", 1) != 1)
			fprintf(stderr, "short write to zfs\n");
	}
	close(fds[1]);
	if (waitpid(pid, &status, 0) < 0)
		die("waitpid: %s", strerror(errno));
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

static void zfs_resolve(const struct mfakr_wrapfile *wf, struct zds *ds)
{
	const char *name = opt_dataset ? opt_dataset : wf ? wf->zfs_dataset : NULL;

	if (zfs_find(name, me->pw_dir, ds) < 0)
		die(name ? "ZFS dataset %s not found" : "no ZFS dataset is mounted at %s%s",
		    name ? name : me->pw_dir, name ? "" : " (use --dataset)");
	if (strcmp(ds->encroot, ds->name) != 0)
		die("%s is not its own encryption root (it inherits its key from %s); "
		    "only a per-user encrypted home can use the secret", ds->name, ds->encroot);
	if (strcmp(ds->keyformat, "passphrase") != 0)
		die("%s has keyformat=%s; pam_zfs_key needs keyformat=passphrase",
		    ds->name, ds->keyformat);
}

/* Loads the dataset key with passphrase if needed.  Returns 1 if we loaded it. */
static int zfs_ensure_loaded(const struct zds *ds, const char *passphrase)
{
	const char *argv[] = { "zfs", "load-key", ds->name, NULL };

	if (strcmp(ds->keystatus, "available") == 0)
		return 0;
	if (run_zfs(argv, passphrase) != 0)
		die("could not load the key for %s", ds->name);
	return 1;
}

static void zfs_unload(const struct zds *ds)
{
	const char *argv[] = { "zfs", "unload-key", ds->name, NULL };

	if (run_zfs(argv, NULL) != 0)
		fprintf(stderr, "warning: could not unload the key for %s again\n", ds->name);
}

static int zfs_change_key(const struct zds *ds, const char *passphrase)
{
	const char *argv[] = { "zfs", "change-key", "-o", "keyformat=passphrase",
	                       "-o", "keylocation=prompt", ds->name, NULL };

	return run_zfs(argv, passphrase);
}

/* Creates MFAKR_STATE_DIR/<user>/ owned by the user, mode 0700. */
static void ensure_user_state_dir(void)
{
	char dir[4096];
	struct stat st;

	if (mkdir(MFAKR_STATE_DIR, 0755) < 0 && errno != EEXIST)
		die("cannot create %s: %s", MFAKR_STATE_DIR, strerror(errno));
	snprintf(dir, sizeof(dir), "%s/%s", MFAKR_STATE_DIR, me->pw_name);
	if (mkdir(dir, 0700) < 0 && errno != EEXIST)
		die("cannot create %s: %s", dir, strerror(errno));
	if (lstat(dir, &st) < 0 || !S_ISDIR(st.st_mode))
		die("%s is not a directory", dir);
	if (st.st_uid != me->pw_uid && chown(dir, me->pw_uid, me->pw_gid) < 0)
		die("cannot chown %s: %s", dir, strerror(errno));
	if (chmod(dir, 0700) < 0)
		die("cannot chmod %s: %s", dir, strerror(errno));
}

static void require_root(const char *cmd)
{
	if (geteuid() != 0)
		die("%s must run as root: sudo mfa-keyring %s", cmd, cmd);
}

static int cmd_zfs_enroll(void)
{
	struct mfakr_wrapfile wf;
	struct zds ds;
	uint8_t secret[MFAKR_SECRET_LEN];
	char pw[MFAKR_PASSWORD_LEN + 1], prompt[512], *cur = NULL, *old_path;
	int loaded = 0;

	require_root("zfs-enroll");
	load_or_die(&wf);
	if (wf.zfs_dataset)
		die("already enrolled for ZFS dataset %s", wf.zfs_dataset);
	zfs_resolve(&wf, &ds);
	if (mfakr_wf_count(&wf, MFAKR_SLOT_PASSWORD) == 0)
		fprintf(stderr, "warning: no password slot, so password logins (console, SSH) "
		        "will not be able to mount %s\n", ds.mountpoint);

	recover_secret(&wf, secret, 1);
	mfakr_secret_to_password(secret, pw);
	sodium_memzero(secret, sizeof(secret));

	if (strcmp(ds.keystatus, "available") != 0) {
		snprintf(prompt, sizeof(prompt), "Current passphrase for %s "
		         "(normally %s's login password): ", ds.name, me->pw_name);
		cur = read_secret(prompt);
		if (!cur)
			die("no passphrase given");
		loaded = zfs_ensure_loaded(&ds, cur);
		mfakr_free_secret_str(cur);
	}

	/* The home is not mounted when pam_mfa_keyring needs the wrap file, so
	 * it moves to the system location before the key changes. */
	ensure_user_state_dir();
	old_path = wrap_path;
	wrap_path = system_path;
	if (mfakr_wf_set_zfs(&wf, ds.name) < 0)
		die("invalid dataset name");
	save(&wf);

	if (zfs_change_key(&ds, pw) != 0) {
		if (strcmp(old_path, wrap_path) != 0) {
			mfakr_unlink_user_file(wrap_path, me->pw_uid, me->pw_gid);
		} else {
			mfakr_wf_set_zfs(&wf, NULL);
			save(&wf);
		}
		if (loaded)
			zfs_unload(&ds);
		die("zfs change-key failed; %s still uses its old passphrase", ds.name);
	}
	sodium_memzero(pw, sizeof(pw));
	if (strcmp(old_path, wrap_path) != 0) {
		int r = mfakr_unlink_user_file(old_path, me->pw_uid, me->pw_gid);
		if (r < 0 && r != -ENOENT)
			fprintf(stderr, "warning: could not remove %s: %s (it is no longer used)\n",
			        old_path, strerror(-r));
	}
	if (loaded)
		zfs_unload(&ds);
	mfakr_wf_free(&wf);
	printf("%s is now unlocked by the same secret as the keyring.\n"
	       "Wrap file moved to %s.\n", ds.name, wrap_path);
	return 0;
}

static int cmd_zfs_disenroll(void)
{
	struct mfakr_wrapfile wf;
	struct zds ds;
	uint8_t secret[MFAKR_SECRET_LEN];
	char pw[MFAKR_PASSWORD_LEN + 1], what[512], *newpw;
	int loaded;

	require_root("zfs-disenroll");
	load_or_die(&wf);
	if (!wf.zfs_dataset)
		die("not enrolled for ZFS");
	zfs_resolve(&wf, &ds);

	recover_secret(&wf, secret, 1);
	mfakr_secret_to_password(secret, pw);
	sodium_memzero(secret, sizeof(secret));
	loaded = zfs_ensure_loaded(&ds, pw);
	sodium_memzero(pw, sizeof(pw));

	snprintf(what, sizeof(what), "passphrase for %s (normally %s's login password)",
	         ds.name, me->pw_name);
	newpw = read_new_password(what);
	if (zfs_change_key(&ds, newpw) != 0) {
		if (loaded)
			zfs_unload(&ds);
		die("zfs change-key failed; %s still uses the secret", ds.name);
	}
	mfakr_free_secret_str(newpw);
	mfakr_wf_set_zfs(&wf, NULL);
	save(&wf);
	if (loaded)
		zfs_unload(&ds);
	mfakr_wf_free(&wf);
	printf("%s now uses the passphrase you entered.\n", ds.name);
	return 0;
}

static void usage(FILE *f)
{
	fprintf(f,
	        "Usage: mfa-keyring [OPTIONS] COMMAND\n"
	        "\n"
	        "Commands:\n"
	        "  status              Show enrolled slots and whether the keyring is locked\n"
	        "  list-keys           List keys on connected PIV cards\n"
	        "  enroll              Protect the login keyring with a random secret, wrapped to a\n"
	        "                      card key (or --fido2 security key) and the login password\n"
	        "  add-piv             Add another card key\n"
	        "  add-fido2           Add a FIDO2 security key (hmac-secret)\n"
	        "  set-password        Re-create the password slot (e.g. after a password reset)\n"
	        "  remove N            Remove slot N\n"
	        "  unlock              Unlock the running login keyring with a card or key\n"
	        "  disenroll           Set a normal keyring password and delete the wrap file\n"
	        "  zfs-enroll          (root) Make the secret the key of the user's encrypted ZFS\n"
	        "                      home too, so card/key logins can mount it\n"
	        "  zfs-disenroll       (root) Give the ZFS home an ordinary passphrase again\n"
	        "\n"
	        "Options:\n"
	        "  --key ID            Card key to use: PKCS#11 id in hex (default 03, the PIV\n"
	        "                      key management key) or a keyid prefix (8+ hex digits)\n"
	        "  --fido2             enroll: use a FIDO2 security key instead of a card\n"
	        "  --uv                FIDO2: also require the security key PIN at unlock\n"
	        "  --no-password-slot  enroll: don't let the login password unlock the keyring\n"
	        "  --force             enroll: overwrite an existing wrap file\n"
	        "  --module PATH       PKCS#11 module (default %s)\n"
	        "  --file PATH         Wrap file (default %s, else %s)\n"
	        "  --user USER         (root) Work on USER's wrap file (default: $SUDO_USER)\n"
	        "  --dataset NAME      zfs-enroll: the home dataset (default: mounted at the home)\n",
	        DEFAULT_PKCS11_MODULE, DEFAULT_SYSTEM_WRAP_FILE, DEFAULT_WRAP_FILE);
}

int main(int argc, char **argv)
{
	enum { O_KEY = 256, O_FIDO2, O_UV, O_NOPW, O_FORCE, O_MODULE, O_FILE, O_USER, O_DATASET };
	static const struct option longopts[] = {
		{ "key", required_argument, NULL, O_KEY },
		{ "fido2", no_argument, NULL, O_FIDO2 },
		{ "uv", no_argument, NULL, O_UV },
		{ "no-password-slot", no_argument, NULL, O_NOPW },
		{ "force", no_argument, NULL, O_FORCE },
		{ "module", required_argument, NULL, O_MODULE },
		{ "file", required_argument, NULL, O_FILE },
		{ "user", required_argument, NULL, O_USER },
		{ "dataset", required_argument, NULL, O_DATASET },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ 0 }
	};
	const char *cmd;
	int c;

	while ((c = getopt_long(argc, argv, "hV", longopts, NULL)) != -1) {
		switch (c) {
		case O_KEY: opt_key = optarg; break;
		case O_FIDO2: opt_fido2 = 1; break;
		case O_UV: opt_uv = 1; break;
		case O_NOPW: opt_no_password = 1; break;
		case O_FORCE: opt_force = 1; break;
		case O_MODULE: opt_module = optarg; break;
		case O_FILE: opt_file = optarg; break;
		case O_USER: opt_user = optarg; break;
		case O_DATASET: opt_dataset = optarg; break;
		case 'h': usage(stdout); return 0;
		case 'V': printf("mfa-keyring %s\n", PACKAGE_VERSION); return 0;
		default: usage(stderr); return 2;
		}
	}
	if (optind >= argc) {
		usage(stderr);
		return 2;
	}
	cmd = argv[optind++];

	if (mfakr_crypto_init() < 0)
		die("cannot initialise libsodium");
	if (!opt_user && geteuid() == 0 && strncmp(cmd, "zfs-", 4) == 0)
		opt_user = getenv("SUDO_USER");
	if (opt_user) {
		if (geteuid() != 0 && strcmp(opt_user, getpwuid(getuid())->pw_name) != 0)
			die("--user needs root");
		me = getpwnam(opt_user);
	} else {
		me = getpwuid(getuid());
	}
	if (!me)
		die("cannot look up user %s", opt_user ? opt_user : "");
	if (me->pw_uid != getuid() && (strcmp(cmd, "enroll") == 0 || strcmp(cmd, "unlock") == 0 ||
	                               strcmp(cmd, "disenroll") == 0))
		die("%s talks to the user's keyring; run it as %s", cmd, me->pw_name);
	if (me->pw_uid == 0 && strncmp(cmd, "zfs-", 4) == 0)
		die("which user? use --user or run through sudo");

	system_path = mfakr_expand_path(DEFAULT_SYSTEM_WRAP_FILE, me->pw_name, me->pw_dir);
	home_path = mfakr_expand_path(DEFAULT_WRAP_FILE, me->pw_name, me->pw_dir);
	if (!system_path || !home_path)
		die("cannot build wrap file paths");
	if (opt_file) {
		wrap_path = mfakr_expand_path(opt_file, me->pw_name, me->pw_dir);
		if (!wrap_path)
			die("invalid --file path");
	} else {
		/* Same order as pam_mfa_keyring.  New enrolments go to the system
		 * location only if an administrator created the user's directory. */
		char *dir = strdup(system_path);
		struct stat st;

		wrap_path = home_path;
		if (dir && (lstat(system_path, &st) == 0 ||
		            (lstat(dirname(dir), &st) == 0 && S_ISDIR(st.st_mode))))
			wrap_path = system_path;
		free(dir);
	}

	if (strcmp(cmd, "status") == 0)
		return cmd_status();
	if (strcmp(cmd, "list-keys") == 0)
		return cmd_list_keys();
	if (strcmp(cmd, "enroll") == 0)
		return cmd_enroll();
	if (strcmp(cmd, "add-piv") == 0)
		return cmd_add(0);
	if (strcmp(cmd, "add-fido2") == 0)
		return cmd_add(1);
	if (strcmp(cmd, "set-password") == 0)
		return cmd_set_password();
	if (strcmp(cmd, "remove") == 0) {
		if (optind >= argc)
			die("remove: which slot?");
		return cmd_remove(argv[optind]);
	}
	if (strcmp(cmd, "unlock") == 0)
		return cmd_unlock();
	if (strcmp(cmd, "disenroll") == 0)
		return cmd_disenroll();
	if (strcmp(cmd, "zfs-enroll") == 0)
		return cmd_zfs_enroll();
	if (strcmp(cmd, "zfs-disenroll") == 0)
		return cmd_zfs_disenroll();
	usage(stderr);
	return 2;
}
