/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal PAM driver for tests (run under pam_wrapper).
 *
 *   pamtest auth|chauthtok SERVICE USER
 *
 * USER "-" starts the transaction without a user, as GDM does for smartcards.
 * Prompts are answered from PAMTEST_ANSWERS (newline-separated); once those
 * run out, the answer is "PROMPTED".  Prompts and info messages go to stderr.
 * Prints "rc=<pam result> authtok=<PAM_AUTHTOK or (null)>" where PAM_AUTHTOK is
 * read back via pam_get_items.so placed at the end of the tested stack.
 */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *answers;

static char *next_answer(void)
{
	char *nl;
	char *a;

	if (!answers || !*answers)
		return strdup("PROMPTED");
	nl = strchr(answers, '\n');
	if (nl)
		*nl = '\0';
	a = strdup(answers);
	answers = nl ? nl + 1 : answers + strlen(answers);
	return a;
}

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
	struct pam_response *r = calloc(n, sizeof(*r));

	if (!r)
		return PAM_BUF_ERR;
	for (int i = 0; i < n; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			fprintf(stderr, "PROMPT: %s\n", msg[i]->msg);
			r[i].resp = next_answer();
			break;
		default:
			fprintf(stderr, "INFO: %s\n", msg[i]->msg);
		}
	}
	*resp = r;
	return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	struct pam_conv c = { conv, NULL };
	pam_handle_t *pamh;
	const char *tok;
	int rc;

	if (argc != 4) {
		fprintf(stderr, "usage: pamtest auth|chauthtok SERVICE USER\n");
		return 2;
	}
	if (getenv("PAMTEST_ANSWERS"))
		answers = strdup(getenv("PAMTEST_ANSWERS"));
	if (pam_start(argv[2], strcmp(argv[3], "-") == 0 ? NULL : argv[3], &c, &pamh) != PAM_SUCCESS)
		return 2;
	if (strcmp(argv[1], "auth") == 0)
		rc = pam_authenticate(pamh, 0);
	else
		rc = pam_chauthtok(pamh, 0);
	tok = pam_getenv(pamh, "PAM_AUTHTOK");
	printf("rc=%d authtok=%s\n", rc, tok ? tok : "(null)");
	pam_end(pamh, rc);
	return 0;
}
