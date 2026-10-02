/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/*
 * Talks to the running gnome-keyring-daemon on the session bus.  These return
 * 0 on success, or -1 with a malloc'd message in *err.
 */
int pivkr_gkr_change_password(const char *oldpw, const char *newpw, char **err);
int pivkr_gkr_unlock(const char *password, char **err);
/* 1 if locked, 0 if unlocked, -1 on error (e.g. no login keyring). */
int pivkr_gkr_is_locked(char **err);
