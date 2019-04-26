package main

/*
#include <errno.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __APPLE__
  #include <sys/ptrace.h>
#elif __linux__
  #include <sys/prctl.h>
#endif
char *string_from_argv(int i, char **argv) {
  return strdup(argv[i]);
}
char *get_user(pam_handle_t *pamh) {
  if (!pamh)
    return NULL;
  int pam_err = 0;
  const char *user;
  if ((pam_err = pam_get_item(pamh, PAM_USER, (const void**)&user)) != PAM_SUCCESS)
    return NULL;
  return strdup(user);
}
int get_uid(char *user) {
  if (!user)
    return -1;
  struct passwd pw, *result;
  char buf[8192];
  int i = getpwnam_r(user, &pw, buf, sizeof(buf), &result);
  if (!result || i != 0)
    return -1;
  return pw.pw_uid;
}
char *get_username(int uid) {
  if (uid < 0)
    return NULL;
  struct passwd pw, *result;
  char buf[8192];
  int i = getpwuid_r(uid, &pw, buf, sizeof(buf), &result);
  if (!result || i != 0)
    return NULL;
  return strdup(pw.pw_name);
}
int change_euid(int uid) {
  return seteuid(uid);
}
int disable_ptrace() {
#ifdef __APPLE__
  return ptrace(PT_DENY_ATTACH, 0, 0, 0);
#elif __linux__
  return prctl(PR_SET_DUMPABLE, 0);
#endif
  return 1;
}
*/
import "C"

func seteuid(uid int) bool {
	return C.change_euid(C.int(uid)) == C.int(0)
}

func disablePtrace() bool {
	return C.disable_ptrace() == C.int(0)
}
