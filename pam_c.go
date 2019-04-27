package main

/*
#include <errno.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
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
#define PAM_CONST const

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

static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS)
    return retval;
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static char *request_pass(pam_handle_t *pamh, int echocode,
                          PAM_CONST char *prompt) {
  PAM_CONST struct pam_message msg = { .msg_style = echocode,
                                   .msg       = prompt };
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;
  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }
  return ret;
}
*/
import "C"
import (
	"unsafe"
)

func seteuid(uid int) bool {
	return C.change_euid(C.int(uid)) == C.int(0)
}

func disablePtrace() bool {
	return C.disable_ptrace() == C.int(0)
}

func requestPass(pamh *C.pam_handle_t, echocode int, prompt string) string {
	cprompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cprompt))
	v := C.request_pass(pamh, C.int(echocode), cprompt)
	defer C.free(unsafe.Pointer(v))
	ret := C.GoString(v)
	return ret
}
