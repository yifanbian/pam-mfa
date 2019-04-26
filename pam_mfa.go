// +build darwin linux

package main

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/user"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	configFile = ".mfa.yml"
	yubicoOtpId = ""
	yubicoOtpSecret = ""
	totpWindow = 5
)

type AuthResult int

const (
	AuthError AuthResult = iota
	AuthSuccess
)

func pamLog(format string, args ...interface{}) {
	l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, "pam-ussh")
	if err != nil {
		return
	}
	l.Warning(fmt.Sprintf(format, args...))
}

func authenticate(w io.Writer, uid int, username string) AuthResult {
	origEUID := os.Geteuid()
	if os.Getuid() != origEUID || origEUID == 0 {
		if !seteuid(uid) {
			pamLog("error dropping privs from %d to %d", origEUID, uid)
			return AuthError
		}
		defer func() {
			if !seteuid(origEUID) {
				pamLog("error resetting uid to %d", origEUID)
			}
		}()
	}
	usr, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		pamLog("error looking for user %d", uid)
		return AuthError
	}
	config, err := ReadYAML(path.Join(usr.HomeDir, configFile))
	if err != nil {
		pamLog("error reading configuration file")
		return AuthError
	}
	auth_pref := config["auth_preference"].([]interface{})
	if len(auth_pref) == 0 {
		pamLog("MFA is not configured for user %s, so access denied.", usr.Username)
		return AuthError
	}
	pamLog("Start MFA challenge for user %s", usr.Username)
	for _, amthd := range auth_pref {
		auth_method := amthd.(string)
		auth_result := false
		switch auth_method {
		case "yubico_otp":
			auth_result = authenticateYubicoOTP(w, config["yubico_otp_id"].(string))
		case "totp":
			auth_result = authenticateTOTP(w, config["totp_key"].(string))
		}
		fmt.Fprintf(w, "\n")
		if auth_result {
			pamLog("User %s passed MFA method %s.", usr.Username, auth_method)
			return AuthSuccess
		} else {
			time.Sleep(3 * time.Second)
			pamLog("User %s failed MFA method %s, turning to next method", usr.Username, auth_method)
		}
	}
	pamLog("All MFA methods failed for user %s.", usr.Username)
	return AuthError
}

func pamAuthenticate(w io.Writer, uid int, username string, argv []string) AuthResult {
	runtime.GOMAXPROCS(1)

	for _, arg := range argv {
		opt := strings.SplitN(arg, "=", 2)
		switch opt[0] {
		case "yubico_otp_id":
			yubicoOtpId = opt[1]
		case "yubico_otp_secret":
			yubicoOtpSecret = opt[1]
		case "totp_window":
			totpWindow, _ = strconv.Atoi(opt[1])
		}
	}

	return authenticate(w, uid, username)
}

func main() {}
