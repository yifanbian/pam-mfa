package main

import (
	"fmt"
	"github.com/GeertJohan/yubigo"
	"github.com/dgryski/dgoogauth"
	"io"
	"strings"
)

func authenticateYubicoOTP(w io.Writer, yubico_otp_id string) bool {
	yubiAuth, err := yubigo.NewYubiAuth(yubicoOtpId, yubicoOtpSecret)
	if err != nil {
		pamLog("Unable to setup Yubico OTP Auth")
		return false
	}
	fmt.Fprintf(w, "YubiKey OTP: ")
	yubico_otp, err := ReadPasswordFromStdin()
	if err != nil {
		return false
	}
	if !strings.HasPrefix(yubico_otp, yubico_otp_id) {
		return false
	}
	_, ok, err := yubiAuth.Verify(yubico_otp)
	if err != nil {
		return false
	}
	return ok
}

func authenticateTOTP(w io.Writer, totp_secret string) bool {
	totp_secret = strings.ToUpper(totp_secret)
	totp_config := dgoogauth.OTPConfig{
		Secret:     totp_secret,
		WindowSize: totpWindow,
		UTC:        true,
	}
	fmt.Fprintf(w, "TOTP Code: ")
	totp_code, err := ReadPasswordFromStdin()
	if err != nil {
		return false
	}
	ok, err := totp_config.Authenticate(strings.TrimSpace(totp_code))
	if err != nil {
		return false
	}
	return ok
}
