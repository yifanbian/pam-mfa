package yubico_otp

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	DefaultApiServers = []string{"api.yubico.com/wsapi/2.0/verify",
		"api2.yubico.com/wsapi/2.0/verify",
		"api3.yubico.com/wsapi/2.0/verify",
		//"api4.yubico.com/wsapi/2.0/verify",
		"api5.yubico.com/wsapi/2.0/verify"}
	dvorakToQwerty = strings.NewReplacer(
		"j", "c", "x", "b", "e", "d", ".", "e", "u", "f", "i", "g", "d", "h", "c", "i",
		"h", "j", "t", "k", "n", "l", "b", "n", "p", "r", "y", "t", "g", "u", "k", "v",
		"J", "C", "X", "B", "E", "D", ".", "E", "U", "F", "I", "G", "D", "H", "C", "I",
		"H", "J", "T", "K", "N", "L", "B", "N", "P", "R", "Y", "T", "G", "U", "K", "V")
	matchDvorak     = regexp.MustCompile(`^[jxe.uidchtnbpygkJXE.UIDCHTNBPYGK]{32,48}$`)
	matchQwerty     = regexp.MustCompile(`^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{32,48}$`)
	signatureUrlFix = regexp.MustCompile(`\+`)
)

type YubiAuth struct {
	id                string
	key               []byte
	apiServerList     []string
	useHttps          bool
	verifyCertificate bool
}

func NewYubiAuth(id string, key string) (auth *YubiAuth, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return
	}
	auth = &YubiAuth{
		id:                id,
		key:               keyBytes,
		apiServerList:     DefaultApiServers,
		useHttps:          true,
		verifyCertificate: true,
	}

	return
}

func ParseOTP(otp string) (prefix string, ciphertext string, err error) {
	if len(otp) < 32 || len(otp) > 48 {
		err = errors.New("Invalid OTP.")
		return
	}
	if matchDvorak.MatchString(otp) {
		otp = dvorakToQwerty.Replace(otp)
	}
	if !matchQwerty.MatchString(otp) {
		err = errors.New("Invalid OTP.")
		return
	}

	l := len(otp)
	prefix = otp[0 : l-32]
	ciphertext = otp[l-32 : l]
	return
}

func (ya *YubiAuth) makeNonce() string {
	rand.Seed(time.Now().UnixNano())
	k := make([]rune, 40)
	for i := 0; i < 40; i++ {
		c := rand.Intn(35)
		if c < 10 {
			c += 48 // numbers (0-9) (0+48 == 48 == '0', 9+48 == 57 == '9')
		} else {
			c += 87 // lower case alphabets (a-z) (10+87 == 97 == 'a', 35+87 == 122 = 'z')
		}
		k[i] = rune(c)
	}
	return string(k)
}

func (ya *YubiAuth) SetApiServerList(urls ...string) {
	ya.apiServerList = urls
}

func (ya *YubiAuth) getUrl(paramString string) string {
	url := "://"
	if ya.useHttps {
		url = "https" + url
	} else {
		url = "http" + url
	}
	url += ya.apiServerList[rand.Intn(len(ya.apiServerList))]
	return url + "?" + paramString
}

func (ya *YubiAuth) hmacSignature(message string, urlEncode bool) (string, error) {
	hmacenc := hmac.New(sha1.New, ya.key)
	_, err := hmacenc.Write([]byte(message))
	if err != nil {
		return "", err
	}
	signature := base64.StdEncoding.EncodeToString(hmacenc.Sum([]byte{}))
	if urlEncode {
		signature = signatureUrlFix.ReplaceAllString(signature, `%2B`)
	}
	return signature, nil
}

func (ya *YubiAuth) VerifyOTP(otp string) (bool, error) {
	_, _, err := ParseOTP(otp)
	if err != nil {
		return false, err
	}
	nonce := ya.makeNonce()
	paramSlice := make([]string, 0)
	paramSlice = append(paramSlice, "id="+ya.id)
	paramSlice = append(paramSlice, "otp="+otp)
	paramSlice = append(paramSlice, "nonce="+nonce)
	paramSlice = append(paramSlice, "sl=secure")
	sort.Strings(paramSlice)
	paramString := strings.Join(paramSlice, "&")
	if len(ya.key) > 0 {
		signature, err := ya.hmacSignature(paramString, true)
		if err != nil {
			return false, err
		}
		paramString = paramString + "&h=" + signature
	}
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	url := ya.getUrl(paramString)
	resp, err := client.Get(url)
	if err != nil {
		return false, err
	}
	bodyReader := bufio.NewReader(resp.Body)
	defer resp.Body.Close()
	resultParameters := make(map[string]string)
	for {
		line, err := bodyReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return false, err
		}

		keyvalue := strings.SplitN(line, "=", 2)
		if len(keyvalue) == 2 {
			resultParameters[keyvalue[0]] = strings.Trim(keyvalue[1], "\n\r")
		}
	}
	otpCheck, ok := resultParameters["otp"]
	if !ok || otp != otpCheck {
		return false, errors.New("Invalid response")
	}
	nonceCheck, ok := resultParameters["nonce"]
	if !ok || nonce != nonceCheck {
		return false, errors.New("Invalid response")
	}
	if len(ya.key) > 0 {
		recvsig, ok := resultParameters["h"]
		if !ok || len(recvsig) == 0 {
			return false, errors.New("Invalid response signature")
		}
		recval := make([]string, 0, len(resultParameters)-1)
		for k, v := range resultParameters {
			if k != "h" {
				recval = append(recval, k+"="+v)
			}
		}
		sort.Strings(recval)
		recvstr := strings.Join(recval, "&")
		signature, err := ya.hmacSignature(recvstr, false)
		if err != nil {
			return false, err
		}
		if recvsig != signature {
			return false, errors.New("Invalid response signature")
		}
	}
	return resultParameters["status"] == "OK", nil
}
