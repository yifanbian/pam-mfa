# pam-mfa

This is a pam module that will authenticate user through the second factor.

Currently we support user to authenticate with YubiKey OTP or Time-based OTP.

## Usage

```bash
# Install dependencies
go mod tidy

go build -buildmode=c-shared -o pam_mfa.so

mkdir -p /lib/security
cp pam_mfa.so /lib/security
```

## Global Configuration

In `/etc/pam.d/sshd`, append the line below after the line includes `common-auth`:

```
auth required /lib/security/pam_mfa.so
```

Currently, this module supports 3 parameters:

- `yubico_otp_id` and `yubico_otp_secret`: It's the credential that will be used to communicate with YubiCloud to verify YubiKey OTP tokens.
- `totp_window`: TOTP validation mercy window. It allows server to check few seconds around the current time.

For now, this module doesn't support self-hosted validation servers. That feature may be implemented in future.
 
A pam configuration line with params looks like:

```
auth required /lib/security/pam_mfa.so yubico_otp_id=12345 yubico_otp_secret=somesecret totp_window=5
```

## User Configuration

User configurations are located in their home directories, and the configuration filename is `.mfa.yml`.

We provide you an example configuration file in `example.yml`.

User can set their YubiKey OTP ID and TOTP key here, and control the order of MFA methods.

## Contributing

We'd like to have you contributing to this project. Contributions can make this project better and more functional.

If you want to make code contributions, fork this repository, make changes in your forked repository, then start a Pull Request.

If you found bugs in this project, you an open an issue or contribute your code by making PR.

## License

This project is under MIT License, with Anti-996 restrictions.

We do not want corporations which does not obey labor-related laws of their jurisdictions to use this project. 
Hereby we want to convey a clear message that all labors' rights must be respected and satisfied.

For further information of Anti-996 movement, please check out [this repository](https://github.com/996icu/996.ICU). 

## Credits

In this project, we use some third-party libraries to implement some functions.

- `github.com/GeertJohan/yubigo`: Used to handle Yubico OTP verifications. BSD 2-Clause Simplified License.
- `github.com/dgryski/dgoogauth`: Used to verify TOTP codes. License unclear.
- `github.com/uber/pam-ussh`: Inspiration of this project, and we used some code of it. MIT License.
