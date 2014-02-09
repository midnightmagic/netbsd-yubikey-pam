netbsd-yubikey-pam
==================

NetBSD Yubikey authenticator for native NetBSD PAM.

Installation is simple (and equally simple to strip back out again.)

Simply clone the repo, then:

cd netbsd-yubikey-pam
./c

This will build and install the authenticator module into:

/usr/lib/security/pam_yubi.so.1

This is the only file that is installed.

Next, to have PAM actually use the new authenticator, you need to add it into
/etc/pam.d/whatever (where "whatever" is "sshd" for example.)

Here's an example:

auth            sufficient      pam_yubi.so     no_warn debug try_first_pass id=1 key=someAPIkeyYOUgenBEFORE= url=http://A.B.C.D:8000/wsapi/2.0/verify?id=%d&otp=%s

So here we have the API key which you generate as per Yubico's normal
instructions, and then the actual yubiserve.py URL.

This PAM authenticator respects ~/.yubico/authorized_keys as per the
Linux PAM authenticator.

WARNING: This is proof-of-concept ONLY. Note the presence of strtok() and
strcmp().
