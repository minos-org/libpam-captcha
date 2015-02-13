## About

[libpam-captcha](https://github.com/minos-org/libpam-captcha) is a visual text-based CAPTCHA challenge module for PAM. This is a custom version, refear to [semicomplete](http://www.semicomplete.com/projects/pam_captcha) for the original one.

<p align="center">
<img src="http://javier.io/assets/img/pam_captcha.png" alt="pam-captcha"/>
</p>

## Quick start

### On Ubuntu (only LTS releases)

1. Set up the minos archive:

   ```
   $ sudo add-apt-repository ppa:minos-archive/main
   ```

2. Install:

   ```
   $ sudo apt-get update && sudo apt-get install libpam-captcha
   ```

3. Enjoy ☺!

### On other Linux distributions + BSD

1. Type `make`

2. Copy pam_captcha.so to your pam module dir.

    - FreeBSD: /usr/lib
    - Arch: /usr/lib/security
    - Others: Find other files named `pam_*.so`

3. Configure the system

Configuration should be setup in your pam config for whatever service you want. It needs to go at the top of your pam auth stack (first entry?):

    auth       requisite     pam_captcha.so    [options]

Available options: **math**, **randomstring**. Example:

    auth       requisite     pam_captcha.so    math randomstring

`requisite` is absolutely necessary here. This keyword means that if a user fails pam_captcha, the whole auth chain is marked as failure. This ensure that users must pass the captcha challenge before being permitted to attempt any other kind of pam authentication, such as a standard login. `required` can work here too but will not break the chain. I like requisite because you cannot even attempt to authenticate via password if you don't pass the captcha.

**IMPORTANT SSHD_CONFIG NOTE FOR NON UBUNTU|MINOS SYSTEMS!**

To prevent brute-force scripts from bypassing the pam stack, you *MUST* disable `password` authentication in your sshd. Disable `password` auth and enable `keyboard-interactive` instead. To do this, put the following in your **sshd_config**:

    PasswordAuthentication no
    ChallengeResponseAuthentication yes
    UsePAM yes

If you use ssh keys to login to your server, you will not be bothered by pam_captcha because publickey authentication does not invoke PAM.
