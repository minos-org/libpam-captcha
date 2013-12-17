pam:
	gcc $(CFLAGS) -Wunused -c -fPIC -DHAVE_SHADOW -O2 pam_captcha.c
	gcc $(LDFLAGS) -o pam_captcha.so -s -lpam -lcrypt --shared pam_captcha.o
clean:
	find . -type f -a -not -iname "*.c" -a -not -iname "make*" -a -not -iname "readme*" -exec rm -rf '{}' \; -exec echo rm -rf '{}' \;
