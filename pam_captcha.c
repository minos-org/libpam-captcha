/* pam_captcha - A Visual text-based CAPTCHA challenge module for PAM
 * Jordan Sissel <jls@semicomplete.com> 
 * 
 * Version 1.5 (July 2010)
 *
 * Released under the BSD license. 
 *
 * If you use or make changes to pam_captcha, shoot me an email or something. I
 * always like to hear how people use my software :) And no, you don't have to
 * do it. Nor do you have to send me patches, though patches are appreciated.
 *
 * Requirements:
 *   - Figlet
 *   - OpenPAM or Linux-PAM (Linux and FreeBSD known to work)
 *
 * Notes: 
 *    - I have tested this in FreeBSD and Linux. It works there.
 *    - It will not build under Solaris 9, and I have no intentions of
 *      fixing that at this time
 *
 * Installation Instructions
 *   - Just type 'make' (assuming you downloaded the Makefile too)
 *   - Copy pam_captcha.so to your pam module dir.
 *       FreeBSD: /usr/lib
 *       Ubuntu: /lib/security
 *       Others: Find other files named 'pam_*.so'
 *
 *   - Place this entry in your pam config for whatever service you want. It
 *     needs to go at the top of your pam auth stack (first entry?):
 *
 *     auth       requisite     pam_captcha.so    [options]
 *
 * Available options: math, randomstring
 * Example:
 *   - Enable 'math' and 'randomstring' captchas:
 *     auth       requisite     pam_captcha.so    math randomstring
 *
 * 'requisite' is absolutely necessary here. This keyword means that if a user
 * fails pam_captcha, the whole auth chain is marked as failure.  This ensure
 * that users must pass the captcha challenge before being permitted to attempt
 * any other kind of pam authentication, such as a standard login. 'required'
 * can work here too but will not break the chain. I like requisite because you
 * cannot even attempt to authenticate via password if you don't pass the
 * captcha.
 *
 * IMPORTANT SSHD_CONFIG NOTE!
 *   To prevent brute-force scripts from bypassing the pam stack, you MUST
 *   disable 'password' authentication in your sshd. Disable 'password' auth
 *   and enable 'keyboard-interactive' instead.
 *
 *   To do this, put the following in your sshd_config
 *   PasswordAuthentication no
 *   ChallengeResponseAuthentication yes
 *
 * If you use ssh keys to login to your server, you will not be bothered by
 * pam_captcha becuase publickey authentication does not invoke PAM.
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <time.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <dirent.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

static char *fonts[] = { "standard", "big" };

#define BUFFERSIZE 10240
const char alphabet[] = "ABCDEFGHJKMNOPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";

static void paminfo(pam_handle_t *pamh, char *fmt, ...);
static void pamvprompt(pam_handle_t *pamh, int style, char **resp, char *fmt, va_list ap);
static int math_captcha(pam_handle_t *pamh, int flags, int argc, const char *argv[]);
static int randomstring_captcha(pam_handle_t *pamh, int flags, int argc, const char *argv[]);

typedef int (*captcha_func_t)(pam_handle_t *, int, int, const char **);


static const struct captcha_entry {
  char *name;
  captcha_func_t func;
} all_captchas[] = {
  { "math", math_captcha, },
  { "randomstring", randomstring_captcha, },
  { NULL, NULL, },
};

static void init_captcha_list(pam_handle_t *pamh, captcha_func_t **captcha_list, 
                              int *num_captchas, const int argc, const char **argv) {
  const char *opt;
  int len = 10;
  int x, y;

  *num_captchas = 0;

  //syslog(LOG_INFO, "no captcha list specified in pam config. Please set 'captchas=\"math\"' or something.");

  *captcha_list = malloc(len * sizeof(captcha_func_t));
  memset(*captcha_list, 0, len * sizeof(captcha_func_t));

  for (y = 0; y < argc; y++) {
    //if (openpam_get_option(pamh, optlist[y]) == NULL)
      //continue;
    opt = argv[y];

    for (x = 0; all_captchas[x].name != NULL; x++) {
      syslog(LOG_INFO, "%s vs %s", opt, all_captchas[x].name);
      if (!strcmp(opt, all_captchas[x].name)) {
        syslog(LOG_INFO, "Matched opt %s", opt);
        (*captcha_list)[(*num_captchas)++] = all_captchas[x].func;
      }
    }
    if (*num_captchas == len) {
      syslog(LOG_INFO, "BLAH");
      len *=2;
      *captcha_list = realloc(*captcha_list, len * sizeof(captcha_func_t));
      /* Zero the new memory */
      memset(*captcha_list + *num_captchas, 0, *num_captchas * sizeof(captcha_func_t));
    }
  }

}

static void figlet(pam_handle_t *pamh, char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);

  char *key;
  FILE *fp = NULL;
  char *buffer, *bp;

  int i;
  char *font = fonts[rand() % (sizeof(fonts) / sizeof(*fonts))];

  vasprintf(&key, fmt, ap);

  buffer = calloc(BUFFERSIZE, 1);
  srand(time(NULL));

  sprintf(buffer, "env PATH=$PATH:/usr/local/bin figlet -f %s -- '%s'", font, key);
  fp = popen(buffer, "r");
  i = 0;
  while (!feof(fp)) {
    int bytes;
    bytes = fread(buffer+i, 1, 1024, fp);
    if (bytes > 0)
      i += bytes;

    /* Ooops, our challenge description is too large */
    if (i > BUFFERSIZE)
      return;
  }

  i = 0;
  bp = buffer;
  while (1) {
    char *ptr = strchr(bp, '\n');
    *ptr = '\0';
    paminfo(pamh, "%s", bp);
    bp = ptr + 1;
    if (*bp == '\0')
      break;
  }

  free(buffer);
  pclose(fp);
}

static void pamprompt(pam_handle_t *pamh, int style, char **resp, char *fmt, ...) {/*{{{*/
  va_list ap;
  va_start(ap, fmt);
  pamvprompt(pamh, style, resp, fmt, ap);
  va_end(ap);
}/*}}}*/

static void pamvprompt(pam_handle_t *pamh, int style, char **resp, char *fmt, va_list ap) {/*{{{*/
  struct pam_conv *conv;
  struct pam_message msg;
  const struct pam_message *msgp;
  struct pam_response *pamresp;
  int pam_err;
  char *text = "";

  vasprintf(&text, fmt, ap);

  pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  pam_set_item(pamh, PAM_AUTHTOK, NULL);

  msg.msg_style = style;;
  msg.msg = text;
  msgp = &msg;
  pamresp = NULL;
  pam_err = (*conv->conv)(1, &msgp, &pamresp, conv->appdata_ptr);

  if (pamresp != NULL) {
    if (resp != NULL)
      *resp = pamresp->resp;
    else
      free(pamresp->resp);
    free(pamresp);
  }

  free(text);
}/*}}}*/

static void paminfo(pam_handle_t *pamh, char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  pamvprompt(pamh, PAM_TEXT_INFO, NULL, fmt, ap);
  va_end(ap);
}

/* Simple math captcha {{{ */
static int math_captcha(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
  int x, y, z, answer = 0;
  static char *ops = "+-*";
  char op = ops[rand() % strlen(ops)];
  char *resp = NULL;
  x = rand() % 1000 + 100;
  y = rand() % 1000 + 100;

  figlet(pamh, "%d %c %d", x, op, y);

  pamprompt(pamh, PAM_PROMPT_ECHO_ON, &resp, "Answer: ");
  z = atoi(resp);

  switch (op) {
    case '+': answer = x + y; break;
    case '-': answer = x - y; break;
    case '*': answer = x * y; break;
  }

  if (answer != z)
    return PAM_PERM_DENIED;

  return PAM_SUCCESS;
}/*}}}*/

/* String Generation Captcha {{{ */
static int randomstring_captcha(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
  char key[9];
  char *resp;
  int i = 0;
  int ret = PAM_SUCCESS;

  for (i = 0; i < 8; i++) 
    key[i] = alphabet[rand() % strlen(alphabet)];
  key[8] = 0;

  figlet(pamh, key);
  pamprompt(pamh, PAM_PROMPT_ECHO_ON, &resp, "Answer: ");

  if (strcmp(resp, key) != 0)
    ret = PAM_PERM_DENIED;

  /* Should we be freeing this? */
  free(resp);
  return ret;
}/*}}}*/

//static int (*captchas[])(pam_handle_t *, int, int, const char **);// = {
  //randomstring_captcha,
  //math_captcha,
//};

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
  int r;
  int ret;
  char *user, *host;
  pam_get_item(pamh, PAM_USER, (const void **)&user);
  pam_get_item(pamh, PAM_RHOST, (const void **)&host);

  /* Captcha function array */
  captcha_func_t *captchas;
  int num_captchas = 0;

  srand(time(NULL)); /* XXX: Should we seed by something less predictable? */

  /* XXX: Uncomment this to have the screen cleared before proceeding */
  //paminfo(pamh, "[2J[0;0H");

  openlog("pam_captcha", 0, LOG_AUTHPRIV);

  init_captcha_list(pamh, &captchas, &num_captchas, argc, argv);

  r = rand() % num_captchas;
  ret = captchas[r](pamh, flags, argc, argv);

  if (ret != PAM_SUCCESS) {
    syslog(LOG_INFO, "User %s failed to pass captcha (from %s)", user, host);
    sleep(3); /* Irritation! */
  } else {
    syslog(LOG_INFO, "User %s passed captcha (from %s)", user, host);
  }

  closelog();
  return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_captcha");
#endif
