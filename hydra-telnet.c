#include "hydra-mod.h"
#include "hydra-telnet.h"
#include <ctype.h>

char *telcmds[] = {
  "EOF", "SUSP", "ABORT", "EOR",
  "SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
  "EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC", 0,
};

extern const unsigned char HYDRA_EXIT[5];
char *buf;
int32_t no_line_mode;

/*
 * Failure-message detection.
 *
 * Patterns are deliberately specific. Earlier revisions matched single
 * generic tokens such as "wrong", "failed" or "too many" which frequently
 * appear in legitimate banners, MOTDs and help text and therefore caused
 * spurious false-negative behaviour. We only accept phrases that are
 * unambiguously associated with an authentication failure.
 *
 * The buffer is copied and lower-cased defensively even though the
 * call-sites already lower-case their input.
 */
static int is_failure(const char *buffer) {
  char temp[4096];

  if (buffer == NULL)
    return 0;

  strncpy(temp, buffer, sizeof(temp) - 1);
  temp[sizeof(temp) - 1] = 0;
  make_to_lower(temp);

  if (strstr(temp, "incorrect") != NULL ||
      strstr(temp, "invalid") != NULL ||
      strstr(temp, "denied") != NULL ||
      strstr(temp, "bad password") != NULL ||
      strstr(temp, "bad passwords") != NULL ||
      strstr(temp, "authentication failed") != NULL ||
      strstr(temp, "authentication failure") != NULL ||
      strstr(temp, "authentication error") != NULL ||
      strstr(temp, "authorization failed") != NULL ||
      strstr(temp, "login failed") != NULL ||
      strstr(temp, "login incorrect") != NULL ||
      strstr(temp, "login failure") != NULL ||
      strstr(temp, "access denied") != NULL ||
      strstr(temp, "permission denied") != NULL ||
      strstr(temp, "wrong password") != NULL ||
      strstr(temp, "wrong login") != NULL ||
      strstr(temp, "wrong username") != NULL ||
      strstr(temp, "wrong credentials") != NULL ||
      strstr(temp, "not allowed") != NULL ||
      strstr(temp, "unable to authenticate") != NULL ||
      strstr(temp, "too many attempts") != NULL ||
      strstr(temp, "too many failures") != NULL ||
      strstr(temp, "too many tries") != NULL ||
      strstr(temp, "too many logins") != NULL ||
      strstr(temp, "user was locked") != NULL ||
      strstr(temp, "account locked") != NULL ||
      strstr(temp, "account is locked") != NULL ||
      strstr(temp, "ip has been blocked") != NULL ||
      strstr(temp, "cannot log on") != NULL ||
      strstr(temp, "please retry") != NULL ||
      strstr(temp, "please try again") != NULL ||
      strstr(temp, "please try it again") != NULL ||
      strstr(temp, "username or password") != NULL ||
      strstr(temp, "user name or password") != NULL ||
      strstr(temp, "password is incorrect") != NULL ||
      strstr(temp, "bye-bye") != NULL ||
      strstr(temp, "% bad passwords") != NULL ||
      strstr(temp, "% authentication failed") != NULL ||
      strstr(temp, "% login failure") != NULL ||
      strstr(temp, "закрыт") != NULL ||
      strstr(temp, "local: authentication failure") != NULL) {
    return 1;
  }
  return 0;
}

/*
 * Recognise password prompts. The caller is expected to have lower-cased
 * the buffer; we use hydra_strcasestr for the multilingual stem matches
 * to stay robust against partially lowered input.
 */
static int is_password_prompt(const char *buffer) {
  if (buffer == NULL)
    return 0;
  return (hydra_strcasestr(buffer, "asswor") != NULL ||
          hydra_strcasestr(buffer, "asscode") != NULL ||
          hydra_strcasestr(buffer, "ennwort") != NULL ||
          strstr(buffer, "passwd:") != NULL ||
          strstr(buffer, "pass:") != NULL ||
          strstr(buffer, "pwd:") != NULL ||
          strstr(buffer, "pin:") != NULL ||
          strstr(buffer, "пароль") != NULL ||
          strstr(buffer, "contraseña") != NULL ||
          strstr(buffer, "enter password") != NULL ||
          strstr(buffer, "password for") != NULL);
}

/*
 * Strict login-prompt detection used after credentials have been sent.
 * Kept narrow on purpose: a post-login MOTD that contains "account:" or a
 * bare "name:" must not be interpreted as the server re-asking for a
 * username, otherwise we would discard a valid credential pair.
 */
static int is_login_prompt(const char *buffer) {
  if (buffer == NULL)
    return 0;
  return ((strstr(buffer, "ogin:") != NULL && strstr(buffer, "last login") == NULL) ||
          strstr(buffer, "sername:") != NULL);
}

/*
 * Loose login-prompt detection used only while reading the initial banner
 * to decide whether the server is in password-only mode. Matching extra
 * tokens here is safe because the worst-case outcome is that a password-
 * only server is treated as a username+password server (and we then fall
 * back to sending the username, which is the documented default).
 */
static int is_login_prompt_banner(const char *buffer) {
  if (buffer == NULL)
    return 0;
  if (is_login_prompt(buffer))
    return 1;
  return (strstr(buffer, "user:") != NULL ||
          strstr(buffer, "login:") != NULL ||
          strstr(buffer, "user id:") != NULL ||
          strstr(buffer, "userid:") != NULL ||
          strstr(buffer, "account:") != NULL ||
          strstr(buffer, "логин:") != NULL ||
          strstr(buffer, "user access verification") != NULL ||
          strstr(buffer, "user name:") != NULL ||
          strstr(buffer, "name:") != NULL);
}

/*
 * Return non-zero when the buffer ends with a recognised shell-prompt
 * character (after trimming trailing whitespace and CR/LF).
 *
 * The previous implementation looked for any of '/', '$', '#', '>' or '%'
 * anywhere inside the buffer, which produced heavy false positives:
 *   - '/' is part of nearly every path printed in a MOTD,
 *   - '$' and '#' appear in pricing, version strings, comments, etc.,
 *   - '%' appears in percentages ("100% loaded"),
 *   - '>' appears in quoted text and arrows.
 *
 * Restricting the test to the final non-whitespace byte is the minimum
 * structural cue that still recognises interactive shells (bash "$"/"#",
 * csh "%", DOS/Cisco ">") while rejecting MOTD / banner false positives.
 */
static int has_shell_prompt(const char *buffer) {
  const char *p;
  size_t len;
  char last;

  if (buffer == NULL)
    return 0;

  len = strlen(buffer);
  if (len == 0)
    return 0;

  p = buffer + len - 1;
  while (p > buffer && (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t'))
    p--;

  last = *p;
  return (last == '$' || last == '#' || last == '>' || last == '%');
}

int32_t start_telnet(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[300];
  int32_t password_prompt_seen = 0;
  int32_t username_prompt_seen = 0;
  int32_t password_only = 0;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  /*
   * Read initial banners to discover which prompt the server uses.
   *
   * This phase must NEVER declare success: no credential has been sent
   * yet, so any structural cue here (a shell-prompt character inside a
   * MOTD, a path in the banner, etc.) cannot prove valid authentication
   * and was a major source of false positives in earlier revisions.
   */
  while ((buf = hydra_receive_line(s)) != NULL) {
    make_to_lower(buf);

    if (is_password_prompt(buf))
      password_prompt_seen = 1;

    if (is_login_prompt_banner(buf))
      username_prompt_seen = 1;

    free(buf);

    if (password_prompt_seen && !username_prompt_seen) {
      password_only = 1;
      break;
    }
    if (username_prompt_seen) {
      break;
    }
  }

  /* Send username only if not in password-only mode */
  if (!password_only) {
    sprintf(buffer, "%.250s\r", login);
    if (no_line_mode) {
      int32_t i;
      for (i = 0; i < strlen(buffer); i++) {
        if (buffer[i] == '\r') {
          send(s, "\r\0", 2, 0);
        } else {
          send(s, &buffer[i], 1, 0);
        }
        usleepn(20);
      }
    } else {
      if (hydra_send(s, buffer, strlen(buffer) + 1, 0) < 0)
        return 1;
    }

    /*
     * Wait for the password prompt after sending the username.
     *
     * This phase, like the banner phase above, must NEVER declare
     * success. Only two outcomes are valid here:
     *   - the server asks for a password   -> proceed to send it
     *   - the server re-prompts for a login -> the username is wrong
     */
    int32_t i = 0;
    do {
      if ((buf = hydra_receive_line(s)) == NULL)
        return 1;

      (void)make_to_lower(buf);

      if (is_password_prompt(buf))
        i = 1;

      if (i == 0 && is_login_prompt(buf)) {
        free(buf);
        hydra_completed_pair();
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
        return 2;
      }
      free(buf);
    } while (i == 0);
  }

  /* Send password */
  sprintf(buffer, "%.250s\r", pass);
  if (no_line_mode) {
    int32_t i;
    for (i = 0; i < strlen(buffer); i++) {
      if (buffer[i] == '\r') {
        send(s, "\r\0", 2, 0);
      } else {
        send(s, &buffer[i], 1, 0);
      }
      usleepn(20);
    }
  } else {
    if (hydra_send(s, buffer, strlen(buffer) + 1, 0) < 0)
      return 1;
  }

  /*
   * Response handling after the password has been sent.
   *
   * Order of checks is significant and must be:
   *   1) explicit failure message,
   *   2) password re-prompt,
   *   3) login re-prompt,
   *   4) success (operator-supplied string OR a trailing shell prompt).
   *
   * Putting success last guarantees that a single response containing
   * both a failure phrase and a stray prompt character (e.g. an error
   * banner followed by "Login:") is correctly treated as a failure.
   */
  while ((buf = hydra_receive_line(s)) != NULL) {
    make_to_lower(buf);

    /* 1) Explicit failure phrase wins over everything else. */
    if (is_failure(buf)) {
      free(buf);
      hydra_completed_pair();
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 2;
    }

    /* 2) The server re-asks for a password -> the password was wrong;
     *    feed the next candidate without dropping the connection. */
    if (is_password_prompt(buf)) {
      hydra_completed_pair();
      free(buf);
      if (strlen(pass = hydra_get_next_password()) == 0)
        pass = empty;
      sprintf(buffer, "%.250s\r", pass);
      if (no_line_mode) {
        int32_t i;
        for (i = 0; i < strlen(buffer); i++) {
          if (buffer[i] == '\r') {
            send(s, "\r\0", 2, 0);
          } else {
            send(s, &buffer[i], 1, 0);
          }
          usleepn(20);
        }
      } else {
        hydra_send(s, buffer, strlen(buffer) + 1, 0);
      }
      continue;
    }

    /* 3) The server re-asks for a username -> the whole pair is wrong;
     *    let the outer loop reconnect and try the next pair. */
    if (is_login_prompt(buf)) {
      free(buf);
      hydra_completed_pair();
      return 2;
    }

    /* 4) Success detection.
     *
     *    - If the operator supplied a success string (-m / miscptr) we
     *      require an exact substring match. This is the recommended
     *      reliable mode and the only one that gives strong guarantees
     *      against false positives.
     *    - Otherwise we accept the response only when its last
     *      non-whitespace byte is a recognised shell-prompt character.
     *      Matching the prompt at the *end* of the line (instead of
     *      anywhere inside it, as before) eliminates the bulk of the
     *      structural false positives the previous logic produced.
     */
    if (miscptr != NULL) {
      if (strstr(buf, miscptr) != NULL) {
        hydra_report_found_host(port, ip, "telnet", fp);
        hydra_completed_pair_found();
        free(buf);
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
        return 1;
      }
    } else if (has_shell_prompt(buf)) {
      hydra_report_found_host(port, ip, "telnet", fp);
      hydra_completed_pair_found();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 1;
    }

    free(buf);
  }

  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 2;
}

void service_telnet(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_TELNET, mysslport = PORT_TELNET_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  if (miscptr != NULL)
    make_to_lower(miscptr);

  while (1) {
    int32_t first = 0;
    int32_t old_waittime = waittime;

    switch (run) {
    case 1: /* connect and init */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      no_line_mode = 0;
      first = 0;

      if ((options & OPTION_SSL) == 0) {
        if (port != 0) myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      } else {
        if (port != 0) mysslport = port;
        sock = hydra_connect_ssl(ip, mysslport, hostname);
        port = mysslport;
      }

      if (sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }

      if ((buf = hydra_receive_line(sock)) == NULL) {
        hydra_report(stderr, "[ERROR] Not a TELNET protocol or service shutdown\n");
        hydra_child_exit(2);
      }

      if (hydra_strcasestr(buf, "ress ENTER") != NULL) {
        hydra_send(sock, "\r\n", 2, 0);
        free(buf);
        if ((buf = hydra_receive_line(sock)) == NULL) {
          hydra_report(stderr, "[ERROR] Not a TELNET protocol or service shutdown\n");
          hydra_child_exit(2);
        }
      }

      if (hydra_strcasestr(buf, "login") != NULL || hydra_strcasestr(buf, "sername:") != NULL) {
        waittime = 6;
        if (debug)
          hydra_report(stdout, "DEBUG: waittime set to %d\n", waittime);
      }

      /* Telnet option negotiation */
      do {
        unsigned char *buf2 = (unsigned char *)buf;
        /* bound the 3-byte IAC walk against the actual line length so a
         * server that stops 1-2 bytes mid-triple doesn't drag us OOB. */
        size_t buf_len = buf ? strlen((char *)buf) : 0;
        while (buf2 + 2 < (unsigned char *)buf + buf_len + 1 && *buf2 == IAC) {
          if (first == 0) {
            if (debug)
              hydra_report(stdout, "DEBUG: requested line mode\n");
            (void)!write(sock, "\xff\xfb\x22", 3); /* WILL LINEMODE */
            first = 1;
          }
          if ((buf[1] == '\xfc' || buf[1] == '\xfe') && buf2[2] == '\x22') {
            no_line_mode = 1;
            if (debug)
              hydra_report(stdout, "DEBUG: TELNETD peer does not like linemode!\n");
          }
          if (buf2[2] != '\x22') {
            if (buf2[1] == WILL || buf2[1] == WONT)
              buf2[1] = DONT;
            else if (buf2[1] == DO || buf2[1] == DONT)
              buf2[1] = WONT;
            (void)!write(sock, buf2, 3);
          }
          buf2 += 3;
        }
        if (buf2 != (unsigned char *)buf) {
          free(buf);
          buf = hydra_receive_line(sock);
        } else {
          buf[0] = 0;
        }
        if (buf != NULL && buf[0] != 0 && (unsigned char)buf[0] != IAC)
          make_to_lower(buf);
      } while (buf != NULL && (unsigned char)buf[0] == IAC &&
               hydra_strcasestr(buf, "ogin:") == NULL &&
               hydra_strcasestr(buf, "sername:") == NULL);

      free(buf);
      waittime = old_waittime;
      next_run = 2;
      break;

    case 2: /* cracking */
      next_run = start_telnet(sock, ip, port, options, miscptr, fp);
      break;

    case 3: /* exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;

    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_telnet_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  return 0;
}

void usage_telnet(const char *service) {
  printf("Module telnet is optionally taking the string which is displayed after\n"
         "a successful login (case insensitive). Supplying this string is the\n"
         "single most reliable way to avoid false positives and is strongly\n"
         "recommended whenever the target's post-login banner is known.\n\n"
         "Default success detection:\n"
         " - Requires an explicit failure phrase to be absent\n"
         " - Requires the response to END with a shell prompt character\n"
         "   ('$', '#', '>' or '%%'); prompt characters appearing inside the\n"
         "   buffer are no longer treated as success on their own\n"
         " - Never declares success before the password has been sent\n\n"
         "Features:\n"
         " - Automatic password-only mode detection (Cisco, embedded devices)\n"
         " - Multilingual prompt support (English, German, Russian, Spanish, ...)\n"
         " - Specific failure-message patterns to minimise misclassification\n\n"
         "For password-only servers, use: hydra -l \"\" -P passwords.txt ip telnet\n");
}
