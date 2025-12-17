#include "hydra-mod.h"
#include <arpa/telnet.h>

extern char *HYDRA_EXIT;
char *buf;
int32_t no_line_mode;

/* Comprehensive failure detection - merged from all provided patterns */
static int is_failure(const char *buffer) {
  char temp[4096];
  strncpy(temp, buffer, sizeof(temp) - 1);
  temp[sizeof(temp) - 1] = 0;
  make_to_lower(temp);

  if (strstr(temp, "incorrect") != NULL ||
      strstr(temp, "invalid") != NULL ||
      strstr(temp, "failed") != NULL ||
      strstr(temp, "denied") != NULL ||
      strstr(temp, "bad password") != NULL ||
      strstr(temp, "authentication failed") != NULL ||
      strstr(temp, "login failed") != NULL ||
      strstr(temp, "login incorrect") != NULL ||
      strstr(temp, "access denied") != NULL ||
      strstr(temp, "wrong") != NULL ||
      strstr(temp, "not allowed") != NULL ||
      strstr(temp, "permission denied") != NULL ||
      strstr(temp, "unable to authenticate") != NULL ||
      strstr(temp, "information incomplete") != NULL ||
      strstr(temp, "incorrect user/password") != NULL ||
      strstr(temp, "please retry after") != NULL ||
      strstr(temp, "bad password, bye-bye") != NULL ||
      strstr(temp, "bad password,bye-bye") != NULL ||
      strstr(temp, "bad password bye-bye") != NULL ||
      strstr(temp, "login failure") != NULL ||
      strstr(temp, "user was locked") != NULL ||
      strstr(temp, "ip has been blocked") != NULL ||
      strstr(temp, "cannot log on") != NULL ||
      strstr(temp, "password is incorrect, left") != NULL ||
      strstr(temp, "authorization failed") != NULL ||
      strstr(temp, "error: authentication") != NULL ||
      strstr(temp, "error: user was locked") != NULL ||
      strstr(temp, "error: username or password") != NULL ||
      strstr(temp, "% bad passwords") != NULL ||
      strstr(temp, "% authentication failed") != NULL ||
      strstr(temp, "% login failure") != NULL ||
      strstr(temp, "bye-bye") != NULL ||
      strstr(temp, "can't resolve symbol") != NULL ||
      strstr(temp, "too many") != NULL ||
      strstr(temp, "закрыт") != NULL ||
      strstr(temp, "local: authentication failure") != NULL ||
      strstr(temp, "please try it again") != NULL ||
      strstr(temp, "username or password error") != NULL ||
      strstr(temp, "user name or password is wrong") != NULL) {
    return 1;
  }
  return 0;
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

  /* Read initial banners after negotiation to detect prompt type */
  while ((buf = hydra_receive_line(s)) != NULL) {
    make_to_lower(buf);

    /* Early success detection */
    if (strchr(buf, '/') != NULL || strchr(buf, '>') != NULL || strchr(buf, '%') != NULL ||
        strchr(buf, '$') != NULL || strchr(buf, '#') != NULL) {
      hydra_report_found_host(port, ip, "telnet", fp);
      hydra_completed_pair_found();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 1;
    }

    /* Enhanced password prompt detection (multilingual + variants) */
    if (hydra_strcasestr(buf, "asswor") != NULL || hydra_strcasestr(buf, "asscode") != NULL ||
        strstr(buf, "passwd:") != NULL || strstr(buf, "pass:") != NULL ||
        strstr(buf, "pwd:") != NULL || strstr(buf, "pin:") != NULL ||
        strstr(buf, "пароль:") != NULL || strstr(buf, "contraseña:") != NULL ||
        strstr(buf, "enter password") != NULL || strstr(buf, "password for") != NULL) {
      password_prompt_seen = 1;
    }

    /* Enhanced username/login prompt detection */
    if ((strstr(buf, "ogin:") != NULL && strstr(buf, "last login") == NULL) ||
        strstr(buf, "sername:") != NULL || strstr(buf, "user:") != NULL ||
        strstr(buf, "login:") != NULL || strstr(buf, "user id:") != NULL ||
        strstr(buf, "userid:") != NULL || strstr(buf, "account:") != NULL ||
        strstr(buf, "логин:") != NULL || strstr(buf, "user access verification") != NULL ||
        strstr(buf, "name:") != NULL || strstr(buf, "user name:") != NULL) {
      username_prompt_seen = 1;
    }

    free(buf);

    if (password_prompt_seen && !username_prompt_seen) {
      password_only = 1;
      break;
    }
    if (username_prompt_seen) {
      break;  /* We need to send login */
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
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0)  /* Note: removed +1 to match common practice */
        return 1;
    }
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
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 1;
  }

  /* Response handling after password */
  while ((buf = hydra_receive_line(s)) != NULL) {
    make_to_lower(buf);

    /* Success detection */
    if ((miscptr != NULL && strstr(buf, miscptr) != NULL) ||
        (miscptr == NULL && 
         (strchr(buf, '/') != NULL || strchr(buf, '>') != NULL ||
          strchr(buf, '$') != NULL || strchr(buf, '#') != NULL ||
          strchr(buf, '%') != NULL || 
          (buf[1] == '\xfd' && buf[2] == '\x18')))) {
      hydra_report_found_host(port, ip, "telnet", fp);
      hydra_completed_pair_found();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 1;
    }

    /* Failure detection using comprehensive patterns */
    if (is_failure(buf)) {
      free(buf);
      hydra_completed_pair();
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 2;
    }

    /* Re-prompt for password -> try next password */
    if (hydra_strcasestr(buf, "asswor") != NULL || strstr(buf, "passwd:") != NULL ||
        strstr(buf, "pass:") != NULL || strstr(buf, "pwd:") != NULL) {
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
        hydra_send(s, buffer, strlen(buffer), 0);
      }
      continue;
    }

    /* Re-prompt for login -> restart entire pair */
    if (strstr(buf, "ogin:") != NULL || strstr(buf, "sername:") != NULL) {
      free(buf);
      hydra_completed_pair();
      return 2;
    }

    free(buf);
  }

  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 2;
}

void service_telnet(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1, fck;
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

      if (hydra_strcasestr(buf, "login") != NULL || hydra_strcasestr(buf, "sername:") != NULL)
        waittime = 6;

      /* Telnet option negotiation */
      do {
        unsigned char *buf2 = (unsigned char *)buf;

        while (*buf2 == IAC) {
          if (first == 0) {
            fck = write(sock, "\xff\xfb\x22", 3); /* WILL LINEMODE */
            first = 1;
          }
          if ((buf[1] == '\xfc' || buf[1] == '\xfe') && buf2[2] == '\x22')
            no_line_mode = 1;

          if (buf2[2] != '\x22') {
            if (buf2[1] == WILL || buf2[1] == WONT)
              buf2[1] = DONT;
            else if (buf2[1] == DO || buf2[1] == DONT)
              buf2[1] = WONT;
            fck = write(sock, buf2, 3);
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
      } while (buf != NULL && (unsigned char)buf[0] == IAC);

      /* Drain remaining banner lines (helps password-only detection) */
      while ((buf = hydra_receive_line(sock)) != NULL && strlen(buf) > 0 && (unsigned char)buf[0] != IAC) {
        free(buf);
      }
      if (buf) free(buf);

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
         "a successful login (case insensitive), useful if default detection has false positives.\n\n"
         "This improved version features:\n"
         " - Automatic password-only mode detection and handling (e.g., Cisco, embedded devices)\n"
         " - Multilingual prompt support (English, Russian, Spanish, etc.)\n"
         " - Extensive failure message detection to avoid false positives\n"
         "For password-only servers, use: hydra -l \"\" -P passwords.txt ip telnet\n");
}
