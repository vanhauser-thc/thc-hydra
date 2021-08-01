
/*

david: module used to enum smtp users with either
VRFY, EXPN or RCPT TO command.
Optional input could be set to
VRFY, EXPN or RCPT to force the mode

login will be used as the username
passwd will be used as the domain name

*/

#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;
char *err = NULL;
int32_t tosent = 0;

#define VRFY 0
#define EXPN 1
#define RCPT 2

int32_t smtp_enum_cmd = VRFY;

int32_t start_smtp_enum(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[500];

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  while (hydra_data_ready(s) > 0) {
    if ((buf = hydra_receive_line(s)) == NULL)
      return (1);
    free(buf);
  }

  if (smtp_enum_cmd == RCPT) {
    tosent = 0;
    if (pass != empty) {
      snprintf(buffer, sizeof(buffer), "MAIL FROM: root@%s\r\n", pass);
    } else {
      snprintf(buffer, sizeof(buffer), "MAIL FROM: root\r\n");
    }
    if (debug)
      hydra_report(stderr, "DEBUG C: %s", buffer);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return (1);
    if (debug)
      hydra_report(stderr, "DEBUG S: %s", buf);
      /* good return values are something like 25x */
#ifdef HAVE_PCRE
    if (hydra_string_match(buf, "^25\\d\\s")) {
#else
    if (strstr(buf, "25") != NULL) {
#endif
      if (pass != empty) {
        snprintf(buffer, sizeof(buffer), "RCPT TO: %s@%s\r\n", login, pass);
      } else {
        snprintf(buffer, sizeof(buffer), "RCPT TO: %s\r\n", login);
      }
      tosent = 1;
    } else {
      err = strstr(buf, "Error");
      if (err) {
        if (debug) {
          hydra_report(stderr, "Server %s", err);
        }
        free(buf);
        hydra_completed_pair();
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
        return 2;
      }
    }
  } else {
    char cmd[5] = "";

    memset(cmd, 0, sizeof(cmd));
    if (smtp_enum_cmd == EXPN)
      strcpy(cmd, "EXPN");
    else
      strcpy(cmd, "VRFY");
    if (pass != empty) {
      snprintf(buffer, sizeof(buffer), "%s %s@%s\r\n", cmd, login, pass);
    } else {
      snprintf(buffer, sizeof(buffer), "%s %s\r\n", cmd, login);
    }
  }
  if (debug)
    hydra_report(stderr, "DEBUG C: %s", buffer);
  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  if ((buf = hydra_receive_line(s)) == NULL)
    return (1);
  if (debug)
    hydra_report(stderr, "DEBUG S: %s", buf);
    /* good return values are something like 25x */
#ifdef HAVE_PCRE
  if (hydra_string_match(buf, "^25\\d\\s")) {
#else
  if (strstr(buf, "25") != NULL) {
#endif
    hydra_report_found_host(port, ip, "smtp-enum", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }
  err = strstr(buf, "Error");
  if (err || tosent || strncmp(buf, "50", 2) == 0) {
    // we should report command not identified by the server
    // 502 5.5.2 Error: command not recognized
    //#ifdef HAVE_PCRE
    //    if ((debug || hydra_string_match(buf,
    //    "\\scommand\\snot\\srecognized")) && err) {
    //#else
    //    if ((debug || strstr(buf, "command") != NULL) && err) {
    //#endif
    //      hydra_report(stderr, "Server %s", err);
    //    }
    if (strncmp(buf, "500 ", 4) == 0 || strncmp(buf, "502 ", 4) == 0) {
      hydra_report(stderr,
                   "[ERROR] command is disabled on the server (choose "
                   "different method): %s",
                   buf);
      free(buf);
      return 4;
    }
    memset(buffer, 0, sizeof(buffer));
    // 503 5.5.1 Error: nested MAIL command
    strncpy(buffer, "RSET\r\n", sizeof(buffer));
    free(buf);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 1;
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
  }

  free(buf);
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 2;
}

void service_smtp_enum(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1, i = 0;
  int32_t myport = PORT_SMTP, mysslport = PORT_SMTP_SSL;
  char *buffer = "HELO hydra\r\n";

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      if ((options & OPTION_SSL) == 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      } else {
        if (port != 0)
          mysslport = port;
        sock = hydra_connect_ssl(ip, mysslport, hostname);
        port = mysslport;
      }
      if (sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      /* receive initial header */
      if ((buf = hydra_receive_line(sock)) == NULL)
        hydra_child_exit(2);
      if (strstr(buf, "220") == NULL) {
        hydra_report(stderr, "Warning: SMTP does not allow connecting: %s\n", buf);
        hydra_child_exit(2);
      }
      //      while (strstr(buf, "220 ") == NULL) {
      //        free(buf);
      //        buf = hydra_receive_line(sock);
      //      }

      //      if (buf[0] != '2') {
      if (hydra_send(sock, buffer, strlen(buffer), 0) < 0) {
        free(buf);
        hydra_child_exit(2);
      }
      //      }

      free(buf);
      if ((buf = hydra_receive_line(sock)) == NULL)
        hydra_child_exit(2);
      if (buf[0] != '2') {
        hydra_report(stderr, "Warning: SMTP does not respond correctly to HELO: %s\n", buf);
        hydra_child_exit(2);
      }

      if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
        for (i = 0; i < strlen(miscptr); i++)
          miscptr[i] = (char)toupper((int32_t)miscptr[i]);

        if (strncmp(miscptr, "EXPN", 4) == 0)
          smtp_enum_cmd = EXPN;

        if (strncmp(miscptr, "RCPT", 4) == 0)
          smtp_enum_cmd = RCPT;
      }
      if (debug) {
        hydra_report(stdout, "[VERBOSE] ");
        switch (smtp_enum_cmd) {
        case VRFY:
          hydra_report(stdout, "using SMTP VRFY command\n");
          break;
        case EXPN:
          hydra_report(stdout, "using SMTP EXPN command\n");
          break;
        case RCPT:
          hydra_report(stdout, "using SMTP RCPT TO command\n");
          break;
        }
      }
      free(buf);
      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_smtp_enum(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0) {
        sock = hydra_disconnect(sock);
      }
      hydra_child_exit(0);
      return;
    case 4: /* unsupported exit */
      if (sock >= 0) {
        sock = hydra_disconnect(sock);
      }
      hydra_child_exit(3);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_smtp_enum_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here

  return 0;
}

void usage_smtp_enum(const char *service) {
  printf("Module smtp-enum is optionally taking one SMTP command of:\n\n"
         "VRFY (default), EXPN, RCPT (which will connect using \"root\" account)\n"
         "login parameter is used as username and password parameter as the "
         "domain name\n"
         "For example to test if john@localhost exists on 192.168.0.1:\n"
         "hydra smtp-enum://192.168.0.1/vrfy -l john -p localhost\n\n");
}
