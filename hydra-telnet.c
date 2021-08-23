#include "hydra-mod.h"
#include <arpa/telnet.h>

extern char *HYDRA_EXIT;
char *buf;
int32_t no_line_mode;

int32_t start_telnet(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[300];
  int32_t i = 0;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  sprintf(buffer, "%.250s\r", login);

  if (no_line_mode) {
    for (i = 0; i < strlen(buffer); i++) {
      if (strcmp(&buffer[i], "\r") == 0) {
        send(s, "\r\0", 2, 0);
      } else {
        send(s, &buffer[i], 1, 0);
      }
      usleepn(20);
    }
  } else {
    if (hydra_send(s, buffer, strlen(buffer) + 1, 0) < 0) {
      return 1;
    }
  }

  do {
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;

    if (strchr(buf, '/') != NULL || strchr(buf, '>') != NULL || strchr(buf, '%') != NULL || strchr(buf, '$') != NULL || strchr(buf, '#') != NULL) {
      hydra_report_found_host(port, ip, "telnet", fp);
      hydra_completed_pair_found();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 1;
    }
    (void)make_to_lower(buf);

    if (hydra_strcasestr(buf, "asswor") != NULL || hydra_strcasestr(buf, "asscode") != NULL || hydra_strcasestr(buf, "ennwort") != NULL)
      i = 1;
    if (i == 0 && ((strstr(buf, "ogin:") != NULL && strstr(buf, "last login") == NULL) || strstr(buf, "sername:") != NULL)) {
      free(buf);
      hydra_completed_pair();
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 2;
    }
    free(buf);
  } while (i == 0);

  sprintf(buffer, "%.250s\r", pass);
  if (no_line_mode) {
    for (i = 0; i < strlen(buffer); i++) {
      if (strcmp(&buffer[i], "\r") == 0) {
        send(s, "\r\0", 2, 0);
      } else {
        send(s, &buffer[i], 1, 0);
      }
      usleepn(20);
    }
  } else {
    if (hydra_send(s, buffer, strlen(buffer) + 1, 0) < 0) {
      return 1;
    }
  }

  /*win7 answering with do terminal type = 0xfd 0x18 */
  while ((buf = hydra_receive_line(s)) != NULL && make_to_lower(buf) && (strstr(buf, "password:") == NULL || strstr(buf, "login:") == NULL || strstr(buf, "last login:") != NULL) && strstr(buf, "sername:") == NULL) {
    if ((miscptr != NULL && strstr(buf, miscptr) != NULL) || (miscptr == NULL && strstr(buf, "invalid") == NULL && strstr(buf, "incorrect") == NULL && strstr(buf, "bad ") == NULL && (strchr(buf, '/') != NULL || strchr(buf, '>') != NULL || strchr(buf, '$') != NULL || strchr(buf, '#') != NULL || strchr(buf, '%') != NULL || ((buf[1] == '\xfd') && (buf[2] == '\x18'))))) {
      hydra_report_found_host(port, ip, "telnet", fp);
      hydra_completed_pair_found();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 1;
    } else if (buf && strstr(buf, "assword:")) {
      hydra_completed_pair();
      // printf("password prompt\n");
      free(buf);
      if (strlen(pass = hydra_get_next_password()) == 0)
        pass = empty;
      sprintf(buffer, "%s\r", pass);
      if (no_line_mode) {
        for (i = 0; i < strlen(buffer); i++) {
          if (strcmp(&buffer[i], "\r") == 0) {
            send(s, "\r\0", 2, 0);
          } else {
            send(s, &buffer[i], 1, 0);
          }
          usleepn(20);
        }
      } else {
        if (hydra_send(s, buffer, strlen(buffer) + 1, 0) < 0) {
          return 1;
        }
      }
    } else if (buf && strstr(buf, "login:")) {
      free(buf);
      hydra_completed_pair();
      return 2;
    } else
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
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //      usleepn(300);
      no_line_mode = 0;
      first = 0;
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
      if ((buf = hydra_receive_line(sock)) == NULL) { /* check the first line */
        hydra_report(stderr, "[ERROR] Not a TELNET protocol or service shutdown\n");
        hydra_child_exit(2);
        //        hydra_child_exit(2);
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
      do {
        unsigned char *buf2 = (unsigned char *)buf;

        while (*buf2 == IAC) {
          if (first == 0) {
            if (debug)
              hydra_report(stdout, "DEBUG: requested line mode\n");
            fck = write(sock, "\xff\xfb\x22", 3);
            first = 1;
          }
          if ((buf[1] == '\xfc' || buf[1] == '\xfe') && buf2[2] == '\x22') {
            no_line_mode = 1;
            if (debug)
              hydra_report(stdout, "DEBUG: TELNETD peer does not like linemode!\n");
          }
          if (buf2[2] != '\x22') {
            if (buf2[1] == WILL || buf2[1] == WONT) {
              buf2[1] = DONT;
            } else if (buf2[1] == DO || buf2[1] == DONT) {
              buf2[1] = WONT;
            }
            fck = write(sock, buf2, 3);
          }
          buf2 = buf2 + 3;
        }

        if (buf2 != (unsigned char *)buf) {
          free(buf);
          buf = hydra_receive_line(sock);
        } else {
          buf[0] = 0;
        }
        if (buf != NULL && buf[0] != 0 && (unsigned char)buf[0] != IAC)
          make_to_lower(buf);
      } while (buf != NULL && (unsigned char)buf[0] == IAC && hydra_strcasestr(buf, "ogin:") == NULL && hydra_strcasestr(buf, "sername:") == NULL);
      free(buf);
      waittime = old_waittime;
      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_telnet(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
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

void usage_telnet(const char *service) {
  printf("Module telnet is optionally taking the string which is displayed after\n"
         "a successful login (case insensitive), use if the default in the "
         "telnet\n"
         "module produces too many false positives\n\n");
}
