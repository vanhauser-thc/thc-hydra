#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;

int32_t start_cisco_enable(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *pass, buffer[300];

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  sprintf(buffer, "%.250s\r\n", pass);
  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = hydra_receive_line(s);
  if (buf != NULL && strstr(buf, "assw") != NULL) {
    hydra_completed_pair();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    if (strlen(pass = hydra_get_next_password()) == 0)
      pass = empty;
    sprintf(buffer, "%.250s\r\n", pass);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    buf = hydra_receive_line(s);
    if (strstr(buf, "assw") != NULL) {
      hydra_completed_pair();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      if (strlen(pass = hydra_get_next_password()) == 0)
        pass = empty;
      sprintf(buffer, "%.250s\r\n", pass);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      buf = hydra_receive_line(s);
    }
  }

  if (buf != NULL && (strstr(buf, "assw") != NULL || strstr(buf, "ad ") != NULL || strstr(buf, "attempt") != NULL || strstr(buf, "fail") != NULL || strstr(buf, "denied") != NULL)) {
    free(buf);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 2;
  }

  if (buf != NULL)
    free(buf);
  hydra_report_found_host(port, ip, "cisco-enable", fp);
  hydra_completed_pair_found();
  return 3;
}

void service_cisco_enable(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, failc = 0, retry = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_TELNET, mysslport = PORT_TELNET_SSL;
  char buffer[300];
  char *login;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    next_run = 0;
    switch (run) {
    case 1: /* connect and service init function */
    {
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //        usleepn(275);
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
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }

      /* Cisco AAA Support */
      if (strlen(login = hydra_get_next_login()) != 0) {
        while ((buf = hydra_receive_line(sock)) != NULL && strstr(buf, "name:") == NULL && strstr(buf, "ogin:") == NULL) {
          if (hydra_strcasestr(buf, "ress ENTER") != NULL)
            hydra_send(sock, "\r\n", 2, 0);
          free(buf);
        }

        sprintf(buffer, "%.250s\r\n", login);
        if (hydra_send(sock, buffer, strlen(buffer), 0) < 0) {
          if (quiet != 1)
            fprintf(stderr, "[ERROR] Child with pid %d terminating, can not send login\n", (int32_t)getpid());
          hydra_child_exit(2);
        }
      }

      if (miscptr != NULL) {
        if (buf != NULL)
          free(buf);
        while ((buf = hydra_receive_line(sock)) != NULL && strstr(buf, "assw") == NULL) {
          if (hydra_strcasestr(buf, "ress ENTER") != NULL)
            hydra_send(sock, "\r\n", 2, 0);
          free(buf);
        }

        sprintf(buffer, "%.250s\r\n", miscptr);
        if (hydra_send(sock, buffer, strlen(buffer), 0) < 0) {
          if (quiet != 1)
            fprintf(stderr, "[ERROR] Child with pid %d terminating, can not send login\n", (int32_t)getpid());
          hydra_child_exit(2);
        }
      }

      if (buf != NULL)
        free(buf);
      buf = hydra_receive_line(sock);
      if (hydra_strcasestr(buf, "ress ENTER") != NULL) {
        hydra_send(sock, "\r\n", 2, 0);
        free(buf);
        buf = hydra_receive_line(sock);
      }

      if (strstr(buf, "assw") != NULL) {
        if (quiet != 1)
          fprintf(stderr,
                  "[ERROR] Child with pid %d terminating - can not login, can "
                  "not login\n",
                  (int32_t)getpid());
        hydra_child_exit(2);
      }
      free(buf);

      next_run = 2;
      break;
    }
    case 2: /* run the cracking function */
    {
      unsigned char *buf2;
      int32_t f = 0;

      sprintf(buffer, "%.250s\r\n", "ena");
      if (hydra_send(sock, buffer, strlen(buffer), 0) < 0) {
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not send 'ena'\n", (int32_t)getpid());
        hydra_child_exit(2);
      }

      do {
        if (f != 0)
          free(buf2);
        else
          f = 1;
        if ((buf2 = (unsigned char *)hydra_receive_line(sock)) == NULL) {
          if (failc < retry) {
            next_run = 1;
            failc++;
            if (quiet != 1)
              fprintf(stderr,
                      "[ERROR] Child with pid %d was disconnected - retrying "
                      "(%d of %d retries)\n",
                      (int32_t)getpid(), failc, retry);
            sleep(3);
            break;
          } else {
            fprintf(stderr, "[ERROR] Child with pid %d was disconnected - exiting\n", (int32_t)getpid());
            hydra_child_exit(0);
          }
        }
      } while (strstr((char *)buf2, "assw") == NULL);
      free(buf2);
      if (next_run != 0)
        break;
      failc = 0;

      next_run = start_cisco_enable(sock, ip, port, options, miscptr, fp);
      break;
    }
    case 3: /* clean exit */
      sprintf(buffer, "%.250s\r\n", "exit");
      if (hydra_send(sock, buffer, strlen(buffer), 0) < 0) {
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not send 'exit'\n", (int32_t)getpid());
        hydra_child_exit(0);
      }
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_cisco_enable_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_cisco_enable(const char *service) {
  printf("Module cisco-enable is optionally taking the logon password for the "
         "cisco device\n"
         "Note: if AAA authentication is used, use the -l option for the "
         "username\n"
         "and the optional parameter for the password of the user.\n"
         "Examples:\n"
         "  hydra -P pass.txt target cisco-enable  (direct console access)\n"
         "  hydra -P pass.txt -m cisco target cisco-enable  (Logon password "
         "cisco)\n"
         "  hydra -l foo -m bar -P pass.txt target cisco-enable  (AAA Login "
         "foo, password bar)\n");
}
