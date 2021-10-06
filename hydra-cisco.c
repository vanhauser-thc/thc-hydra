#ifdef PALM
#include "palm/hydra-mod.h"
#else
#include "hydra-mod.h"
#endif

extern char *HYDRA_EXIT;
static char *buf = NULL;

int32_t start_cisco(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *pass, buffer[300];

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

#ifdef PALM
  sprintf(buffer, "%s\r\n", pass);
#else
  sprintf(buffer, "%.250s\r\n", pass);
#endif

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  sleep(1);
  buf = NULL;
  do {
    if (buf != NULL)
      free(buf);
    if ((buf = hydra_receive_line(s)) == NULL)
      return 3;
    if (buf[strlen(buf) - 1] == '\n')
      buf[strlen(buf) - 1] = 0;
    if (buf[strlen(buf) - 1] == '\r')
      buf[strlen(buf) - 1] = 0;
  } while (strlen(buf) <= 1);
  if (strstr(buf, "assw") != NULL) {
    hydra_completed_pair();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    if (strlen(pass = hydra_get_next_password()) == 0)
      pass = empty;

#ifdef PALM
    sprintf(buffer, "%s\r\n", pass);
#else
    sprintf(buffer, "%.250s\r\n", pass);
#endif

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }

    buf = NULL;
    do {
      if (buf != NULL)
        free(buf);
      if ((buf = hydra_receive_line(s)) == NULL)
        return 3;
      if (buf[strlen(buf) - 1] == '\n')
        buf[strlen(buf) - 1] = 0;
      if (buf[strlen(buf) - 1] == '\r')
        buf[strlen(buf) - 1] = 0;
    } while (strlen(buf) <= 1);
    if (buf != NULL && strstr(buf, "assw") != NULL) {
      hydra_completed_pair();
      free(buf);
      buf = NULL;
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      if (strlen(pass = hydra_get_next_password()) == 0)
        pass = empty;

#ifdef PALM
      sprintf(buffer, "%s\r\n", pass);
#else
      sprintf(buffer, "%.250s\r\n", pass);
#endif

      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      buf = NULL;
      do {
        if (buf != NULL)
          free(buf);
        buf = hydra_receive_line(s);
        if (buf != NULL) {
          if (buf[strlen(buf) - 1] == '\n')
            buf[strlen(buf) - 1] = 0;
          if (buf[strlen(buf) - 1] == '\r')
            buf[strlen(buf) - 1] = 0;
        }
      } while (buf != NULL && strlen(buf) <= 1);
    }
  }

  if (buf != NULL && (strstr(buf, "assw") != NULL || strstr(buf, "ad ") != NULL || strstr(buf, "attempt") != NULL || strstr(buf, "ailur") != NULL)) {
    free(buf);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }

  hydra_report_found_host(port, ip, "cisco", fp);
  hydra_completed_pair_found();
  if (buf != NULL)
    free(buf);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_cisco(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, failc = 0, retry = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_TELNET, mysslport = PORT_TELNET_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    next_run = 0;
    switch (run) {
    case 1: /* connect and service init function */
    {
      unsigned char *buf2 = NULL;
      int32_t f = 0;

      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //        usleepn(275);
      if ((options & OPTION_SSL) == 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
        if (miscptr != NULL && hydra_strcasestr(miscptr, "enter") != NULL)
          hydra_send(sock, "\r\n", 2, 0);
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
      do {
        if (f != 0) {
          free(buf2);
          buf2 = NULL;
        } else
          f = 1;
        if ((buf2 = (unsigned char *)hydra_receive_line(sock)) == NULL) {
          if (failc < retry) {
            next_run = 1;
            failc++;
            if (quiet != 1)
              hydra_report(stderr,
                           "[ERROR] Child with pid %d was disconnected - "
                           "retrying (%d of %d retries)\n",
                           (int32_t)getpid(), failc, retry);
            sleep(3);
            break;
          } else {
            if (quiet != 1)
              hydra_report(stderr, "[ERROR] Child with pid %d was disconnected - exiting\n", (int32_t)getpid());
            hydra_child_exit(0);
          }
        }
        if (buf2 != NULL && hydra_strcasestr((char *)buf2, "ress ENTER") != NULL)
          hydra_send(sock, "\r\n", 2, 0);
      } while (buf2 != NULL && strstr((char *)buf2, "assw") == NULL);
      free(buf2);
      if (next_run != 0)
        break;
      failc = 0;
      next_run = 2;
      break;
    }
    case 2: /* run the cracking function */
      next_run = start_cisco(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
#ifdef PALM
      return;
#else
      hydra_child_exit(2);
#endif
    }
    run = next_run;
  }
}

int32_t service_cisco_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_cisco(const char *service) {
  printf("Module cisco is optionally taking the keyword ENTER, it then sends "
         "an initial\n"
         "ENTER when connecting to the service.\n");
}
