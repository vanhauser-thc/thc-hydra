#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;

int32_t start_ftp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "\"\"";
  char *login, *pass, buffer[510];

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  sprintf(buffer, "USER %.250s\r\n", login);

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = hydra_receive_line(s);
  if (buf == NULL)
    return 1;
  /* special hack to identify 530 user unknown msg. suggested by
   * Jean-Baptiste.BEAUFRETON@turbomeca.fr */
  if (buf[0] == '5' && buf[1] == '3' && buf[2] == '0') {
    if (verbose)
      printf("[INFO] user %s does not exist, skipping\n", login);
    hydra_completed_pair_skip();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 4;
    free(buf);
    return 1;
  }
  // for servers supporting anon access without password
  if (buf[0] == '2') {
    hydra_report_found_host(port, ip, "ftp", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 4;
    free(buf);
    return 1;
  }
  if (buf[0] != '3') {
    if (buf) {
      if (verbose || debug)
        hydra_report(stderr, "[ERROR] Not an FTP protocol or service shutdown: %s\n", buf);
      free(buf);
    }
    return 3;
  }
  free(buf);

  sprintf(buffer, "PASS %.250s\r\n", pass);

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = hydra_receive_line(s);
  if (buf == NULL)
    return 1;
  if (buf[0] == '2') {
    hydra_report_found_host(port, ip, "ftp", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 4;
    free(buf);
    return 1;
  }

  free(buf);
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 4;

  return 2;
}

void service_ftp_core(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname, int32_t tls) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_FTP, mysslport = PORT_FTP_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    hydra_child_exit(0);
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //      usleepn(300);
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
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      usleepn(250);
      buf = hydra_receive_line(sock);
      if (buf == NULL || buf[0] != '2') { /* check the first line */
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Not an FTP protocol or service shutdown: %s\n", buf);
        hydra_child_exit(2);
        if (buf != NULL)
          free(buf);
        hydra_child_exit(2);
      }

      while (buf != NULL && strncmp(buf, "220 ", 4) != 0 && strstr(buf, "\n220 ") == NULL) {
        free(buf);
        buf = hydra_receive_line(sock);
      }
      free(buf);

      // this mode is manually chosen, so if it fails we giving up
      if (tls) {
        if (hydra_send(sock, "AUTH TLS\r\n", strlen("AUTH TLS\r\n"), 0) < 0) {
          hydra_child_exit(2);
        }
        buf = hydra_receive_line(sock);
        if (buf == NULL) {
          if (verbose || debug)
            hydra_report(stderr, "[ERROR] Not an FTP protocol or service shutdown: %s\n", buf);
          hydra_child_exit(2);
        }
        if (buf[0] == '2') {
          if ((hydra_connect_to_ssl(sock, hostname) == -1) && verbose) {
            hydra_report(stderr, "[ERROR] Can't use TLS\n");
            hydra_child_exit(2);
          } else {
            if (verbose)
              hydra_report(stderr, "[VERBOSE] TLS connection done\n");
          }
        } else {
          hydra_report(stderr, "[ERROR] TLS negotiation failed %s\n", buf);
          hydra_child_exit(2);
        }
        free(buf);
      }

      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_ftp(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* error exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      break;
    case 4: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      break;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

void service_ftp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_ftp_core(ip, sp, options, miscptr, fp, port, hostname, 0); }

void service_ftps(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_ftp_core(ip, sp, options, miscptr, fp, port, hostname, 1); }

int32_t service_ftp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
