#include "hydra-mod.h"

/*

RFC: 1928
This module enable bruteforcing for socks5, only following types are supported:
0x00 "No Authentication Required"
0x02 "Username/Password"

*/

extern char *HYDRA_EXIT;
unsigned char *buf;

int32_t fail_cnt;

int32_t start_socks5(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[300];
  int32_t pport, fud = 0;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  memcpy(buffer, "\x05\x02\x00\x02", 4);
  if (hydra_send(s, buffer, 4, 0) < 0) {
    return 1;
  }
  if ((buf = (unsigned char *)hydra_receive_line(s)) == NULL) {
    fail_cnt++;
    if (fail_cnt >= 10)
      return 5;
    return (1);
  }

  fail_cnt = 0;
  if (buf[0] != 5) {
    if (buf[0] == 4) {
      hydra_report(stderr, "[ERROR] Sorry Socks4 / Socks4a ident is not supported\n");
    } else {
      hydra_report(stderr, "[ERROR] Socks5 protocol or service shutdown: %s\n", buf);
    }
    free(buf);
    return (4);
  }
  if (buf[1] == 0 || buf[1] == 32) {
    hydra_report(stderr, "[INFO] Socks5 server does NOT require any authentication!\n");
    free(buf);
    return (4);
  }
  if (buf[1] != 0x2) {
    hydra_report(stderr, "[ERROR] Socks5 protocol or service shutdown: %s\n", buf);
    free(buf);
    return (4);
  }
  free(buf);

  /* RFC 1929
    For username/password authentication the client's authentication request is
    field 1: version number, 1 byte (must be 0x01)
  */
  snprintf(buffer, sizeof(buffer), "\x01%c%s%c%s", (char)strlen(login), login, (char)strlen(pass), pass);

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
    return 1;

  if ((buf = (unsigned char *)hydra_receive_line(s)) == NULL)
    return (1);

  if (buf[1] != 255) {
    /* new: false positive check */
    free(buf);
    pport = htons(port);
    if (ip[0] == 16) {
      memcpy(buffer, "\x05\x01\x00\x04", 4);
      memcpy(buffer + 4, &ip[1], 16);
      memcpy(buffer + 20, &pport, 2);
      hydra_send(s, buffer, 22, 0);
    } else {
      memcpy(buffer, "\x05\x01\x00\x01", 4);
      memcpy(buffer + 4, &ip[1], 4);
      memcpy(buffer + 8, &pport, 2);
      hydra_send(s, buffer, 10, 0);
    }
    if ((buf = (unsigned char *)hydra_receive_line(s)) != NULL) {
      if (buf[1] == 0 || buf[1] == 32) {
        hydra_report_found_host(port, ip, "socks5", fp);
        hydra_completed_pair_found();
        fud = 1;
      } else if (buf[1] != 2) {
        hydra_report_found_host_msg(port, ip, "socks5", fp, "might be a false positive!");
      }
    }
  }
  if (buf != NULL)
    free(buf);
  if (fud == 0)
    hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 2;
}

void service_socks5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_SOCKS5, mysslport = PORT_SOCKS5_SSL;

  hydra_register_socket(sp);
  if (port != 0)
    myport = port;
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

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
      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_socks5(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    case 4: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      return;
    case 5: /* clean exit, server may blocking connections */
      hydra_report(stderr, "[ERROR] Server may blocking connections\n");
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_socks5_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
