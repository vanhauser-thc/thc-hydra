// rpcap
// Petar Kaleychev

#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;

int32_t start_rpcap(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[1024];

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  char bfr1[] = "\x00";
  char bfr2[] = "\x08";
  char bfr3[] = "\x00\x00\x00\x00\x00";
  char bfr4[] = " ";
  bfr4[0] = strlen(login) + strlen(pass) + 8;
  char bfr5[] = "\x00";
  char bfr6[] = "\x01"; // x01 - when a password is required, x00 - when no need
                        // of password
  char bfr7[] = "\x00\x00\x00";
  char bfr8[] = " ";
  bfr8[0] = strlen(login);
  char bfr9[] = "\x00";
  char bfr10[] = " ";
  bfr10[0] = strlen(pass);

  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, bfr1, 1);
  memcpy(buffer + 1, bfr2, 1);
  memcpy(buffer + 2, bfr3, 5);
  memcpy(buffer + 7, bfr4, 1);
  memcpy(buffer + 8, bfr5, 1);
  memcpy(buffer + 9, bfr6, 1);
  memcpy(buffer + 10, bfr7, 3);
  memcpy(buffer + 13, bfr8, 1);
  memcpy(buffer + 14, bfr9, 1);
  memcpy(buffer + 15, bfr10, 1);
  memcpy(buffer + 16, login, strlen(login));
  memcpy(buffer + 16 + strlen(login), pass, strlen(pass));

  if (hydra_send(s, buffer, 16 + strlen(login) + strlen(pass), 0) < 0) {
    return 1;
  }

  buf = hydra_receive_line(s);

  if (buf[1] == '\x88') {
    hydra_report_found_host(port, ip, "rpcap", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }
  /*
    if (strstr(buf, "Logon failure") == NULL) {
      hydra_report(stderr, "[ERROR] rpcap error or service shutdown: %s\n",
    buf); free(buf); return 4;
    }
  */
  free(buf);
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 2;
}

void service_rpcap(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_RPCAP, mysslport = PORT_RPCAP_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      // usleep(300000);
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
      next_run = start_rpcap(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
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

int32_t service_rpcap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, performed once only.
  // return codes:
  // 0 - rpcap with authentication
  // 1 - rpcap error or no need of authentication

  int32_t sock = -1;
  int32_t myport = PORT_RPCAP, mysslport = PORT_RPCAP_SSL;
  char buffer[] = "\x00\x08\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00";

  hydra_register_socket(sp);
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
    hydra_report(stderr, "[ERROR] Can not connect to port %d on the target\n", myport);
    hydra_child_exit(1);
  }

  if (hydra_send(sock, buffer, 16, 0) < 0) {
    return 1;
  }

  buf = hydra_receive_line(sock);

  if (strstr(buf, "NULL authentication not permitted") == NULL) {
    hydra_report(stderr, "[!] rpcap error or no need of authentication!\n");
    free(buf);
    return 1;
  }

  free(buf);
  sock = hydra_disconnect(sock);
  return 0;
}
