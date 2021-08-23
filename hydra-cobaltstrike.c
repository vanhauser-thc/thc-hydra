#include "hydra-mod.h"

#define CSLEN 256

extern char *HYDRA_EXIT;
char *buf;

int32_t start_cobaltstrike(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *pass, buffer[4 + 1 + 256];
  char cs_pass[CSLEN + 1];
  unsigned char len_pass;
  unsigned char reply_byte_0;
  unsigned char reply_byte_1;
  unsigned char reply_byte_2;
  unsigned char reply_byte_3;
  int32_t ret = -1;

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;
  if (strlen(pass) > CSLEN)
    pass[CSLEN - 1] = 0;
  len_pass = strlen(pass);
  memset(cs_pass, 0, CSLEN + 1);
  strcpy(cs_pass, pass);

  memset(buffer, 0x41, sizeof(buffer));
  buffer[0] = 0x00;
  buffer[1] = 0x00;
  buffer[2] = 0xBE;
  buffer[3] = 0xEF;
  memcpy(buffer + 4, &len_pass, 1);
  memcpy(buffer + 5, cs_pass, len_pass);

  if (hydra_send(s, buffer, sizeof(buffer), 0) < 0)
    return 1;

  reply_byte_0 = 0x00;
  ret = hydra_recv_nb(s, &reply_byte_0, 1);
  if (ret <= 0)
    return 3;

  reply_byte_1 = 0x00;
  ret = hydra_recv_nb(s, &reply_byte_1, 1);
  if (ret <= 0)
    return 3;

  reply_byte_2 = 0x00;
  ret = hydra_recv_nb(s, &reply_byte_2, 1);
  if (ret <= 0)
    return 3;

  reply_byte_3 = 0x00;
  ret = hydra_recv_nb(s, &reply_byte_3, 1);
  if (ret <= 0)
    return 3;

  if (reply_byte_0 == 0x00 && reply_byte_1 == 0x00 && reply_byte_2 == 0xCA && reply_byte_3 == 0xFE) {
    hydra_report_found_host(port, ip, "cobaltstrike", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 2;
    return 1;
  }

  free(buf);
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 2;

  return 1;
}

void service_cobaltstrike(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t mysslport = PORT_COBALTSTRIKE_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (port != 0)
        mysslport = port;
      sock = hydra_connect_ssl(ip, mysslport, hostname);
      port = mysslport;
      if (sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = start_cobaltstrike(sock, ip, port, options, miscptr, fp);
      hydra_disconnect(sock);
      break;
    case 2: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_cobaltstrike_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
