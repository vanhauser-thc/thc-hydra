#include "hydra-mod.h"

#define MSLEN 30

extern char *HYDRA_EXIT;
char *buf;

unsigned char p_hdr[] = "\x02\x00\x02\x00\x00\x00\x02\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00";
unsigned char p_pk2[] = "\x30\x30\x30\x30\x30\x30\x61\x30\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x20\x18\x81\xb8\x2c\x08\x03"
                        "\x01\x06\x0a\x09\x01\x01\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x73\x71\x75\x65\x6c\x64\x61"
                        "\x20\x31\x2e\x30\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00";
unsigned char p_pk3[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x04\x02\x00\x00\x4d\x53\x44"
                        "\x42\x4c\x49\x42\x00\x00\x00\x07\x06\x00\x00"
                        "\x00\x00\x0d\x11\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00";
unsigned char p_lng[] = "\x02\x01\x00\x47\x00\x00\x02\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x30\x30\x30\x00\x00"
                        "\x00\x03\x00\x00\x00";

int32_t start_mssql(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[1024];
  char ms_login[MSLEN + 1];
  char ms_pass[MSLEN + 1];
  unsigned char len_login, len_pass;
  int32_t ret = -1;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;
  if (strlen(login) > MSLEN)
    login[MSLEN - 1] = 0;
  if (strlen(pass) > MSLEN)
    pass[MSLEN - 1] = 0;
  len_login = strlen(login);
  len_pass = strlen(pass);
  memset(ms_login, 0, MSLEN + 1);
  memset(ms_pass, 0, MSLEN + 1);
  strcpy(ms_login, login);
  strcpy(ms_pass, pass);

  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, p_hdr, 39);
  memcpy(buffer + 39, ms_login, MSLEN);
  memcpy(buffer + MSLEN + 39, &len_login, 1);
  memcpy(buffer + MSLEN + 1 + 39, ms_pass, MSLEN);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN, &len_pass, 1);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN + 1, p_pk2, 110);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN + 1 + 110, &len_pass, 1);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN + 1 + 110 + 1, ms_pass, MSLEN);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN + 1 + 110 + 1 + MSLEN, p_pk3, 270);

  if (hydra_send(s, buffer, MSLEN + 1 + 39 + MSLEN + 1 + 110 + 1 + MSLEN + 270, 0) < 0)
    return 1;
  if (hydra_send(s, (char *)p_lng, 71, 0) < 0)
    return 1;

  memset(buffer, 0, sizeof(buffer));
  ret = hydra_recv_nb(s, buffer, sizeof(buffer));

  if (ret <= 0)
    return 3;

  if (ret > 10 && buffer[8] == '\xe3') {
    hydra_report_found_host(port, ip, "mssql", fp);
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

void service_mssql(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_MSSQL, mysslport = PORT_MSSQL_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
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
      next_run = start_mssql(sock, ip, port, options, miscptr, fp);
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

int32_t service_mssql_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
