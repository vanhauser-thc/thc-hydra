// submitted by Alexander Timorin <ATimorin@ptsecurity.com> and Sergey
// Gordeychik

#include "hydra-mod.h"

#define S7PASSLEN 8

extern char *HYDRA_EXIT;

unsigned char p_cotp[] = "\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x17"
                         "\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0"
                         "\x01\x0a";

unsigned char p_s7_negotiate_pdu[] = "\x03\x00\x00\x19\x02\xf0\x80\x32\x01\x00"
                                     "\x00\x02\x00\x00\x08\x00\x00\xf0\x00\x00"
                                     "\x01\x00\x01\x01\xe0";

unsigned char p_s7_read_szl[] = "\x03\x00\x00\x21\x02\xf0\x80\x32\x07\x00"
                                "\x00\x03\x00\x00\x08\x00\x08\x00\x01\x12"
                                "\x04\x11\x44\x01\x00\xff\x09\x00\x04\x01"
                                "\x32\x00\x04";

unsigned char p_s7_password_request[] = "\x03\x00\x00\x25\x02\xf0\x80\x32\x07\x00"
                                        "\x00\x00\x00\x00\x08\x00\x0c\x00\x01\x12"
                                        "\x04\x11\x45\x01\x00\xff\x09\x00\x08";

int32_t start_s7_300(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *pass, buffer[1024];
  char context[S7PASSLEN + 1];
  unsigned char encoded_password[S7PASSLEN];
  char *spaces = "        ";
  int32_t ret = -1;

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  // prepare password
  memset(context, 0, sizeof(context));
  if (strlen(pass) < S7PASSLEN) {
    strncpy(context, pass, strlen(pass));
    strncat(context, spaces, S7PASSLEN - strlen(pass));
  } else {
    strncpy(context, pass, S7PASSLEN);
  }

  // encode password
  encoded_password[0] = context[0] ^ 0x55;
  encoded_password[1] = context[1] ^ 0x55;
  int32_t i;

  for (i = 2; i < S7PASSLEN; i++) {
    encoded_password[i] = context[i] ^ encoded_password[i - 2] ^ 0x55;
  }

  // send p_cotp and check first 2 bytes of answer
  if (hydra_send(s, (char *)p_cotp, 22, 0) < 0)
    return 1;
  memset(buffer, 0, sizeof(buffer));
  ret = hydra_recv_nb(s, buffer, sizeof(buffer));

  if (ret <= 0)
    return 3;

  if (ret > 2 && (buffer[0] != 0x03 && buffer[1] != 0x00))
    return 3;

  // send p_s7_negotiate_pdu and check first 2 bytes of answer
  if (hydra_send(s, (char *)p_s7_negotiate_pdu, 25, 0) < 0)
    return 1;
  memset(buffer, 0, sizeof(buffer));
  ret = hydra_recv_nb(s, buffer, sizeof(buffer));

  if (ret <= 0)
    return 3;

  if (ret > 2 && (buffer[0] != 0x03 && buffer[1] != 0x00))
    return 3;

  // send p_s7_read_szl and check first 2 bytes of answer
  if (hydra_send(s, (char *)p_s7_read_szl, 33, 0) < 0)
    return 1;
  memset(buffer, 0, sizeof(buffer));
  ret = hydra_recv_nb(s, buffer, sizeof(buffer));

  if (ret <= 0)
    return 3;

  if (ret > 2 && (buffer[0] != 0x03 && buffer[1] != 0x00))
    return 3;

  // so now add encoded_password to p_s7_password_request and send
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, p_s7_password_request, 29);
  memcpy(buffer + 29, encoded_password, S7PASSLEN);

  if (hydra_send(s, buffer, 29 + S7PASSLEN, 0) < 0)
    return 1;

  memset(buffer, 0, sizeof(buffer));
  ret = hydra_recv_nb(s, buffer, sizeof(buffer));

  if (ret <= 0)
    return 3;

  // now check answer
  // 0x0000 - valid password
  // 0xd605 - no password
  // 0xd602 - wrong password
  if (ret > 30) {
    if (buffer[27] == '\x00' && buffer[28] == '\x00') {
      hydra_report_found_host(port, ip, "s7-300", fp);
      hydra_completed_pair_found();
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 2;
      return 1;
    }

    if (buffer[27] == '\xd6' && buffer[28] == '\x05') {
      // hydra_report_found_host(port, ip, "s7-300", fp);
      hydra_completed_pair_found();
      hydra_report(stderr, "[INFO] No password protection enabled\n");
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 2;
      return 1;
    }
  }

  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 2;

  return 1;
}

void service_s7_300(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t s7port = PORT_S7_300;

  if (port != 0)
    s7port = port;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      sock = hydra_connect_tcp(ip, s7port);
      if (sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = start_s7_300(sock, ip, s7port, options, miscptr, fp);
      sock = hydra_disconnect(sock);
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

int32_t service_s7_300_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   1 skip target without generating an error
  //   2 skip target because of protocol problems
  //   3 skip target because its unreachable
  int32_t sock = -1;
  int32_t s7port = PORT_S7_300;
  char *empty = "";
  char *pass, buffer[1024];
  char context[S7PASSLEN + 1];
  unsigned char encoded_password[S7PASSLEN];
  char *spaces = "        ";
  int32_t ret = -1;
  int32_t i;

  if (port != 0)
    s7port = port;

  if (debug || verbose)
    printf("[INFO] Checking authentication setup...\n");

  sock = hydra_connect_tcp(ip, s7port);
  if (sock < 0) {
    hydra_report(stderr, "[ERROR] Can not connect to port %d on the target\n", s7port);
    return 2;
  }

  pass = empty;

  // prepare password
  memset(context, 0, sizeof(context));
  strncat(context, spaces, S7PASSLEN - strlen(pass));

  // encode password
  encoded_password[0] = context[0] ^ 0x55;
  encoded_password[1] = context[1] ^ 0x55;
  for (i = 2; i < S7PASSLEN; i++) {
    encoded_password[i] = context[i] ^ encoded_password[i - 2] ^ 0x55;
  }

  // send p_cotp and check first 2 bytes of answer
  if (hydra_send(sock, (char *)p_cotp, 22, 0) < 0) {
    fprintf(stderr, "[ERROR] can not send data to service\n");
    return 3;
  }
  memset(buffer, 0, sizeof(buffer));
  if ((ret = hydra_recv_nb(sock, buffer, sizeof(buffer))) <= 0) {
    fprintf(stderr, "[ERROR] did not received data from the service\n");
    return 3;
  }

  if (ret < 2 || (buffer[0] != 0x03 && buffer[1] != 0x00)) {
    fprintf(stderr, "[ERROR] invalid reply to init packet\n");
    return 3;
  }
  // send p_s7_negotiate_pdu and check first 2 bytes of answer
  if (hydra_send(sock, (char *)p_s7_negotiate_pdu, 25, 0) < 0) {
    fprintf(stderr, "[ERROR] can not send data to service (2)\n");
    return 3;
  }
  memset(buffer, 0, sizeof(buffer));
  if ((ret = hydra_recv_nb(sock, buffer, sizeof(buffer))) <= 0) {
    fprintf(stderr, "[ERROR] did not received data from the service (2)\n");
    return 3;
  }

  if (ret > 2 && (buffer[0] != 0x03 && buffer[1] != 0x00)) {
    fprintf(stderr, "[ERROR] invalid reply to init packet (2)\n");
    return 3;
  }
  // send p_s7_read_szl and check first 2 bytes of answer
  if (hydra_send(sock, (char *)p_s7_read_szl, 33, 0) < 0) {
    fprintf(stderr, "[ERROR] can not send data to service (3)\n");
    return 3;
  }
  memset(buffer, 0, sizeof(buffer));
  if ((ret = hydra_recv_nb(sock, buffer, sizeof(buffer))) >= 0) {
    fprintf(stderr, "[ERROR] did not received data from the service (3)\n");
    return 3;
  }

  if (ret > 2 && (buffer[0] != 0x03 && buffer[1] != 0x00)) {
    fprintf(stderr, "[ERROR] invalid reply to init packet (3)\n");
    return 3;
  }
  // so now add encoded_password to p_s7_password_request and send
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, p_s7_password_request, 29);
  memcpy(buffer + 29, encoded_password, S7PASSLEN);

  if (hydra_send(sock, buffer, 29 + S7PASSLEN, 0) < 0) {
    fprintf(stderr, "[ERROR] can not send data to service (4)\n");
    return 3;
  }

  memset(buffer, 0, sizeof(buffer));
  if ((ret = hydra_recv_nb(sock, buffer, sizeof(buffer))) <= 0) {
    fprintf(stderr, "[ERROR] did not received data from the service (4)\n");
    return 3;
  }
  // now check answer
  // 0x0000 - valid password
  // 0xd605 - no password
  // 0xd602 - wrong password
  if (ret > 30) {
    if ((buffer[27] == '\x00' && buffer[28] == '\x00') || (buffer[27] == '\xd6' && buffer[28] == '\x05')) {
      hydra_report(stderr, "[INFO] No password protection enabled, no password "
                           "tests are necessary!\n");
      return 1;
    }
  }

  sock = hydra_disconnect(sock);

  return 0;
}

void usage_s7_300(const char *service) {
  printf("Module S7-300 is for a special Siemens PLC. It either requires only a "
         "password or no authentication, so just use the -p or -P option.\n\n");
}
