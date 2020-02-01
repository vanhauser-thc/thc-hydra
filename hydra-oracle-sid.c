
/*
david:

module used to check for a valid oracle SID
ORCL and XE are a good start, but you should
find a big list on the Internet

*/

#include "hydra-mod.h"
#ifndef LIBOPENSSL
#include <stdio.h>
void dummy_oracle_sid() { printf("\n"); }
#else
#include <openssl/des.h>
#define HASHSIZE 16

extern char *HYDRA_EXIT;
char *buf;
unsigned char *hash;

int32_t start_oracle_sid(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  /*
     PP is the packet length
     XX is the length of connect data
     PP + tns_packet_begin + XX + tns_packet_end
   */
  unsigned char tns_packet_begin[22] = {"\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00\x7f\xff\x86\x0e"
                                        "\x00\x00\x01\x00"};
  unsigned char tns_packet_end[32] = {"\x00\x3a\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                      "\x00\x00\x09\x94\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00"};
  char *empty = "";
  char *login;
  char connect_string[200];
  char buffer2[260];
  int32_t siz = 0;

  memset(connect_string, 0, sizeof(connect_string));
  memset(buffer2, 0, sizeof(buffer2));

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;

  snprintf(connect_string, sizeof(connect_string),
           "(DESCRIPTION=(CONNECT_DATA=(SID=%s)(CID=(PROGRAM=)(HOST=__jdbc__)("
           "USER=)))(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d)))",
           login, hydra_address2string(ip), port);
  siz = 2 + sizeof(tns_packet_begin) + 2 + sizeof(tns_packet_end) + strlen(connect_string);
  if (siz > 255) {
    buffer2[0] = 1;
    buffer2[1] = siz - 256;
  } else {
    buffer2[1] = siz;
  }
  memcpy(buffer2 + 2, (char *)tns_packet_begin, sizeof(tns_packet_begin));
  siz = strlen(connect_string);
  if (siz > 255) {
    buffer2[2 + sizeof(tns_packet_begin)] = 1;
    buffer2[1 + 2 + sizeof(tns_packet_begin)] = siz - 256;
  } else {
    buffer2[1 + 2 + sizeof(tns_packet_begin)] = siz;
  }
  memcpy(buffer2 + 2 + sizeof(tns_packet_begin) + 2, (char *)tns_packet_end, sizeof(tns_packet_end));
  memcpy(buffer2 + 2 + sizeof(tns_packet_begin) + 2 + sizeof(tns_packet_end), connect_string, strlen(connect_string));
  if (hydra_send(s, buffer2, 2 + sizeof(tns_packet_begin) + 2 + sizeof(tns_packet_end) + strlen(connect_string), 0) < 0) {
    return 1;
  }

  if ((buf = hydra_receive_line(s)) == NULL)
    return 1;
  // if no error reported. it should be a resend packet type 00 08 00 00 0b 00
  // 00 00, 4 is refuse
  if ((strstr(buf, "ERR=") == NULL) && (buf[4] != 4)) {
    hydra_report_found_host(port, ip, "oracle-sid", fp);
    hydra_completed_pair_found();
  } else
    hydra_completed_pair();

  free(buf);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_oracle_sid(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_ORACLE, mysslport = PORT_ORACLE_SSL;

  hydra_register_socket(sp);
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
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      /* run the cracking function */
      next_run = start_oracle_sid(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    case 4:
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

int32_t service_oracle_sid_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

#endif
