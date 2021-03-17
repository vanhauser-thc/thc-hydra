#include "hydra-mod.h"

#ifdef HAVE_ZLIB
#include <zlib.h>
#else
#include "crc32.h"
#endif

/*

This module brings support for Teamspeak version 2.x (TS2 protocol)
Tested with version 2.0.r23.b19, server uses to ban ip for 10 min
when bruteforce is detected.

TS1 protocol (tcp/8765) is not supported
TS3 protocol (udp/9987) is not needed as user/pass is not used anymore

*/

struct team_speak {
  char header[16];
  unsigned long crc;
  char clientlen;
  char client[29];
  char oslen;
  char os[29];
  char misc[10];
  char userlen;
  char user[29];
  char passlen;
  char pass[29];
  char loginlen;
  char login[29];
};

extern int32_t hydra_data_ready_timed(int32_t socket, long sec, long usec);

extern char *HYDRA_EXIT;

int32_t start_teamspeak(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;
  char buf[100];
  struct team_speak teamspeak;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  memset(&teamspeak, 0, sizeof(struct team_speak));

  memcpy(&teamspeak.header, "\xf4\xbe\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00", 16);

  teamspeak.clientlen = 9;
  strcpy((char *)&teamspeak.client, "TeamSpeak");

  teamspeak.oslen = 11;
  strcpy((char *)&teamspeak.os, "Linux 2.6.9");

  memcpy(&teamspeak.misc, "\x02\x00\x00\x00\x20\x00\x3c\x00\x01\x02", 10);

  teamspeak.userlen = strlen(login);
  strncpy((char *)&teamspeak.user, login, 29);

  teamspeak.passlen = strlen(pass);
  strncpy((char *)&teamspeak.pass, pass, 29);

  teamspeak.loginlen = 0;
  strcpy((char *)&teamspeak.login, "");

#ifdef HAVE_ZLIB
  teamspeak.crc = crc32(0L, (const Bytef *)&teamspeak, sizeof(struct team_speak));
#else
  teamspeak.crc = crc32(&teamspeak, sizeof(struct team_speak));
#endif

  if (hydra_send(s, (char *)&teamspeak, sizeof(struct team_speak), 0) < 0) {
    return 3;
  }

  if (hydra_data_ready_timed(s, 5, 0) > 0) {
    hydra_recv(s, (char *)buf, sizeof(buf));
    if (buf[0x58] == 1) {
      hydra_report_found_host(port, ip, "teamspeak", fp);
      hydra_completed_pair_found();
    }
    if (buf[0x4B] != 0) {
      hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
      hydra_child_exit(1);
    }
  } else {
    hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
    hydra_child_exit(1);
  }

  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 1;
}

void service_teamspeak(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_TEAMSPEAK;

  hydra_register_socket(sp);

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    run = 3;

  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
            //      if (sock >= 0)
            //      sock = hydra_disconnect(sock);
            //      usleepn(300);
      if (sock < 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_udp(ip, myport);
        port = myport;
        if (sock < 0) {
          hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
          hydra_child_exit(1);
        }
      }
      next_run = start_teamspeak(sock, ip, port, options, miscptr, fp);
      break;
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

int32_t service_teamspeak_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
