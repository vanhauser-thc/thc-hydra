#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;

int start_redis(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp) {
  char *pass, buffer[510];
  char *empty = "";

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  sprintf(buffer, "AUTH %.250s\r\n", pass);

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = hydra_receive_line(s);
  if (buf[0] == '+') {
    hydra_report_found_host(port, ip, "redis", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }
  if (verbose > 1)
    hydra_report(stderr, "[VERBOSE] Authentication failed for password %s\n", pass);
  hydra_completed_pair();

  free(buf);

  return 1;
}

void service_redis_core(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, int tls) {
  int run = 1, next_run = 1, sock = -1;
  int myport = PORT_REDIS, mysslport = PORT_REDIS_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    hydra_child_exit(0);

  while (1) {
    switch (run) {
    case 1:                    /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      if ((options & OPTION_SSL) == 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      } else {
        if (port != 0)
          mysslport = port;
        sock = hydra_connect_ssl(ip, mysslport);
        port = mysslport;
      }
      if (sock < 0) {
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int) getpid());
        hydra_child_exit(1);
      }
      usleep(250);
      next_run = 2;
      break;
    case 2:                    /* run the cracking function */
      next_run = start_redis(sock, ip, port, options, miscptr, fp);
      break;
    case 3:                    /* error exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
    case 4:                    /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

void service_redis(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  service_redis_core(ip, sp, options, miscptr, fp, port, 0);
}

int service_redis_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
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
