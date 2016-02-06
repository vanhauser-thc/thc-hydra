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
      usleepn(250);
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

/* 
* Initial password authentication test and response test for the redis server,
* added by Petar Kaleychev <petar.kaleychev@gmail.com>
* The service_redis_init function is generating ping request as redis-cli (command line interface). 
* You can use redis-cli to connect with Redis. After start of the redis-server in another terminal the following:
*    % ./redis-cli
*    redis> ping
*    when the server do not require password, leads to:
*    PONG
*    when the server requires password, leads to:
*    (error) NOAUTH Authentication required.
* That is used for initial password authentication and redis server response tests in service_redis_init
*/
int service_redis_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  // return codes:
  // 0 - when the server is redis and it requires password
  // 1 - when the server is not redis or when the server do not require password

  int sock = -1;
  int myport = PORT_REDIS, mysslport = PORT_REDIS_SSL;
  char buffer[] = "\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x70\x69\x6e\x67\x0d\x0a";

  hydra_register_socket(sp);
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
  if (verbose)
    printf("[VERBOSE] Initial redis password authentication test and response test ...\n");
  if (sock < 0) {
    hydra_report(stderr, "[ERROR] Can not connect to port %d on the target\n", myport);
    hydra_child_exit(1);
  }
  // generating ping request as redis-cli
  if (debug)
    printf("[DEBUG] buffer = %s\n", buffer);
    //    [debug mode]: buffer is:
    //    *1
    //    $4
    //    ping
  if (hydra_send(sock, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = hydra_receive_line(sock);
  if (debug)
    printf("[DEBUG] buf = %s\n", buf);
  // authentication test
  if (strstr(buf, "+PONG") != NULL) { // the server do not require password
    hydra_report(stderr, "[!] The server do not require password.\n");
    free(buf);
    return 1;
  }
  // server response test
  if (strstr(buf, "-NOAUTH Authentication required") == NULL) {
    hydra_report(stderr, "[ERROR] The server is not redis, exit.\n");
    free(buf);
    return 1;
  }
  if (verbose)
    printf("[VERBOSE] The redis server requires password.\n");
  free(buf);
  sock = hydra_disconnect(sock);
  return 0;
}
