// This plugin was written by david@
//
// This plugin is written for Asterisk Call Manager
// which is running by default on TCP/5038
//

#include "hydra-mod.h"

extern char *HYDRA_EXIT;

char *buf;

int32_t start_asterisk(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "\"\"";
  char *login, *pass, buffer[1024];

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  while (hydra_data_ready(s) > 0) {
    if ((buf = hydra_receive_line(s)) == NULL)
      return (1);
    free(buf);
  }
  memset(buffer, 0, sizeof(buffer));
  sprintf(buffer, "Action: Login\r\nUsername: %.250s\r\nSecret: %.250s\r\n\r\n", login, pass);

  if (debug)
    hydra_report(stderr, "[DEBUG] C: %s\n", buffer);

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  if ((buf = hydra_receive_line(s)) == NULL)
    return 1;

  if (debug)
    hydra_report(stderr, "[DEBUG] S: %s\n", buf);

  if (buf == NULL || (strstr(buf, "Response: ") == NULL)) {
    hydra_report(stderr,
                 "[ERROR] Asterisk Call Manager protocol error or service "
                 "shutdown: %s\n",
                 buf);
    free(buf);
    return 4;
  }

  if (strstr(buf, "Response: Success") != NULL) {
    hydra_report_found_host(port, ip, "asterisk", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }
  free(buf);
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 2;
}

void service_asterisk(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_ASTERISK, mysslport = PORT_ASTERISK_SSL;

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
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      buf = hydra_receive_line(sock);
      // fprintf(stderr, "%s\n",buf);
      // banner should look like:
      // Asterisk Call Manager/1.1

      if (buf == NULL || strstr(buf, "Asterisk Call Manager/") == NULL) {
        /* check the first line */
        if (verbose || debug)
          hydra_report(stderr,
                       "[ERROR] Not an Asterisk Call Manager protocol or "
                       "service shutdown: %s\n",
                       buf);
        hydra_child_exit(2);
      }
      free(buf);

      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_asterisk(sock, ip, port, options, miscptr, fp);
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

int32_t service_asterisk_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
