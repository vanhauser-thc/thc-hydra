// This plugin was written by david@
//
// This plugin is written for VMware Authentication Daemon
//

#include "hydra-mod.h"

extern char *HYDRA_EXIT;

char *buf;

int32_t start_vmauthd(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "\"\"";
  char *login, *pass, buffer[300];

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  while (hydra_data_ready(s) > 0) {
    if ((buf = hydra_receive_line(s)) == NULL)
      return (1);
    free(buf);
  }

  sprintf(buffer, "USER %.250s\r\n", login);
  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  if ((buf = hydra_receive_line(s)) == NULL)
    return (1);
  if (strncmp(buf, "331 ", 4) != 0) {
    hydra_report(stderr, "[ERROR] vmware authd protocol or service shutdown: %s\n", buf);
    free(buf);
    return (3);
  }
  free(buf);

  sprintf(buffer, "PASS %.250s\r\n", pass);
  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  if ((buf = hydra_receive_line(s)) == NULL)
    return (1);

  // fprintf(stderr, "%s\n", buf);
  // 230 User test logged in.
  // 530 Login incorrect.

  if (strncmp(buf, "230 ", 4) == 0) {
    hydra_report_found_host(port, ip, "vmauthd", fp);
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

void service_vmauthd(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_VMAUTHD, mysslport = PORT_VMAUTHD_SSL;

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
      // 220 VMware Authentication Daemon Version 1.00
      // 220 VMware Authentication Daemon Version 1.10: SSL Required
      // 220 VMware Authentication Daemon Version 1.10: SSL Required,
      // ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC ,

      if (buf == NULL || strstr(buf, "220 VMware Authentication Daemon Version ") == NULL) {
        /* check the first line */
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Not an vmware authd protocol or service shutdown: %s\n", buf);
        hydra_child_exit(2);
      }
      if ((strstr(buf, "Version 1.00") == NULL) && (strstr(buf, "Version 1.10") == NULL)) {
        hydra_report(stderr,
                     "[ERROR] this vmware authd protocol is not supported, "
                     "please report: %s\n",
                     buf);
        free(buf);
        hydra_child_exit(2);
      }
      // by default this service is waiting for ssl connections
      if (strstr(buf, "SSL Required") != NULL) {
        if ((options & OPTION_SSL) == 0) {
          // reconnecting using SSL
          if (hydra_connect_to_ssl(sock, hostname) == -1) {
            free(buf);
            hydra_report(stderr, "[ERROR] Can't use SSL\n");
            hydra_child_exit(2);
          }
        }
      }
      free(buf);

      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_vmauthd(sock, ip, port, options, miscptr, fp);
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

int32_t service_vmauthd_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
