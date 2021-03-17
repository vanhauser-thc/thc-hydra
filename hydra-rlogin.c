#include "hydra-mod.h"

/*

RFC 1258
client have to use port from 512 -> 1023 or server is denying the connection

no memleaks found on 110425
*/

#define TERM "vt100/9600"

extern char *HYDRA_EXIT;

int32_t start_rlogin(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[300] = "", buffer2[100], *bptr = buffer2;
  int32_t ret;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  memset(buffer2, 0, sizeof(buffer2));
  bptr++;

  strcpy(bptr, login);
  bptr += 1 + strlen(login);

  strcpy(bptr, login);
  bptr += 1 + strlen(login);

  strcpy(bptr, TERM);

  if (hydra_send(s, buffer2, 4 + strlen(login) + strlen(login) + strlen(TERM), 0) < 0) {
    return 4;
  }
  buffer[0] = 0;
  if ((ret = hydra_recv(s, buffer, sizeof(buffer) - 1)) >= 0)
    buffer[ret] = 0;
  /* 0x00 is sent but hydra_recv transformed it */
  if (strlen(buffer) == 0) {
    ret = hydra_recv(s, buffer, sizeof(buffer) - 1);
  }
  if (ret >= 0)
    buffer[ret] = 0;

  if (ret > 0 && (strstr(buffer, "rlogind:") != NULL))
    return 1;

  if (ret > 0 && (strstr(buffer, "ssword") != NULL)) {
    if (strlen((pass = hydra_get_next_password())) == 0)
      pass = empty;
    sprintf(buffer2, "%s\r", pass);
    if (hydra_send(s, buffer2, 1 + strlen(pass), 0) < 0) {
      return 1;
    }
    memset(buffer, 0, sizeof(buffer));
    ret = hydra_recv(s, buffer, sizeof(buffer));
    if (strcmp(buffer, "\r\n"))
      if ((ret = hydra_recv(s, buffer, sizeof(buffer) - 1)) > 0)
        buffer[ret] = 0;
  }
  /* Authentication failure */

  if (ret > 0 && (strstr(buffer, "ssword") == NULL)) {
#ifdef HAVE_PCRE
    if (!hydra_string_match(buffer, "\\s(failure|incorrect|denied)")) {
#else
    /* check for failure and incorrect msg */
    if ((strstr(buffer, "ailure") == NULL) && (strstr(buffer, "ncorrect") == NULL) && (strstr(buffer, "denied") == NULL)) {
#endif
      hydra_report_found_host(port, ip, "rlogin", fp);
      hydra_completed_pair_found();
    } else {
      hydra_completed_pair();
    }
  } else {
    /* if password is asked a second time, it means the pass we provided is
     * wrong */
    hydra_completed_pair();
  }

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_rlogin(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_RLOGIN, mysslport = PORT_RLOGIN_SSL;

  hydra_register_socket(sp);

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    next_run = 0;
    switch (run) {
    case 1: /* connect and service init function */
    {
      /* 512 -> 1023 */
      hydra_set_srcport(1023);
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //        usleepn(275);
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
      next_run = 2;
      break;
    }
    case 2: /* run the cracking function */
      next_run = start_rlogin(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_rlogin_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
