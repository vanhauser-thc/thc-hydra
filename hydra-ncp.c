/*
 *	Novell Network Core Protocol Support - by David Maciejak @ GMAIL dot com
 *	Tested on Netware 6.5
 *
 * you need to install libncp and libncp-dev (tested with version 2.2.6-3)
 *
 *	you can passed full context as OPT
 *
 * example: ./hydra -L login -P passw 172.16.246.129 ncp .O=cx
 *
 */

#include "hydra-mod.h"

#ifndef LIBNCP
void dummy_ncp() { printf("\n"); }
#else

#include <ncp/nwcalls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char *HYDRA_EXIT;
extern int32_t child_head_no;

typedef struct __NCP_DATA {
  struct ncp_conn_spec spec;
  struct ncp_conn *conn;
  char *context;
} _NCP_DATA;

// uncomment line below to see more trace stack
//#define NCP_DEBUG

int32_t start_ncp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *login;
  char *pass;
  char context[256];
  uint32_t ncp_lib_error_code;
  char *empty = "";
  int32_t object_type = NCP_BINDERY_USER;

  _NCP_DATA *session;

  session = malloc(sizeof(_NCP_DATA));
  memset(session, 0, sizeof(_NCP_DATA));
  login = empty;
  pass = empty;

  if (strlen(login = hydra_get_next_login()) == 0) {
    login = empty;
  } else {
    if (miscptr) {
      if (strlen(miscptr) + strlen(login) > sizeof(context)) {
        free(session);
        return 4;
      }
      memset(context, 0, sizeof(context));
      strncpy(context, login, sizeof(context) - 2);
      context[sizeof(context) - 2] = 0;
      strncpy(context + strlen(login), miscptr, sizeof(context) - strlen(login) - 1);
      context[sizeof(context) - 1] = 0;
      login = context;
    }
  }

  // login and password are case insensitive
  // str_upper(login);

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  ncp_lib_error_code = ncp_find_conn_spec3(hydra_address2string(ip), login, "", 1, getuid(), 0, &session->spec);
  if (ncp_lib_error_code) {
    free(session);
    return 1;
  }

  ncp_lib_error_code = NWCCOpenConnByName(NULL, session->spec.server, NWCC_NAME_FORMAT_BIND, NWCC_OPEN_NEW_CONN, NWCC_RESERVED, &session->conn);
  if (ncp_lib_error_code) {
    free(session);
    return 1;
  }

  memset(session->spec.password, 0, sizeof(session->spec.password));
  memcpy(session->spec.password, pass, strlen(pass) + 1);
  // str_upper(session->spec.password);

  ncp_lib_error_code = ncp_login_conn(session->conn, session->spec.user, object_type, session->spec.password);
  switch (ncp_lib_error_code & 0x0000FFFF) {
  case 0x0000: /* Success */
#ifdef NCP_DEBUG
    printf("Connection success (%s / %s). Error code: %X\n", login, pass, ncp_lib_error_code);
#endif
    ncp_close(session->conn);
    hydra_report_found_host(port, ip, "ncp", fp); // ok
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3; // exit
    free(session);
    return 2; // next
    break;
  case 0x89DE: /* PASSWORD INVALID */
  case 0x89F0: /* BIND WILDCARD INVALID */
  case 0x89FF: /* NO OBJ OR BAD PASSWORD */
  case 0xFD63: /* FAILED_AUTHENTICATION */
  case 0xFDA7: /* NO_SUCH_ENTRY */
#ifdef NCP_DEBUG
    printf("Incorrect password (%s / %s). Error code: %X\n", login, pass, ncp_lib_error_code);
#endif
    ncp_close(session->conn);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
      free(session);
      return 2; // next
    }
    break;
  default:
#ifdef NCP_DEBUG
    printf("Failed to open connection. Error code: %X\n", ncp_lib_error_code);
#endif
    if (session->conn != NULL)
      ncp_close(session->conn);
    break;
  }
  free(session);
  return 1; // reconnect
}

void service_ncp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_NCP;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      if (port != 0)
        myport = port;
      sock = hydra_connect_tcp(ip, myport);
      port = myport;
      if (sock < 0) {
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = 2;
      break;
    case 2:
      /*
       *      Here we start the password cracking process
       */
      next_run = start_ncp(sock, ip, port, options, miscptr, fp);
      break;
    case 3:
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    case 4:
      if (child_head_no == 0)
        fprintf(stderr, "[ERROR] Optional parameter too long!\n");
      hydra_child_exit(0);

    default:
      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

#endif

int32_t service_ncp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_ncp(const char *service) {
  printf("Module ncp is optionally taking the full context, for example "
         "\".O=cx\"\n\n");
}
