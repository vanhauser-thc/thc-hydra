/*

Firebird Support - by David Maciejak @ GMAIL dot com

you need to pass full path to the fdb file as argument
default account is SYSDBA/masterkey

on Firebird 2.0, access to the database file directly
is not possible anymore, in verbose mode you will see
the msg: "no permission for direct access to security database"

 */

#include "hydra-mod.h"

#ifndef LIBFIREBIRD
void dummy_firebird() { printf("\n"); }
#else

#include <ibase.h>
#include <stdio.h>

#define DEFAULT_DB "C:\\Program Files\\Firebird\\Firebird_1_5\\security.fdb"

extern char *HYDRA_EXIT;

int32_t start_firebird(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;
  char database[256];
  char connection_string[1024];

  isc_db_handle db;        /* database handle */
  ISC_STATUS_ARRAY status; /* status vector */

  char *dpb = NULL; /* DB parameter buffer */
  short dpb_length = 0;

  if (miscptr)
    strncpy(database, miscptr, sizeof(database));
  else
    strncpy(database, DEFAULT_DB, sizeof(database));
  database[sizeof(database) - 1] = 0;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  dpb_length = (short)(1 + strlen(login) + 2 + strlen(pass) + 2);
  if ((dpb = (char *)malloc(dpb_length)) == NULL) {
    hydra_report(stderr, "[ERROR] Can't allocate memory\n");
    return 1;
  }

  /* Add user and password to dpb */
  *dpb = isc_dpb_version1;
  dpb_length = 1;
  isc_modify_dpb(&dpb, &dpb_length, isc_dpb_user_name, login, strlen(login));
  isc_modify_dpb(&dpb, &dpb_length, isc_dpb_password, pass, strlen(pass));

  /* Create connection string */
  snprintf(connection_string, sizeof(connection_string), "%s:%s", hydra_address2string(ip), database);

  if (isc_attach_database(status, 0, connection_string, &db, dpb_length, dpb)) {
    /* for debugging perpose */
    if (verbose) {
      hydra_report(stderr, "[VERBOSE] ");
      isc_print_status(status);
    }
    isc_free(dpb);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 2;
  } else {
    isc_detach_database(status, &db);
    isc_free(dpb);
    hydra_report_found_host(port, ip, "firebird", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 2;
  }
  return 1;
}

void service_firebird(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_FIREBIRD, mysslport = PORT_FIREBIRD_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
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
        sock = hydra_connect_ssl(ip, mysslport, hostname);
        port = mysslport;
      }
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

      next_run = start_firebird(sock, ip, port, options, miscptr, fp);
      break;
    case 3:

      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;

    default:

      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

#endif

int32_t service_firebird_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_firebird(const char *service) {
  printf("Module firebird is optionally taking the database path to attack,\n"
         "default is \"C:\\Program "
         "Files\\Firebird\\Firebird_1_5\\security.fdb\"\n\n");
}
