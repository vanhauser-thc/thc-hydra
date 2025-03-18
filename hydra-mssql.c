#include "hydra-mod.h"
#include <sybdb.h>
#include <sybfront.h>

extern char *HYDRA_EXIT;
char *buf;

int32_t start_mssql(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;
  char *ipaddr_str = hydra_address2string(ip);

  fprintf(stdout, "The target ip is: %s\n", ipaddr_str);


  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  DBPROCESS *dbproc;
  LOGINREC *attempt;

  dbinit();
  attempt = dblogin();
  DBSETLUSER(attempt, login);
  DBSETLPWD(attempt, pass);

  // Connect without specifying a database
  dbproc = dbopen(attempt, ipaddr_str);  

  if (dbproc != NULL) {
    hydra_report_found_host(port, ip, "mssql", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 2;
    return 1;
  }

  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 2;

  return 1;
}

void service_mssql(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_MSSQL, mysslport = PORT_MSSQL_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
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
      next_run = start_mssql(sock, ip, port, options, miscptr, fp);
      hydra_disconnect(sock);
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

int32_t service_mssql_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
