
/*

david: code is based on SNORT spo_database.c

tested with :
-instantclient_10_2 on Oracle 10.2.0
-instantclient-basic-linux.*-11.2.0.3.0.zip + instantclient-sdk-linux.*-11.2.0.3.0.zip
on Oracle 9i and on Oracle 11g

*/

#include "hydra-mod.h"

#ifndef LIBORACLE

void dummy_oracle() {
  printf("\n");
}

#else

#include <oci.h>
#include <sys/types.h>

extern char *HYDRA_EXIT;

OCIEnv *o_environment;
OCISvcCtx *o_servicecontext;
OCIBind *o_bind;
OCIError *o_error;
OCIStmt *o_statement;
OCIDefine *o_define;
text o_errormsg[512];
sb4 o_errorcode;

void print_oracle_error(char *err) {
  if (verbose) {
    OCIErrorGet(o_error, 1, NULL, &o_errorcode, o_errormsg, sizeof(o_errormsg), OCI_HTYPE_ERROR);
    fprintf(stderr, "[ERROR] Oracle_error: %s - %s\n", o_errormsg, err);
  }
}

int start_oracle(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp) {
  char *empty = "";
  char *login, *pass, buffer[200], sid[100];

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  strncpy(sid, miscptr, sizeof(sid) - 1);
  sid[sizeof(sid) - 1] = 0;
  snprintf(buffer, sizeof(buffer), "//%s:%d/%s", hydra_address2string(ip), port, sid);

  /*

     To use the Easy Connect naming method, PHP must be linked with Oracle 10g or greater Client libraries.
     The Easy Connect string for Oracle 10g is of the form: [//]host_name[:port][/service_name].
     With Oracle 11g, the syntax is: [//]host_name[:port][/service_name][:server_type][/instance_name].
     Service names can be found by running the Oracle utility lsnrctl status on the database server machine.

     The tnsnames.ora file can be in the Oracle Net search path, which includes $ORACLE_HOME/network/admin
     and /etc. Alternatively set TNS_ADMIN so that $TNS_ADMIN/tnsnames.ora is read. Make sure the web
     daemon has read access to the file. 

   */

  if (OCIInitialize(OCI_DEFAULT, NULL, NULL, NULL, NULL)) {
    print_oracle_error("OCIInitialize");
    return 4;
  }
  if (OCIEnvInit(&o_environment, OCI_DEFAULT, 0, NULL)) {
    print_oracle_error("OCIEnvInit");
    return 4;
  }
  if (OCIEnvInit(&o_environment, OCI_DEFAULT, 0, NULL)) {
    print_oracle_error("OCIEnvInit 2");
    return 4;
  }
  if (OCIHandleAlloc(o_environment, (dvoid **) & o_error, OCI_HTYPE_ERROR, (size_t) 0, NULL)) {
    print_oracle_error("OCIHandleAlloc");
    return 4;
  }

  if (OCILogon(o_environment, o_error, &o_servicecontext, (const OraText *) login, strlen(login), (const OraText *) pass, strlen(pass), (const OraText *) buffer, strlen(buffer))) {
    OCIErrorGet(o_error, 1, NULL, &o_errorcode, o_errormsg, sizeof(o_errormsg), OCI_HTYPE_ERROR);
    //database: oracle_error: ORA-01017: invalid username/password; logon denied
    //database: oracle_error: ORA-12514: TNS:listener does not currently know of service requested in connect descriptor
    //database: oracle_error: ORA-28000: the account is locked
    //Failed login attempts is set to 10 by default
    if (verbose) {
      hydra_report(stderr, "[VERBOSE] database: oracle_error: %s\n", o_errormsg);
    }
    if (strstr((const char *) o_errormsg, "ORA-12514") != NULL) {
      hydra_report(stderr, "[ERROR] ORACLE SID is not valid, you should try to enumerate them.\n");
    }
    if (strstr((const char *) o_errormsg, "ORA-28000") != NULL) {
      hydra_report(stderr, "[ERROR] ORACLE account %s is locked.\n", login);
    }

    if (o_error) {
      OCIHandleFree((dvoid *) o_error, OCI_HTYPE_ERROR);
    }

    hydra_completed_pair();
    //by default, set in sqlnet.ora, the trace file is generated in pwd to log any errors happening,
    //as we don't care, we are deleting the file
    //set these parameters to not generate the file
    //LOG_DIRECTORY_CLIENT = /dev/null
    //LOG_FILE_CLIENT = /dev/null
    unlink("sqlnet.log");

    return 2;
  } else {
    OCILogoff(o_servicecontext, o_error);
    if (o_error) {
      OCIHandleFree((dvoid *) o_error, OCI_HTYPE_ERROR);
    }
    hydra_report_found_host(port, ip, "oracle", fp);
    hydra_completed_pair_found();
  }
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_oracle(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  int run = 1, next_run = 1, sock = -1;
  int myport = PORT_ORACLE;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  if ((miscptr == NULL) || (strlen(miscptr) == 0)) {
    //SID is required as miscptr
    hydra_report(stderr, "[ERROR] Oracle SID is required, using ORCL as default\n");
    miscptr = "ORCL";
  }

  while (1) {
    switch (run) {
    case 1:                    /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      if (port != 0)
        myport = port;
      sock = hydra_connect_tcp(ip, myport);
      port = myport;

      if (sock < 0) {
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int) getpid());
        hydra_child_exit(1);
      }
      next_run = 2;
      break;
    case 2:
      next_run = start_oracle(sock, ip, port, options, miscptr, fp);
      hydra_child_exit(0);
      break;
    case 3:                    /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

#endif

int service_oracle_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
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
