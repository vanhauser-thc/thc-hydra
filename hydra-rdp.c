/*
   This module is using freerdp3 lib

   Tested on:
  - Windows 7 pro SP1
  - Windows 10 pro build 1809
  - Windows Server 2016 build 1607
*/

#include "hydra-mod.h"

extern hydra_option hydra_options;
extern char *HYDRA_EXIT;
#ifndef LIBFREERDP
void dummy_rdp() { printf("\n"); }
#else

#include <freerdp/freerdp.h>
freerdp *instance = 0;
BOOL rdp_connect(char *server, int32_t port, char *domain, char *login, char *password) {
  int32_t err = 0;

  instance->settings->Username = login;
  instance->settings->Password = password;
  instance->settings->IgnoreCertificate = TRUE;
  if (password[0] == 0)
    instance->settings->AuthenticationOnly = FALSE;
  else
    instance->settings->AuthenticationOnly = TRUE;
  instance->settings->ServerHostname = server;
  instance->settings->ServerPort = port;
  instance->settings->Domain = domain;
  instance->settings->MaxTimeInCheckLoop = 100;
  // freerdp timeout format is microseconds -> default:15000
  instance->settings->TcpConnectTimeout = hydra_options.waittime * 1000;
  instance->settings->TlsSecLevel = 0;
  freerdp_connect(instance);
  err = freerdp_get_last_error(instance->context);
  return err;
}

/* Client program */
int32_t start_rdp(char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;
  char server[64];
  char domain[256];
  int32_t login_result = 0;

  memset(domain, 0, sizeof(domain));

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  strncpy(server, hydra_address2string(ip), sizeof(server) - 1);

  if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
    strncpy(domain, miscptr, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = 0;
  }

  login_result = rdp_connect(server, port, domain, login, pass);
  if (debug)
    hydra_report(stderr, "[DEBUG] rdp reported %08x\n", login_result);
  switch (login_result) {
  case 0:
    // login success
    hydra_report_found_host(port, ip, "rdp", fp);
    hydra_completed_pair_found();
    break;
  case 0x00020009:
  case 0x00020014:
  case 0x00020015:
    // login failure
    hydra_completed_pair();
    break;
  case 0x0002000d:
    hydra_report(stderr,
                 "[%d][rdp] account on %s might be valid but account not "
                 "active for remote desktop: login: %s password: %s, "
                 "continuing attacking the account.\n",
                 port, hydra_address2string_beautiful(ip), login, pass);
    hydra_completed_pair();
    break;
  case 0x00020006:
  case 0x00020008:
  case 0x0002000c:
    // cannot establish rdp connection, either the port is not opened or it's
    // not rdp
    return 3;
  default:
    if (verbose) {
      hydra_report(stderr, "[ERROR] freerdp: %s (0x%.8x)\n", freerdp_get_last_error_string(login_result), login_result);
    }
    return login_result;
  }
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 2;
  return 1;
}

void service_rdp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1;
  int32_t myport = PORT_RDP;
  int32_t __first_rdp_connect = 1;

  if (port != 0)
    myport = port;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    next_run = 0;
    switch (run) {
    case 1: /* run the cracking function */
      if (__first_rdp_connect != 0)
        __first_rdp_connect = 0;
      else
        sleep(hydra_options.conwait);
      next_run = start_rdp(ip, myport, options, miscptr, fp);
      break;
    case 2: /* clean exit */
      freerdp_disconnect(instance);
      freerdp_free(instance);
      hydra_child_exit(0);
      return;
    case 3: /* connection error case */
      hydra_report(stderr, "[ERROR] freerdp: %s\n", "The connection failed to establish.");
      freerdp_free(instance);
      hydra_child_exit(1);
      return;
    default:
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_rdp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here

  // Disable freerdp output
  wLog *root = WLog_GetRoot();
  WLog_SetStringLogLevel(root, "OFF");

  // Init freerdp instance
  instance = freerdp_new();
  if (instance == NULL || freerdp_context_new(instance) == FALSE) {
    hydra_report(stderr, "[ERROR] freerdp init failed\n");
    return -1;
  }
  return 0;
}

void usage_rdp(const char *service) {
  printf("Module rdp is optionally taking the windows domain name.\n"
         "For example:\nhydra rdp://192.168.0.1/firstdomainname -l john -p "
         "doe\n\n");
}
#endif
