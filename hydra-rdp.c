/*
   This module is using freerdp3 lib

   Tested on:
  - Windows 7 pro SP1
  - Windows 10 pro build 1809
  - Windows Server 2016 build 1607
*/

#include "hydra-mod.h"

extern hydra_option hydra_options;
extern const unsigned char HYDRA_EXIT[5];
#ifndef LIBFREERDP
void dummy_rdp() { printf("\n"); }
#else

#include <freerdp/freerdp.h>
#include <freerdp/version.h>

/* RDP security protocols selected during the X.224 negotiation
 * (see [MS-RDPBCGR] 2.2.1.2.1). They are defined in a private FreeRDP header
 * (libfreerdp/core/nego.h), so the values we need are redefined here.
 * Only NLA/CredSSP (PROTOCOL_HYBRID*) validates the supplied credentials during
 * the connection handshake. Without it an AuthenticationOnly connect succeeds
 * for any credentials, which is the root cause of the xrdp false positives in
 * issue #923. */
#ifndef PROTOCOL_HYBRID
#define PROTOCOL_HYBRID 0x00000002
#endif
#ifndef PROTOCOL_HYBRID_EX
#define PROTOCOL_HYBRID_EX 0x00000008
#endif

freerdp *instance = 0;
BOOL rdp_connect(char *server, int32_t port, char *domain, char *login, char *password) {
  int32_t err = 0;

  rdpSettings *settings = instance->context->settings;

  settings->Username = login;
  settings->Password = password;
  settings->IgnoreCertificate = TRUE;
  if (password[0] == 0)
    settings->AuthenticationOnly = FALSE;
  else
    settings->AuthenticationOnly = TRUE;
  settings->ServerHostname = server;
  settings->ServerPort = port;
  settings->Domain = domain;

#if FREERDP_VERSION_MAJOR == 2
  settings->MaxTimeInCheckLoop = 100;
#endif
  // freerdp timeout format is microseconds -> default:15000
  settings->TcpConnectTimeout = hydra_options.waittime * 1000;
  settings->TlsSecLevel = 0;
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
  case 0x0002000f:
    /* ERRCONNECT_LOGON_FAILURE = wrong credentials. Keep trying other
     * passwords for this user instead of skipping the user entirely. */
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
      if (next_run == 1 && hydra_options.conwait)
        sleep(hydra_options.conwait);
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
  // return codes:
  //   0 all OK
  //   1 skip target without generating an error
  //   2 skip target because of protocol problems
  //   3 skip target because its unreachable
  //   -1 error, hydra will exit, so print a good error message here
  int32_t err;
  UINT32 selected;
  char server[64];
  char domain[256];
  char probe_login[] = "hydra";
  char probe_pass[] = "hydra";
  rdpSettings *settings;
  freerdp *probe;

  // Disable freerdp output
  wLog *root = WLog_GetRoot();
  WLog_SetStringLogLevel(root, "OFF");

  /* hydra can only verify RDP credentials when the server enforces NLA/CredSSP:
   * only then are the credentials validated during the connection handshake.
   * Without NLA (e.g. xrdp, or a Windows host with NLA disabled) the server
   * defers authentication to an in-session login, so any connect succeeds and
   * every login looks valid (issue #923). Probe the negotiated security layer
   * once here with throwaway credentials (the protocol is negotiated before
   * authentication is attempted), and skip the target if NLA is absent instead
   * of reporting false positives. */
  probe = freerdp_new();
  if (probe == NULL || freerdp_context_new(probe) == FALSE) {
    hydra_report(stderr, "[ERROR] freerdp init failed\n");
    return -1;
  }
  settings = probe->context->settings;
  memset(server, 0, sizeof(server));
  memset(domain, 0, sizeof(domain));
  strncpy(server, hydra_address2string(ip), sizeof(server) - 1);
  if (miscptr != NULL && strlen(miscptr) > 0) {
    strncpy(domain, miscptr, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = 0;
  }
  settings->Username = probe_login;
  settings->Password = probe_pass;
  settings->Domain = domain;
  settings->ServerHostname = server;
  settings->ServerPort = port;
  settings->IgnoreCertificate = TRUE;
  settings->AuthenticationOnly = TRUE;
#if FREERDP_VERSION_MAJOR == 2
  settings->MaxTimeInCheckLoop = 100;
#endif
  settings->TcpConnectTimeout = hydra_options.waittime * 1000;
  settings->TlsSecLevel = 0;
  freerdp_connect(probe);
  err = freerdp_get_last_error(probe->context);
  selected = settings->SelectedProtocol;
  freerdp_disconnect(probe);
  freerdp_free(probe);

  if (err == 0x00020006 || err == 0x00020008 || err == 0x0002000c) {
    // cannot establish rdp connection, port closed or not rdp
    hydra_report(stderr, "[ERROR] could not connect to rdp://%s:%d\n",
                 hydra_address2string_beautiful(ip), port);
    return 3;
  }
  /* NLA/CredSSP (PROTOCOL_HYBRID*) was negotiated only if the corresponding bit
   * is set; anything else (plain RDP or TLS) means credentials are not checked
   * during connect, so hydra would report false positives. */
  if (!(selected & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX))) {
    hydra_report(stderr,
                 "[ERROR] %s does not enforce NLA/CredSSP for RDP; credentials "
                 "cannot be verified (every login would be a false positive). "
                 "Skipping this target. Enable NLA on the target, or verify "
                 "credentials interactively, to scan it.\n",
                 hydra_address2string_beautiful(ip));
    return 1;
  }

  // NLA is available, set up the instance the cracking children will use
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
         "doe\n"
         "Note: hydra can only verify RDP credentials on targets that enforce\n"
         "NLA/CredSSP. Targets without NLA (e.g. xrdp, or Windows with NLA\n"
         "disabled) defer authentication to an in-session login and are\n"
         "reported as not verifiable instead of being brute forced.\n\n");
}
#endif
