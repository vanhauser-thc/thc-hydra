/*

libssh is available at http://www.libssh.org
If you want support for ssh v1 protocol, you
have to add option -DWITH_SSH1=On in the cmake

*/

#include "hydra-mod.h"
#ifndef LIBSSH
void dummy_ssh() { printf("\n"); }
#else

#include <libssh/libssh.h>

#if LIBSSH_VERSION_MAJOR == 0 && LIBSSH_VERSION_MINOR >= 4

ssh_session session = NULL;

extern hydra_option hydra_options;
extern char *HYDRA_EXIT;
int32_t new_session = 1;

int32_t start_ssh(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, keep_login[300];
  int32_t auth_state = 0, rc = 0, i = 0;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  if (new_session) {
    if (session) {
      ssh_disconnect(session);
      // ssh_finalize();
      ssh_free(session);
    } else {
      ssh_init();
    }

    session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_HOST, hydra_address2string(ip));
    ssh_options_set(session, SSH_OPTIONS_USER, login);
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &hydra_options.waittime);
    ssh_options_set(session, SSH_OPTIONS_COMPRESSION_C_S, "none");
    ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "none");
    if (ssh_connect(session) != 0) {
      // if the connection was drop, exit and let hydra main handle it
      if (verbose)
        hydra_report(stderr, "[ERROR] could not connect to target port %d: %s\n", port, ssh_get_error(session));
      return 3;
    }

    if ((rc = ssh_userauth_none(session, NULL)) == SSH_AUTH_ERROR) {
      return 3;
    } else if (rc == SSH_AUTH_SUCCESS) {
      hydra_report_found_host(port, ip, "ssh", fp);
      hydra_completed_pair_found();
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 2;
      else
        return 1;
    }
  } else
    new_session = 1;

  auth_state = ssh_auth_list(session);
  if ((auth_state & SSH_AUTH_METHOD_PASSWORD) > 0) {
    auth_state = ssh_userauth_password(session, NULL, pass);
  } else if ((auth_state & SSH_AUTH_METHOD_INTERACTIVE) > 0) {
    auth_state = ssh_userauth_kbdint(session, NULL, NULL);
    while (auth_state == SSH_AUTH_INFO) {
      rc = ssh_userauth_kbdint_getnprompts(session);
      for (i = 0; i < rc; i++)
        ssh_userauth_kbdint_setanswer(session, i, pass);
      auth_state = ssh_userauth_kbdint(session, NULL, NULL);
    }
  } else {
    return 4;
  }

  if (auth_state == SSH_AUTH_ERROR || !ssh_is_connected(session)) {
    new_session = 1;
    return 1;
  }

  if (auth_state == SSH_AUTH_SUCCESS || auth_state == SSH_AUTH_PARTIAL) {
    hydra_report_found_host(port, ip, "ssh", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 2;
    return 1;
  } else {
    strncpy(keep_login, login, sizeof(keep_login) - 1);
    keep_login[sizeof(keep_login) - 1] = '\0';
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 2;
    login = hydra_get_next_login();
    if (strcmp(login, keep_login) == 0)
      new_session = 0;
    return 1;
  }

  /* not reached */
  return 1;
}

void service_ssh(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      next_run = start_ssh(sock, ip, port, options, miscptr, fp);
      break;
    case 2:
      ssh_disconnect(session);
      ssh_finalize();
      ssh_free(session);
      hydra_child_exit(0);
      break;
    case 3:
      ssh_disconnect(session);
      ssh_finalize();
      ssh_free(session);
      if (verbose)
        fprintf(stderr, "[ERROR] ssh protocol error\n");
      hydra_child_exit(2);
      break;
    case 4:
      ssh_disconnect(session);
      ssh_finalize();
      ssh_free(session);
      fprintf(stderr, "[ERROR] ssh target does not support password auth\n");
      hydra_child_exit(2);
      break;
    default:
      ssh_disconnect(session);
      ssh_finalize();
      ssh_free(session);
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}
#else
#error "You are not using v0.4.x. Download from http://www.libssh.org and add -DWITH_SSH1=On in cmake to enable SSH v1 support"
#endif
#endif

//
// dirty workaround here: miscptr is the ptr to the logins, and the first one is
// used to test if password authentication is enabled!!
//
int32_t service_ssh_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   1 skip target without generating an error
  //   2 skip target because of protocol problems
  //   3 skip target because its unreachable
#ifdef LIBSSH
  int32_t rc, method;
  ssh_init();
  ssh_session session = ssh_new();

  if (verbose || debug)
    printf("[INFO] Testing if password authentication is supported by "
           "ssh://%s@%s:%d\n",
           miscptr == NULL ? "hydra" : miscptr, hydra_address2string_beautiful(ip), port);
  ssh_options_set(session, SSH_OPTIONS_PORT, &port);
  ssh_options_set(session, SSH_OPTIONS_HOST, hydra_address2string(ip));
  if (miscptr == NULL)
    ssh_options_set(session, SSH_OPTIONS_USER, "hydra");
  else
    ssh_options_set(session, SSH_OPTIONS_USER, miscptr);
  ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &hydra_options.waittime);
  ssh_options_set(session, SSH_OPTIONS_COMPRESSION_C_S, "none");
  ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "none");
  if (ssh_connect(session) != 0) {
    fprintf(stderr, "[ERROR] could not connect to ssh://%s:%d - %s\n", hydra_address2string_beautiful(ip), port, ssh_get_error(session));
    return 2;
  }
  rc = ssh_userauth_none(session, NULL);
  method = ssh_userauth_list(session, NULL);
  ssh_disconnect(session);
  ssh_finalize();
  ssh_free(session);

  if (debug)
    printf("[DEBUG] SSH method check: %08x\n", method);

  if ((method & SSH_AUTH_METHOD_INTERACTIVE) || (method & SSH_AUTH_METHOD_PASSWORD)) {
    if (verbose || debug)
      printf("[INFO] Successful, password authentication is supported by "
             "ssh://%s:%d\n",
             hydra_address2string_beautiful(ip), port);
    return 0;
  } else if (method == 0) {
    if (verbose || debug)
      fprintf(stderr,
              "[WARNING] invalid SSH method reply from ssh://%s:%d, continuing "
              "anyway ... (check for empty password!)\n",
              hydra_address2string_beautiful(ip), port);
    return 0;
  }

  fprintf(stderr,
          "[ERROR] target ssh://%s:%d/ does not support password "
          "authentication (method reply %d).\n",
          hydra_address2string_beautiful(ip), port, method);
  return 1;
#else
  return 0;
#endif
}
