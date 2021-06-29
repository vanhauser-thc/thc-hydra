
/*
 libssh is available at http://www.libssh.org
 current version is 0.4.8
 If you want support for ssh v1 protocol, you
 have to add option -DWITH_SSH1=On in the cmake
*/

#include "hydra-mod.h"
#ifndef LIBSSH
void dummy_sshkey() { printf("\n"); }
#else

#include <libssh/libssh.h>

#if LIBSSH_VERSION_MAJOR >= 0 && LIBSSH_VERSION_MINOR >= 4

extern ssh_session session;
extern char *HYDRA_EXIT;
extern int32_t new_session;

int32_t start_sshkey(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *key, keep_login[300];
  int32_t auth_state = 0, rc = 0;
  ssh_private_key privkey;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(key = hydra_get_next_password()) == 0)
    key = empty;

  if (new_session) {
    if (session) {
      ssh_disconnect(session);
      ssh_free(session);
    } else {
      ssh_init();
    }

    session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_HOST, hydra_address2string(ip));
    ssh_options_set(session, SSH_OPTIONS_USER, login);
    ssh_options_set(session, SSH_OPTIONS_COMPRESSION_C_S, "none");
    ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "none");
    if (ssh_connect(session) != 0) {
      // if the connection was drop, exit and let hydra main handle it
      if (verbose)
        hydra_report(stderr, "[ERROR] could not connect to target port %d\n", port);
      return 3;
    }

    if ((rc = ssh_userauth_none(session, NULL)) == SSH_AUTH_ERROR) {
      return 3;
    } else if (rc == SSH_AUTH_SUCCESS) {
      hydra_report_found_host(port, ip, "sshkey", fp);
      hydra_completed_pair_found();
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 2;
      else
        return 1;
    }
  } else
    new_session = 1;

  auth_state = ssh_auth_list(session);
  if ((auth_state & SSH_AUTH_METHOD_PUBLICKEY) > 0) {
    privkey = privatekey_from_file(session, key, 0, NULL);
    if (!privkey) {
      hydra_report(stderr, "[ERROR] skipping invalid private key: \"%s\"\n", key);
      hydra_completed_pair();
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 2;

      return 1;
    }
    auth_state = ssh_userauth_pubkey(session, NULL, NULL, privkey);
  } else {
    return 4;
  }

  if (auth_state == SSH_AUTH_ERROR) {
    new_session = 1;
    return 1;
  }

  if (auth_state == SSH_AUTH_SUCCESS || auth_state == SSH_AUTH_PARTIAL) {
    hydra_report_found_host(port, ip, "sshkey", fp);
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

void service_sshkey(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      next_run = start_sshkey(sock, ip, port, options, miscptr, fp);
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
      fprintf(stderr, "[ERROR] ssh protocol error\n");
      hydra_child_exit(2);
      break;
    case 4:
      ssh_disconnect(session);
      ssh_finalize();
      ssh_free(session);
      fprintf(stderr, "[ERROR] ssh target does not support pubkey auth\n");
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
#error "You are not using at least v0.4.x. Download from http://www.libssh.org and add -DWITH_SSH1=On in cmake to enable SSH v1 support"
#endif
#endif

int32_t service_sshkey_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_sshkey(const char *service) {
  printf("Module sshkey does not provide additional options, although the "
         "semantic for\n"
         "options -p and -P is changed:\n"
         "  -p expects a path to an unencrypted private key in PEM format.\n"
         "  -P expects a filename containing a list of path to some unencrypted\n"
         "     private keys in PEM format.\n\n");
}
