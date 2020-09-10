// This plugin was written by <david dot maciejak at gmail D O T com>
// Tested on memcached 1.5.6-0ubuntu1

#ifdef LIBMCACHED
#include <libmemcached/memcached.h>
#endif

#include "hydra-mod.h"

#ifndef LIBMCACHED
void dummy_mcached() { printf("\n"); }
#else

extern int32_t hydra_data_ready_timed(int32_t socket, long sec, long usec);

extern char *HYDRA_EXIT;

int mcached_send_com_quit(int32_t sock) {
  char *com_quit = "quit\r\n";

  if (hydra_send(sock, com_quit, strlen(com_quit), 0) < 0)
    return 1;
  return 0;
}

int mcached_send_com_version(int32_t sock) {
  char *com_version = "version\r\n";

  if (hydra_send(sock, com_version, strlen(com_version), 0) < 0)
    return 1;
  return 0;
}

int32_t start_mcached(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;

  memcached_server_st *servers = NULL;
  memcached_return_t rc;
  memcached_st *cache;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  cache = memcached_create(NULL);

  rc = memcached_set_sasl_auth_data(cache, login, pass);
  if (rc != MEMCACHED_SUCCESS) {
    if (verbose)
      hydra_report(stderr, "[ERROR] Couldn't setup SASL auth: %s\n", memcached_strerror(cache, rc));
    memcached_free(cache);
    return 3;
  }

  rc = memcached_behavior_set(cache, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
  if (rc != MEMCACHED_SUCCESS) {
    if (verbose)
      hydra_report(stderr, "[ERROR] Couldn't use the binary protocol: %s\n", memcached_strerror(cache, rc));
    memcached_destroy_sasl_auth_data(cache);
    memcached_free(cache);
    return 3;
  }
  rc = memcached_behavior_set(cache, MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT, 10000);
  if (rc != MEMCACHED_SUCCESS) {
    if (verbose)
      hydra_report(stderr, "[ERROR] Couldn't set the connect timeout: %s\n", memcached_strerror(cache, rc));
    memcached_destroy_sasl_auth_data(cache);
    memcached_free(cache);
    return 3;
  }

  servers = memcached_server_list_append(servers, hydra_address2string(ip), port, &rc);
  rc = memcached_server_push(cache, servers);
  if (rc != MEMCACHED_SUCCESS) {
    if (verbose)
      hydra_report(stderr, "[ERROR] Couldn't add server: %s\n", memcached_strerror(cache, rc));
    memcached_destroy_sasl_auth_data(cache);
    memcached_free(cache);
    return 3;
  }

  rc = memcached_stat_execute(cache, "", NULL, NULL);
  if (rc != MEMCACHED_SUCCESS) {
    if (verbose)
      hydra_report(stderr, "[ERROR] Couldn't get server stats: %s\n", memcached_strerror(cache, rc));
    memcached_destroy_sasl_auth_data(cache);
    memcached_free(cache);
    hydra_completed_pair_skip();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
      return 3;
    }
    return 2;
  }

  memcached_destroy_sasl_auth_data(cache);
  memcached_free(cache);

  hydra_report_found_host(port, ip, "memcached", fp);
  hydra_completed_pair_found();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 2;
}

void service_mcached(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;

  hydra_register_socket(sp);

  while (1) {
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return;

    switch (run) {
    case 1:
      next_run = start_mcached(sock, ip, port, options, miscptr, fp);
      break;
    case 2:
      hydra_child_exit(0);
      return;
    default:
      if (!verbose)
        hydra_report(stderr, "[ERROR] Caught unknown return code, try verbose "
                             "option for more details\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_mcached_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.

  int32_t sock = -1;
  int32_t myport = PORT_MCACHED;
  char *buf;

  if (port != 0)
    myport = port;

  sock = hydra_connect_tcp(ip, myport);
  if (sock < 0) {
    if (verbose || debug)
      hydra_report(stderr, "[ERROR] Can not connect\n");
    return -1;
  }

  if (mcached_send_com_version(sock)) {
    if (verbose || debug)
      hydra_report(stderr, "[ERROR] Can not send request\n");
    return -1;
  }

  if (hydra_data_ready_timed(sock, 0, 1000) > 0) {
    buf = hydra_receive_line(sock);
    if (strstr(buf, "VERSION ")) {
      hydra_report_found_host(port, ip, "memcached", fp);
      mcached_send_com_quit(sock);
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_report(stderr, "[ERROR] Memcached server does not require any authentication\n");
    }
    free(buf);
    return -1;
  }
  if (sock >= 0)
    sock = hydra_disconnect(sock);
  return 0;
}

#endif
