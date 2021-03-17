// This plugin was written by <david dot maciejak at gmail D O T com>
// checked for memleaks on 110425, none found

#ifdef LIBSVN

/* needed on openSUSE */
#define _GNU_SOURCE

#if !defined PATH_MAX && defined HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <svn_client.h>
#include <svn_cmdline.h>
#include <svn_config.h>
#include <svn_fs.h>
#include <svn_pools.h>
#include <svn_version.h>
#if SVN_VER_MINOR > 7
#include <svn_path.h>
#endif

#endif

#include "hydra-mod.h"

#ifndef LIBSVN
void dummy_svn() { printf("\n"); }
#else

extern int32_t hydra_data_ready_timed(int32_t socket, long sec, long usec);

extern char *HYDRA_EXIT;

#define DEFAULT_BRANCH "trunk"

static svn_error_t *print_dirdummy(void *baton, const char *path, const svn_dirent_t *dirent, const svn_lock_t *lock, const char *abs_path, apr_pool_t *pool) { return SVN_NO_ERROR; }

static svn_error_t *my_simple_prompt_callback(svn_auth_cred_simple_t **cred, void *baton, const char *realm, const char *username, svn_boolean_t may_save, apr_pool_t *pool) {
  char *empty = "";
  char *login, *pass;
  svn_auth_cred_simple_t *ret = apr_pcalloc(pool, sizeof(*ret));

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  ret->username = apr_pstrdup(pool, login);
  ret->password = apr_pstrdup(pool, pass);

  *cred = ret;
  return SVN_NO_ERROR;
}

int32_t start_svn(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  // int32_t ipv6 = 0;
  char URL[1024];
  char URLBRANCH[256];
#if SVN_VER_MINOR > 7
  const char *canonical;
#endif
  apr_pool_t *pool;
  svn_error_t *err;
  svn_opt_revision_t revision;
  apr_uint32_t dirents;
  svn_client_ctx_t *ctx;
  svn_auth_provider_object_t *provider;
  apr_array_header_t *providers;

  if (miscptr)
    strncpy(URLBRANCH, miscptr, sizeof(URLBRANCH));
  else
    strncpy(URLBRANCH, DEFAULT_BRANCH, sizeof(URLBRANCH));

  if (svn_cmdline_init("hydra", stderr) != EXIT_SUCCESS)
    return 4;

  // if (ip[0] == 16)
  //  ipv6 = 1;

  pool = svn_pool_create(NULL);

  err = svn_config_ensure(NULL, pool);
  if (err) {
    svn_pool_destroy(pool);
    svn_handle_error2(err, stderr, FALSE, "hydra: ");
    return 4;
  }

#if SVN_VER_MINOR > 7
  if ((err = svn_client_create_context2(&ctx, NULL, pool))) {
#else
  if ((err = svn_client_create_context(&ctx, pool))) {
#endif
    svn_pool_destroy(pool);
    svn_handle_error2(err, stderr, FALSE, "hydra: ");
    return 4;
  }

  if ((err = svn_config_get_config(&(ctx->config), NULL, pool))) {
    svn_pool_destroy(pool);
    svn_handle_error2(err, stderr, FALSE, "hydra: ");
    return 4;
  }

  providers = apr_array_make(pool, 1, sizeof(svn_auth_provider_object_t *));

  svn_auth_get_simple_prompt_provider(&provider, my_simple_prompt_callback, NULL, /* baton */
                                      0, pool);
  APR_ARRAY_PUSH(providers, svn_auth_provider_object_t *) = provider;

  /* Register the auth-providers into the context's auth_baton. */
  svn_auth_open(&ctx->auth_baton, providers, pool);

  revision.kind = svn_opt_revision_head;
  snprintf(URL, sizeof(URL), "svn://%s:%d/%s", hydra_address2string_beautiful(ip), port, URLBRANCH);
  dirents = SVN_DIRENT_KIND;
#if SVN_VER_MINOR > 9
  canonical = svn_uri_canonicalize(URL, pool);
  err = svn_client_list4(canonical, &revision, &revision, NULL, svn_depth_unknown, dirents, FALSE, FALSE, (svn_client_list_func2_t)print_dirdummy, NULL, ctx, pool);
#elif SVN_VER_MINOR > 7
  canonical = svn_uri_canonicalize(URL, pool);
  err = svn_client_list3(canonical, &revision, &revision, svn_depth_unknown, dirents, FALSE, FALSE, (svn_client_list_func2_t)print_dirdummy, NULL, ctx, pool);
#else
err = svn_client_list2(URL, &revision, &revision, svn_depth_unknown, dirents, FALSE, print_dirdummy, NULL, ctx, pool);
#endif

  svn_pool_destroy(pool);

  if (err) {
    if (debug || (verbose && (err->apr_err != 170001 && err->apr_err != 170013)))
      hydra_report(stderr, "[ERROR] Access refused (error code %d) , message: %s\n", err->apr_err, err->message);
    // Username not found 170001 ": Username not found"
    // Password incorrect 170001 ": Password incorrect"
    if (err->apr_err != 170001 && err->apr_err != 170013) {
      return 4; // error
    } else {
      if (strstr(err->message, "Username not found")) {
        // if (verbose)
        // printf("[INFO] user %s does not exist, skipping\n", login);
        hydra_completed_pair_skip();
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
      } else {
        hydra_completed_pair();
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
      }
    }
  } else {
    if (verbose)
      hydra_report(stderr, "[VERBOSE] Access granted\n");
    hydra_report_found_host(port, ip, "svn", fp);
    hydra_completed_pair_found();
    return 3;
  }
  return 3;
}

void service_svn(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_SVN, mysslport = PORT_SVN_SSL;

  hydra_register_socket(sp);

  while (1) {
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return;

    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);

      //      usleepn(300);
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
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }

      next_run = 2;
      break;
    case 2:
      next_run = start_svn(sock, ip, port, options, miscptr, fp);
      break;
    case 3:
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      if (!verbose)
        hydra_report(stderr, "[ERROR] Caught unknown return code, try verbose "
                             "option for more details\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

#endif

int32_t service_svn_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here

#ifdef LIBSVN
  if (verbose)
    hydra_report(stderr, "[VERBOSE] detected subversion library v%d.%d\n", SVN_VER_MAJOR, SVN_VER_MINOR);
  if (SVN_VER_MAJOR != 1 && SVN_VER_MINOR >= 5) {
    hydra_report(stderr, "[ERROR] unsupported subversion library v%d.%d, exiting!\n", SVN_VER_MAJOR, SVN_VER_MINOR);
    return -1;
  }
#endif
  return 0;
}

void usage_svn(const char *service) {
  printf("Module svn is optionally taking the repository name to attack, "
         "default is \"trunk\"\n\n");
}
