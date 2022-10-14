/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Copyright (C) 2021 Karim Kanso, all rights reserved.
 *  kaz 'dot' kanso 'at' g mail 'dot' com
 */

#if defined(LIBSMBCLIENT)

#include "hydra-mod.h"

#include <errno.h>
#include <libsmbclient.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

extern char *HYDRA_EXIT;

typedef struct creds {
  const char *workgroup;
  const char *user;
  const char *pass;
} creds_t;

const char default_workgroup[] = "WORKGROUP";
bool use_nt_hash = false;
const char *workgroup = default_workgroup;
const char *netbios_name = NULL;

#define EXIT_PROTOCOL_ERROR hydra_child_exit(2)
#define EXIT_CONNECTION_ERROR hydra_child_exit(1)
#define EXIT_NORMAL hydra_child_exit(0)

void smb2_auth_provider(SMBCCTX *c, const char *srv, const char *shr, char *wg, int wglen, char *un, int unlen, char *pw, int pwlen) {
  creds_t *cr = (creds_t *)smbc_getOptionUserData(c);
  strncpy(wg, cr->workgroup, wglen);
  strncpy(un, cr->user, unlen);
  strncpy(pw, cr->pass, pwlen);
  wg[wglen - 1] = 0;
  un[unlen - 1] = 0;
  pw[pwlen - 1] = 0;
}

bool smb2_run_test(creds_t *cr, const char *server, uint16_t port) {
  SMBCCTX *ctx = smbc_new_context();
  if (ctx == NULL) {
    hydra_report(stderr, "[ERROR] failed to create context\n");
    EXIT_PROTOCOL_ERROR;
  }
  // samba internal debugging will be dumped to stderr
  smbc_setDebug(ctx, debug ? 7 : 0);
  smbc_setOptionDebugToStderr(ctx, true);
  smbc_setFunctionAuthDataWithContext(ctx, smb2_auth_provider);
  smbc_setOptionUserData(ctx, cr);
  // 0 will use default port
  smbc_setPort(ctx, port);
  smbc_setOptionNoAutoAnonymousLogin(ctx, false);
  smbc_setOptionUseNTHash(ctx, use_nt_hash);
  if (netbios_name) {
    smbc_setNetbiosName(ctx, (char *)netbios_name);
  }

  ctx = smbc_init_context(ctx);
  if (!ctx) {
    hydra_report(stderr, "[ERROR] smbc_init_context fail\n");
    smbc_free_context(ctx, 1);
    EXIT_PROTOCOL_ERROR;
  }

  char uri[2048];
  snprintf(uri, sizeof(uri) - 1, "smb://%s/IPC$", server);
  uri[sizeof(uri) - 1] = 0;
  if (verbose) {
    printf("[INFO] Connecting to: %s with %s\\%s%%%s\n", uri, cr->workgroup, cr->user, cr->pass);
  }
  SMBCFILE *fd = smbc_getFunctionOpendir(ctx)(ctx, uri);
  if (fd) {
    hydra_report(stderr, "[WARNING] Unexpected open on IPC$\n");
    smbc_getFunctionClosedir(ctx)(ctx, fd);
    smbc_free_context(ctx, 1);
    fd = NULL;
    return true;
  }

  /*
    errno is set to 22 (EINVAL) when IPC$ as been opened but can not
    be opened like a normal share. This corresponds to samba error
    NT_STATUS_INVALID_INFO_CLASS, however this precise error code is
    not available outside of the library. Thus, instead the library
    sets a generic error (EINVAL) which can also correspond to other
    cases (see below test).

    This is not ideal, but appears to be the best that the
    libsmbclient library offers as detailed state information is
    internalised and not available. Further, it is also not possible
    from the api to separate the connection, authentication and
    authorisation.

    The following text is taken from the libsmbclient header file for
    the return value of the smbc_getFunctionOpendir function:

        Valid directory handle. < 0 on error with errno set:
        - EACCES Permission denied.
        - EINVAL A NULL file/URL was passed, or the URL would
        not parse, or was of incorrect form or smbc_init not
        called.
        - ENOENT durl does not exist, or name is an
        - ENOMEM Insufficient memory to complete the
        operation.
        - ENOTDIR name is not a directory.
        - EPERM the workgroup could not be found.
        - ENODEV the workgroup or server could not be found.

  */
  switch (errno) {
  case 0: 
    // maybe false positive? unclear ... :( ... needs more testing
    smbc_free_context(ctx, 1);
    return true;
    break;
  case ENOENT:
    // Noticed this when connecting to older samba servers on linux
    // where any credentials are accepted.
    hydra_report(stderr, "[WARNING] %s might accept any credential\n", server);
  case EINVAL: // 22
    // probably password ok, nominal case when connecting to a windows
    // smb server with good credentials.
    smbc_free_context(ctx, 1);
    return true;
    break;
  case EPERM:
    // Probably this means access denied inspite of mention above
    // about being related to wrong workgroup. I have observed
    // libsmbclient emitting this when connecting to a vanilla install
    // of Windows 2019 server (non-domain) with wrong credentials. It
    // appears related to a fallback null session being rejected after
    // the library tries with provided credentials. If the null
    // session is accepted, EACCES is returned.
  case EACCES:
    // 100% access denied
    break;
  case EHOSTUNREACH:
  case ETIMEDOUT:
  case ECONNREFUSED:
    // there are probably more codes that could be added here to
    // indicate connection errors.
    hydra_report(stderr, "[ERROR] Error %s (%d) while connecting to %s\n", strerror(errno), errno, server);
    smbc_free_context(ctx, 1);
    EXIT_CONNECTION_ERROR;
    break;
  default:
    // unexpected error
    hydra_report(stderr, "[ERROR] %s (%d)\n", strerror(errno), errno);
    smbc_free_context(ctx, 1);
    EXIT_PROTOCOL_ERROR;
  }

  smbc_free_context(ctx, 1);
  return false;
}

void service_smb2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  hydra_register_socket(sp);
  while (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT))) {
    char *login, *pass;

    login = hydra_get_next_login();
    pass = hydra_get_next_password();

    creds_t cr = {
        .user = login,
        .pass = pass,
        .workgroup = workgroup,
    };

    if (smb2_run_test(&cr, hydra_address2string(ip), port & 0xffff)) {
      hydra_completed_pair_found();
    } else {
      hydra_completed_pair();
    }
  }
  EXIT_NORMAL;
}

// constants used by option parser
const char tkn_workgroup[] = "workgroup:{";
const char tkn_nthash_true[] = "nthash:true";
const char tkn_nthash_false[] = "nthash:false";
const char tkn_netbios[] = "netbios:{";

#define CMP(s1, s2) (strncmp(s1, s2, sizeof(s1) - 1) == 0)

int32_t service_smb2_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  if (!miscptr)
    return 0;

  while (*miscptr) {
    if (isspace(*miscptr)) {
      miscptr++;
      continue;
    }
    if (CMP(tkn_workgroup, miscptr)) {
      if (workgroup != default_workgroup) {
        // miscptr has already been processed, goto end
        miscptr += strlen(miscptr) + 1;
        continue;
      }
      miscptr += sizeof(tkn_workgroup) - 1;
      char *p = strchr(miscptr, '}');
      if (p == NULL) {
        hydra_report(stderr, "[ERROR] missing closing brace in workgroup\n");
        return -1;
      }
      *p = '\0';
      workgroup = miscptr;
      miscptr = p + 1;
      if (verbose || debug) {
        printf("[VERBOSE] Set workgroup to: %s\n", workgroup);
      }
      continue;
    }
    if (CMP(tkn_netbios, miscptr)) {
      if (netbios_name != NULL) {
        // miscptr has already been processed, goto end
        miscptr += strlen(miscptr) + 1;
        continue;
      }
      miscptr += sizeof(tkn_netbios) - 1;
      char *p = strchr(miscptr, '}');
      if (p == NULL) {
        hydra_report(stderr, "[ERROR] missing closing brace in netbios name\n");
        return -1;
      }
      *p = '\0';
      netbios_name = miscptr;
      miscptr = p + 1;
      if (verbose || debug) {
        printf("[VERBOSE] Set netbios name to: %s\n", netbios_name);
      }
      continue;
    }
    if (CMP(tkn_nthash_true, miscptr)) {
      miscptr += sizeof(tkn_nthash_true) - 1;
      use_nt_hash = true;
      if (verbose || debug) {
        printf("[VERBOSE] Enabled nthash.\n");
      }
      continue;
    }
    if (CMP(tkn_nthash_false, miscptr)) {
      miscptr += sizeof(tkn_nthash_false) - 1;
      use_nt_hash = false;
      if (verbose || debug) {
        printf("[VERBOSE] Disabled nthash.\n");
      }
      continue;
    }

    hydra_report(stderr, "[ERROR] unable to parse: %s\n", miscptr);
    return -1;
  }

  return 0;
}

void usage_smb2(const char *service) {
  puts("Module is a thin wrapper over the Samba client library (libsmbclient).\n"
       "Thus, is capable of negotiating v1, v2 and v3 of the protocol.\n"
       "\n"
       "As this relies on Samba libraries, the system smb.conf will be parsed\n"
       "when library starts up. It is possible to add configuration options\n"
       "into that file that affect this module (such as min/max supported\n"
       "protocol version).\n"
       "\n"
       "Caution: due to the high-level libsmbclient api (compared the smb\n"
       "Hydra module), the accuracy is reduced. That is, this module works by\n"
       "attempting to open the IPC$ share, which is reported as an error,\n"
       "e.g. try this with the smbclient tool and it will raise the\n"
       "NT_STATUS_INVALID_INFO_CLASS error). Sadly, the level of feedback\n"
       "from the api does not distinguish this error from general/unknown\n"
       "errors, so it might be possible to have false positives due to this\n"
       "fact. One example of this is when the library can not parse the uri\n"
       "correctly. On the other hand, false negatives could occur when a\n"
       "valid credential is unable to open the share due to access control,\n"
       "e.g. a locked/suspended account.\n"
       "\n"
       "There are three module options available:\n"
       "  workgroup:{XXX} - set the users workgroup\n"
       "  netbios:{XXX} - set the recipients netbios name\n"
       "  nthash:true or nthash:false - threat password as an nthash\n"
       "\n"
       "Examples: \n"
       "  hydra smb2://abc.com -l admin -p xxx -m workgroup:{OFFICE}\n"
       "  hydra smb2://1.2.3.4 -l admin -p F54F3A1D3C38140684FF4DAD029F25B5 -m "
       "'workgroup:{OFFICE} nthash:true'\n"
       "  hydra -l admin -p F54F3A1D3C38140684FF4DAD029F25B5 "
       "'smb2://1.2.3.4/workgroup:{OFFICE} nthash:true'\n");
}

#endif // LIBSMBCLIENT
