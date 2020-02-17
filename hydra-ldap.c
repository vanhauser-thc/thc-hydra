#include "hydra-mod.h"
#include "sasl.h"

extern char *HYDRA_EXIT;

unsigned char *buf;
int32_t counter;
int32_t tls_required = 0;

int32_t start_ldap(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp, char *hostname, char version, int32_t auth_method) {
  char *empty = "", *result = NULL;
  char *login = "", *pass, *fooptr = "";
  unsigned char buffer[512];
  int32_t length = 0;
  int32_t ldap_auth_mechanism = auth_method;

  /*
     The LDAP "simple" method has three modes of operation:
     * anonymous= no user no pass
     * unauthenticated= user but no pass
     * user/password authenticated= user and pass
   */

  if ((miscptr != NULL) && (ldap_auth_mechanism == AUTH_CLEAR)) {
    login = miscptr;
  } else {
    if (strlen(login = hydra_get_next_login()) == 0)
      login = empty;
  }
  if (miscptr == NULL)
    miscptr = fooptr;

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  switch (ldap_auth_mechanism) {
  case AUTH_CLEAR:
    length = 14 + strlen(login) + strlen(pass);
    break;
#ifdef LIBOPENSSL
  case AUTH_CRAMMD5:
    length = 14 + strlen(miscptr) + strlen("CRAM-MD5") + 2;
    break;
  case AUTH_DIGESTMD5:
    length = 14 + strlen(miscptr) + strlen("DIGEST-MD5") + 2;
    break;
#endif
  }

  memset(buffer, 0, sizeof(buffer));
  buffer[0] = 48;
  buffer[1] = length - 2;

  buffer[2] = 2;
  buffer[3] = 1;
  buffer[4] = counter % 256;

  buffer[5] = 96;
  buffer[6] = length - 7;
  buffer[7] = 2;
  buffer[8] = 1;
  buffer[9] = version;
  buffer[10] = 4;

  if (ldap_auth_mechanism == AUTH_CLEAR) {
    buffer[11] = strlen(login); /* DN */
    memcpy(&buffer[12], login, strlen(login));
    buffer[12 + strlen(login)] = (unsigned char)128;
    buffer[13 + strlen(login)] = strlen(pass);
    memcpy(&buffer[14 + strlen(login)], pass, strlen(pass)); /* PASS */
  } else {
    char *authm = "DIGEST-MD5";

    if (ldap_auth_mechanism == AUTH_CRAMMD5) {
      authm = "CRAM-MD5";
    }

    if ((strlen(miscptr)) > sizeof(buffer) - 16 - strlen(authm)) {
      miscptr[sizeof(buffer) - 16 - strlen(authm)] = '\0';
    }

    buffer[11] = strlen(miscptr); /* DN */
    memcpy(&buffer[12], miscptr, strlen(miscptr));
    buffer[12 + strlen(miscptr)] = 163;
    buffer[13 + strlen(miscptr)] = 2 + strlen(authm);
    buffer[14 + strlen(miscptr)] = 4;
    buffer[15 + strlen(miscptr)] = strlen(authm);
    memcpy(&buffer[16 + strlen(miscptr)], authm, strlen(authm));
  }
  if (hydra_send(s, (char *)buffer, length, 0) < 0)
    return 1;
  if ((buf = (unsigned char *)hydra_receive_line(s)) == NULL)
    return 1;

  if (buf[0] != 0 && buf[0] != 32 && buf[9] == 2) {
    if (verbose)
      hydra_report(stderr, "[VERBOSE] Protocol invalid\n");
    free(buf);
    return 3;
  }

  if (buf[0] != 0 && buf[0] != 32 && buf[9] == 13) {
    if (verbose)
      hydra_report(stderr, "[VERBOSE] Confidentiality required, TLS has to be enabled\n");
    tls_required = 1;
    free(buf);
    return 1;
  }

  if ((buf[0] != 0 && buf[0] != 32) && buf[9] == 34) {
    hydra_report(stderr, "[ERROR] Invalid DN Syntax\n");
    hydra_child_exit(2);
    free(buf);
    return 3;
  }
#ifdef LIBOPENSSL

  /* one more step auth for CRAM and DIGEST */
  if (ldap_auth_mechanism == AUTH_CRAMMD5) {
    /* get the challenge, need to extract it */
    char *ptr;
    char buf2[32];

    ptr = strstr((char *)buf, "<");
    fooptr = buf2;
    result = sasl_cram_md5(fooptr, pass, ptr);
    if (result == NULL)
      return 1;
    counter++;
    if (strstr(miscptr, "^USER^") != NULL) {
      miscptr = hydra_strrep(miscptr, "^USER^", login);
    }

    length = 12 + strlen(miscptr) + 4 + strlen("CRAM-MD5") + 2 + strlen(login) + 1 + strlen(buf2);

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 48;
    buffer[1] = length - 2;

    buffer[2] = 2;
    buffer[3] = 1;
    buffer[4] = counter % 256;

    buffer[5] = 96;
    buffer[6] = length - 7;
    buffer[7] = 2;
    buffer[8] = 1;
    buffer[9] = version;
    buffer[10] = 4;

    buffer[11] = strlen(miscptr); /* DN */
    memcpy(&buffer[12], miscptr, strlen(miscptr));
    buffer[12 + strlen(miscptr)] = 163;
    buffer[13 + strlen(miscptr)] = 2 + strlen("CRAM-MD5") + 2 + strlen(login) + 1 + strlen(buf2);
    buffer[14 + strlen(miscptr)] = 4;
    buffer[15 + strlen(miscptr)] = strlen("CRAM-MD5");
    memcpy(&buffer[16 + strlen(miscptr)], "CRAM-MD5", strlen("CRAM-MD5"));
    buffer[16 + strlen(miscptr) + strlen("CRAM-MD5")] = 4;
    buffer[17 + strlen(miscptr) + strlen("CRAM-MD5")] = strlen(login) + 1 + strlen(buf2);
    memcpy(&buffer[18 + strlen(miscptr) + strlen("CRAM-MD5")], login, strlen(login));
    buffer[18 + strlen(miscptr) + strlen("CRAM-MD5") + strlen(login)] = ' ';
    memcpy(&buffer[18 + strlen(miscptr) + strlen("CRAM-MD5") + strlen(login) + 1], buf2, strlen(buf2));

    if (hydra_send(s, (char *)buffer, length, 0) < 0)
      return 1;
    free(buf);
    if ((buf = (unsigned char *)hydra_receive_line(s)) == NULL)
      return 1;
  } else {
    if (ldap_auth_mechanism == AUTH_DIGESTMD5) {
      char *ptr;
      char buffer2[500];
      int32_t ind = 0;

      ptr = strstr((char *)buf, "realm=");

      counter++;
      if (strstr(miscptr, "^USER^") != NULL) {
        miscptr = hydra_strrep(miscptr, "^USER^", login);
      }

      fooptr = buffer2;
      result = sasl_digest_md5(fooptr, login, pass, ptr, miscptr, "ldap", NULL, 0, NULL);
      if (result == NULL) {
        free(buf);
        return 3;
      }

      length = 26 + strlen(miscptr) + strlen("DIGEST-MD5") + strlen(buffer2);

      memset(buffer, 0, sizeof(buffer));
      ind = 0;
      buffer[ind] = 48;
      ind++;
      buffer[ind] = 130;
      ind++;

      if (length - 4 > 255) {
        buffer[ind] = 1;
        ind++;
        buffer[ind] = length - 256 - 4;
        ind++;
      } else {
        buffer[ind] = 0;
        ind++;
        buffer[ind] = length - 4;
        ind++;
      }

      buffer[ind] = 2;
      ind++;
      buffer[ind] = 1;
      ind++;
      buffer[ind] = counter % 256;
      ind++;
      buffer[ind] = 96; /*0x60 */
      ind++;
      buffer[ind] = 130;
      ind++;
      if (length - 7 - 4 > 255) {
        buffer[ind] = 1;
        ind++;
        buffer[ind] = length - 256 - 11;
        ind++;
      } else {
        buffer[ind] = 0;
        ind++;
        buffer[ind] = length - 11;
        ind++;
      }

      buffer[ind] = 2;
      ind++;
      buffer[ind] = 1;
      ind++;
      buffer[ind] = version;
      ind++;
      buffer[ind] = 4;
      ind++;
      buffer[ind] = strlen(miscptr);
      ind++;
      memcpy(&buffer[ind], miscptr, strlen(miscptr));
      /*DN*/ buffer[ind + strlen(miscptr)] = 163; // 0xa3
      ind++;
      buffer[ind + strlen(miscptr)] = 130; // 0x82
      ind++;

      if (strlen(buffer2) + 6 + strlen("DIGEST-MD5") > 255) {
        buffer[ind + strlen(miscptr)] = 1;
        ind++;
        buffer[ind + strlen(miscptr)] = strlen(buffer2) + 6 + strlen("DIGEST-MD5") - 256;
      } else {
        buffer[ind + strlen(miscptr)] = 0;
        ind++;
        buffer[ind + strlen(miscptr)] = strlen(buffer2) + 6 + strlen("DIGEST-MD5");
      }
      ind++;

      buffer[ind + strlen(miscptr)] = 4;
      ind++;
      buffer[ind + strlen(miscptr)] = strlen("DIGEST-MD5");
      ind++;
      memcpy(&buffer[ind + strlen(miscptr)], "DIGEST-MD5", strlen("DIGEST-MD5"));
      buffer[ind + strlen(miscptr) + strlen("DIGEST-MD5")] = 4;
      ind++;
      buffer[ind + strlen(miscptr) + strlen("DIGEST-MD5")] = 130;
      ind++;

      if (strlen(buffer2) > 255) {
        buffer[ind + strlen(miscptr) + strlen("DIGEST-MD5")] = 1;
        ind++;
        buffer[ind + strlen(miscptr) + strlen("DIGEST-MD5")] = strlen(buffer2) - 256;
      } else {
        buffer[ind + strlen(miscptr) + strlen("DIGEST-MD5")] = 0;
        ind++;
        buffer[ind + strlen(miscptr) + strlen("DIGEST-MD5")] = strlen(buffer2);
      }
      ind++;
      memcpy(&buffer[ind + strlen(miscptr) + strlen("DIGEST-MD5")], buffer2, strlen(buffer2));
      ind++;

      if (hydra_send(s, (char *)buffer, length, 0) < 0)
        return 1;
      free(buf);
      if ((buf = (unsigned char *)hydra_receive_line(s)) == NULL)
        return 1;
    }
  }
#endif

  /* success is: 0a 01 00 - failure is: 0a 01 31 */
  if ((buf[0] != 0 && buf[9] == 0) || (buf[0] != 32 && buf[9] == 32)) {
    hydra_report_found_host(port, ip, "ldap", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }

  if ((buf[0] != 0 && buf[0] != 32) && buf[9] == 7) {
    hydra_report(stderr, "[ERROR] Unknown authentication method\n");
    free(buf);
    hydra_child_exit(2);
  }

  if ((buf[0] != 0 && buf[0] != 32) && buf[9] == 53) {
    if (verbose)
      hydra_report(stderr,
                   "[VERBOSE] Server unwilling to perform action, maybe deny by server "
                   "config or too busy when tried login: %s   password: %s\n",
                   login, pass);
    free(buf);
    return 1;
  }

  if ((buf[0] != 0 && buf[0] != 32) && buf[9] == 2) {
    hydra_report(stderr,
                 "[ERROR] Invalid protocol version, you tried ldap%c, better "
                 "try ldap%c\n",
                 version + '0', version == 2 ? '3' : '2');
    free(buf);
    hydra_child_exit(2);
    sleep(1);
    hydra_child_exit(2);
  }
  // 0 0x30, 0x84, 0x20, 0x20, 0x20, 0x10, 0x02, 0x01,
  // 8 0x01, 0x61, 0x84, 0x20, 0x20, 0x20, 0x07, 0x0a,
  // 16 0x01, 0x20, 0x04, 0x20, 0x04, 0x20, 0x00, 0x00,

  // this is for w2k8 active directory ldap auth
  if (buf[0] == 48 && buf[1] == 132) {
    if (buf[9] == 0x61 && buf[1] == 0x84) {
      if (buf[17] == 0 || buf[17] == 0x20) {
        hydra_report_found_host(port, ip, "ldap", fp);
        hydra_completed_pair_found();
        free(buf);
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
        return 1;
      }
    }
  } else {
    if (buf[9] != 49 && buf[9] != 2 && buf[9] != 53) {
      hydra_report(stderr, "[ERROR] Uh, unknown LDAP response! Please report this: \n");
      print_hex((unsigned char *)buf, 24);
      free(buf);
      return 3;
    }
  }

  hydra_completed_pair();
  free(buf);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 2;
}

void service_ldap(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname, char version, int32_t auth_method) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_LDAP, mysslport = PORT_LDAP_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //      usleepn(275);
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
      counter = 1;
      if (tls_required) {
        /* Start TLS operation OID = 1.3.6.1.4.1.1466.20037 according to RFC
         * 2830 */
        char confidentiality_required[] = "\x30\x1d\x02\x01\x01\x77\x18\x80\x16\x31\x2e\x33\x2e\x36\x2e\x31"
                                          "\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37";

        if (hydra_send(sock, confidentiality_required, strlen(confidentiality_required), 0) < 0)
          hydra_child_exit(1);

        if ((buf = (unsigned char *)hydra_receive_line(sock)) == NULL)
          hydra_child_exit(1);

        if ((buf[0] != 0 && buf[9] == 0) || (buf[0] != 32 && buf[9] == 32)) {
          /* TLS option negociation goes well, now trying to connect */
          free(buf);
          if ((hydra_connect_to_ssl(sock, hostname) == -1) && verbose) {
            hydra_report(stderr, "[ERROR] Can't use TLS\n");
            hydra_child_exit(1);
          } else {
            if (verbose)
              hydra_report(stderr, "[VERBOSE] TLS connection done\n");
            counter++;
          }
        } else {
          hydra_report(stderr, "[ERROR] Can't use TLS %s\n", buf);
          free(buf);
          hydra_child_exit(1);
        }
      }
      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_ldap(sock, ip, port, options, miscptr, fp, hostname, version, auth_method);
      counter++;
      break;
    case 3: /* clean exit */
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

void service_ldap2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_ldap(ip, sp, options, miscptr, fp, port, hostname, 2, AUTH_CLEAR); }

void service_ldap3(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_ldap(ip, sp, options, miscptr, fp, port, hostname, 3, AUTH_CLEAR); }

void service_ldap3_cram_md5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_ldap(ip, sp, options, miscptr, fp, port, hostname, 3, AUTH_CRAMMD5); }

void service_ldap3_digest_md5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_ldap(ip, sp, options, miscptr, fp, port, hostname, 3, AUTH_DIGESTMD5); }

int32_t service_ldap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here
  if (miscptr != NULL && strlen(miscptr) > 220) {
    fprintf(stderr, "[ERROR] the option string to this module may not be "
                    "larger than 220 bytes\n");
    return -1;
  }

  return 0;
}

void usage_ldap(const char *service) {
  printf("Module %s is optionally taking the DN (depending of the auth method "
         "choosed\n"
         "Note: you can also specify the DN as login when Simple auth method "
         "is used).\n"
         "The keyword \"^USER^\" is replaced with the login.\n"
         "Special notes for Simple method has 3 operation modes: anonymous, "
         "(no user no pass),\n"
         "unauthenticated (user but no pass), user/pass authenticated (user "
         "and pass).\n"
         "So don't forget to set empty string as user/pass to test all modes.\n"
         "Hint: to authenticate to a windows active directory ldap, this is "
         "usually\n"
         " cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com\n\n",
         service);
}
