#include "hydra-mod.h"
#include "sasl.h"

/*

Based on:

RFC 3977: Network News Transfer Protocol (NNTP)
RFC 4643: Network News Transfer Protocol (NNTP) Extension for Authentication

*/

int32_t nntp_auth_mechanism = AUTH_CLEAR;

extern char *HYDRA_EXIT;
char *buf;

char *nntp_read_server_capacity(int32_t sock) {
  char *ptr = NULL;
  int32_t resp = 0;
  char *buf = NULL;

  do {
    if (buf != NULL)
      free(buf);
    ptr = buf = hydra_receive_line(sock);
    if (buf != NULL) {
      if (isdigit((int32_t)buf[0]) && buf[3] == ' ')
        resp = 1;
      else {
        if (buf[strlen(buf) - 1] == '\n')
          buf[strlen(buf) - 1] = 0;
        if (buf[strlen(buf) - 1] == '\r')
          buf[strlen(buf) - 1] = 0;
#ifdef NO_STRRCHR
        if ((ptr = rindex(buf, '\n')) != NULL) {
#else
        if ((ptr = strrchr(buf, '\n')) != NULL) {
#endif
          ptr++;
          if (isdigit((int32_t)*ptr) && *(ptr + 3) == ' ')
            resp = 1;
        }
      }
    }
  } while (buf != NULL && resp == 0);
  return buf;
}

int32_t start_nntp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "\"\"", *result = NULL;
  char *login, *pass, buffer[500], buffer2[500], *fooptr;
  int32_t i = 1;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  while (i > 0 && hydra_data_ready(s) > 0)
    i = hydra_recv(s, buffer, 300);

  if (i < 0)
    i = 0;
  buffer[i] = 0;

  switch (nntp_auth_mechanism) {
  case AUTH_LOGIN:
    sprintf(buffer, "AUTHINFO SASL LOGIN\r\n");
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (buf == NULL || strstr(buf, "383") == NULL) {
      hydra_report(stderr, "[ERROR] NNTP LOGIN AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    free(buf);
    strcpy(buffer2, login);
    hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));

    sprintf(buffer, "%.250s\r\n", buffer2);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (buf == NULL || strstr(buf, "383") == NULL) {
      hydra_report(stderr, "[ERROR] NNTP LOGIN AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    free(buf);
    strcpy(buffer2, pass);
    hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
    sprintf(buffer, "%.250s\r\n", buffer2);
    break;
  case AUTH_PLAIN:
    sprintf(buffer, "AUTHINFO SASL PLAIN\r\n");
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (buf == NULL || strstr(buf, "383") == NULL) {
      hydra_report(stderr, "[ERROR] NNTP PLAIN AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    free(buf);

    memset(buffer, 0, sizeof(buffer));
    result = sasl_plain(buffer, login, pass);
    if (result == NULL)
      return 3;

    char tmp_buffer[sizeof(buffer)];
    sprintf(tmp_buffer, "%.250s\r\n", buffer);
    strcpy(buffer, tmp_buffer);

    break;
#ifdef LIBOPENSSL
  case AUTH_CRAMMD5: {
    int32_t rc = 0;
    char *preplogin;

    rc = sasl_saslprep(login, SASL_ALLOW_UNASSIGNED, &preplogin);
    if (rc) {
      return 3;
    }

    sprintf(buffer, "AUTHINFO SASL CRAM-MD5\r\n");
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    // get the one-time BASE64 encoded challenge
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (buf == NULL || strstr(buf, "383") == NULL) {
      hydra_report(stderr, "[ERROR] NNTP CRAM-MD5 AUTH : %s\n", buf);
      free(buf);
      return 3;
    }

    memset(buffer, 0, sizeof(buffer));
    from64tobits((char *)buffer, buf + 4);
    free(buf);

    memset(buffer2, 0, sizeof(buffer2));
    result = sasl_cram_md5(buffer2, pass, buffer);
    if (result == NULL)
      return 3;

    sprintf(buffer, "%s %.250s", preplogin, buffer2);
    hydra_tobase64((unsigned char *)buffer, strlen(buffer), sizeof(buffer));

    char tmp_buffer[sizeof(buffer)];
    sprintf(tmp_buffer, "%.250s\r\n", buffer);
    strcpy(buffer, tmp_buffer);
    free(preplogin);
  } break;

  case AUTH_DIGESTMD5: {
    sprintf(buffer, "AUTHINFO SASL DIGEST-MD5\r\n");

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 1;
    // receive
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (buf == NULL || strstr(buf, "383") == NULL || strlen(buf) < 8) {
      hydra_report(stderr, "[ERROR] NNTP DIGEST-MD5 AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    memset(buffer, 0, sizeof(buffer));
    from64tobits((char *)buffer, buf + 4);
    free(buf);

    if (debug)
      hydra_report(stderr, "DEBUG S: %s\n", buffer);
    fooptr = buffer2;
    result = sasl_digest_md5(fooptr, login, pass, buffer, miscptr, "nntp", NULL, 0, NULL);
    if (result == NULL)
      return 3;

    if (debug)
      hydra_report(stderr, "DEBUG C: %s\n", buffer2);
    hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
    sprintf(buffer, "%s\r\n", buffer2);
  } break;

#endif

  case AUTH_NTLM: {
    unsigned char buf1[4096];
    unsigned char buf2[4096];

    // send auth and receive challenge
    buildAuthRequest((tSmbNtlmAuthRequest *)buf2, 0, NULL, NULL);
    to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthRequest *)buf2));
    sprintf(buffer, "AUTHINFO SASL NTLM %s\r\n", (char *)buf1);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (buf == NULL || strstr(buf, "383") == NULL || strlen(buf) < 8) {
      hydra_report(stderr, "[ERROR] NNTP NTLM AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    // recover challenge
    from64tobits((char *)buf1, buf + 4);
    free(buf);

    buildAuthResponse((tSmbNtlmAuthChallenge *)buf1, (tSmbNtlmAuthResponse *)buf2, 0, login, pass, NULL, NULL);
    to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse *)buf2));
    sprintf(buffer, "%s\r\n", (char *)buf1);
  } break;

  default: {
    sprintf(buffer, "AUTHINFO USER %.250s\r\n", login);

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    buf = hydra_receive_line(s);
    if (buf == NULL)
      return 1;
    if (buf[0] != '3') {
      if (verbose || debug)
        hydra_report(stderr, "[ERROR] Not an NNTP protocol or service shutdown: %s\n", buf);
      free(buf);
      return (3);
    }
    free(buf);
    sprintf(buffer, "AUTHINFO PASS %.250s\r\n", pass);
  } break;
  }

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = hydra_receive_line(s);
  if (buf == NULL)
    return 1;

  if (buf[0] == '2') {
    hydra_report_found_host(port, ip, "nntp", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }

  free(buf);
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 2;
}

void service_nntp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t i = 0, run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_NNTP, mysslport = PORT_NNTP_SSL, disable_tls = 0;
  char *buffer1 = "CAPABILITIES\r\n";

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
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
      //      usleepn(300);
      buf = hydra_receive_line(sock);
      if (buf == NULL || buf[0] != '2') { /* check the first line */
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Not an NNTP protocol or service shutdown: %s\n", buf);
        hydra_child_exit(2);
      }
      free(buf);

      /* send capability request */
      if (hydra_send(sock, buffer1, strlen(buffer1), 0) < 0)
        hydra_child_exit(2);
      buf = nntp_read_server_capacity(sock);

      if (buf == NULL) {
        hydra_child_exit(2);
      }
#ifdef LIBOPENSSL
      if (!disable_tls) {
        /* if we got a positive answer */
        if (strstr(buf, "STARTTLS") != NULL) {
          hydra_send(sock, "STARTTLS\r\n", strlen("STARTTLS\r\n"), 0);
          free(buf);
          buf = hydra_receive_line(sock);

          /* 382 Begin TLS negotiation now */
          if (buf == NULL || strstr(buf, "382") == NULL) {
            if (verbose)
              hydra_report(stderr, "[VERBOSE] TLS negotiation failed\n");
          } else {
            free(buf);
            if ((hydra_connect_to_ssl(sock, hostname) == -1)) {
              if (verbose)
                hydra_report(stderr, "[ERROR] Can't use TLS\n");
              disable_tls = 1;
              run = 1;
              break;
            } else {
              if (verbose)
                hydra_report(stderr, "[VERBOSE] TLS connection done\n");
            }
            /* ask again capability request but in TLS mode */
            if (hydra_send(sock, buffer1, strlen(buffer1), 0) < 0)
              hydra_child_exit(2);
            /* we asking again cause often plain and login can only
               be negociate in SSL tunnel
             */
            buf = nntp_read_server_capacity(sock);
            if (buf == NULL) {
              hydra_child_exit(2);
            }
          }
        }
      }
#endif

      /*
      AUTHINFO USER SASL
      SASL PLAIN DIGEST-MD5 LOGIN NTLM CRAM-MD5
      */

#ifdef HAVE_PCRE
      if (hydra_string_match(buf, "SASL\\s.*NTLM")) {
#else
      if (strstr(buf, "NTLM") != NULL) {
#endif
        nntp_auth_mechanism = AUTH_NTLM;
      }
#ifdef LIBOPENSSL

#ifdef HAVE_PCRE
      if (hydra_string_match(buf, "SASL\\s.*DIGEST-MD5")) {
#else
      if (strstr(buf, "DIGEST-MD5") != NULL) {
#endif
        nntp_auth_mechanism = AUTH_DIGESTMD5;
      }
#ifdef HAVE_PCRE
      if (hydra_string_match(buf, "SASL\\s.*CRAM-MD5")) {
#else
      if (strstr(buf, "CRAM-MD5") != NULL) {
#endif
        nntp_auth_mechanism = AUTH_CRAMMD5;
      }
#endif
#ifdef HAVE_PCRE
      if (hydra_string_match(buf, "SASL\\s.*PLAIN")) {
#else
      if (strstr(buf, "PLAIN") != NULL) {
#endif
        nntp_auth_mechanism = AUTH_PLAIN;
      }
#ifdef HAVE_PCRE
      if (hydra_string_match(buf, "SASL\\s.*LOGIN")) {
#else
      if (strstr(buf, "LOGIN") != NULL) {
#endif
        nntp_auth_mechanism = AUTH_LOGIN;
      }
#ifdef HAVE_PCRE
      if (hydra_string_match(buf, "AUTHINFO\\sUSER")) {
#else
      if (strstr(buf, "AUTHINFO USER") != NULL) {
#endif
        nntp_auth_mechanism = AUTH_CLEAR;
      }

      if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
        for (i = 0; i < strlen(miscptr); i++)
          miscptr[i] = (char)toupper((int32_t)miscptr[i]);

        if (strncmp(miscptr, "USER", 4) == 0)
          nntp_auth_mechanism = AUTH_CLEAR;

        if (strncmp(miscptr, "LOGIN", 5) == 0)
          nntp_auth_mechanism = AUTH_LOGIN;

        if (strncmp(miscptr, "PLAIN", 5) == 0)
          nntp_auth_mechanism = AUTH_PLAIN;

#ifdef LIBOPENSSL
        if (strncmp(miscptr, "CRAM-MD5", 8) == 0)
          nntp_auth_mechanism = AUTH_CRAMMD5;

        if (strncmp(miscptr, "DIGEST-MD5", 10) == 0)
          nntp_auth_mechanism = AUTH_DIGESTMD5;
#endif

        if (strncmp(miscptr, "NTLM", 4) == 0)
          nntp_auth_mechanism = AUTH_NTLM;
      }
      if (verbose) {
        switch (nntp_auth_mechanism) {
        case AUTH_CLEAR:
          hydra_report(stderr, "[VERBOSE] using NNTP AUTHINFO USER mechanism\n");
          break;
        case AUTH_LOGIN:
          hydra_report(stderr, "[VERBOSE] using NNTP LOGIN AUTH mechanism\n");
          break;
        case AUTH_PLAIN:
          hydra_report(stderr, "[VERBOSE] using NNTP PLAIN AUTH mechanism\n");
          break;
#ifdef LIBOPENSSL
        case AUTH_CRAMMD5:
          hydra_report(stderr, "[VERBOSE] using NNTP CRAM-MD5 AUTH mechanism\n");
          break;
        case AUTH_DIGESTMD5:
          hydra_report(stderr, "[VERBOSE] using NNTP DIGEST-MD5 AUTH mechanism\n");
          break;
#endif
        case AUTH_NTLM:
          hydra_report(stderr, "[VERBOSE] using NNTP NTLM AUTH mechanism\n");
          break;
        }
      }
      usleepn(25);
      free(buf);
      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_nntp(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_nntp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_nntp(const char *service) {
  printf("Module nntp is optionally taking one authentication type of:\n"
         "  USER (default), LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5, NTLM\n\n");
}
