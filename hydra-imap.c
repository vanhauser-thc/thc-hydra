#include "hydra-mod.h"
#include "sasl.h"

extern char *HYDRA_EXIT;
char *buf;
int32_t counter;

int32_t imap_auth_mechanism = AUTH_CLEAR;

char *imap_read_server_capacity(int32_t sock) {
  char *ptr = NULL;
  int32_t resp = 0;
  char *buf = NULL;

  do {
    if (buf != NULL)
      free(buf);
    ptr = buf = hydra_receive_line(sock);
    if (buf != NULL) {
      if (strstr(buf, "CAPABILITY") != NULL && buf[0] == '*') {
        resp = 1;
        usleepn(300);
        /* we got the capability info then get the completed warning info from
         * server */
        while (hydra_data_ready(sock)) {
          free(buf);
          buf = hydra_receive_line(sock);
        }
      } else {
        if (buf[strlen(buf) - 1] == '\n')
          buf[strlen(buf) - 1] = 0;
        if (buf[strlen(buf) - 1] == '\r')
          buf[strlen(buf) - 1] = 0;
        if (isdigit((int32_t)*ptr) && *(ptr + 1) == ' ') {
          resp = 1;
        }
      }
    }
  } while (buf != NULL && resp == 0);
  return buf;
}

int32_t start_imap(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "", *result = NULL;
  char *login, *pass, buffer[500], buffer2[500], *fooptr;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  while (hydra_data_ready(s)) {
    if ((buf = hydra_receive_line(s)) == NULL)
      return (1);
    free(buf);
  }

  switch (imap_auth_mechanism) {
  case AUTH_LOGIN:
    sprintf(buffer, "%d AUTHENTICATE LOGIN\r\n", counter);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL) {
      hydra_report(stderr, "[ERROR] IMAP LOGIN AUTH : %s\n", buf);
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
    if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL) {
      hydra_report(stderr, "[ERROR] IMAP LOGIN AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    free(buf);
    strcpy(buffer2, pass);
    hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
    sprintf(buffer, "%.250s\r\n", buffer2);
    break;

  case AUTH_PLAIN:
    sprintf(buffer, "%d AUTHENTICATE PLAIN\r\n", counter);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL) {
      hydra_report(stderr, "[ERROR] IMAP PLAIN AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    free(buf);

    memset(buffer2, 0, sizeof(buffer2));
    result = sasl_plain(buffer2, login, pass);
    if (result == NULL)
      return 3;
    sprintf(buffer, "%.250s\r\n", buffer2);
    break;

#ifdef LIBOPENSSL
  case AUTH_CRAMMD5:
  case AUTH_CRAMSHA1:
  case AUTH_CRAMSHA256: {
    int32_t rc = 0;
    char *preplogin;

    rc = sasl_saslprep(login, SASL_ALLOW_UNASSIGNED, &preplogin);
    if (rc) {
      return 3;
    }

    switch (imap_auth_mechanism) {
    case AUTH_CRAMMD5:
      sprintf(buffer, "%d AUTHENTICATE CRAM-MD5\r\n", counter);
      break;
    case AUTH_CRAMSHA1:
      sprintf(buffer, "%d AUTHENTICATE CRAM-SHA1\r\n", counter);
      break;
    case AUTH_CRAMSHA256:
      sprintf(buffer, "%d AUTHENTICATE CRAM-SHA256\r\n", counter);
      break;
    }
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    // get the one-time BASE64 encoded challenge
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL || strstr(buf, "BYE") != NULL) {
      switch (imap_auth_mechanism) {
      case AUTH_CRAMMD5:
        hydra_report(stderr, "[ERROR] IMAP CRAM-MD5 AUTH : %s\n", buf);
        break;
      case AUTH_CRAMSHA1:
        hydra_report(stderr, "[ERROR] IMAP CRAM-SHA1 AUTH : %s\n", buf);
        break;
      case AUTH_CRAMSHA256:
        hydra_report(stderr, "[ERROR] IMAP CRAM-SHA256 AUTH : %s\n", buf);
        break;
      }
      free(buf);
      return 3;
    }

    memset(buffer, 0, sizeof(buffer));
    from64tobits((char *)buffer, buf + 2);
    free(buf);

    memset(buffer2, 0, sizeof(buffer2));

    switch (imap_auth_mechanism) {
    case AUTH_CRAMMD5: {
      result = sasl_cram_md5(buffer2, pass, buffer);
      if (result == NULL)
        return 3;
      sprintf(buffer, "%s %.250s", preplogin, buffer2);
    } break;
    case AUTH_CRAMSHA1: {
      result = sasl_cram_sha1(buffer2, pass, buffer);
      if (result == NULL)
        return 3;
      sprintf(buffer, "%s %.250s", preplogin, buffer2);
    } break;
    case AUTH_CRAMSHA256: {
      result = sasl_cram_sha256(buffer2, pass, buffer);
      if (result == NULL)
        return 3;
      sprintf(buffer, "%s %.250s", preplogin, buffer2);
    } break;
    }
    hydra_tobase64((unsigned char *)buffer, strlen(buffer), sizeof(buffer));

    char tmp_buffer[sizeof(buffer)];
    sprintf(tmp_buffer, "%.250s\r\n", buffer);
    strcpy(buffer, tmp_buffer);

    free(preplogin);
  } break;
  case AUTH_DIGESTMD5: {
    sprintf(buffer, "%d AUTHENTICATE DIGEST-MD5\r\n", counter);

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 1;
    // receive
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL || strstr(buf, "BYE") != NULL) {
      hydra_report(stderr, "[ERROR] IMAP DIGEST-MD5 AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    memset(buffer, 0, sizeof(buffer));
    from64tobits((char *)buffer, buf);
    free(buf);

    if (debug)
      hydra_report(stderr, "DEBUG S: %s\n", buffer);

    fooptr = buffer2;
    result = sasl_digest_md5(fooptr, login, pass, buffer, miscptr, "imap", NULL, 0, NULL);
    if (result == NULL)
      return 3;
    if (debug)
      hydra_report(stderr, "DEBUG C: %s\n", buffer2);
    hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
    sprintf(buffer, "%s\r\n", buffer2);

  } break;
  case AUTH_SCRAMSHA1: {
    char clientfirstmessagebare[200];
    char serverfirstmessage[200];
    char *preplogin;
    int32_t rc = sasl_saslprep(login, SASL_ALLOW_UNASSIGNED, &preplogin);

    if (rc) {
      return 3;
    }
    sprintf(buffer, "%d AUTHENTICATE SCRAM-SHA-1\r\n", counter);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL || strstr(buf, "BYE") != NULL) {
      hydra_report(stderr, "[ERROR] IMAP SCRAM-SHA1 AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    free(buf);

    snprintf(clientfirstmessagebare, sizeof(clientfirstmessagebare), "n=%s,r=hydra", preplogin);
    free(preplogin);
    memset(buffer2, 0, sizeof(buffer2));
    sprintf(buffer2, "n,,%.200s", clientfirstmessagebare);
    hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
    snprintf(buffer, sizeof(buffer), "%s\r\n", buffer2);

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    buf = hydra_receive_line(s);
    if (buf == NULL)
      return 1;
    if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL || strstr(buf, "BYE") != NULL) {
      if (verbose || debug)
        hydra_report(stderr, "[ERROR] Not a valid server challenge\n");
      free(buf);
      return 1;
    } else {
      /* recover server challenge */
      memset(buffer, 0, sizeof(buffer));
      //+ cj1oeWRyYU9VNVZqcHQ5RjNqcmVXRVFWTCxzPWhGbTNnRGw0akdidzJVVHosaT00MDk2
      from64tobits((char *)buffer, buf + 2);
      free(buf);
      strncpy(serverfirstmessage, buffer, sizeof(serverfirstmessage) - 1);
      serverfirstmessage[sizeof(serverfirstmessage) - 1] = '\0';

      memset(buffer2, 0, sizeof(buffer2));
      fooptr = buffer2;
      result = sasl_scram_sha1(fooptr, pass, clientfirstmessagebare, serverfirstmessage);
      if (result == NULL) {
        hydra_report(stderr, "[ERROR] Can't compute client response\n");
        return 1;
      }
      hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
      sprintf(buffer, "%s\r\n", buffer2);
    }
  } break;
#endif
  case AUTH_NTLM: {
    unsigned char buf1[4096];
    unsigned char buf2[4096];

    // Send auth request
    sprintf(buffer, "%d AUTHENTICATE NTLM\r\n", counter);

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 1;
    // receive
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL || strstr(buf, "BYE") != NULL) {
      hydra_report(stderr, "[ERROR] IMAP NTLM AUTH : %s\n", buf);
      free(buf);
      return 3;
    }
    free(buf);
    // send auth and receive challenge
    // send auth request: lst the server send it's own hostname and domainname
    buildAuthRequest((tSmbNtlmAuthRequest *)buf2, 0, NULL, NULL);
    to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthRequest *)buf2));

    sprintf(buffer, "%s\r\n", buf1);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 1;
    if ((buf = hydra_receive_line(s)) == NULL)
      return 1;
    if (strlen(buf) < 6) {
      free(buf);
      return 1;
    }

    // recover challenge
    from64tobits((char *)buf1, buf + 2);
    free(buf);

    // Send response
    buildAuthResponse((tSmbNtlmAuthChallenge *)buf1, (tSmbNtlmAuthResponse *)buf2, 0, login, pass, NULL, NULL);
    to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse *)buf2));

    sprintf(buffer, "%s\r\n", buf1);
  } break;
  default:
    // clear authentication
    sprintf(buffer, "%d LOGIN \"%.100s\" \"%.100s\"\r\n", counter, login, pass);
  }

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  if ((buf = hydra_receive_line(s)) == NULL)
    return (1);

  if (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL || strstr(buf, "BYE") != NULL) {
    if (verbose)
      hydra_report(stderr, "[ERROR] %s\n", buf);
    free(buf);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    if (counter == 4)
      return 1;
    return (2);
  }
  free(buf);

  hydra_report_found_host(port, ip, "imap", fp);
  hydra_completed_pair_found();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_imap(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_IMAP, mysslport = PORT_IMAP_SSL, disable_tls = 1;
  char *buffer1 = "1 CAPABILITY\r\n";

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
      buf = hydra_receive_line(sock);

      if ((buf == NULL) || (strstr(buf, "OK") == NULL && buf[0] != '*')) { /* check the first line */
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Not an IMAP protocol or service shutdown:\n");
        if (buf != NULL)
          free(buf);
        hydra_child_exit(2);
      }
      free(buf);
      /* send capability request */
      if (hydra_send(sock, buffer1, strlen(buffer1), 0) < 0)
        exit(-1);
      counter = 2;
      buf = imap_read_server_capacity(sock);

      if (buf == NULL) {
        hydra_child_exit(2);
      }

      if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
        int32_t i;

        for (i = 0; i < strlen(miscptr); i++)
          miscptr[i] = (char)toupper((int32_t)miscptr[i]);

        if (strstr(miscptr, "TLS") || strstr(miscptr, "SSL") || strstr(miscptr, "STARTTLS")) {
          disable_tls = 0;
        }
      }
#ifdef LIBOPENSSL
      if (!disable_tls) {
        /* check for STARTTLS, if available we may have access to more basic
         * auth methods */
        if (strstr(buf, "STARTTLS") != NULL) {
          hydra_send(sock, "2 STARTTLS\r\n", strlen("2 STARTTLS\r\n"), 0);
          counter++;
          free(buf);
          buf = hydra_receive_line(sock);
          if (buf == NULL || (strstr(buf, " NO ") != NULL || strstr(buf, "failed") != NULL || strstr(buf, " BAD ") != NULL)) {
            hydra_report(stderr, "[ERROR] TLS negotiation failed, no answer "
                                 "received from STARTTLS request\n");
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
            if (hydra_send(sock, "3 CAPABILITY\r\n", strlen("3 CAPABILITY\r\n"), 0) < 0)
              hydra_child_exit(2);
            buf = imap_read_server_capacity(sock);
            counter++;
            if (buf == NULL)
              hydra_child_exit(2);
          }
        } else
          hydra_report(stderr, "[ERROR] option to use TLS/SSL failed as it is "
                               "not supported by the server\n");
      }
#endif

      if (verbose)
        hydra_report(stderr, "[VERBOSE] CAPABILITY: %s", buf);

      // authentication should be listed AUTH= like in the extract below
      // STARTTLS LOGINDISABLED AUTH=GSSAPI AUTH=DIGEST-MD5 AUTH=CRAM-MD5
      if ((strstr(buf, "=LOGIN") == NULL) && (strstr(buf, "=NTLM") != NULL)) {
        imap_auth_mechanism = AUTH_NTLM;
      }
#ifdef LIBOPENSSL
      if ((strstr(buf, "=LOGIN") == NULL) && (strstr(buf, "=SCRAM-SHA-1") != NULL)) {
        imap_auth_mechanism = AUTH_SCRAMSHA1;
      }

      if ((strstr(buf, "=LOGIN") == NULL) && (strstr(buf, "=DIGEST-MD5") != NULL)) {
        imap_auth_mechanism = AUTH_DIGESTMD5;
      }

      if ((strstr(buf, "=LOGIN") == NULL) && (strstr(buf, "=CRAM-SHA256") != NULL)) {
        imap_auth_mechanism = AUTH_CRAMSHA256;
      }

      if ((strstr(buf, "=LOGIN") == NULL) && (strstr(buf, "=CRAM-SHA1") != NULL)) {
        imap_auth_mechanism = AUTH_CRAMSHA1;
      }

      if ((strstr(buf, "=LOGIN") == NULL) && (strstr(buf, "=CRAM-MD5") != NULL)) {
        imap_auth_mechanism = AUTH_CRAMMD5;
      }
#endif
      if ((strstr(buf, "=LOGIN") == NULL) && (strstr(buf, "=PLAIN") != NULL)) {
        imap_auth_mechanism = AUTH_PLAIN;
      }

      if (strstr(buf, "=LOGIN") != NULL) {
        imap_auth_mechanism = AUTH_LOGIN;
      }
      free(buf);

      if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
        if (strstr(miscptr, "CLEAR"))
          imap_auth_mechanism = AUTH_CLEAR;

        if (strstr(miscptr, "LOGIN"))
          imap_auth_mechanism = AUTH_LOGIN;

        if (strstr(miscptr, "PLAIN"))
          imap_auth_mechanism = AUTH_PLAIN;

#ifdef LIBOPENSSL
        if (strstr(miscptr, "CRAM-MD5"))
          imap_auth_mechanism = AUTH_CRAMMD5;

        if (strstr(miscptr, "CRAM-SHA1"))
          imap_auth_mechanism = AUTH_CRAMSHA1;

        if (strstr(miscptr, "CRAM-SHA256"))
          imap_auth_mechanism = AUTH_CRAMSHA256;

        if (strstr(miscptr, "DIGEST-MD5"))
          imap_auth_mechanism = AUTH_DIGESTMD5;

        if (strstr(miscptr, "SCRAM-SHA1"))
          imap_auth_mechanism = AUTH_SCRAMSHA1;

#endif
        if (strstr(miscptr, "NTLM"))
          imap_auth_mechanism = AUTH_NTLM;
      }

      if (verbose) {
        switch (imap_auth_mechanism) {
        case AUTH_CLEAR:
          hydra_report(stderr, "[VERBOSE] using IMAP CLEAR LOGIN mechanism\n");
          break;
        case AUTH_LOGIN:
          hydra_report(stderr, "[VERBOSE] using IMAP LOGIN AUTH mechanism\n");
          break;
        case AUTH_PLAIN:
          hydra_report(stderr, "[VERBOSE] using IMAP PLAIN AUTH mechanism\n");
          break;
#ifdef LIBOPENSSL
        case AUTH_CRAMMD5:
          hydra_report(stderr, "[VERBOSE] using IMAP CRAM-MD5 AUTH mechanism\n");
          break;
        case AUTH_CRAMSHA1:
          hydra_report(stderr, "[VERBOSE] using IMAP CRAM-SHA1 AUTH mechanism\n");
          break;
        case AUTH_CRAMSHA256:
          hydra_report(stderr, "[VERBOSE] using IMAP CRAM-SHA256 AUTH mechanism\n");
          break;
        case AUTH_DIGESTMD5:
          hydra_report(stderr, "[VERBOSE] using IMAP DIGEST-MD5 AUTH mechanism\n");
          break;
        case AUTH_SCRAMSHA1:
          hydra_report(stderr, "[VERBOSE] using IMAP SCRAM-SHA1 AUTH mechanism\n");
          break;
#endif
        case AUTH_NTLM:
          hydra_report(stderr, "[VERBOSE] using IMAP NTLM AUTH mechanism\n");
          break;
        }
      }

      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_imap(sock, ip, port, options, miscptr, fp);
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

int32_t service_imap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_imap(const char *service) {
  printf("Module imap is optionally taking one authentication type of:\n"
         "  CLEAR or APOP (default), LOGIN, PLAIN, CRAM-MD5, CRAM-SHA1,\n"
         "  CRAM-SHA256, DIGEST-MD5, NTLM\n"
         "Additionally TLS encryption via STARTTLS can be enforced with the "
         "TLS option.\n\n"
         "Example: imap://target/TLS:PLAIN\n");
}
