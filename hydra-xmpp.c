#include "hydra-mod.h"
#include "sasl.h"

/* david: ref http://xmpp.org/rfcs/rfc3920.html */

extern char *HYDRA_EXIT;
static char *domain = NULL;

int32_t xmpp_auth_mechanism = AUTH_ERROR;

char *JABBER_CLIENT_INIT_STR = "<?xml version='1.0' ?><stream:stream to='";
char *JABBER_CLIENT_INIT_END_STR = "' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' "
                                   "version='1.0'>";

int32_t start_xmpp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "\"\"", *result = NULL;
  char *login, *pass, buffer[500], buffer2[500];
  char *AUTH_STR = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='";
  char *AUTH_STR_END = "'/>";
  char *CHALLENGE_STR = "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>";
  char *CHALLENGE_STR2 = "<challenge xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">";
  char *CHALLENGE_END_STR = "</challenge>";
  char *RESPONSE_STR = "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>";
  char *RESPONSE_END_STR = "</response>";
  char *fooptr, *buf;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  switch (xmpp_auth_mechanism) {
  case AUTH_SCRAMSHA1:
    sprintf(buffer, "%s%s%s", AUTH_STR, "SCRAM-SHA-1", AUTH_STR_END);
    break;
  case AUTH_CRAMMD5:
    sprintf(buffer, "%s%s%s", AUTH_STR, "CRAM-MD5", AUTH_STR_END);
    break;
  case AUTH_DIGESTMD5:
    sprintf(buffer, "%s%s%s", AUTH_STR, "DIGEST-MD5", AUTH_STR_END);
    break;
  case AUTH_PLAIN:
    sprintf(buffer, "%s%s%s", AUTH_STR, "PLAIN", AUTH_STR_END);
    break;
  default:
    sprintf(buffer, "%s%s%s", AUTH_STR, "LOGIN", AUTH_STR_END);
    break;
  }

  hydra_send(s, buffer, strlen(buffer), 0);
  usleepn(300);
  if ((buf = hydra_receive_line(s)) == NULL)
    return 3;

  if (debug)
    hydra_report(stderr, "DEBUG S: %s\n", buf);

  if ((strstr(buf, CHALLENGE_STR) != NULL) || (strstr(buf, CHALLENGE_STR2) != NULL)) {
    /*
       the challenge string is sent depending of the
       auth chosen it's the case for login auth
     */

    char *ptr = strstr(buf, CHALLENGE_STR);

    if (!ptr)
      ptr = strstr(buf, CHALLENGE_STR2);
    char *ptr_end = strstr(ptr, CHALLENGE_END_STR);
    int32_t chglen = ptr_end - ptr - strlen(CHALLENGE_STR);

    if ((chglen > 0) && (chglen < sizeof(buffer2))) {
      strncpy(buffer2, ptr + strlen(CHALLENGE_STR), chglen);
      buffer2[chglen] = '\0';
      memset(buffer, 0, sizeof(buffer));
      from64tobits((char *)buffer, buffer2);
      if (debug)
        hydra_report(stderr, "DEBUG S: %s\n", buffer);
    }

    switch (xmpp_auth_mechanism) {
    case AUTH_LOGIN: {
      if (strstr(buffer, "sername") != NULL) {
        strncpy(buffer2, login, sizeof(buffer2) - 1);
        buffer2[sizeof(buffer2) - 1] = '\0';

        hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
        sprintf(buffer, "%s%.250s%s", RESPONSE_STR, buffer2, RESPONSE_END_STR);
        if (debug)
          hydra_report(stderr, "DEBUG C: %s\n", buffer);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
          free(buf);
          return 1;
        }
        buf = hydra_receive_line(s);
        if (buf == NULL)
          return 1;
        /* server now would ask for the password */
        if ((strstr(buf, CHALLENGE_STR) != NULL) || (strstr(buf, CHALLENGE_STR2) != NULL)) {
          char *ptr = strstr(buf, CHALLENGE_STR);

          if (!ptr)
            ptr = strstr(buf, CHALLENGE_STR2);
          char *ptr_end = strstr(ptr, CHALLENGE_END_STR);
          int32_t chglen = ptr_end - ptr - strlen(CHALLENGE_STR);

          if ((chglen > 0) && (chglen < sizeof(buffer2))) {
            strncpy(buffer2, ptr + strlen(CHALLENGE_STR), chglen);
            buffer2[chglen] = '\0';
            memset(buffer, 0, sizeof(buffer));
            from64tobits((char *)buffer, buffer2);
            if (strstr(buffer, "assword") != NULL) {
              strncpy(buffer2, pass, sizeof(buffer2) - 1);
              buffer2[sizeof(buffer2) - 1] = '\0';
              hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
              sprintf(buffer, "%s%.250s%s", RESPONSE_STR, buffer2, RESPONSE_END_STR);
            }
          } else {
            hydra_report(stderr, "[ERROR] xmpp could not extract challenge from server\n");
            free(buf);
            return 1;
          }
        }
      }
    } break;
#ifdef LIBOPENSSL
    case AUTH_PLAIN: {
      memset(buffer2, 0, sizeof(buffer));
      result = sasl_plain(buffer2, login, pass);
      if (result == NULL)
        return 3;
      sprintf(buffer, "%s%.250s%s", RESPONSE_STR, buffer2, RESPONSE_END_STR);
      if (debug)
        hydra_report(stderr, "DEBUG C: %s\n", buffer);

    } break;
    case AUTH_CRAMMD5: {
      int32_t rc = 0;
      char *preplogin;

      memset(buffer2, 0, sizeof(buffer2));
      result = sasl_cram_md5(buffer2, pass, buffer);
      if (result == NULL)
        return 3;

      rc = sasl_saslprep(login, SASL_ALLOW_UNASSIGNED, &preplogin);
      if (rc) {
        free(buf);
        return 3;
      }

      sprintf(buffer, "%.200s %.250s", preplogin, buffer2);
      if (debug)
        hydra_report(stderr, "DEBUG C: %s\n", buffer);
      hydra_tobase64((unsigned char *)buffer, strlen(buffer), sizeof(buffer));
      sprintf(buffer2, "%s%.250s%s", RESPONSE_STR, buffer, RESPONSE_END_STR);
      strncpy(buffer, buffer2, sizeof(buffer) - 1);
      buffer[sizeof(buffer) - 1] = '\0';
      free(preplogin);
    } break;
    case AUTH_DIGESTMD5: {
      memset(buffer2, 0, sizeof(buffer2));
      fooptr = buffer2;
      result = sasl_digest_md5(fooptr, login, pass, buffer, domain, "xmpp", NULL, 0, NULL);
      if (result == NULL) {
        free(buf);
        return 3;
      }
      if (debug)
        hydra_report(stderr, "DEBUG C: %s\n", buffer2);
      hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
      snprintf(buffer, sizeof(buffer), "%s%s%s", RESPONSE_STR, buffer2, RESPONSE_END_STR);
    } break;
    case AUTH_SCRAMSHA1: {
      /*client-first-message */
      char clientfirstmessagebare[200];
      char *preplogin;
      int32_t rc = sasl_saslprep(login, SASL_ALLOW_UNASSIGNED, &preplogin);

      if (rc) {
        free(buf);
        return 3;
      }

      snprintf(clientfirstmessagebare, sizeof(clientfirstmessagebare), "n=%s,r=hydra", preplogin);
      free(preplogin);
      sprintf(buffer2, "n,,%.200s", clientfirstmessagebare);
      hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
      snprintf(buffer, sizeof(buffer), "%s%s%s", RESPONSE_STR, buffer2, RESPONSE_END_STR);

      free(buf);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      buf = hydra_receive_line(s);
      if (buf == NULL)
        return 1;

      if ((strstr(buf, CHALLENGE_STR) != NULL) || (strstr(buf, CHALLENGE_STR2) != NULL)) {
        char serverfirstmessage[200];
        char *ptr = strstr(buf, CHALLENGE_STR);

        if (!ptr)
          ptr = strstr(buf, CHALLENGE_STR2);
        char *ptr_end = strstr(ptr, CHALLENGE_END_STR);
        int32_t chglen = ptr_end - ptr - strlen(CHALLENGE_STR);

        if ((chglen > 0) && (chglen < sizeof(buffer2))) {
          strncpy(buffer2, ptr + strlen(CHALLENGE_STR), chglen);
          buffer2[chglen] = '\0';
        } else {
          hydra_report(stderr, "[ERROR] xmpp could not extract challenge from server\n");
          free(buf);
          return 1;
        }

        /*server-first-message */
        memset(buffer, 0, sizeof(buffer));
        from64tobits((char *)buffer, buffer2);
        strncpy(serverfirstmessage, buffer, sizeof(serverfirstmessage) - 1);
        serverfirstmessage[sizeof(serverfirstmessage) - 1] = '\0';

        memset(buffer2, 0, sizeof(buffer2));
        fooptr = buffer2;
        result = sasl_scram_sha1(fooptr, pass, clientfirstmessagebare, serverfirstmessage);
        if (result == NULL) {
          hydra_report(stderr, "[ERROR] Can't compute client response\n");
          free(buf);
          return 1;
        }
        hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
        snprintf(buffer, sizeof(buffer), "%s%s%s", RESPONSE_STR, buffer2, RESPONSE_END_STR);
      } else {
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Not a valid server challenge\n");
        free(buf);
        return 1;
      }
    } break;
#endif
      ptr = 0;
    }

    free(buf);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    usleepn(50);
    buf = hydra_receive_line(s);
    if (buf == NULL)
      return 1;

    // we test the challenge tag as digest-md5 when connected is sending
    // "rspauth" value so if we are receiving a second challenge we assume the
    // auth is good

    if ((strstr(buf, "<success") != NULL) || (strstr(buf, "<challenge ") != NULL)) {
      hydra_report_found_host(port, ip, "xmpp", fp);
      hydra_completed_pair_found();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 1;
    }

    if (verbose)
      hydra_report(stderr, "[ERROR] %s\n", buf);

    free(buf);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;

    return 2;
  }
  if (strstr(buf, "<failure")) {
    hydra_report(stderr, "[ERROR] Protocol failure, try using another auth method. %s\n", strstr(buf, "<failure"));
  }
  free(buf);
  return 3;
}

void service_xmpp(char *target, char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1, tls = 0;
  char buffer[500], *buf = NULL;
  int32_t myport = PORT_XMPP, mysslport = PORT_XMPP_SSL, disable_tls = 0;
  char *enddomain = NULL;

  // we have to pass the target here as the reverse dns resolution is not
  // working for some servers try to extract only the domain name from the
  // target so for o.nimbuzz.com will get nimbuzz.com and hermes.jabber.org will
  // get jabber.org

  domain = strchr(target, '.');
  if (!domain) {
    hydra_report(stderr, "[ERROR] can't extract the domain name, you have to "
                         "specify a fqdn xmpp server, the domain name will be "
                         "used in the jabber init request\n");
    hydra_child_exit(1);
  }

  enddomain = strrchr(target, '.');
  // check if target is not already a domain name aka only . char in the string
  if (enddomain && (enddomain == domain)) {
    domain = target;
  } else {
    // moving to pass the . char
    domain = domain + 1;
  }

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
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
      memset(buffer, 0, sizeof(buffer));
      snprintf(buffer, sizeof(buffer), "%s%s%s", JABBER_CLIENT_INIT_STR, domain, JABBER_CLIENT_INIT_END_STR);
      if (hydra_send(sock, buffer, strlen(buffer), 0) < 0) {
        hydra_child_exit(1);
      }
      // some server is longer to answer
      usleepn(300);
      do {
        if ((buf = hydra_receive_line(sock)) == NULL) {
          /* no auth method identified */
          hydra_report(stderr, "[ERROR] no authentication methods can be identified\n");
          hydra_child_exit(1);
        }

        if (strstr(buf, "<stream:stream") == NULL) {
          if (verbose || debug)
            hydra_report(stderr, "[ERROR] Not an xmpp protocol or service shutdown: %s\n", buf);
          free(buf);
          hydra_child_exit(1);
        }

        if (strstr(buf, "<stream:error")) {
          if (strstr(buf, "<host-unknown"))
            hydra_report(stderr,
                         "[ERROR] %s host unknown, you have to specify a fqdn "
                         "xmpp server, the domain name will be used in the "
                         "jabber init request : %s\n",
                         domain, buf);
          else
            hydra_report(stderr, "[ERROR] xmpp protocol : %s\n", buf);
          free(buf);
          hydra_child_exit(1);
        }

        /* try to identify which features is supported */
        if (strstr(buf, ":xmpp-tls") != NULL) {
          tls = 1;
        }

        if (strstr(buf, ":xmpp-sasl") != NULL) {
          if (strstr(buf, "<mechanism>SCRAM-SHA-1</mechanism>") != NULL) {
            xmpp_auth_mechanism = AUTH_SCRAMSHA1;
          }
          if (strstr(buf, "<mechanism>CRAM-MD5</mechanism>") != NULL) {
            xmpp_auth_mechanism = AUTH_CRAMMD5;
          }
          if (strstr(buf, "<mechanism>DIGEST-MD5</mechanism>") != NULL) {
            xmpp_auth_mechanism = AUTH_DIGESTMD5;
          }
          if (strstr(buf, "<mechanism>PLAIN</mechanism>") != NULL) {
            xmpp_auth_mechanism = AUTH_PLAIN;
          }
          if (strstr(buf, "<mechanism>LOGIN</mechanism>") != NULL) {
            xmpp_auth_mechanism = AUTH_LOGIN;
          }
        }
        free(buf);
      } while (xmpp_auth_mechanism == AUTH_ERROR);

      if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
        int32_t i;

        for (i = 0; i < strlen(miscptr); i++)
          miscptr[i] = (char)toupper((int32_t)miscptr[i]);

        if (strncmp(miscptr, "LOGIN", 5) == 0)
          xmpp_auth_mechanism = AUTH_LOGIN;

        if (strncmp(miscptr, "PLAIN", 5) == 0)
          xmpp_auth_mechanism = AUTH_PLAIN;

#ifdef LIBOPENSSL
        if (strncmp(miscptr, "CRAM-MD5", 8) == 0)
          xmpp_auth_mechanism = AUTH_CRAMMD5;

        if (strncmp(miscptr, "SCRAM-SHA1", 10) == 0)
          xmpp_auth_mechanism = AUTH_SCRAMSHA1;

        if (strncmp(miscptr, "DIGEST-MD5", 10) == 0)
          xmpp_auth_mechanism = AUTH_DIGESTMD5;
#endif
      }

      if (verbose) {
        switch (xmpp_auth_mechanism) {
        case AUTH_LOGIN:
          hydra_report(stderr, "[VERBOSE] using XMPP LOGIN AUTH mechanism\n");
          break;
        case AUTH_PLAIN:
          hydra_report(stderr, "[VERBOSE] using XMPP PLAIN AUTH mechanism\n");
          break;
#ifdef LIBOPENSSL
        case AUTH_CRAMMD5:
          hydra_report(stderr, "[VERBOSE] using XMPP CRAM-MD5 AUTH mechanism\n");
          break;
        case AUTH_SCRAMSHA1:
          hydra_report(stderr, "[VERBOSE] using XMPP SCRAM-SHA1 AUTH mechanism\n");
          break;
        case AUTH_DIGESTMD5:
          hydra_report(stderr, "[VERBOSE] using XMPP DIGEST-MD5 AUTH mechanism\n");
          break;
#endif
        }
      }
#ifdef LIBOPENSSL
      // check if tls is not wanted and if tls is available
      if (!disable_tls && tls) {
        char *STARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";

        hydra_send(sock, STARTTLS, strlen(STARTTLS), 0);
        usleepn(300);
        buf = hydra_receive_line(sock);

        if (buf == NULL || strstr(buf, "<failure") != NULL) {
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
          /* we have to resend the init stream */
          memset(buffer, 0, sizeof(buffer));
          snprintf(buffer, sizeof(buffer), "%s%s%s", JABBER_CLIENT_INIT_STR, domain, JABBER_CLIENT_INIT_END_STR);
          if (hydra_send(sock, buffer, strlen(buffer), 0) < 0) {
            hydra_child_exit(1);
          }
          // some server is longer to answer
          usleepn(300);
          buf = hydra_receive_line(sock);
          if ((buf == NULL) || (strstr(buf, "<stream:stream") == NULL))
            hydra_child_exit(1);
        }
        free(buf);
      }
#endif
      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_xmpp(sock, ip, port, options, miscptr, fp);
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

int32_t service_xmpp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_xmpp(const char *service) {
  printf("Module xmpp is optionally taking one authentication type of:\n"
         "  LOGIN (default), PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-SHA1\n\n"
         "Note, the target passed should be a fdqn as the value is used in the "
         "Jabber init request, example: hermes.jabber.org\n\n");
}
