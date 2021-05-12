#include "hydra-mod.h"
#include "sasl.h"

extern char *HYDRA_EXIT;
static int32_t http_proxy_auth_mechanism = AUTH_ERROR;
char *http_proxy_buf = NULL;

int32_t start_http_proxy(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp, char *hostname) {
  char *empty = "";
  char *login, *pass, buffer[5000], buffer2[4500];
  char url[510], host[60];
  char *header = ""; /* XXX TODO */
  char *ptr, *fooptr, *auth_hdr;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  if (miscptr == NULL) {
    strcpy(url, "http://www.microsoft.com/");
    strcpy(host, "Host: www.microsoft.com\r\n");
  } else {
    sprintf(url, "%.500s", miscptr);
    ptr = strstr(miscptr, "://"); // :// check is in hydra.c
    sprintf(host, "Host: %.50s", ptr + 3);
    if ((ptr = strchr(host, '/')) != NULL)
      *ptr = 0;
    if ((ptr = strchr(host + 6, ':')) != NULL && host[0] != '[')
      *ptr = 0;
    strcat(host, "\r\n");
  }

  if (http_proxy_auth_mechanism != AUTH_BASIC && (http_proxy_auth_mechanism == AUTH_ERROR || http_proxy_buf == NULL)) {
    // send dummy request
    sprintf(buffer, "GET %s HTTP/1.0\r\n%sUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n", url, host, header);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 3;

    // receive first 40x
    http_proxy_buf = hydra_receive_line(s);
    while (http_proxy_buf != NULL && strstr(http_proxy_buf, "HTTP/") == NULL) {
      free(http_proxy_buf);
      http_proxy_buf = hydra_receive_line(s);
    }

    if (http_proxy_buf == NULL) {
      if (verbose)
        hydra_report(stderr, "[ERROR] Server did not answer\n");
      return 3;
    }

    if (debug) {
      hydra_report(stderr, "S:%-.*s\n", (int)(strchr(http_proxy_buf, '\r') - http_proxy_buf), http_proxy_buf);
    }

    while (http_proxy_buf != NULL && (auth_hdr = hydra_strcasestr(http_proxy_buf, "Proxy-Authenticate:")) == NULL) {
      free(http_proxy_buf);
      http_proxy_buf = hydra_receive_line(s);
    }

    if (auth_hdr == NULL) {
      if (verbose)
        hydra_report(stderr, "[ERROR] Proxy seems not to require authentication\n");
      return 3;
    }

    if (debug) {
      hydra_report(stderr, "S:%-.*s\n", (int)(strchr(auth_hdr, '\r') - auth_hdr), auth_hdr);
    }

    // after the first query we should have been disconnected from web server
    s = hydra_disconnect(s);
    if ((options & OPTION_SSL) == 0) {
      s = hydra_connect_tcp(ip, port);
    } else {
      s = hydra_connect_ssl(ip, port, hostname);
    }
  }

  if (http_proxy_auth_mechanism == AUTH_BASIC || hydra_strcasestr(auth_hdr, "Proxy-Authenticate: Basic") != NULL) {
    http_proxy_auth_mechanism = AUTH_BASIC;
    auth_hdr = NULL;
    sprintf(buffer2, "%.50s:%.50s", login, pass);
    hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
    sprintf(buffer,
            "GET %s HTTP/1.0\r\n%sProxy-Authorization: Basic %s\r\nUser-Agent: "
            "Mozilla/4.0 (Hydra)\r\n%s\r\n",
            url, host, buffer2, header);
    if (debug)
      hydra_report(stderr, "C:%s\n", buffer);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 3;
    free(http_proxy_buf);
    http_proxy_buf = hydra_receive_line(s);
    while (http_proxy_buf != NULL && strstr(http_proxy_buf, "HTTP/1.") == NULL) {
      free(http_proxy_buf);
      http_proxy_buf = hydra_receive_line(s);
    }

    // if server cut the connection, just exit cleanly or
    // this will be an infinite loop
    if (http_proxy_buf == NULL) {
      if (verbose)
        hydra_report(stderr, "[ERROR] Server did not answer\n");
      return 3;
    }

    if (debug) {
      hydra_report(stderr, "S:%-.*s\n", (int)(strchr(http_proxy_buf, '\r') - http_proxy_buf), http_proxy_buf);
    }
  } else {
    if (http_proxy_auth_mechanism == AUTH_NTLM || hydra_strcasestr(auth_hdr, "Proxy-Authenticate: NTLM") != NULL) {
      unsigned char buf1[4096];
      unsigned char buf2[4096];
      char *pos = NULL;

      http_proxy_auth_mechanism = AUTH_NTLM;
      auth_hdr = NULL;
      // send auth and receive challenge
      // send auth request: let the server send it's own hostname and domainname
      buildAuthRequest((tSmbNtlmAuthRequest *)buf2, 0, NULL, NULL);
      to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthRequest *)buf2));

      /* to be portable, no snprintf, buffer is big enough so it can't overflow
       */
      // send the first..
      sprintf(buffer,
              "GET %s HTTP/1.0\r\n%sProxy-Authorization: NTLM %s\r\nUser-Agent: "
              "Mozilla/4.0 (Hydra)\r\nProxy-Connection: keep-alive\r\n%s\r\n",
              url, host, buf1, header);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
        return 3;

      // receive challenge
      free(http_proxy_buf);
      http_proxy_buf = hydra_receive_line(s);
      while (http_proxy_buf != NULL && (pos = hydra_strcasestr(http_proxy_buf, "Proxy-Authenticate: NTLM ")) == NULL) {
        free(http_proxy_buf);
        http_proxy_buf = hydra_receive_line(s);
      }
      if (pos != NULL) {
        char *str;

        pos += 25;
        if ((str = strchr(pos, '\r')) != NULL) {
          pos[str - pos] = 0;
        }
        if ((str = strchr(pos, '\n')) != NULL) {
          pos[str - pos] = 0;
        }
      }
      // recover challenge
      if (http_proxy_buf != NULL && strlen(http_proxy_buf) >= 4) {
        from64tobits((char *)buf1, pos);
        free(http_proxy_buf);
        http_proxy_buf = NULL;
        return 3;
      }
      // Send response
      buildAuthResponse((tSmbNtlmAuthChallenge *)buf1, (tSmbNtlmAuthResponse *)buf2, 0, login, pass, NULL, NULL);
      to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse *)buf2));
      sprintf(buffer,
              "GET %s HTTP/1.0\r\n%sProxy-Authorization: NTLM %s\r\nUser-Agent: "
              "Mozilla/4.0 (Hydra)\r\nProxy-Connection: keep-alive\r\n%s\r\n",
              url, host, buf1, header);
      if (debug)
        hydra_report(stderr, "C:%s\n", buffer);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
        return 3;

      if (http_proxy_buf != NULL)
        free(http_proxy_buf);
      http_proxy_buf = hydra_receive_line(s);
      while (http_proxy_buf != NULL && strstr(http_proxy_buf, "HTTP/1.") == NULL) {
        free(http_proxy_buf);
        http_proxy_buf = hydra_receive_line(s);
      }

      if (http_proxy_buf == NULL)
        return 3;
    } else {
#ifdef LIBOPENSSL
      if (hydra_strcasestr(auth_hdr, "Proxy-Authenticate: Digest") != NULL) {
        char *pbuffer, *result;

        http_proxy_auth_mechanism = AUTH_DIGESTMD5;
        auth_hdr = NULL;
        pbuffer = hydra_strcasestr(http_proxy_buf, "Proxy-Authenticate: Digest ");
        strncpy(buffer, pbuffer + strlen("Proxy-Authenticate: Digest "), sizeof(buffer));
        buffer[sizeof(buffer) - 1] = '\0';
        pbuffer = NULL;

        fooptr = buffer2;
        result = sasl_digest_md5(fooptr, login, pass, buffer, miscptr, "proxy", host, 0, header);
        if (result == NULL)
          return 3;

        if (debug)
          hydra_report(stderr, "C:%s\n", buffer2);
        if (hydra_send(s, buffer2, strlen(buffer2), 0) < 0)
          return 3;

        free(http_proxy_buf);
        http_proxy_buf = hydra_receive_line(s);
        while (http_proxy_buf != NULL && strstr(http_proxy_buf, "HTTP/1.") == NULL) {
          free(http_proxy_buf);
          http_proxy_buf = hydra_receive_line(s);
        }

        if (debug && http_proxy_buf != NULL) {
          hydra_report(stderr, "S:%-.*s\n", (int)(strchr(http_proxy_buf, '\r') - http_proxy_buf), http_proxy_buf);
        }

        if (http_proxy_buf == NULL)
          return 3;

      } else
#endif
      {
        if (auth_hdr != NULL) {
          //          buf[strlen(http_proxy_buf) - 1] = '\0';
          hydra_report(stderr, "Unsupported Auth type:\n%-.*s\n", (int)(strchr(http_proxy_buf, '\r') - auth_hdr), auth_hdr);
          auth_hdr = NULL;
          free(http_proxy_buf);
          http_proxy_buf = NULL;
        } else {
          hydra_report(stderr, "Unsupported Auth type\n");
        }
        return 3;
      }
    }
  }

  ptr = ((char *)strchr(http_proxy_buf, ' ')) + 1;
  if (*ptr == '2' || (*ptr == '3' && *(ptr + 2) == '1') || (*ptr == '3' && *(ptr + 2) == '2') || (*ptr == '4' && *(ptr + 2) == '4')) {
    hydra_report_found_host(port, ip, "http-proxy", fp);
    hydra_completed_pair_found();
    free(http_proxy_buf);
    http_proxy_buf = NULL;
  } else {
    if (*ptr != '4')
      hydra_report(stderr, "[INFO] Unusual return code: %c for %s:%s\n", (char)*(strchr(http_proxy_buf, ' ') + 1), login, pass);
    else if (verbose && *(ptr + 2) == '3')
      hydra_report(stderr, "[INFO] Potential success, could be false positive: %s:%s\n", login, pass);
    hydra_completed_pair();
    free(http_proxy_buf);
    http_proxy_buf = hydra_receive_line(s);
    while (http_proxy_buf != NULL && hydra_strcasestr(http_proxy_buf, "Proxy-Authenticate:") == NULL) {
      free(http_proxy_buf);
      http_proxy_buf = hydra_receive_line(s);
    }
  }

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  if (http_proxy_buf != NULL)
    return 2;
  else
    return 1;
}

void service_http_proxy(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_HTTP_PROXY, mysslport = PORT_HTTP_PROXY_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  while (1) {
    next_run = 0;
    switch (run) {
    case 1: /* connect and service init function */
    {
      if (http_proxy_buf != NULL)
        free(http_proxy_buf);
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //        usleepn(275);
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
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = 2;
      break;
    }
    case 2: /* run the cracking function */
      next_run = start_http_proxy(sock, ip, port, options, miscptr, fp, hostname);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_http_proxy_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_http_proxy(const char *service) {
  printf("Module http-proxy is optionally taking the page to authenticate at.\n"
         "Default is http://www.microsoft.com/)\n"
         "Basic, DIGEST-MD5 and NTLM are supported and negotiated "
         "automatically.\n\n");
}
