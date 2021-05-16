#include "hydra-mod.h"
#include "sasl.h"

extern char *HYDRA_EXIT;
char *buf;
static int32_t http_proxy_auth_mechanism = AUTH_ERROR;

int32_t start_http_proxy_urlenum(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp, char *hostname) {
  char *empty = "";
  char *login, *pass, buffer[500], buffer2[500], mlogin[260], mpass[260], mhost[260];
  char url[260], host[30];
  char *header = ""; /* XXX TODO */
  char *ptr;
  int32_t auth = 0;

  login = hydra_get_next_login();
  if (login == NULL || strlen(login) == 0 || strstr(login, "://") == NULL) {
    hydra_completed_pair();
    return 1;
  }
  pass = hydra_get_next_password();
  pass = empty; // ignored

  strncpy(url, login, sizeof(url) - 1);
  url[sizeof(url) - 1] = 0;
  ptr = strstr(login, "://") + 3;
  if (ptr[0] == '[')
    ptr++;
  strncpy(mhost, ptr, sizeof(mhost) - 1);
  mhost[sizeof(mhost) - 1] = 0;
  if ((ptr = strchr(mhost, '/')) != NULL)
    *ptr = 0;
  if ((ptr = strchr(mhost, ']')) != NULL)
    *ptr = 0;
  else if ((ptr = strchr(mhost, ':')) != NULL)
    *ptr = 0;

  if (miscptr != NULL && strchr(miscptr, ':') != NULL) {
    strncpy(mlogin, miscptr, sizeof(mlogin) - 1);
    mlogin[sizeof(mlogin) - 1] = 0;
    ptr = strchr(mlogin, ':');
    *ptr++ = 0;
    strncpy(mpass, ptr, sizeof(mpass) - 1);
    mpass[sizeof(mpass) - 1] = 0;
    auth = 1;
  }

  if (http_proxy_auth_mechanism == AUTH_ERROR) {
    // send dummy request
    sprintf(buffer, "GET %s HTTP/1.0\r\n%sUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n", url, mhost, header);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
      return 1;

    // receive first 40x
    buf = hydra_receive_line(s);
    while (buf != NULL && strstr(buf, "HTTP/") == NULL) {
      free(buf);
      buf = hydra_receive_line(s);
    }

    if (debug)
      hydra_report(stderr, "S:%s\n", buf);

    // after the first query we should have been disconnected from web server
    s = hydra_disconnect(s);
    if ((options & OPTION_SSL) == 0) {
      s = hydra_connect_tcp(ip, port);
    } else {
      s = hydra_connect_ssl(ip, port, hostname);
    }
  }

  if (auth) {
    if (hydra_strcasestr(buf, "Proxy-Authenticate: Basic") != NULL) {
      http_proxy_auth_mechanism = AUTH_BASIC;
      sprintf(buffer2, "%.50s:%.50s", login, pass);
      hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
      sprintf(buffer,
              "GET %s HTTP/1.0\r\n%sProxy-Authorization: Basic "
              "%s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
              url, host, buffer2, header);
      if (debug)
        hydra_report(stderr, "C:%s\n", buffer);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
        return 1;
      free(buf);
      buf = hydra_receive_line(s);
      while (buf != NULL && strstr(buf, "HTTP/1.") == NULL) {
        free(buf);
        buf = hydra_receive_line(s);
      }

      // if server cut the connection, just exit cleanly or
      // this will be an infinite loop
      if (buf == NULL) {
        if (verbose)
          hydra_report(stderr, "[ERROR] Server did not answer\n");
        return 3;
      }

      if (debug)
        hydra_report(stderr, "S:%s\n", buf);
    } else {
      if (hydra_strcasestr(buf, "Proxy-Authenticate: NTLM") != NULL) {
        unsigned char buf1[4096];
        unsigned char buf2[4096];
        char *pos = NULL;

        http_proxy_auth_mechanism = AUTH_NTLM;
        // send auth and receive challenge
        // send auth request: let the server send it's own hostname and
        // domainname
        buildAuthRequest((tSmbNtlmAuthRequest *)buf2, 0, NULL, NULL);
        to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthRequest *)buf2));

        /* to be portable, no snprintf, buffer is big enough so it can't
         * overflow */
        // send the first..
        sprintf(buffer,
                "GET %s HTTP/1.0\r\n%sProxy-Authorization: NTLM %s\r\nUser-Agent: "
                "Mozilla/4.0 (Hydra)\r\nProxy-Connection: keep-alive\r\n%s\r\n",
                url, host, buf1, header);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
          return 1;

        // receive challenge
        free(buf);
        buf = hydra_receive_line(s);
        while (buf != NULL && (pos = hydra_strcasestr(buf, "Proxy-Authenticate: NTLM ")) == NULL) {
          free(buf);
          buf = hydra_receive_line(s);
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
        if (buf != NULL) {
          if (strlen(buf) >= 4)
            from64tobits((char *)buf1, pos);
          free(buf);
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
          return 1;

        buf = hydra_receive_line(s);
        while (buf != NULL && strstr(buf, "HTTP/1.") == NULL) {
          free(buf);
          buf = hydra_receive_line(s);
        }

        if (buf == NULL)
          return 1;
      } else {
#ifdef LIBOPENSSL
        if (hydra_strcasestr(buf, "Proxy-Authenticate: Digest") != NULL) {
          char *pbuffer, *result;

          http_proxy_auth_mechanism = AUTH_DIGESTMD5;
          pbuffer = hydra_strcasestr(buf, "Proxy-Authenticate: Digest ");
          strncpy(buffer, pbuffer + strlen("Proxy-Authenticate: Digest "), sizeof(buffer));
          buffer[sizeof(buffer) - 1] = '\0';

          pbuffer = buffer2;
          result = sasl_digest_md5(pbuffer, login, pass, buffer, miscptr, "proxy", host, 0, header);
          if (result == NULL)
            return 3;

          if (debug)
            hydra_report(stderr, "C:%s\n", buffer2);
          if (hydra_send(s, buffer2, strlen(buffer2), 0) < 0)
            return 1;

          free(buf);
          buf = hydra_receive_line(s);
          while (buf != NULL && strstr(buf, "HTTP/1.") == NULL) {
            free(buf);
            buf = hydra_receive_line(s);
          }

          if (debug && buf != NULL)
            hydra_report(stderr, "S:%s\n", buf);

          if (buf == NULL)
            return 1;

        } else
#endif
        {
          if (buf != NULL) {
            buf[strlen(buf) - 1] = '\0';
            hydra_report(stderr, "Unsupported Auth type:\n%s\n", buf);
          } else {
            hydra_report(stderr, "Unsupported Auth type\n");
          }
          return 3;
        }
      }
    }
  }
  // result analysis
  ptr = ((char *)strchr(buf, ' ')) + 1;
  if (*ptr == '2' || (*ptr == '3' && (*(ptr + 2) == '1' || *(ptr + 2) == '2')) || strncmp(ptr, "404", 4) == 0 || strncmp(ptr, "403", 4) == 0) {
    hydra_report_found_host(port, ip, "http-proxy", fp);
    if (fp != stdout)
      fprintf(fp, "[%d][http-proxy-urlenum] host: %s   url: %s\n", port, hydra_address2string_beautiful(ip), url);
    printf("[%d][http-proxy-urlenum] host: %s   url: %s\n", port, hydra_address2string_beautiful(ip), url);
    hydra_completed_pair_found();
  } else {
    if (strncmp(ptr, "407", 3) == 0 /*|| strncmp(ptr, "401", 3) == 0 */) {
      hydra_report(stderr, "[ERROR] Proxy reports bad credentials!\n");
      return 3;
    }
    hydra_completed_pair();
  }

  free(buf);

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_http_proxy_urlenum(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
      next_run = start_http_proxy_urlenum(sock, ip, port, options, miscptr, fp, hostname);
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

int32_t service_http_proxy_urlenum_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_http_proxy_urlenum(const char *service) {
  printf("Module http-proxy-urlenum only uses the -L option, not -x or -p/-P "
         "option.\n"
         "The -L loginfile must contain the URL list to try through the proxy.\n"
         "The proxy credentials cann be put as the optional parameter, e.g.\n"
         "   hydra -L urllist.txt -s 3128 target.com http-proxy-urlenum "
         "user:pass\n"
         "   hydra -L urllist.txt "
         "http-proxy-urlenum://target.com:3128/user:pass\n\n");
}
