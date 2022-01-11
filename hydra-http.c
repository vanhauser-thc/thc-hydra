#include "hydra-http.h"
#include "sasl.h"

extern char *HYDRA_EXIT;
char *webtarget = NULL;
char *slash = "/";
char *http_buf = NULL;

#define END_CONDITION_MAX_LEN 100
static char end_condition[END_CONDITION_MAX_LEN];
int end_condition_type = -1;

int32_t webport;
int32_t http_auth_mechanism = AUTH_UNASSIGNED;

int32_t start_http(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp, char *type, ptr_header_node ptr_head) {
  char *empty = "";
  char *login, *pass, *buffer, buffer2[500];
  char *header;
  char *ptr, *fooptr;
  int32_t complete_line = 0, buffer_size;
  char tmpreplybuf[1024] = "", *tmpreplybufptr;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  if (strcmp(type, "POST") == 0)
    add_header(&ptr_head, "Content-Length", "0", HEADER_TYPE_DEFAULT);

  header = stringify_headers(&ptr_head);

  buffer_size = strlen(header) + 500;
  if (!(buffer = malloc(buffer_size))) {
    free(header);
    return 3;
  }

  // we must reset this if buf is NULL and we do MD5 digest
  if (http_buf == NULL && http_auth_mechanism == AUTH_DIGESTMD5)
    http_auth_mechanism = AUTH_BASIC;

  if (use_proxy > 0 && proxy_count > 0)
    selected_proxy = random() % proxy_count;

  switch (http_auth_mechanism) {
  case AUTH_BASIC:
    sprintf(buffer2, "%.50s:%.50s", login, pass);
    hydra_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));

    /* again: no snprintf to be portable. don't worry, buffer can't overflow */
    if (use_proxy == 1 && proxy_authentication[selected_proxy] != NULL)
      sprintf(buffer,
              "%s http://%s%.250s HTTP/1.1\r\nHost: %s\r\nConnection: "
              "close\r\nAuthorization: Basic %s\r\nProxy-Authorization: Basic "
              "%s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
              type, webtarget, miscptr, webtarget, buffer2, proxy_authentication[selected_proxy], header);
    else {
      if (use_proxy == 1)
        sprintf(buffer,
                "%s http://%s%.250s HTTP/1.1\r\nHost: %s\r\nConnection: "
                "close\r\nAuthorization: Basic %s\r\nUser-Agent: Mozilla/4.0 "
                "(Hydra)\r\n%s\r\n",
                type, webtarget, miscptr, webtarget, buffer2, header);
      else
        sprintf(buffer,
                "%s %.250s HTTP/1.1\r\nHost: %s\r\nConnection: "
                "close\r\nAuthorization: Basic %s\r\nUser-Agent: Mozilla/4.0 "
                "(Hydra)\r\n%s\r\n",
                type, miscptr, webtarget, buffer2, header);
    }
    if (debug)
      hydra_report(stderr, "C:%s\n", buffer);
    break;

#ifdef LIBOPENSSL
  case AUTH_DIGESTMD5: {
    char *pbuffer, *result;

    pbuffer = hydra_strcasestr(http_buf, "WWW-Authenticate: Digest ");
    strncpy(buffer, pbuffer + strlen("WWW-Authenticate: Digest "), buffer_size - 1);
    buffer[buffer_size - 1] = '\0';

    fooptr = buffer2;
    result = sasl_digest_md5(fooptr, login, pass, buffer, miscptr, type, webtarget, webport, header);
    if (result == NULL) {
      free(buffer);
      free(header);
      return 3;
    }

    if (debug)
      hydra_report(stderr, "C:%s\n", buffer2);
    strcpy(buffer, buffer2);
  } break;
#endif

  case AUTH_NTLM: {
    unsigned char buf1[4096];
    unsigned char buf2[4096];
    char *pos = NULL;

    // send auth and receive challenge
    // send auth request: let the server send it's own hostname and domainname
    buildAuthRequest((tSmbNtlmAuthRequest *)buf2, 0, NULL, NULL);
    to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthRequest *)buf2));

    /* to be portable, no snprintf, buffer is big enough so it can't overflow */
    // send the first..
    if (use_proxy == 1 && proxy_authentication[selected_proxy] != NULL)
      sprintf(buffer,
              "%s http://%s%s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM "
              "%s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/4.0 "
              "(Hydra)\r\n%s\r\n",
              type, webtarget, miscptr, webtarget, buf1, proxy_authentication[selected_proxy], header);
    else {
      if (use_proxy == 1)
        sprintf(buffer,
                "%s http://%s%s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM "
                "%s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
                type, webtarget, miscptr, webtarget, buf1, header);
      else
        sprintf(buffer,
                "%s %s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM "
                "%s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
                type, miscptr, webtarget, buf1, header);
    }

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      free(buffer);
      free(header);
      return 1;
    }

    // receive challenge
    if (http_buf != NULL)
      free(http_buf);

    http_buf = hydra_receive_line(s);
    if (http_buf == NULL) {
      if (verbose)
        hydra_report(stderr, "[ERROR] Server did not answer\n");
      free(buffer);
      free(header);
      return 3;
    }

    pos = hydra_strcasestr(http_buf, "WWW-Authenticate: NTLM ");
    if (pos != NULL) {
      char *str;

      pos += 23;
      if ((str = strchr(pos, '\r')) != NULL) {
        pos[str - pos] = 0;
      }
      if ((str = strchr(pos, '\n')) != NULL) {
        pos[str - pos] = 0;
      }
    } else {
      hydra_report(stderr, "[ERROR] It is not NTLM authentication type\n");
      return 3;
    }

    // recover challenge
    from64tobits((char *)buf1, pos);
    free(http_buf);
    http_buf = NULL;

    // Send response
    buildAuthResponse((tSmbNtlmAuthChallenge *)buf1, (tSmbNtlmAuthResponse *)buf2, 0, login, pass, NULL, NULL);
    to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse *)buf2));

    // create the auth response
    if (use_proxy == 1 && proxy_authentication[selected_proxy] != NULL)
      sprintf(buffer,
              "%s http://%s%s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM "
              "%s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/4.0 "
              "(Hydra)\r\n%s\r\n",
              type, webtarget, miscptr, webtarget, buf1, proxy_authentication[selected_proxy], header);
    else {
      if (use_proxy == 1)
        sprintf(buffer,
                "%s http://%s%s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM "
                "%s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
                type, webtarget, miscptr, webtarget, buf1, header);
      else
        sprintf(buffer,
                "%s %s HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM "
                "%s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
                type, miscptr, webtarget, buf1, header);
    }

    if (debug)
      hydra_report(stderr, "C:%s\n", buffer);
  } break;
  }

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    free(buffer);
    free(header);
    return 1;
  }

  if (http_buf != NULL)
    free(http_buf);
  http_buf = hydra_receive_line(s);
  complete_line = 0;
  tmpreplybuf[0] = 0;

  while (http_buf != NULL && (strstr(http_buf, "HTTP/1.") == NULL || (strchr(http_buf, '\n') == NULL && complete_line == 0))) {
    if (debug)
      printf("il: %d, tmpreplybuf: %s, http_buf: %s\n", complete_line, tmpreplybuf, http_buf);
    if (tmpreplybuf[0] == 0 && strstr(http_buf, "HTTP/1.") != NULL) {
      strncpy(tmpreplybuf, http_buf, sizeof(tmpreplybuf) - 1);
      tmpreplybuf[sizeof(tmpreplybuf) - 1] = 0;
      free(http_buf);
      http_buf = hydra_receive_line(s);
    } else if (tmpreplybuf[0] != 0) {
      complete_line = 1;
      if ((tmpreplybufptr = malloc(strlen(tmpreplybuf) + strlen(http_buf) + 1)) != NULL) {
        strcpy(tmpreplybufptr, tmpreplybuf);
        strcat(tmpreplybufptr, http_buf);
        free(http_buf);
        http_buf = tmpreplybufptr;
        if (debug)
          printf("http_buf now: %s\n", http_buf);
      }
    } else {
      free(http_buf);
      http_buf = hydra_receive_line(s);
    }
  }

  // if server cut the connection, just exit cleanly or
  // this will be an infinite loop
  if (http_buf == NULL) {
    if (verbose)
      hydra_report(stderr, "[ERROR] Server did not answer\n");
    free(buffer);
    free(header);
    return 3;
  }

  if (debug)
    hydra_report(stderr, "S:%s\n", http_buf);

  ptr = ((char *)strchr(http_buf, ' '));
  if (ptr != NULL)
    ptr++;
  if (ptr != NULL && (*ptr == '2' || *ptr == '3' || strncmp(ptr, "403", 3) == 0 || strncmp(ptr, "404", 3) == 0)) {
#ifdef HAVE_PCRE
    if (end_condition_type >= 0 && hydra_string_match(http_buf, end_condition) != end_condition_type) {
#else
    if (end_condition_type >= 0 && (strstr(http_buf, end_condition) == NULL ? 0 : 1) != end_condition_type) {
#endif
      if (debug)
        hydra_report(stderr, "End condition not match continue.\n");
      hydra_completed_pair();
    } else {
      if (debug)
        hydra_report(stderr, "END condition %s match.\n", end_condition);
      hydra_report_found_host(port, ip, "www", fp);
      hydra_completed_pair_found();
    }
    if (http_buf != NULL) {
      free(http_buf);
      http_buf = NULL;
    }
  } else {
    if (ptr != NULL && *ptr != '4')
      fprintf(stderr, "[WARNING] Unusual return code: %.3s for %s:%s\n", (char *)ptr, login, pass);

    // the first authentication type failed, check the type from server header
    if ((hydra_strcasestr(http_buf, "WWW-Authenticate: Basic") == NULL) && (http_auth_mechanism == AUTH_BASIC)) {
      // seems the auth supported is not Basic scheme so testing further
      int32_t find_auth = 0;

      if (hydra_strcasestr(http_buf, "WWW-Authenticate: NTLM") != NULL) {
        http_auth_mechanism = AUTH_NTLM;
        find_auth = 1;
      }
#ifdef LIBOPENSSL
      if (hydra_strcasestr(http_buf, "WWW-Authenticate: Digest") != NULL) {
        http_auth_mechanism = AUTH_DIGESTMD5;
        find_auth = 1;
      }
#endif

      if (find_auth) {
        //        free(http_buf);
        //        http_buf = NULL;
        free(buffer);
        free(header);
        return 1;
      }
    }
    hydra_completed_pair();
  }
  //  free(http_buf);
  //  http_buf = NULL;

  free(buffer);
  free(header);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 1;
}

void service_http(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname, char *type) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_HTTP, mysslport = PORT_HTTP_SSL;
  char *ptr, *ptr2;
  ptr_header_node ptr_head = NULL;
#ifdef AF_INET6
  unsigned char addr6[sizeof(struct in6_addr)];
#endif

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  if (strlen(miscptr) == 0)
    miscptr = strdup("/");
  if (port != 0)
    webport = port;
  else if ((options & OPTION_SSL) == 0)
    webport = myport;
  else
    webport = mysslport;

  /* normalise the webtarget for ipv6/port number */
  webtarget = malloc(strlen(hostname) + 1 /* null */ + 6 /* :65535  */
#ifdef AF_INET6
                     + 2 /* [] */
#endif
  );
#ifdef AF_INET6
  /* let libc decide if target is an ipv6 address */
  if (inet_pton(AF_INET6, hostname, addr6)) {
    ptr = webtarget + sprintf(webtarget, "[%s]", hostname);
  } else {
#endif
    ptr = webtarget + sprintf(webtarget, "%s", hostname);
#ifdef AF_INET6
  }
#endif
  if (options & OPTION_SSL && webport != PORT_HTTP_SSL || !(options & OPTION_SSL) && webport != PORT_HTTP) {
    sprintf(ptr, ":%d", webport);
  }
  ptr = NULL;

  /* Advance to options string */
  ptr = miscptr;
  while (*ptr != 0 && (*ptr != ':' || *(ptr - 1) == '\\'))
    ptr++;
  if (*ptr != 0)
    *ptr++ = 0;
  optional1 = ptr;

  if (!parse_options(optional1,
                     &ptr_head)) // this function is in hydra-http-form.c !!
    run = 4;

  if (http_auth_mechanism == AUTH_UNASSIGNED)
    http_auth_mechanism = AUTH_BASIC;

  while (1) {
    next_run = 0;
    switch (run) {
    case 1: /* connect and service init function */
    {
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
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = 2;
      break;
    }
    case 2: /* run the cracking function */
      next_run = start_http(sock, ip, port, options, miscptr, fp, type, ptr_head);
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

void service_http_get(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_http(ip, sp, options, miscptr, fp, port, hostname, "GET"); }

void service_http_post(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_http(ip, sp, options, miscptr, fp, port, hostname, "POST"); }

void service_http_head(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_http(ip, sp, options, miscptr, fp, port, hostname, "HEAD"); }

int32_t service_http_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here

  /*POU CODE */
  char *start = strstr(miscptr, "F=");
  if (start == NULL)
    start = strstr(miscptr, "S=");

  if (start != NULL) {
    if (start[0] == 'F')
      end_condition_type = 0;
    else
      end_condition_type = 1;

    int condition_len = strlen(start);
    memset(end_condition, 0, END_CONDITION_MAX_LEN);
    if (condition_len >= END_CONDITION_MAX_LEN) {
      hydra_report(stderr, "Condition string cannot be bigger than %u.", END_CONDITION_MAX_LEN);
      return -1;
    }
    // copy condition witout starting string (F= or S=  2char)
    strncpy(end_condition, start + 2, condition_len - 2);
    if (debug)
      hydra_report(stderr, "End condition is %s, mod is %d\n", end_condition, end_condition_type);

    if (*(start - 1) == ' ')
      start--;
    memset(start, '\0', condition_len);
    if (debug)
      hydra_report(stderr, "Modificated options:%s\n", miscptr);
  } else {
    if (debug)
      hydra_report(stderr, "Condition not found\n");
  }

  return 0;
}

void usage_http(const char *service) {
  printf("Module %s requires the page to authenticate.\n"
         "The following parameters are optional:\n"
         " (a|A)=auth-type   specify authentication mechanism to use: BASIC, "
         "NTLM or MD5\n"
         " (h|H)=My-Hdr\\: foo   to send a user defined HTTP header with each "
         "request\n"
         " (F|S)=check for text in the HTTP reply. S= means if this text is "
         "found, a\n"
         "       valid account has been found, F= means if this string is "
         "present the\n"
         "       combination is invalid. Note: this must be the last option "
         "supplied.\n"
         "For example:  \"/secret\" or \"http://bla.com/foo/bar:H=Cookie\\: "
         "sessid=aaaa\" or \"https://test.com:8080/members:A=NTLM\"\n\n",
         service);
}
