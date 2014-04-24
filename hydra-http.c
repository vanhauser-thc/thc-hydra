#include "hydra-mod.h"
#include "sasl.h"

extern char *HYDRA_EXIT;
char *buf = NULL;
char *webtarget = NULL;
char *slash = "/";
int webport, freemischttp = 0;

int http_auth_mechanism = AUTH_BASIC;

int start_http(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp, char *type) {
  char *empty = "";
  char *login, *pass, buffer[500], buffer2[500];
  char *header = "";            /* XXX TODO */
  char *ptr;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  // we must reset this if buf is NULL and we do MD5 digest
  if (buf == NULL && http_auth_mechanism == AUTH_DIGESTMD5)
    http_auth_mechanism = AUTH_BASIC;

  switch (http_auth_mechanism) {
  case AUTH_BASIC:
    sprintf(buffer2, "%.50s:%.50s", login, pass);
    hydra_tobase64((unsigned char *) buffer2, strlen(buffer2), sizeof(buffer2));

    /* again: no snprintf to be portable. dont worry, buffer cant overflow */
    if (use_proxy == 1 && proxy_authentication != NULL)
      sprintf(buffer, "%s http://%s:%d%.250s HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
              type, webtarget, webport, miscptr, webtarget, buffer2, proxy_authentication, header);
    else {
      if (use_proxy == 1)
        sprintf(buffer, "%s http://%s:%d%.250s HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
                type, webtarget, webport, miscptr, webtarget, buffer2, header);
      else
        sprintf(buffer, "%s %.250s HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n", type, miscptr, webtarget, buffer2, header);
    }
    if (debug)
      hydra_report(stderr, "C:%s\n", buffer);
    break;

#ifdef LIBOPENSSL
  case AUTH_DIGESTMD5:{
      char *pbuffer;

      pbuffer = hydra_strcasestr(buf, "WWW-Authenticate: Digest ");
      strncpy(buffer, pbuffer + strlen("WWW-Authenticate: Digest "), sizeof(buffer));
      buffer[sizeof(buffer) - 1] = '\0';

      sasl_digest_md5(buffer2, login, pass, buffer, miscptr, type, webtarget, webport, header);
      if (buffer2 == NULL) {
        return 3;
      }

      if (debug)
        hydra_report(stderr, "C:%s\n", buffer2);
      strcpy(buffer, buffer2);
    }
    break;
#endif

  case AUTH_NTLM:{
      unsigned char buf1[4096];
      unsigned char buf2[4096];
      char *pos = NULL;

      //send auth and receive challenge
      //send auth request: let the server send it's own hostname and domainname
      buildAuthRequest((tSmbNtlmAuthRequest *) buf2, 0, NULL, NULL);
      to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthRequest *) buf2));

      /* to be portable, no snprintf, buffer is big enough so it cant overflow */
      //send the first..
      if (use_proxy == 1 && proxy_authentication != NULL)
        sprintf(buffer,
                "%s http://%s:%d%s HTTP/1.0\r\nHost: %s\r\nAuthorization: NTLM %s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\nConnection: keep-alive\r\n%s\r\n",
                type, webtarget, webport, miscptr, webtarget, buf1, proxy_authentication, header);
      else {
        if (use_proxy == 1)
          sprintf(buffer, "%s http://%s:%d%s HTTP/1.0\r\nHost: %s\r\nAuthorization: NTLM %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\nConnection: keep-alive\r\n%s\r\n",
                  type, webtarget, webport, miscptr, webtarget, buf1, header);
        else
          sprintf(buffer, "%s %s HTTP/1.0\r\nHost: %s\r\nAuthorization: NTLM %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\nConnection: keep-alive\r\n%s\r\n", type, miscptr, webtarget,
                  buf1, header);
      }

      if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
        return 1;

      //receive challenge
      if (buf != NULL)
        free(buf);
      buf = hydra_receive_line(s);
      while (buf != NULL && (pos = hydra_strcasestr(buf, "WWW-Authenticate: NTLM ")) == NULL) {
        free(buf);
        buf = hydra_receive_line(s);
      }

      if (buf == NULL)
        return 1;

      if (pos != NULL) {
        char *str;

        pos += 23;
        if ((str = strchr(pos, '\r')) != NULL) {
          pos[str - pos] = 0;
        }
        if ((str = strchr(pos, '\n')) != NULL) {
          pos[str - pos] = 0;
        }
      }
      //recover challenge
      from64tobits((char *) buf1, pos);
      free(buf);
      buf = NULL;

      //Send response
      buildAuthResponse((tSmbNtlmAuthChallenge *) buf1, (tSmbNtlmAuthResponse *) buf2, 0, login, pass, NULL, NULL);
      to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse *) buf2));

      //create the auth response
      if (use_proxy == 1 && proxy_authentication != NULL)
        sprintf(buffer,
                "%s http://%s:%d%s HTTP/1.0\r\nHost: %s\r\nAuthorization: NTLM %s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\nConnection: keep-alive\r\n%s\r\n",
                type, webtarget, webport, miscptr, webtarget, buf1, proxy_authentication, header);
      else {
        if (use_proxy == 1)
          sprintf(buffer, "%s http://%s:%d%s HTTP/1.0\r\nHost: %s\r\nAuthorization: NTLM %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\nConnection: keep-alive\r\n%s\r\n",
                  type, webtarget, webport, miscptr, webtarget, buf1, header);
        else
          sprintf(buffer, "%s %s HTTP/1.0\r\nHost: %s\r\nAuthorization: NTLM %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\nConnection: keep-alive\r\n%s\r\n", type, miscptr, webtarget,
                  buf1, header);
      }

      if (debug)
        hydra_report(stderr, "C:%s\n", buffer);
    }
    break;
  }

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }

  if (buf != NULL)
    free(buf);
  buf = hydra_receive_line(s);
  while (buf != NULL && strstr(buf, "HTTP/1.") == NULL) {
    free(buf);
    buf = hydra_receive_line(s);
  }

  //if server cut the connection, just exit cleanly or 
  //this will be an infinite loop
  if (buf == NULL) {
    if (verbose)
      hydra_report(stderr, "[ERROR] Server did not answer\n");
    return 3;
  }

  if (debug)
    hydra_report(stderr, "S:%s\n", buf);

  ptr = ((char *) index(buf, ' ')) + 1;
  if (ptr != NULL && (*ptr == '2' || *ptr == '3' || strncmp(ptr, "403", 3) == 0 || strncmp(ptr, "404", 3) == 0)) {
    hydra_report_found_host(port, ip, "www", fp);
    hydra_completed_pair_found();
    if (buf != NULL) {
      free(buf);
      buf = NULL;
    }
  } else {
    if (ptr != NULL && *ptr != '4')
      fprintf(stderr, "[WARNING] Unusual return code: %c for %s:%s\n", (char) *(index(buf, ' ') + 1), login, pass);

    //the first authentication type failed, check the type from server header
    if ((hydra_strcasestr(buf, "WWW-Authenticate: Basic") == NULL) && (http_auth_mechanism == AUTH_BASIC)) {
      //seems the auth supported is not Basic shceme so testing further
      int find_auth = 0;

      if (hydra_strcasestr(buf, "WWW-Authenticate: NTLM") != NULL) {
        http_auth_mechanism = AUTH_NTLM;
        find_auth = 1;
      }
#ifdef LIBOPENSSL
      if (hydra_strcasestr(buf, "WWW-Authenticate: Digest") != NULL) {
        http_auth_mechanism = AUTH_DIGESTMD5;
        find_auth = 1;
      }
#endif

      if (find_auth) {
//        free(buf);
//        buf = NULL;
        return 1;
      }
    }
    hydra_completed_pair();
  }
//  free(buf);
//  buf = NULL;
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_http(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *type) {
  int run = 1, next_run = 1, sock = -1;
  int myport = PORT_HTTP, mysslport = PORT_HTTP_SSL;
  char *ptr, *ptr2;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  if ((webtarget = strstr(miscptr, "://")) != NULL) {
    webtarget += strlen("://");
    if ((ptr2 = index(webtarget, ':')) != NULL) {       /* step over port if present */
      *ptr2 = 0;
      ptr2++;
      ptr = ptr2;
      if (*ptr == '/' || (ptr = index(ptr2, '/')) != NULL)
        miscptr = ptr;
      else
        miscptr = slash;        /* to make things easier to user */
    } else if ((ptr2 = index(webtarget, '/')) != NULL) {
      miscptr = malloc(strlen(ptr2) + 1);
      freemischttp = 1;
      strcpy(miscptr, ptr2);
      *ptr2 = 0;
    } else
      webtarget = NULL;
  }
  if (cmdlinetarget != NULL && webtarget == NULL)
    webtarget = cmdlinetarget;
  else if (webtarget == NULL && cmdlinetarget == NULL)
    webtarget = hydra_address2string(ip);
  if (port != 0)
    webport = port;
  else if ((options & OPTION_SSL) == 0)
    webport = myport;
  else
    webport = mysslport;

  while (1) {
    next_run = 0;
    switch (run) {
    case 1:                    /* connect and service init function */
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
          sock = hydra_connect_ssl(ip, mysslport);
          port = mysslport;
        }
        if (sock < 0) {
          if (freemischttp)
            free(miscptr);
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int) getpid());
          hydra_child_exit(1);
        }
        next_run = 2;
        break;
      }
    case 2:                    /* run the cracking function */
      next_run = start_http(sock, ip, port, options, miscptr, fp, type);
      break;
    case 3:                    /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      if (freemischttp)
        free(miscptr);
      hydra_child_exit(0);
      return;
    default:
      if (freemischttp)
        free(miscptr);
      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

void service_http_get(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  service_http(ip, sp, options, miscptr, fp, port, "GET");
}

void service_http_head(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  service_http(ip, sp, options, miscptr, fp, port, "HEAD");
}

int service_http_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
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
