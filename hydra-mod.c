#include "hydra-mod.h"
#include <arpa/inet.h>
#ifdef LIBOPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#endif
#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#define MAX_CONNECT_RETRY 1
#define WAIT_BETWEEN_CONNECT_RETRY 3
#define HYDRA_DUMP_ROWS 16

/* rfc 1928 SOCKS proxy */
#define SOCKS_V5	5
#define SOCKS_V4	4
#define SOCKS_NOAUTH	0

/* http://tools.ietf.org/html/rfc1929 */
#define SOCKS_PASSAUTH	2
#define SOCKS_NOMETHOD	0xff
#define SOCKS_CONNECT	1
#define SOCKS_IPV4	1
#define SOCKS_DOMAIN	3
#define SOCKS_IPV6	4

extern int conwait;
char quiet;
int do_retry = 1;
int module_auth_type = -1;
int intern_socket, extern_socket;
char pair[260];
char HYDRA_EXIT[5] = "\x00\xff\x00\xff\x00";
char *HYDRA_EMPTY = "\x00\x00\x00\x00";
char *fe80 = "\xfe\x80\x00";
int fail = 0;
int alarm_went_off = 0;
int use_ssl = 0;
char ipaddr_str[64];
int src_port = 0;
int __fck = 0;
int ssl_first = 1;
int __first_connect = 1;
char ipstring[64];
unsigned int colored_output = 1;
char quiet = 0;

#ifdef LIBOPENSSL
SSL *ssl = NULL;
SSL_CTX *sslContext = NULL;
RSA *rsa = NULL;
#endif

/* prototype */
int my_select(int fd, fd_set * fdread, fd_set * fdwrite, fd_set * fdex, long sec, long usec);

/* ----------------- alarming functions ---------------- */
void alarming() {
  fail++;
  alarm_went_off++;

/* uh, I think it's not good for performance if we try to reconnect to a timeout system!
 *  if (fail > MAX_CONNECT_RETRY) {
 */
  //fprintf(stderr, "Process %d: Can not connect [timeout], process exiting\n", (int) getpid());
  if (debug)
    printf("DEBUG_CONNECT_TIMEOUT\n");
  hydra_child_exit(1);

/*
 *   } else {
 *     if (verbose) fprintf(stderr, "Process %d: Can not connect [timeout], retrying (%d of %d retries)\n", (int)getpid(), fail, MAX_CONNECT_RETRY);
 *   }
 */
}

void interrupt() {
  if (debug)
    printf("DEBUG_INTERRUPTED\n");
}

/* ----------------- internal functions ----------------- */

int internal__hydra_connect(char *host, int port, int protocol, int type) {
  int s, ret = -1, ipv6 = 0;

#ifdef AF_INET6
  struct sockaddr_in6 target6;
  struct sockaddr_in6 sin6;
#endif
  struct sockaddr_in target;
  struct sockaddr_in sin;
  char *buf, *tmpptr = NULL;
  int err = 0;

#ifdef AF_INET6
  memset(&target6, 0, sizeof(target6));
  memset(&sin6, 0, sizeof(sin6));
  if ((host[0] == 16 && proxy_string_ip[0] != 4) || proxy_string_ip[0] == 16)
    ipv6 = 1;
#endif

#ifdef AF_INET6
  if (ipv6)
    s = socket(AF_INET6, protocol, type);
  else
#endif
    s = socket(PF_INET, protocol, type);
  if (s >= 0) {
    if (src_port != 0) {
      int bind_ok = 0;

#ifdef AF_INET6
      if (ipv6) {
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(src_port);
      } else
#endif
      {
        sin.sin_family = PF_INET;
        sin.sin_port = htons(src_port);
        sin.sin_addr.s_addr = INADDR_ANY;
      }

      //we will try to find a free port down to 512
      while (!bind_ok && src_port >= 512) {
#ifdef AF_INET6
        if (ipv6)
          ret = bind(s, (struct sockaddr *) &sin6, sizeof(sin6));
        else
#endif
          ret = bind(s, (struct sockaddr *) &sin, sizeof(sin));

        if (ret == -1) {
          if (verbose)
            perror("internal_hydra_connect error");
          if (errno == EADDRINUSE) {
            src_port--;
#ifdef AF_INET6
            if (ipv6)
              sin6.sin6_port = htons(src_port);
            else
#endif
              sin.sin_port = htons(src_port);
          } else {
            if (errno == EACCES && (getuid() > 0)) {
              fprintf(stderr, "[ERROR] You need to be root to test this service\n");
              close(s);
              return -1;
            }
          }
        } else
          bind_ok = 1;
      }
    }
    if (use_proxy > 0) {
      if (proxy_string_ip[0] == 4) {
        memcpy(&target.sin_addr.s_addr, &proxy_string_ip[1], 4);
        target.sin_family = AF_INET;
        target.sin_port = htons(proxy_string_port);
      }
#ifdef AF_INET6
      if (proxy_string_ip[0] == 16) {
        memcpy(&target6.sin6_addr, &proxy_string_ip[1], 16);
        target6.sin6_family = AF_INET6;
        target6.sin6_port = htons(proxy_string_port);
      }
#endif
    } else {
      if (host[0] == 4) {
        memcpy(&target.sin_addr.s_addr, &host[1], 4);
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
      }
#ifdef AF_INET6
      if (host[0] == 16) {
        memcpy(&target6.sin6_addr, &host[1], 16);
        target6.sin6_family = AF_INET6;
        target6.sin6_port = htons(port);
      }
#endif
    }
    signal(SIGALRM, alarming);
    do {
      if (fail > 0)
        sleep(WAIT_BETWEEN_CONNECT_RETRY);
      alarm_went_off = 0;
      alarm(waittime);
#ifdef AF_INET6
#ifdef SO_BINDTODEVICE
      if (host[17] != 0) {
        setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, &host[17], strlen(&host[17]) + 1);
      }
#else
#ifdef IP_FORCE_OUT_IFP
      if (host[17] != 0) {
        setsockopt(s, SOL_SOCKET, IP_FORCE_OUT_IFP, &host[17], strlen(&host[17]) + 1);
      }
#endif
#endif

      if (ipv6)
        ret = connect(s, (struct sockaddr *) &target6, sizeof(target6));
      else
#endif
        ret = connect(s, (struct sockaddr *) &target, sizeof(target));
      alarm(0);
      if (ret < 0 && alarm_went_off == 0) {
        fail++;
        if (verbose ) {
          if (do_retry && fail <= MAX_CONNECT_RETRY)
            fprintf(stderr, "Process %d: Can not connect [unreachable], retrying (%d of %d retries)\n", (int) getpid(), fail, MAX_CONNECT_RETRY);
          else
            fprintf(stderr, "Process %d: Can not connect [unreachable]\n", (int) getpid());
        }
      }
    } while (ret < 0 && fail <= MAX_CONNECT_RETRY && do_retry);
    if (ret < 0 && fail > MAX_CONNECT_RETRY) {
      if (debug)
        printf("DEBUG_CONNECT_UNREACHABLE\n");

/* we wont quit here, thats up to the module to decide what to do 
 *              fprintf(stderr, "Process %d: Can not connect [unreachable], process exiting\n", (int)getpid());
 *              hydra_child_exit(1);
 */
      extern_socket = -1;
      close(s);
      ret = -1;
      return ret;
    }
    ret = s;
    extern_socket = s;
    if (debug)
      printf("DEBUG_CONNECT_OK\n");

    err = 0;
    if (use_proxy == 2) {
      if ((buf = malloc(4096)) == NULL) {
        fprintf(stderr, "[ERROR] could not malloc()\n");
        close(s);
        return -1;
      }
      memset(&target, 0, sizeof(target));
      if (host[0] == 4) {
        memcpy(&target.sin_addr.s_addr, &host[1], 4);
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
      }
#ifdef AF_INET6
      memset(&target6, 0, sizeof(target6));
      if (host[0] == 16) {
        memcpy(&target6.sin6_addr, &host[1], 16);
        target6.sin6_family = AF_INET6;
        target6.sin6_port = htons(port);
      }
#endif

      if (hydra_strcasestr(proxy_string_type, "connect") || hydra_strcasestr(proxy_string_type, "http")) {
        if (proxy_authentication == NULL)
          if (host[0] == 16)
            snprintf(buf, 4096, "CONNECT [%s]:%d HTTP/1.0\r\n\r\n", hydra_address2string(host), port);
          else
            snprintf(buf, 4096, "CONNECT %s:%d HTTP/1.0\r\n\r\n", hydra_address2string(host), port);
        else if (host[0] == 16)
          snprintf(buf, 4096, "CONNECT [%s]:%d HTTP/1.0\r\nProxy-Authorization: Basic %s\r\n\r\n", hydra_address2string(host), port, proxy_authentication);
        else
          snprintf(buf, 4096, "CONNECT %s:%d HTTP/1.0\r\nProxy-Authorization: Basic %s\r\n\r\n", hydra_address2string(host), port, proxy_authentication);

        send(s, buf, strlen(buf), 0);
        recv(s, buf, 4096, 0);
        if (strncmp("HTTP/", buf, 5) == 0 && (tmpptr = index(buf, ' ')) != NULL && *++tmpptr == '2') {
          if (debug)
            printf("DEBUG_CONNECT_PROXY_OK\n");
        } else {
          if (debug)
            printf("DEBUG_CONNECT_PROXY_FAILED (Code: %c%c%c)\n", *tmpptr, *(tmpptr + 1), *(tmpptr + 2));
          if (verbose)
            fprintf(stderr, "[ERROR] CONNECT call to proxy failed with code %c%c%c\n", *tmpptr, *(tmpptr + 1), *(tmpptr + 2));
          err = 1;
        }
//        free(buf);
      } else {
        if (hydra_strcasestr(proxy_string_type, "socks5")) {
//          char buf[1024];
          size_t cnt, wlen;

          /* socks v5 support */
          buf[0] = SOCKS_V5;
          buf[1] = 1;
          if (proxy_authentication == NULL)
            buf[2] = SOCKS_NOAUTH;
          else
            buf[2] = SOCKS_PASSAUTH;
          cnt = hydra_send(s, buf, 3, 0);
          if (cnt != 3) {
            hydra_report(stderr, "[ERROR] SOCKS5 proxy write failed (%zu/3)\n", cnt);
            err = 1;
          } else {
            cnt = hydra_recv(s, buf, 2);
            if (cnt != 2) {
              hydra_report(stderr, "[ERROR] SOCKS5 proxy read failed (%zu/2)\n", cnt);
              err = 1;
            }
            if ((unsigned int) buf[1] == SOCKS_NOMETHOD) {
              hydra_report(stderr, "[ERROR] SOCKS5 proxy authentication method negotiation failed\n");
              err = 1;
            }
            /* SOCKS_DOMAIN not supported here, do we need it ? */
            if (err != 1) {
              /* send user/pass */
              if (proxy_authentication != NULL) {
                //format was checked previously
                char *login = strtok(proxy_authentication, ":");
                char *pass = strtok(NULL, ":");

                snprintf(buf, sizeof(buf), "\x01%c%s%c%s", (char) strlen(login), login, (char) strlen(pass), pass);

                cnt = hydra_send(s, buf, strlen(buf), 0);
                if (cnt != strlen(buf)) {
                  hydra_report(stderr, "[ERROR] SOCKS5 proxy write failed (%zu/3)\n", cnt);
                  err = 1;
                } else {
                  cnt = hydra_recv(s, buf, 2);
                  if (cnt != 2) {
                    hydra_report(stderr, "[ERROR] SOCKS5 proxy read failed (%zu/2)\n", cnt);
                    err = 1;
                  }
                  if (buf[1] != 0) {
                    hydra_report(stderr, "[ERROR] SOCKS5 proxy authentication failure\n");
                    err = 1;
                  } else {
                    if (debug)
                      hydra_report(stderr, "[DEBUG] SOCKS5 proxy authentication success\n");
                  }
                }
              }
#ifdef AF_INET6
              if (ipv6) {
                /* Version 5, connect: IPv6 address */
                buf[0] = SOCKS_V5;
                buf[1] = SOCKS_CONNECT;
                buf[2] = 0;
                buf[3] = SOCKS_IPV6;
                memcpy(buf + 4, &target6.sin6_addr, sizeof target6.sin6_addr);
                memcpy(buf + 20, &target6.sin6_port, sizeof target6.sin6_port);
                wlen = 22;
              } else {
#endif
                /* Version 5, connect: IPv4 address */
                buf[0] = SOCKS_V5;
                buf[1] = SOCKS_CONNECT;
                buf[2] = 0;
                buf[3] = SOCKS_IPV4;
                memcpy(buf + 4, &target.sin_addr, sizeof target.sin_addr);
                memcpy(buf + 8, &target.sin_port, sizeof target.sin_port);
                wlen = 10;
#ifdef AF_INET6
              }
#endif
              cnt = hydra_send(s, buf, wlen, 0);
              if (cnt != wlen) {
                hydra_report(stderr, "[ERROR] SOCKS5 proxy write failed (%zu/%zu)\n", cnt, wlen);
                err = 1;
              } else {
                cnt = hydra_recv(s, buf, 10);
                if (cnt != 10) {
                  hydra_report(stderr, "[ERROR] SOCKS5 proxy read failed (%zu/10)\n", cnt);
                  err = 1;
                }
                if (buf[1] != 0) {
                  /* 0x05 = connection refused by destination host */
                  if (buf[1] == 5)
                    hydra_report(stderr, "[ERROR] SOCKS proxy request failed\n");
                  else
                    hydra_report(stderr, "[ERROR] SOCKS error %d\n", buf[1]);
                  err = 1;
                }
              }
            }
          }
        } else {
          if (hydra_strcasestr(proxy_string_type, "socks4")) {
            if (ipv6) {
              hydra_report(stderr, "[ERROR] SOCKS4 proxy does not support IPv6\n");
              err = 1;
            } else {
//              char buf[1024];
              size_t cnt, wlen;

              /* socks v4 support */
              buf[0] = SOCKS_V4;
              buf[1] = SOCKS_CONNECT;   /* connect */
              memcpy(buf + 2, &target.sin_port, sizeof target.sin_port);
              memcpy(buf + 4, &target.sin_addr, sizeof target.sin_addr);
              buf[8] = 0;       /* empty username */
              wlen = 9;
              cnt = hydra_send(s, buf, wlen, 0);
              if (cnt != wlen) {
                hydra_report(stderr, "[ERROR] SOCKS4 proxy write failed (%zu/%zu)\n", cnt, wlen);
                err = 1;
              } else {
                cnt = hydra_recv(s, buf, 8);
                if (cnt != 8) {
                  hydra_report(stderr, "[ERROR] SOCKS4 proxy read failed (%zu/8)\n", cnt);
                  err = 1;
                }
                if (buf[1] != 90) {
                  /* 91 = 0x5b = request rejected or failed */
                  if (buf[1] == 91)
                    hydra_report(stderr, "[ERROR] SOCKS proxy request failed\n");
                  else
                    hydra_report(stderr, "[ERROR] SOCKS error %d\n", buf[1]);
                  err = 1;
                }
              }
            }
          } else {
            hydra_report(stderr, "[ERROR] Unknown proxy type: %s, valid type are \"connect\", \"socks4\" or \"socks5\"\n", proxy_string_type);
            err = 1;
          }
        }
      }
      free(buf);
    }
    if (err) {
      close(s);
      extern_socket = -1;
      ret = -1;
      return ret;
    }
    fail = 0;
    return ret;
  }
  return ret;
}

#ifdef LIBOPENSSL
RSA *ssl_temp_rsa_cb(SSL * ssl, int export, int keylength) {
  if (rsa == NULL) {
#ifdef NO_RSA_LEGACY
    RSA *private = RSA_new();
    BIGNUM *f4 = BN_new();

    BN_set_word(f4, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, f4, NULL);
#else
    rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL);
#endif
  }
  return rsa;
}


int internal__hydra_connect_to_ssl(int socket) {
  int err;

  if (ssl_first) {
    SSL_load_error_strings();
//    SSL_add_ssl_algoritms();
    SSL_library_init();         // ?
    ssl_first = 0;
  }

  if (sslContext == NULL) {
    /* context: ssl2 + ssl3 is allowed, whatever the server demands */
    if ((sslContext = SSL_CTX_new(SSLv23_client_method())) == NULL) {
      if (verbose) {
        err = ERR_get_error();
        fprintf(stderr, "[ERROR] SSL allocating context: %s\n", ERR_error_string(err, NULL));
      }
      return -1;
    }
    /* set the compatbility mode */
    SSL_CTX_set_options(sslContext, SSL_OP_ALL);
    SSL_CTX_set_options(sslContext, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(sslContext, SSL_OP_NO_TLSv1);

    /* we set the default verifiers and dont care for the results */
    (void) SSL_CTX_set_default_verify_paths(sslContext);
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);
    SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
  }

  if ((ssl = SSL_new(sslContext)) == NULL) {
    if (verbose) {
      err = ERR_get_error();
      fprintf(stderr, "[ERROR] preparing an SSL context: %s\n", ERR_error_string(err, NULL));
    }
    SSL_set_bio(ssl, NULL, NULL);
    SSL_clear(ssl);
    return -1;
  }

  SSL_set_fd(ssl, socket);
  if (SSL_connect(ssl) <= 0) {
//    fprintf(stderr, "[ERROR] SSL Connect %d\n", SSL_connect(ssl));
    if (verbose) {
      err = ERR_get_error();
      fprintf(stderr, "[VERBOSE] Could not create an SSL session: %s\n", ERR_error_string(err, NULL));
    }
    close(socket);
    return -1;
  }
  if (debug)
    fprintf(stderr, "[VERBOSE] SSL negotiated cipher: %s\n", SSL_get_cipher(ssl));

  use_ssl = 1;

  return socket;
}

int internal__hydra_connect_ssl(char *host, int port, int protocol, int type) {
  int socket;

  if ((socket = internal__hydra_connect(host, port, protocol, type)) < 0)
    return -1;

  return internal__hydra_connect_to_ssl(socket);
}
#endif

int internal__hydra_recv(int socket, char *buf, int length) {
#ifdef LIBOPENSSL
  if (use_ssl) {
    return SSL_read(ssl, buf, length);
  } else
#endif
    return recv(socket, buf, length, 0);
}

int internal__hydra_send(int socket, char *buf, int size, int options) {
#ifdef LIBOPENSSL
  if (use_ssl) {
    return SSL_write(ssl, buf, size);
  } else
#endif
    return send(socket, buf, size, options);
}

/* ------------------ public functions ------------------ */

void hydra_child_exit(int code) {
  char buf[2];

  if (debug)
    printf("[DEBUG] pid %d called child_exit with code %d\n", getpid(), code);
  if (code == 0)                /* normal quitting */
    __fck = write(intern_socket, "Q", 1);
  else if (code == 1)           /* no connect possible */
    __fck = write(intern_socket, "C", 1);
  else if (code == 2)           /* application protocol error or service shutdown */
    __fck = write(intern_socket, "E", 1);
  // code 3 means exit without telling mommy about it - a bad idea. mommy should know
  else if (code == -1 || code > 3) {
    fprintf(stderr, "[TOTAL FUCKUP] a module should not use hydra_child_exit(-1) ! Fix it in the source please ...\n");
    __fck = write(intern_socket, "E", 1);
  }
  do {
    usleep(10000);
  } while (read(intern_socket, buf, 1) <= 0);
//  sleep(2); // be sure that mommy receives our message
  exit(0);                      // might be killed before reaching this
}

void hydra_register_socket(int s) {
  intern_socket = s;
}

char *hydra_get_next_pair() {
  if (pair[0] == 0) {
    pair[sizeof(pair) - 1] = 0;
    __fck = read(intern_socket, pair, sizeof(pair) - 1);
    //if (debug) hydra_dump_data(pair, __fck, "CHILD READ PAIR");
    if (memcmp(&HYDRA_EXIT, &pair, sizeof(HYDRA_EXIT)) == 0)
      return HYDRA_EXIT;
    if (pair[0] == 0)
      return HYDRA_EMPTY;
  }
  return pair;
}

char *hydra_get_next_login() {
  if (pair[0] == 0)
    return HYDRA_EMPTY;
  return pair;
}

char *hydra_get_next_password() {
  char *ptr = pair;

  while (*ptr != '\0')
    ptr++;
  ptr++;
  if (*ptr == 0)
    return HYDRA_EMPTY;
  return ptr;
}

void hydra_completed_pair() {
  __fck = write(intern_socket, "N", 1);
  pair[0] = 0;
}

void hydra_completed_pair_found() {
  char *login;

  __fck = write(intern_socket, "F", 1);
  login = hydra_get_next_login();
  __fck = write(intern_socket, login, strlen(login) + 1);
  pair[0] = 0;
}

void hydra_completed_pair_skip() {
  char *login;

  __fck = write(intern_socket, "f", 1);
  login = hydra_get_next_login();
  __fck = write(intern_socket, login, strlen(login) + 1);
  pair[0] = 0;
}

/*
based on writeError from Medusa project
*/
void hydra_report_debug(FILE * st, char *format, ...) {
  va_list ap;
  char buf[8200];
  char bufOut[33000];
  char temp[6];
  unsigned char cTemp;
  int i = 0;

  if (format == NULL) {
    fprintf(stderr, "[ERROR] no msg passed.\n");
  } else {
    va_start(ap, format);
    memset(bufOut, 0, sizeof(bufOut));
    memset(buf, 0, 512);
    vsnprintf(buf, sizeof(buf), format, ap);

    // Convert any chars less than 32d or greater than 126d to hex
    for (i = 0; i < sizeof(buf); i++) {
      memset(temp, 0, 6);
      cTemp = (unsigned char) buf[i];
      if ((cTemp < 32 && cTemp > 0) || cTemp > 126) {
        sprintf(temp, "[%02X]", cTemp);
      } else
        sprintf(temp, "%c", cTemp);

      if (strlen(bufOut) + 6 < sizeof(bufOut))
        strncat(bufOut, temp, 6);
      else
        break;
    }
    fprintf(st, "%s\n", bufOut);
    va_end(ap);
  }
  return;
}

void hydra_report_found(int port, char *svc, FILE * fp) {
/*
  if (!strcmp(svc, "rsh"))
    if (colored_output)
      fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] login: \e[32m%s\e[0m\n", port, svc, hydra_get_next_login());
    else
      fprintf(fp, "[%d][%s] login: %s\n", port, svc, hydra_get_next_login());
  else if (colored_output)
    fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] login: \e[32m%s\e[0m   password: \e[32m%s\e[0m\n", port, svc, hydra_get_next_login(), hydra_get_next_password());
  else
    fprintf(fp, "[%d][%s] login: %s   password: %s\n", port, svc, hydra_get_next_login(), hydra_get_next_password());

  if (stdout != fp) {
    if (!strcmp(svc, "rsh"))
      printf("[%d][%s] login: %s\n", port, svc, hydra_get_next_login());
    else
      printf("[%d][%s] login: %s   password: %s\n", port, svc, hydra_get_next_login(), hydra_get_next_password());
  }

  fflush(fp);
*/
}

/* needed for irc module to display the general server password */
void hydra_report_pass_found(int port, char *ip, char *svc, FILE * fp) {
/*
  strcpy(ipaddr_str, hydra_address2string(ip));
  if (colored_output)
    fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   password: \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_password());
  else
    fprintf(fp, "[%d][%s] host: %s   password: %s\n", port, svc, ipaddr_str, hydra_get_next_password());
  if (stdout != fp)
    printf("[%d][%s] host: %s   password: %s\n", port, svc, ipaddr_str, hydra_get_next_password());
  fflush(fp);
*/
}

void hydra_report_found_host(int port, char *ip, char *svc, FILE * fp) {
/*  char *keyw = "password";

  strcpy(ipaddr_str, hydra_address2string(ip));
  if (!strcmp(svc, "smtp-enum"))
    keyw = "domain";
  if (!strcmp(svc, "rsh") || !strcmp(svc, "oracle-sid"))
    if (colored_output)
      fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   login: \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_login());
    else
      fprintf(fp, "[%d][%s] host: %s   login: %s\n", port, svc, ipaddr_str, hydra_get_next_login());
  else if (!strcmp(svc, "snmp3"))
    if (colored_output)
      fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   login: \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_password());
    else
      fprintf(fp, "[%d][%s] host: %s   login: %s\n", port, svc, ipaddr_str, hydra_get_next_password());
  else if (!strcmp(svc, "cisco-enable") || !strcmp(svc, "cisco"))
    if (colored_output)
      fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   password: \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_password());
    else
      fprintf(fp, "[%d][%s] host: %s   password: %s\n", port, svc, ipaddr_str, hydra_get_next_password());
  else if (colored_output)
    fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   login: \e[32m%s\e[0m   %s: \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_login(), keyw,
            hydra_get_next_password());
  else
    fprintf(fp, "[%d][%s] host: %s   login: %s   %s: %s\n", port, svc, ipaddr_str, hydra_get_next_login(), keyw, hydra_get_next_password());
  if (stdout != fp) {
    if (!strcmp(svc, "rsh") || !strcmp(svc, "oracle-sid"))
      printf("[%d][%s] host: %s   login: %s\n", port, svc, ipaddr_str, hydra_get_next_login());
    else if (!strcmp(svc, "snmp3"))
      printf("[%d][%s] host: %s   login: %s\n", port, svc, ipaddr_str, hydra_get_next_password());
    else if (!strcmp(svc, "cisco-enable") || !strcmp(svc, "cisco"))
      printf("[%d][%s] host: %s   password: %s\n", port, svc, ipaddr_str, hydra_get_next_password());
    else
      printf("[%d][%s] host: %s   login: %s   %s: %s\n", port, svc, ipaddr_str, hydra_get_next_login(), keyw, hydra_get_next_password());
  }
  fflush(fp);
  fflush(stdout);
*/
}

void hydra_report_found_host_msg(int port, char *ip, char *svc, FILE * fp, char *msg) {
/*
  strcpy(ipaddr_str, hydra_address2string(ip));
  if (colored_output)
    fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   login: \e[32m%s\e[0m   password: \e[32m%s\e[0m  [%s]\n", port, svc, ipaddr_str, hydra_get_next_login(),
            hydra_get_next_password(), msg);
  else
    fprintf(fp, "[%d][%s] host: %s   login: %s   password: %s  [%s]\n", port, svc, ipaddr_str, hydra_get_next_login(), hydra_get_next_password(), msg);
  if (stdout != fp)
    printf("[%d][%s] host: %s   login: %s   password: %s\n", port, svc, ipaddr_str, hydra_get_next_login(), hydra_get_next_password());
  fflush(fp);
*/
}

int hydra_connect_to_ssl(int socket) {
#ifdef LIBOPENSSL
  return (internal__hydra_connect_to_ssl(socket));
#else
  return -1;
#endif
}

int hydra_connect_ssl(char *host, int port) {
  if (__first_connect != 0)
    __first_connect = 0;
  else
    sleep(conwait);
#ifdef LIBOPENSSL
  return (internal__hydra_connect_ssl(host, port, SOCK_STREAM, 6));
#else
  return (internal__hydra_connect(host, port, SOCK_STREAM, 6));
#endif
}

int hydra_connect_tcp(char *host, int port) {
  if (__first_connect != 0)
    __first_connect = 0;
  else
    sleep(conwait);
  return (internal__hydra_connect(host, port, SOCK_STREAM, 6));
}

int hydra_connect_udp(char *host, int port) {
  if (__first_connect != 0)
    __first_connect = 0;
  else
    sleep(conwait);
  return (internal__hydra_connect(host, port, SOCK_DGRAM, 17));
}

int hydra_disconnect(int socket) {
#ifdef LIBOPENSSL
  if (use_ssl && SSL_get_fd(ssl) == socket) {
    /* SSL_shutdown(ssl); ...skip this--it slows things down */
    SSL_set_bio(ssl, NULL, NULL);
    SSL_clear(ssl);
    use_ssl = 0;
  }
#endif
  close(socket);
  if (debug)
    printf("DEBUG_DISCONNECT\n");
  return -1;
}

int hydra_data_ready_writing_timed(int socket, long sec, long usec) {
  fd_set fds;

  FD_ZERO(&fds);
  FD_SET(socket, &fds);
  return (my_select(socket + 1, &fds, NULL, NULL, sec, usec));
}

int hydra_data_ready_writing(int socket) {
  return (hydra_data_ready_writing_timed(socket, 30, 0));
}

int hydra_data_ready_timed(int socket, long sec, long usec) {
  fd_set fds;

  FD_ZERO(&fds);
  FD_SET(socket, &fds);
  return (my_select(socket + 1, &fds, NULL, NULL, sec, usec));
}

int hydra_data_ready(int socket) {
  return (hydra_data_ready_timed(socket, 0, 100));
}

int hydra_recv(int socket, char *buf, int length) {
  int ret;
  char text[64];

  ret = internal__hydra_recv(socket, buf, length);
  if (debug) {
    sprintf(text, "[DEBUG] RECV [pid:%d]", getpid());
    hydra_dump_data(buf, ret, text);
    //hydra_report_debug(stderr, "DEBUG_RECV_BEGIN|%s|END [pid:%d ret:%d]", buf, getpid(), ret);
  }
  return ret;
}

int hydra_recv_nb(int socket, char *buf, int length) {
  int ret = -1;
  char text[64];

  if (hydra_data_ready_timed(socket, (long) waittime, 0) > 0) {
    if ((ret = internal__hydra_recv(socket, buf, length)) <= 0) {
      buf[0] = 0;
      if (debug) {
        sprintf(text, "[DEBUG] RECV [pid:%d]", getpid());
        hydra_dump_data(buf, ret, text);
      }
      return ret;
    }
    if (debug) {
      sprintf(text, "[DEBUG] RECV [pid:%d]", getpid());
      hydra_dump_data(buf, ret, text);
      //hydra_report_debug(stderr, "DEBUG_RECV_BEGIN|%s|END [pid:%d ret:%d]", buf, getpid(), ret);
    }
  }
  return ret;
}

char *hydra_receive_line(int socket) {
  char buf[1024], *buff, *buff2, text[64];
  int i, j = 1, k, got = 0;

  if ((buff = malloc(sizeof(buf))) == NULL) {
    fprintf(stderr, "[ERROR] could not malloc\n");
    return NULL;
  }
  memset(buff, 0, sizeof(buf));
  if (debug)
    printf("[DEBUG] hydra_receive_line: waittime: %d, conwait: %d, socket: %d, pid: %d\n", waittime, conwait, socket, getpid());

  if ((i = hydra_data_ready_timed(socket, (long) waittime, 0)) > 0) {
    if ((got = internal__hydra_recv(socket, buff, sizeof(buf) - 1)) < 0) {
      free(buff);
      return NULL;
    }
  } else {
    if (debug)
      printf("[DEBUG] hydra_data_ready_timed: %d, waittime: %d, conwait: %d, socket: %d\n", i, waittime, conwait, socket);
    i = 0;
  }

  if (got < 0) {
    if (debug) {
      sprintf(text, "[DEBUG] RECV [pid:%d]", getpid());
      hydra_dump_data("", -1, text);
      //hydra_report_debug(stderr, "DEBUG_RECV_BEGIN||END [pid:%d %d]", getpid(), i);
      perror("recv");
    }
    free(buff);
    return NULL;
  } else {
    if (got > 0) {
      for (k = 0; k < got; k++)
        if (buff[k] == 0)
          buff[k] = 32;
      buff[got] = 0;
      usleep(100);
    }
  }

  while (hydra_data_ready(socket) > 0 && j > 0) {
    j = internal__hydra_recv(socket, buf, sizeof(buf) - 1);
    if (j > 0) {
      for (k = 0; k < j; k++)
        if (buf[k] == 0)
          buf[k] = 32;
      buf[j] = 0;
      if ((buff2 = realloc(buff, got + j + 1)) == NULL) {
        free(buff);
        return NULL;
      } else
        buff = buff2;
      memcpy(buff + got, &buf, j + 1);
      got += j;
      buff[got] = 0;
    }
    usleep(100);
  }

  if (debug) {
    sprintf(text, "[DEBUG] RECV [pid:%d]", getpid());
    hydra_dump_data(buff, got, text);
    //hydra_report_debug(stderr, "DEBUG_RECV_BEGIN [pid:%d len:%d]|%s|END", getpid(), got, buff);
  }
  if (got == 0) {
    free(buff);
    return NULL;
  }
  return buff;
}

int hydra_send(int socket, char *buf, int size, int options) {
  char text[64];

  if (debug) {
    sprintf(text, "[DEBUG] SEND [pid:%d]", getpid());
    hydra_dump_data(buf, size, text);

/*    int k;
    char *debugbuf = malloc(size + 1);

    if (debugbuf != NULL) {
      for (k = 0; k < size; k++)
        if (buf[k] == 0)
          debugbuf[k] = 32;
        else
          debugbuf[k] = buf[k];
      debugbuf[size] = 0;
      hydra_report_debug(stderr, "DEBUG_SEND_BEGIN|%s|END [pid:%d]", debugbuf, getpid());
      free(debugbuf);
    }*/
  }

/*    if (hydra_data_ready_writing(socket)) < 1) return -1; XXX maybe needed in the future */
  return (internal__hydra_send(socket, buf, size, options));
}

int make_to_lower(char *buf) {
  if (buf == NULL)
    return 1;
  while (buf[0] != 0) {
    buf[0] = tolower((int) buf[0]);
    buf++;
  }
  return 1;
}

char *hydra_strrep(char *string, char *oldpiece, char *newpiece) {
  int str_index, newstr_index, oldpiece_index, end, new_len, old_len, cpy_len;
  char *c, oldstring[1024];
  static char newstring[1024];

  if (string == NULL || oldpiece == NULL || newpiece == NULL || strlen(string) >= sizeof(oldstring) - 1
      || (strlen(string) + strlen(newpiece) - strlen(oldpiece) >= sizeof(newstring) - 1 && strlen(string) > strlen(oldpiece)))
    return NULL;

  strcpy(newstring, string);
  strcpy(oldstring, string);

  // while ((c = (char *) strstr(oldstring, oldpiece)) != NULL) {
  c = (char *) strstr(oldstring, oldpiece);
  new_len = strlen(newpiece);
  old_len = strlen(oldpiece);
  end = strlen(oldstring) - old_len;
  oldpiece_index = c - oldstring;
  newstr_index = 0;
  str_index = 0;
  while (c != NULL && str_index <= end) {
    /* Copy characters from the left of matched pattern occurence */
    cpy_len = oldpiece_index - str_index;
    strncpy(newstring + newstr_index, oldstring + str_index, cpy_len);
    newstr_index += cpy_len;
    str_index += cpy_len;

    /* Copy replacement characters instead of matched pattern */
    strcpy(newstring + newstr_index, newpiece);
    newstr_index += new_len;
    str_index += old_len;
    /* Check for another pattern match */
    if ((c = (char *) strstr(oldstring + str_index, oldpiece)) != NULL)
      oldpiece_index = c - oldstring;
  }
  /* Copy remaining characters from the right of last matched pattern */
  strcpy(newstring + newstr_index, oldstring + str_index);
  strcpy(oldstring, newstring);
//  }
  return newstring;
}

unsigned char hydra_conv64(unsigned char in) {
  if (in < 26)
    return (in + 'A');
  else if (in >= 26 && in < 52)
    return (in + 'a' - 26);
  else if (in >= 52 && in < 62)
    return (in + '0' - 52);
  else if (in == 62)
    return '+';
  else if (in == 63)
    return '/';
  else {
    fprintf(stderr, "[ERROR] too high for base64: %d\n", in);
    return 0;
  }
}

void hydra_tobase64(unsigned char *buf, int buflen, int bufsize) {
  unsigned char small[3] = { 0, 0, 0 };
  unsigned char big[5];
  unsigned char *ptr = buf;
  int i = bufsize;
  unsigned int len = 0;
  unsigned char bof[i];

  if (buf == NULL || strlen((char *) buf) == 0)
    return;
  bof[0] = 0;
  memset(big, 0, sizeof(big));
  memset(bof, 0, bufsize);

  for (i = 0; i < buflen / 3; i++) {
    memset(big, 0, sizeof(big));
    big[0] = hydra_conv64(*ptr >> 2);
    big[1] = hydra_conv64(((*ptr & 3) << 4) + (*(ptr + 1) >> 4));
    big[2] = hydra_conv64(((*(ptr + 1) & 15) << 2) + (*(ptr + 2) >> 6));
    big[3] = hydra_conv64(*(ptr + 2) & 63);
    len += strlen((char *) big);
    if (len > bufsize) {
      buf[0] = 0;
      return;
    }
    strcat((char *) bof, (char *) big);
    ptr += 3;
  }

  if (*ptr != 0) {
    small[0] = *ptr;
    if (*(ptr + 1) != 0)
      small[1] = *(ptr + 1);
    else
      small[1] = 0;
    ptr = small;
    big[0] = hydra_conv64(*ptr >> 2);
    big[1] = hydra_conv64(((*ptr & 3) << 4) + (*(ptr + 1) >> 4));
    big[2] = hydra_conv64(((*(ptr + 1) & 15) << 2) + (*(ptr + 2) >> 6));
    big[3] = hydra_conv64(*(ptr + 2) & 63);
    if (small[1] == 0)
      big[2] = '=';
    big[3] = '=';
    strcat((char *) bof, (char *) big);
  }

  strcpy((char *) buf, (char *) bof);   /* can not overflow */
}

void hydra_dump_asciihex(unsigned char *string, int length) {
  unsigned char *p = (unsigned char *) string;
  unsigned char lastrow_data[16];
  int rows = length / HYDRA_DUMP_ROWS;
  int lastrow = length % HYDRA_DUMP_ROWS;
  int i, j;

  for (i = 0; i < rows; i++) {
    printf("%04hx:  ", i * 16);
    for (j = 0; j < HYDRA_DUMP_ROWS; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1)
        printf(" ");
    }
    printf("   [ ");
    for (j = 0; j < HYDRA_DUMP_ROWS; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    printf(" ]\n");
  }
  if (lastrow > 0) {
    memset(lastrow_data, 0, sizeof(lastrow_data));
    memcpy(lastrow_data, p + length - lastrow, lastrow);
    printf("%04hx:  ", i * 16);
    for (j = 0; j < lastrow; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1)
        printf(" ");
    }
    while (j < HYDRA_DUMP_ROWS) {
      printf("  ");
      if (j % 2 == 1)
        printf(" ");
      j++;
    }
    printf("   [ ");
    for (j = 0; j < lastrow; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    while (j < HYDRA_DUMP_ROWS) {
      printf(" ");
      j++;
    }
    printf(" ]\n");
  }
}

char *hydra_address2string(char *address) {
  struct sockaddr_in target;
  struct sockaddr_in6 target6;

  if (address[0] == 4) {
    memcpy(&target.sin_addr.s_addr, &address[1], 4);
    return inet_ntoa((struct in_addr) target.sin_addr);
  } else
#ifdef AF_INET6
  if (address[0] == 16) {
    memcpy(&target6.sin6_addr, &address[1], 16);
    inet_ntop(AF_INET6, &target6.sin6_addr, ipstring, sizeof(ipstring));
    return ipstring;
  } else
#endif
  {
    if (debug)
      fprintf(stderr, "[ERROR] unknown address string size!\n");
    return NULL;
  }
  return NULL;                  // not reached
}

void hydra_set_srcport(int port) {
  src_port = port;
}

#ifdef HAVE_PCRE
int hydra_string_match(char *str, const char *regex) {
  pcre *re = NULL;
  int offset_error = 0;
  const char *error = NULL;
  int rc = 0;

  re = pcre_compile(regex, PCRE_CASELESS | PCRE_DOTALL, &error, &offset_error, NULL);
  if (re == NULL) {
    fprintf(stderr, "[ERROR] PCRE compilation failed at offset %d: %s\n", offset_error, error);
    return 0;
  }

  rc = pcre_exec(re, NULL, str, strlen(str), 0, 0, NULL, 0);
  if (rc >= 0) {
    return 1;
  }
  return 0;
}
#endif

/*
 * str_replace.c implements a str_replace PHP like function
 * Copyright (C) 2009  chantra <chantra__A__debuntu__D__org>
 *
 * Create a new string with [substr] being replaced ONCE by [replacement] in [string]
 * Returns the new string, or NULL if out of memory.
 * The caller is responsible for freeing this new string.
 *
 */
char *hydra_string_replace(const char *string, const char *substr, const char *replacement) {
  char *tok = NULL;
  char *newstr = NULL;

  tok = strstr(string, substr);
  if (tok == NULL)
    return strdup(string);
  newstr = malloc(strlen(string) - strlen(substr) + strlen(replacement) + 1);
  if (newstr == NULL)
    return NULL;
  memcpy(newstr, string, tok - string);
  memcpy(newstr + (tok - string), replacement, strlen(replacement));
  memcpy(newstr + (tok - string) + strlen(replacement), tok + strlen(substr), strlen(string) - strlen(substr) - (tok - string));
  memset(newstr + strlen(string) - strlen(substr) + strlen(replacement), 0, 1);
  return newstr;
}

char *hydra_strcasestr(const char *haystack, const char *needle) {
  if (needle == NULL || *needle == 0)
    return NULL;

  for (; *haystack; ++haystack) {
    if (toupper((int) *haystack) == toupper((int) *needle)) {
      const char *h, *n;

      for (h = haystack, n = needle; *h && *n; ++h, ++n) {
        if (toupper((int) *h) != toupper((int) *n)) {
          break;
        }
      }
      if (!*n) {                /* matched all of 'needle' to null termination */
        return (char *) haystack;       /* return the start of the match */
      }
    }
  }
  return NULL;
}

void hydra_dump_data(unsigned char *buf, int len, char *text) {
  unsigned char *p = (unsigned char *) buf;
  unsigned char lastrow_data[16];
  int rows = len / 16;
  int lastrow = len % 16;
  int i, j;

  if (text != NULL && text[0] != 0)
    printf("%s (%d bytes):\n", text, len);

  if (buf == NULL || len < 1)
    return;

  for (i = 0; i < rows; i++) {
    printf("%04hx:  ", i * 16);
    for (j = 0; j < 16; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1)
        printf(" ");
    }
    printf("   [ ");
    for (j = 0; j < 16; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    printf(" ]\n");
  }
  if (lastrow > 0) {
    memset(lastrow_data, 0, sizeof(lastrow_data));
    memcpy(lastrow_data, p + len - lastrow, lastrow);
    printf("%04hx:  ", i * 16);
    for (j = 0; j < lastrow; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1)
        printf(" ");
    }
    while (j < 16) {
      printf("  ");
      if (j % 2 == 1)
        printf(" ");
      j++;
    }
    printf("   [ ");
    for (j = 0; j < lastrow; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    while (j < 16) {
      printf(" ");
      j++;
    }
    printf(" ]\n");
  }
}

int hydra_memsearch(char *haystack, int hlen, char *needle, int nlen) {
  int i;

  for (i = 0; i <= hlen - nlen; i++)
    if (memcmp(haystack + i, needle, nlen) == 0)
      return i;
  return -1;
}
