#include "hydra-mod.h"
#include <arpa/inet.h>
#ifdef LIBOPENSSL
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#endif
#ifdef HAVE_PCRE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#define MAX_CONNECT_RETRY 1
#define WAIT_BETWEEN_CONNECT_RETRY 3
#define HYDRA_DUMP_ROWS 16

/* rfc 1928 SOCKS proxy */
#define SOCKS_V5 5
#define SOCKS_V4 4
#define SOCKS_NOAUTH 0

/* http://tools.ietf.org/html/rfc1929 */
#define SOCKS_PASSAUTH 2
#define SOCKS_NOMETHOD 0xff
#define SOCKS_CONNECT 1
#define SOCKS_IPV4 1
#define SOCKS_DOMAIN 3
#define SOCKS_IPV6 4

extern int32_t conwait;
char quiet;
int32_t do_retry = 1;
int32_t module_auth_type = -1;
int32_t intern_socket, extern_socket;
char pair[260];
char *HYDRA_EXIT = "\x00\xff\x00\xff\x00";
char *HYDRA_EMPTY = "\x00\x00\x00\x00";
char *fe80 = "\xfe\x80\x00";
int32_t fail = 0;
int32_t alarm_went_off = 0;
int32_t use_ssl = 0;
char ipaddr_str[64];
int32_t src_port = 0;
int32_t __fck = 0;
int32_t ssl_first = 1;
int32_t __first_connect = 1;
char ipstring[64];
uint32_t colored_output = 1;
char quiet = 0;
int32_t old_ssl = 0;

#ifdef LIBOPENSSL
SSL *ssl = NULL;
SSL_CTX *sslContext = NULL;
RSA *rsa = NULL;
#endif

/* prototype */
int32_t my_select(int32_t fd, fd_set *fdread, fd_set *fdwrite, fd_set *fdex, long sec, long usec);

/* ----------------- alarming functions ---------------- */
void alarming() {
  fail++;
  alarm_went_off++;

  /* uh, I think it's not good for performance if we try to reconnect to a
   * timeout system! if (fail > MAX_CONNECT_RETRY) {
   */
  // fprintf(stderr, "Process %d: Can not connect [timeout], process exiting\n",
  // (int32_t) getpid());
  if (debug)
    printf("DEBUG_CONNECT_TIMEOUT\n");
  hydra_child_exit(1);

  /*
   *   } else {
   *     if (verbose) fprintf(stderr, "Process %d: Can not connect [timeout],
   * retrying (%d of %d retries)\n", (int32_t)getpid(), fail,
   * MAX_CONNECT_RETRY);
   *   }
   */
}

void interrupt() {
  if (debug)
    printf("DEBUG_INTERRUPTED\n");
}

/* ----------------- internal functions ----------------- */

int32_t internal__hydra_connect(char *host, int32_t port, int32_t type, int32_t protocol) {
  int32_t s, ret = -1, ipv6 = 0, reset_selected = 0;

#ifdef AF_INET6
  struct sockaddr_in6 target6;
  struct sockaddr_in6 sin6;
#endif
  struct sockaddr_in target;
  struct sockaddr_in sin;
  char *buf, *tmpptr = NULL;
  int32_t err = 0;

  if (proxy_count > 0 && use_proxy > 0 && selected_proxy == -1) {
    reset_selected = 1;
    selected_proxy = random() % proxy_count;
  }

  memset(&target, 0, sizeof(target));
  memset(&sin, 0, sizeof(sin));
#ifdef AF_INET6
  memset(&target6, 0, sizeof(target6));
  memset(&sin6, 0, sizeof(sin6));
  if ((host[0] == 16 && proxy_string_ip[selected_proxy][0] != 4) || proxy_string_ip[selected_proxy][0] == 16)
    ipv6 = 1;
#endif

#ifdef AF_INET6
  if (ipv6)
    s = socket(AF_INET6, type, protocol);
  else
#endif
    s = socket(PF_INET, type, protocol);
  if (s >= 0) {
    if (src_port != 0) {
      int32_t bind_ok = 0;

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

      // we will try to find a free port down to 512
      while (!bind_ok && src_port >= 512) {
#ifdef AF_INET6
        if (ipv6)
          ret = bind(s, (struct sockaddr *)&sin6, sizeof(sin6));
        else
#endif
          ret = bind(s, (struct sockaddr *)&sin, sizeof(sin));

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
              if (reset_selected)
                selected_proxy = -1;
              return -1;
            }
          }
        } else
          bind_ok = 1;
      }
    }
    if (use_proxy > 0 && proxy_count > 0) {
      if (proxy_string_ip[selected_proxy][0] == 4) {
        memcpy(&target.sin_addr.s_addr, &proxy_string_ip[selected_proxy][1], 4);
        target.sin_family = AF_INET;
        target.sin_port = htons(proxy_string_port[selected_proxy]);
      }
#ifdef AF_INET6
      if (proxy_string_ip[selected_proxy][0] == 16) {
        memcpy(&target6.sin6_addr, &proxy_string_ip[selected_proxy][1], 16);
        target6.sin6_family = AF_INET6;
        target6.sin6_port = htons(proxy_string_port[selected_proxy]);
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
        ret = connect(s, (struct sockaddr *)&target6, sizeof(target6));
      else
#endif
        ret = connect(s, (struct sockaddr *)&target, sizeof(target));
      alarm(0);
      if (ret < 0 && alarm_went_off == 0) {
        fail++;
        if (verbose) {
          if (do_retry && fail <= MAX_CONNECT_RETRY)
            fprintf(stderr,
                    "Process %d: Can not connect [unreachable], retrying (%d "
                    "of %d retries)\n",
                    (int32_t)getpid(), fail, MAX_CONNECT_RETRY);
          else
            fprintf(stderr, "Process %d: Can not connect [unreachable]\n", (int32_t)getpid());
        }
      }
    } while (ret < 0 && fail <= MAX_CONNECT_RETRY && do_retry);
    if (ret < 0 && fail > MAX_CONNECT_RETRY) {
      if (debug)
        printf("DEBUG_CONNECT_UNREACHABLE\n");

      /* we wont quit here, thats up to the module to decide what to do
       *              fprintf(stderr, "Process %d: Can not connect
       * [unreachable], process exiting\n", (int32_t)getpid());
       *              hydra_child_exit(1);
       */
      extern_socket = -1;
      close(s);
      ret = -1;
      if (reset_selected)
        selected_proxy = -1;
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
        if (reset_selected)
          selected_proxy = -1;
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

      if (hydra_strcasestr(proxy_string_type[selected_proxy], "connect") || hydra_strcasestr(proxy_string_type[selected_proxy], "http")) {
        if (proxy_authentication[selected_proxy] == NULL)
          if (host[0] == 16)
            snprintf(buf, 4096, "CONNECT [%s]:%d HTTP/1.0\r\n\r\n", hydra_address2string(host), port);
          else
            snprintf(buf, 4096, "CONNECT %s:%d HTTP/1.0\r\n\r\n", hydra_address2string(host), port);
        else if (host[0] == 16)
          snprintf(buf, 4096,
                   "CONNECT [%s]:%d HTTP/1.0\r\nProxy-Authorization: Basic "
                   "%s\r\n\r\n",
                   hydra_address2string(host), port, proxy_authentication[selected_proxy]);
        else
          snprintf(buf, 4096, "CONNECT %s:%d HTTP/1.0\r\nProxy-Authorization: Basic %s\r\n\r\n", hydra_address2string(host), port, proxy_authentication[selected_proxy]);

        send(s, buf, strlen(buf), 0);
        if (debug) {
          char *ptr = strchr(buf, '\r');
          if (ptr != NULL)
            *ptr = 0;
          printf("DEBUG_CONNECT_PROXY_SENT: %s\n", buf);
        }
        recv(s, buf, 4096, 0);
        if (strncmp("HTTP/", buf, 5) == 0 && (tmpptr = strchr(buf, ' ')) != NULL && *++tmpptr == '2') {
          if (debug)
            printf("DEBUG_CONNECT_PROXY_OK\n");
        } else {
          if (debug && tmpptr)
            printf("DEBUG_CONNECT_PROXY_FAILED (Code: %c%c%c)\n", *tmpptr, *(tmpptr + 1), *(tmpptr + 2));
          if (verbose && tmpptr)
            fprintf(stderr, "[ERROR] CONNECT call to proxy failed with code %c%c%c\n", *tmpptr, *(tmpptr + 1), *(tmpptr + 2));
          err = 1;
        }
        //        free(buf);
      } else {
        if (hydra_strcasestr(proxy_string_type[selected_proxy], "socks5")) {
          //          char buf[1024];
          size_t cnt, wlen;

          /* socks v5 support */
          buf[0] = SOCKS_V5;
          buf[1] = 1;
          if (proxy_authentication[selected_proxy] == NULL)
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
            if ((unsigned char)buf[1] == SOCKS_NOMETHOD) {
              hydra_report(stderr, "[ERROR] SOCKS5 proxy authentication method "
                                   "negotiation failed\n");
              err = 1;
            }
            /* SOCKS_DOMAIN not supported here, do we need it ? */
            if (err != 1) {
              /* send user/pass */
              if (proxy_authentication[selected_proxy] != NULL) {
                // format was checked previously
                char *login = strtok(proxy_authentication[selected_proxy], ":");
                char *pass = strtok(NULL, ":");

                snprintf(buf, 4096, "\x01%c%s%c%s", (char)strlen(login), login, (char)strlen(pass), pass);

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
          if (hydra_strcasestr(proxy_string_type[selected_proxy], "socks4")) {
            if (ipv6) {
              hydra_report(stderr, "[ERROR] SOCKS4 proxy does not support IPv6\n");
              err = 1;
            } else {
              //              char buf[1024];
              size_t cnt, wlen;

              /* socks v4 support */
              buf[0] = SOCKS_V4;
              buf[1] = SOCKS_CONNECT; /* connect */
              memcpy(buf + 2, &target.sin_port, sizeof target.sin_port);
              memcpy(buf + 4, &target.sin_addr, sizeof target.sin_addr);
              buf[8] = 0; /* empty username */
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
            hydra_report(stderr,
                         "[ERROR] Unknown proxy type: %s, valid type are "
                         "\"connect\", \"socks4\" or \"socks5\"\n",
                         proxy_string_type[selected_proxy]);
            err = 1;
          }
        }
      }
      free(buf);
    }
    if (err) {
      close(s);
      extern_socket = -1;
      if (reset_selected)
        selected_proxy = -1;
      ret = -1;
      return ret;
    }
    fail = 0;
    if (reset_selected)
      selected_proxy = -1;
    return ret;
  }
  if (reset_selected)
    selected_proxy = -1;
  return ret;
}

#if defined(LIBOPENSSL) && !defined(LIBRESSL_VERSION_NUMBER)
RSA *ssl_temp_rsa_cb(SSL *ssl, int32_t export, int32_t keylength) {
  int32_t nok = 0;
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
  BIGNUM *n;
  if ((n = BN_new()) == NULL)
    nok = 1;
  RSA_get0_key(rsa, (const struct bignum_st **)&n, NULL, NULL);
  BN_zero(n);
#else
  if (rsa->n == 0)
    nok = 1;
#endif
  if (nok == 0 && RSA_size(rsa) != (keylength / 8)) { // n is not zero
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    BN_free(n);
#endif
    RSA_free(rsa);
    rsa = NULL;
  }
  if (nok != 0) { // n is zero
#if defined(NO_RSA_LEGACY) || OPENSSL_VERSION_NUMBER >= 0x10100000L
    RSA *rsa = RSA_new();
    BIGNUM *f4 = BN_new();
    BN_set_word(f4, RSA_F4);
    RSA_generate_key_ex(rsa, keylength, f4, NULL);
#else
    rsa = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
#endif
  }
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
  BN_free(n);
#endif
  return rsa;
}
#endif

#if defined(LIBOPENSSL)
int32_t internal__hydra_connect_to_ssl(int32_t socket, char *hostname) {
  int32_t err;

  if (ssl_first) {
    SSL_load_error_strings();
    //    SSL_add_ssl_algoritms();
    SSL_library_init(); // ?
    ssl_first = 0;
  }

  if (sslContext == NULL) {
    /* context: ssl2 + ssl3 is allowed, whatever the server demands */
    if (old_ssl) {
      if ((sslContext = SSL_CTX_new(SSLv23_client_method())) == NULL) {
        if (verbose) {
          err = ERR_get_error();
          fprintf(stderr, "[ERROR] SSL allocating context: %s\n", ERR_error_string(err, NULL));
        }
        return -1;
      }
    } else {
#ifndef TLSv1_2_client_method
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define TLSv1_2_client_method TLSv1_2_client_method
#else
#define TLSv1_2_client_method TLS_client_method
#endif
#endif
      if ((sslContext = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {
        if (verbose) {
          err = ERR_get_error();
          fprintf(stderr, "[ERROR] SSL allocating context: %s\n", ERR_error_string(err, NULL));
        }
        return -1;
      }
    }
    /* set the compatbility mode */
    SSL_CTX_set_options(sslContext, SSL_OP_ALL);
    //    SSL_CTX_set_options(sslContext, SSL_OP_NO_SSLv2);
    //    SSL_CTX_set_options(sslContext, SSL_OP_NO_TLSv1);

    /* we set the default verifiers and don't care for the results */
    (void)SSL_CTX_set_default_verify_paths(sslContext);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);
#endif
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

  /* add SNI */
  SSL_set_tlsext_host_name(ssl, hostname);

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

int32_t internal__hydra_connect_ssl(char *host, int32_t port, int32_t type, int32_t protocol, char *hostname) {
  int32_t socket;

  if ((socket = internal__hydra_connect(host, port, type, protocol)) < 0)
    return -1;

  return internal__hydra_connect_to_ssl(socket, hostname);
}
#endif

int32_t internal__hydra_recv(int32_t socket, char *buf, uint32_t length) {
#ifdef LIBOPENSSL
  if (use_ssl) {
    return SSL_read(ssl, buf, length);
  } else
#endif
    return recv(socket, buf, length, 0);
}

int32_t internal__hydra_send(int32_t socket, char *buf, uint32_t size, int32_t options) {
#ifdef LIBOPENSSL
  if (use_ssl) {
    return SSL_write(ssl, buf, size);
  } else
#endif
    return send(socket, buf, size, options);
}

/* ------------------ public functions ------------------ */

void hydra_child_exit(int32_t code) {
  char buf[2];

  if (debug)
    printf("[DEBUG] pid %d called child_exit with code %d\n", getpid(), code);
  if (code == 0) /* normal quitting */
    __fck = write(intern_socket, "Q", 1);
  else if (code == 1) /* no connect possible */
    __fck = write(intern_socket, "C", 1);
  else if (code == 2) /* application protocol error or service shutdown */
    __fck = write(intern_socket, "E", 1);
  else if (code == 3) /* application protocol error or service shutdown */
    __fck = write(intern_socket, "D", 1);
  // code 4 means exit without telling mommy about it - a bad idea. mommy should
  // know
  else if (code == -1 || code > 4) {
    fprintf(stderr, "[TOTAL FUCKUP] a module should not use "
                    "hydra_child_exit(-1) ! Fix it in the source please ...\n");
    __fck = write(intern_socket, "E", 1);
  }
  do {
    usleepn(10);
  } while (read(intern_socket, buf, 1) <= 0);
  close(intern_socket);
  //  sleep(2); // be sure that mommy receives our message
  exit(0); // might be killed before reaching this
}

void hydra_register_socket(int32_t s) { intern_socket = s; }

char *hydra_get_next_pair() {
  if (pair[0] == 0) {
    pair[sizeof(pair) - 1] = 0;
    __fck = read(intern_socket, pair, sizeof(pair) - 1);
    // if (debug) hydra_dump_data(pair, __fck, "CHILD READ PAIR");
    if (pair[0] == 0 || __fck <= 0)
      return HYDRA_EMPTY;
    if (__fck >=  sizeof(HYDRA_EXIT) && memcmp(&HYDRA_EXIT, &pair, sizeof(HYDRA_EXIT)) == 0)
      return HYDRA_EXIT;
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
void hydra_report_debug(FILE *st, char *format, ...) {
  va_list ap;
  char buf[8200];
  char bufOut[33000];
  char temp[6];
  unsigned char cTemp;
  int32_t i = 0, len;

  if (format == NULL) {
    fprintf(stderr, "[ERROR] no msg passed.\n");
  } else {
    va_start(ap, format);
    memset(bufOut, 0, sizeof(bufOut));
    memset(buf, 0, sizeof(buf));
    len = vsnprintf(buf, sizeof(buf), format, ap);

    // Convert any chars less than 32d or greater than 126d to hex
    for (i = 0; i < len; i++) {
      memset(temp, 0, 6);
      cTemp = (unsigned char)buf[i];
      if (cTemp < 32 || cTemp > 126) {
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

void hydra_report_found(int32_t port, char *svc, FILE *fp) {
  /*
    if (!strcmp(svc, "rsh"))
      if (colored_output)
        fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] login: \e[32m%s\e[0m\n",
    port, svc, hydra_get_next_login()); else fprintf(fp, "[%d][%s] login: %s\n",
    port, svc, hydra_get_next_login()); else if (colored_output) fprintf(fp,
    "[\e[31m%d\e[0m][\e[31m%s\e[0m] login: \e[32m%s\e[0m   password:
    \e[32m%s\e[0m\n", port, svc, hydra_get_next_login(),
    hydra_get_next_password()); else fprintf(fp, "[%d][%s] login: %s   password:
    %s\n", port, svc, hydra_get_next_login(), hydra_get_next_password());

    if (stdout != fp) {
      if (!strcmp(svc, "rsh"))
        printf("[%d][%s] login: %s\n", port, svc, hydra_get_next_login());
      else
        printf("[%d][%s] login: %s   password: %s\n", port, svc,
    hydra_get_next_login(), hydra_get_next_password());
    }

    fflush(fp);
  */
}

/* needed for irc module to display the general server password */
void hydra_report_pass_found(int32_t port, char *ip, char *svc, FILE *fp) {
  /*
    strcpy(ipaddr_str, hydra_address2string(ip));
    if (colored_output)
      fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m password:
    \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_password()); else
      fprintf(fp, "[%d][%s] host: %s   password: %s\n", port, svc, ipaddr_str,
    hydra_get_next_password()); if (stdout != fp) printf("[%d][%s] host: %s
    password: %s\n", port, svc, ipaddr_str, hydra_get_next_password());
    fflush(fp);
  */
}

void hydra_report_found_host(int32_t port, char *ip, char *svc, FILE *fp) {
  /*  char *keyw = "password";

    strcpy(ipaddr_str, hydra_address2string(ip));
    if (!strcmp(svc, "smtp-enum"))
      keyw = "domain";
    if (!strcmp(svc, "rsh") || !strcmp(svc, "oracle-sid"))
      if (colored_output)
        fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   login:
    \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_login()); else
        fprintf(fp, "[%d][%s] host: %s   login: %s\n", port, svc, ipaddr_str,
    hydra_get_next_login()); else if (!strcmp(svc, "snmp3")) if (colored_output)
        fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   login:
    \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_password()); else
        fprintf(fp, "[%d][%s] host: %s   login: %s\n", port, svc, ipaddr_str,
    hydra_get_next_password()); else if (!strcmp(svc, "cisco-enable") ||
    !strcmp(svc, "cisco")) if (colored_output) fprintf(fp,
    "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   password:
    \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_password()); else
        fprintf(fp, "[%d][%s] host: %s   password: %s\n", port, svc, ipaddr_str,
    hydra_get_next_password()); else if (colored_output) fprintf(fp,
    "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   login: \e[32m%s\e[0m
    %s: \e[32m%s\e[0m\n", port, svc, ipaddr_str, hydra_get_next_login(), keyw,
              hydra_get_next_password());
    else
      fprintf(fp, "[%d][%s] host: %s   login: %s   %s: %s\n", port, svc,
    ipaddr_str, hydra_get_next_login(), keyw, hydra_get_next_password()); if
    (stdout != fp) { if (!strcmp(svc, "rsh") || !strcmp(svc, "oracle-sid"))
        printf("[%d][%s] host: %s   login: %s\n", port, svc, ipaddr_str,
    hydra_get_next_login()); else if (!strcmp(svc, "snmp3")) printf("[%d][%s]
    host: %s   login: %s\n", port, svc, ipaddr_str, hydra_get_next_password());
      else if (!strcmp(svc, "cisco-enable") || !strcmp(svc, "cisco"))
        printf("[%d][%s] host: %s   password: %s\n", port, svc, ipaddr_str,
    hydra_get_next_password()); else printf("[%d][%s] host: %s   login: %s   %s:
    %s\n", port, svc, ipaddr_str, hydra_get_next_login(), keyw,
    hydra_get_next_password());
    }
    fflush(fp);
    fflush(stdout);
  */
}

void hydra_report_found_host_msg(int32_t port, char *ip, char *svc, FILE *fp, char *msg) {
  /*
    strcpy(ipaddr_str, hydra_address2string(ip));
    if (colored_output)
      fprintf(fp, "[\e[31m%d\e[0m][\e[31m%s\e[0m] host: \e[32m%s\e[0m   login:
    \e[32m%s\e[0m   password: \e[32m%s\e[0m  [%s]\n", port, svc, ipaddr_str,
    hydra_get_next_login(), hydra_get_next_password(), msg); else fprintf(fp,
    "[%d][%s] host: %s   login: %s   password: %s  [%s]\n", port, svc,
    ipaddr_str, hydra_get_next_login(), hydra_get_next_password(), msg); if
    (stdout != fp) printf("[%d][%s] host: %s   login: %s   password: %s\n",
    port, svc, ipaddr_str, hydra_get_next_login(), hydra_get_next_password());
    fflush(fp);
  */
}

int32_t hydra_connect_to_ssl(int32_t socket, char *hostname) {
#ifdef LIBOPENSSL
  return (internal__hydra_connect_to_ssl(socket, hostname));
#else
  fprintf(stderr, "Error: not compiled with SSL\n");
  return -1;
#endif
}

int32_t hydra_connect_ssl(char *host, int32_t port, char *hostname) {
  if (__first_connect != 0)
    __first_connect = 0;
  else
    sleep(conwait);
#ifdef LIBOPENSSL
  return (internal__hydra_connect_ssl(host, port, SOCK_STREAM, 6, hostname));
#else
  fprintf(stderr, "Error: not compiled with SSL\n");
  return -1;
#endif
}

int32_t hydra_connect_tcp(char *host, int32_t port) {
  if (__first_connect != 0)
    __first_connect = 0;
  else
    sleep(conwait);
  return (internal__hydra_connect(host, port, SOCK_STREAM, 6));
}

int32_t hydra_connect_udp(char *host, int32_t port) {
  if (__first_connect != 0)
    __first_connect = 0;
  else
    sleep(conwait);
  return (internal__hydra_connect(host, port, SOCK_DGRAM, 17));
}

int32_t hydra_disconnect(int32_t socket) {
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

int32_t hydra_data_ready_writing_timed(int32_t socket, long sec, long usec) {
  fd_set fds;

  FD_ZERO(&fds);
  FD_SET(socket, &fds);
  return (my_select(socket + 1, &fds, NULL, NULL, sec, usec));
}

int32_t hydra_data_ready_writing(int32_t socket) { return (hydra_data_ready_writing_timed(socket, 30, 0)); }

int32_t hydra_data_ready_timed(int32_t socket, long sec, long usec) {
  fd_set fds;

  FD_ZERO(&fds);
  FD_SET(socket, &fds);
  return (my_select(socket + 1, &fds, NULL, NULL, sec, usec));
}

int32_t hydra_data_ready(int32_t socket) { return (hydra_data_ready_timed(socket, 0, 100)); }

int32_t hydra_recv(int32_t socket, char *buf, uint32_t length) {
  int32_t ret;
  char text[64];

  ret = internal__hydra_recv(socket, buf, length);
  if (debug) {
    sprintf(text, "[DEBUG] RECV [pid:%d]", getpid());
    hydra_dump_data(buf, ret, text);
    // hydra_report_debug(stderr, "DEBUG_RECV_BEGIN|%s|END [pid:%d ret:%d]",
    // buf, getpid(), ret);
  }
  return ret;
}

int32_t hydra_recv_nb(int32_t socket, char *buf, uint32_t length) {
  int32_t ret = -1;
  char text[64];

  if (hydra_data_ready_timed(socket, (long)waittime, 0) > 0) {
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
      // hydra_report_debug(stderr, "DEBUG_RECV_BEGIN|%s|END [pid:%d ret:%d]",
      // buf, getpid(), ret);
    }
  }
  return ret;
}

char *hydra_receive_line(int32_t socket) {
  char buf[1024], *buff, *buff2, pid[64];
  int32_t i, j, k, got = 0;

  if ((buff = malloc(sizeof(buf))) == NULL) {
    fprintf(stderr, "[ERROR] could not malloc\n");
    return NULL;
  }

  memset(buff, 0, sizeof(buf));

  if (debug)
    printf("[DEBUG] hydra_receive_line: waittime: %d, conwait: %d, socket: %d, "
           "pid: %d\n",
           waittime, conwait, socket, getpid());

  if ((i = hydra_data_ready_timed(socket, (long)waittime, 0)) > 0) {
    do {
      j = internal__hydra_recv(socket, buf, sizeof(buf) - 1);
      if (j > 0) {
        for (k = 0; k < j; k++)
          if (buf[k] == 0)
            buf[k] = 32;

        buf[j] = 0;

        if ((buff2 = realloc(buff, got + j + 1)) == NULL) {
          free(buff);
          return NULL;
        }

        buff = buff2;
        memcpy(buff + got, &buf, j + 1);
        got += j;
        buff[got] = 0;
      } else if (j < 0) {
        // some error occured
        got = -1;
      }
    } while (hydra_data_ready(socket) > 0 && j > 0
#ifdef LIBOPENSSL
             || use_ssl && SSL_pending(ssl)
#endif
    );

    if (got > 0) {
      if (debug) {
        sprintf(pid, "[DEBUG] RECV [pid:%d]", getpid());
        hydra_dump_data(buff, got, pid);
        // hydra_report_debug(stderr, "DEBUG_RECV_BEGIN [pid:%d len:%d]|%s|END",
        // getpid(), got, buff);
      }
    } else {
      if (got < 0) {
        if (debug) {
          sprintf(pid, "[DEBUG] RECV [pid:%d]", getpid());
          hydra_dump_data((unsigned char *)"", -1, pid);
          // hydra_report_debug(stderr, "DEBUG_RECV_BEGIN||END [pid:%d %d]",
          // getpid(), i);
          perror("recv");
        }
      }
      free(buff);
      return NULL;
    }

    usleepn(100);
  } else {
    if (debug)
      printf("[DEBUG] hydra_data_ready_timed: %d, waittime: %d, conwait: %d, "
             "socket: %d\n",
             i, waittime, conwait, socket);
  }

  return buff;
}

int32_t hydra_send(int32_t socket, char *buf, uint32_t size, int32_t options) {
  char text[64];

  if (debug) {
    sprintf(text, "[DEBUG] SEND [pid:%d]", getpid());
    hydra_dump_data(buf, size, text);

    /*    int32_t k;
        char *debugbuf = malloc(size + 1);

        if (debugbuf != NULL) {
          for (k = 0; k < size; k++)
            if (buf[k] == 0)
              debugbuf[k] = 32;
            else
              debugbuf[k] = buf[k];
          debugbuf[size] = 0;
          hydra_report_debug(stderr, "DEBUG_SEND_BEGIN|%s|END [pid:%d]",
       debugbuf, getpid()); free(debugbuf);
        }*/
  }

  /*    if (hydra_data_ready_writing(socket)) < 1) return -1; XXX maybe needed
   * in the future */
  return (internal__hydra_send(socket, buf, size, options));
}

int32_t make_to_lower(char *buf) {
  if (buf == NULL)
    return 1;
  while (buf[0] != 0) {
    buf[0] = tolower((int32_t)buf[0]);
    buf++;
  }
  return 1;
}

char *hydra_strrep(char *string, char *oldpiece, char *newpiece) {
  int32_t str_index, newstr_index, oldpiece_index, end, new_len, old_len, cpy_len;
  char *c, oldstring[6096],
      newstring[6096]; // updated due to issue 192 on github.
  static char finalstring[6096];

  if (string == NULL || oldpiece == NULL || newpiece == NULL || strlen(string) >= sizeof(oldstring) - 1 || (strlen(string) + strlen(newpiece) - strlen(oldpiece) >= sizeof(newstring) - 1 && strlen(string) > strlen(oldpiece)))
    return NULL;

  if (strlen(string) > 6000) {
    hydra_report(stderr, "[ERROR] Supplied URL or POST data too large. Max "
                         "limit is 6000 characters.\n");
    exit(-1);
  }

  strcpy(newstring, string);
  strcpy(oldstring, string);

  // while ((c = (char *) strstr(oldstring, oldpiece)) != NULL) {
  c = (char *)strstr(oldstring, oldpiece);
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
    if ((c = (char *)strstr(oldstring + str_index, oldpiece)) != NULL)
      oldpiece_index = c - oldstring;
  }
  /* Copy remaining characters from the right of last matched pattern */
  strcpy(newstring + newstr_index, oldstring + str_index);
  strcpy(oldstring, newstring);
  //  }
  strcpy(finalstring, newstring);
  return finalstring;
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

void hydra_tobase64(unsigned char *buf, uint32_t buflen, uint32_t bufsize) {
  unsigned char small[3] = {0, 0, 0};
  unsigned char big[5];
  unsigned char *ptr = buf;
  uint32_t i = bufsize;
  uint32_t len = 0;
  unsigned char bof[i];

  if (buf == NULL || strlen((char *)buf) == 0 || buflen == 0)
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
    len += strlen((char *)big);
    if (len > bufsize) {
      buf[0] = 0;
      return;
    }
    strcat((char *)bof, (char *)big);
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
    strcat((char *)bof, (char *)big);
  }

  strcpy((char *)buf, (char *)bof); /* can not overflow */
}

void hydra_dump_asciihex(unsigned char *string, int32_t length) {
  unsigned char *p = (unsigned char *)string;
  unsigned char lastrow_data[16];
  int32_t rows = length / HYDRA_DUMP_ROWS;
  int32_t lastrow = length % HYDRA_DUMP_ROWS;
  int32_t i, j;

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
    return inet_ntoa((struct in_addr)target.sin_addr);
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
  return NULL; // not reached
}

char *hydra_address2string_beautiful(char *address) {
  struct sockaddr_in target;
  struct sockaddr_in6 target6;

  if (address[0] == 4) {
    memcpy(&target.sin_addr.s_addr, &address[1], 4);
    return inet_ntoa((struct in_addr)target.sin_addr);
  } else
#ifdef AF_INET6
      if (address[0] == 16) {
    memcpy(&target6.sin6_addr, &address[1], 16);
    ipstring[0] = '[';
    inet_ntop(AF_INET6, &target6.sin6_addr, ipstring + 1, sizeof(ipstring) - 1);
    if (address[17] != 0) {
      strcat(ipstring, "%");
      strcat(ipstring, address + 17);
    }
    strcat(ipstring, "]");
    return ipstring;
  } else
#endif
  {
    if (debug)
      fprintf(stderr, "[ERROR] unknown address string size!\n");
    return NULL;
  }
  return NULL; // not reached
}

void hydra_set_srcport(int32_t port) { src_port = port; }

#ifdef HAVE_PCRE
int32_t hydra_string_match(char *str, const char *regex) {
  pcre2_code *re = NULL;
  int32_t error_code = 0;
  PCRE2_SIZE error_offset;
  int32_t rc = 0;

  re = pcre2_compile(regex, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS | PCRE2_DOTALL, &error_code, &error_offset, NULL);
  if (re == NULL) {
    fprintf(stderr, "[ERROR] PCRE compilation failed at offset %d: %d\n", error_offset, error_code);
    return 0;
  }

  pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
  rc = pcre2_match(re, str, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
  pcre2_match_data_free(match_data);
  pcre2_code_free(re);

  if (rc >= 1) {
    return 1;
  }
  return 0;
}
#endif

/*
 * str_replace.c implements a str_replace PHP like function
 * Copyright (C) 2009  chantra <chantra__A__debuntu__D__org>
 *
 * Create a new string with [substr] being replaced ONCE by [replacement] in
 * [string] Returns the new string, or NULL if out of memory. The caller is
 * responsible for freeing this new string.
 *
 */
char *hydra_string_replace(const char *string, const char *substr, const char *replacement) {
  char *tok = NULL;
  char *newstr = NULL;

  if (string == NULL)
    return NULL;
  if (substr == NULL || replacement == NULL)
    return strdup(string);
  tok = strstr(string, substr);
  if (tok == NULL)
    return strdup(string);
  newstr = malloc(strlen(string) - strlen(substr) + strlen(replacement) + 2);
  if (newstr == NULL)
    return NULL;
  memset(newstr, 0, strlen(string) - strlen(substr) + strlen(replacement) + 2);
  memcpy(newstr, string, tok - string);
  memcpy(newstr + (tok - string), replacement, strlen(replacement));
  memcpy(newstr + (tok - string) + strlen(replacement), tok + strlen(substr), strlen(string) - strlen(substr) - (tok - string));
  return newstr;
}

char *hydra_strcasestr(const char *haystack, const char *needle) {
  if (needle == NULL || *needle == 0)
    return NULL;

  for (; *haystack; ++haystack) {
    if (toupper((int32_t)*haystack) == toupper((int32_t)*needle)) {
      const char *h, *n;

      for (h = haystack, n = needle; *h && *n; ++h, ++n) {
        if (toupper((int32_t)*h) != toupper((int32_t)*n)) {
          break;
        }
      }
      if (!*n) {                 /* matched all of 'needle' to null termination */
        return (char *)haystack; /* return the start of the match */
      }
    }
  }
  return NULL;
}

void hydra_dump_data(unsigned char *buf, int32_t len, char *text) {
  unsigned char *p = (unsigned char *)buf;
  unsigned char lastrow_data[16];
  int32_t rows = len / 16;
  int32_t lastrow = len % 16;
  int32_t i, j;

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

int32_t hydra_memsearch(char *haystack, int32_t hlen, char *needle, int32_t nlen) {
  int32_t i;

  for (i = 0; i <= hlen - nlen; i++)
    if (memcmp(haystack + i, needle, nlen) == 0)
      return i;
  return -1;
}
