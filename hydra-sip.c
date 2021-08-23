/* simple sip digest auth (md5) module 2009/02/19
 * written by gh0st 2005
 * modified by Jean-Baptiste Aviat <jba [at] hsc [dot] `french tld`> - should
 * work now, but only with -T 1
 *
 * 05042011 david: modified to use sasl lib
 */

#include "hydra-mod.h"

#ifndef LIBOPENSSL
#include <stdio.h>
void dummy_sip() { printf("\n"); }
#else

#include "sasl.h"
#include <stdint.h>

extern int32_t hydra_data_ready_timed(int32_t socket, long sec, long usec);

char external_ip_addr[17] = "";
char *get_iface_ip(uint64_t ip);
int32_t cseq;
extern char *HYDRA_EXIT;

#define SIP_MAX_BUF 1024

void empty_register(char *buf, char *host, char *lhost, int32_t port, int32_t lport, char *user) {
  memset(buf, 0, SIP_MAX_BUF);
  snprintf(buf, SIP_MAX_BUF,
           "REGISTER sip:%s SIP/2.0\r\n"
           "Via: SIP/2.0/UDP %s:%i\r\n"
           "From: <sip:%s@%s>\r\n"
           "To: <sip:%s@%s>\r\n"
           "Call-ID: 1337@%s\r\n"
           "CSeq: %i REGISTER\r\n"
           "Content-Length: 0\r\n\r\n",
           host, lhost, lport, user, host, user, host, host, cseq);
}

int32_t get_sip_code(char *buf) {
  int32_t code;
  char tmpbuf[SIP_MAX_BUF], word[SIP_MAX_BUF];

  if (sscanf(buf, "%256s %i %256s", tmpbuf, &code, word) != 3)
    return -1;
  return code;
}

int32_t start_sip(int32_t s, char *ip, char *lip, int32_t port, int32_t lport, unsigned char options, char *miscptr, FILE *fp) {
  char *login, *pass, *host, buffer[SIP_MAX_BUF], *result = NULL;
  int32_t i;
  char buf[SIP_MAX_BUF];

  if (strlen(login = hydra_get_next_login()) == 0)
    return 3;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = NULL;

  if (external_ip_addr[0])
    lip = external_ip_addr;

  host = miscptr;
  cseq = 1;

  empty_register(buffer, host, lip, port, lport, login);
  cseq++;

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 3;
  }

  int32_t has_sip_cred = 0;
  int32_t try = 0;

  /* We have to check many times because server may begin to send "100 Trying"
   * before "401 Unauthorized" */
  while (try < 2 && !has_sip_cred) {
    try++;
    if (hydra_data_ready_timed(s, 3, 0) > 0) {
      i = hydra_recv(s, (char *)buf, sizeof(buf) - 1);
      if (i > 0)
        buf[i] = '\0';
      if (strncmp(buf, "SIP/2.0 404", 11) == 0) {
        hydra_report(stdout, "[ERROR] Get error code 404 : user '%s' not found\n", login);
        return 2;
      }
      if (strncmp(buf, "SIP/2.0 606", 11) == 0) {
        char *ptr = NULL;
        int32_t i = 0;

        // if we already tried to connect, exit
        if (external_ip_addr[0]) {
          hydra_report(stdout, "[ERROR] Get error code 606 : session is not "
                               "acceptable by the server\n");
          return 2;
        }

        if (verbose)
          hydra_report(stdout, "[VERBOSE] Get error code 606 : session is not "
                               "acceptable by the server,\n"
                               "maybe it's an addressing issue as you are "
                               "using NAT, trying to reconnect\n"
                               "using addr from the server reply\n");
          /*
             SIP/2.0 606 Not Acceptable
             Via: SIP/2.0/UDP 192.168.0.21:46759;received=82.227.229.137
           */
#ifdef HAVE_PCRE
        if (hydra_string_match(buf, "Via: SIP.*received=")) {
          ptr = strstr(buf, "received=");
#else
        if ((ptr = strstr(buf, "received="))) {
#endif
          strncpy(external_ip_addr, ptr + strlen("received="), sizeof(external_ip_addr));
          external_ip_addr[sizeof(external_ip_addr) - 1] = '\0';
          for (i = 0; i < strlen(external_ip_addr); i++) {
            if (external_ip_addr[i] <= 32) {
              external_ip_addr[i] = '\0';
            }
          }
          if (verbose)
            hydra_report(stderr, "[VERBOSE] Will reconnect using external IP address %s\n", external_ip_addr);
          return 1;
        }
        hydra_report(stderr, "[ERROR] Could not find external IP address in server answer\n");
        return 2;
      }
    }
  }
  if (!strstr(buf, "WWW-Authenticate: Digest")) {
    hydra_report(stderr, "[ERROR] no www-authenticate header found!\n");
    return -1;
  }
  if (debug)
    hydra_report(stderr, "[INFO] S: %s\n", buf);
  char buffer2[512];

  result = sasl_digest_md5(buffer2, login, pass, strstr(buf, "WWW-Authenticate: Digest") + strlen("WWW-Authenticate: Digest") + 1, host, "sip", NULL, 0, NULL);
  if (result == NULL)
    return 3;

  memset(buffer, 0, SIP_MAX_BUF);
  snprintf(buffer, SIP_MAX_BUF,
           "REGISTER sip:%s SIP/2.0\n"
           "Via: SIP/2.0/UDP %s:%i\n"
           "From: <sip:%s@%s>\n"
           "To: <sip:%s@%s>\n"
           "Call-ID: 1337@%s\n"
           "CSeq: %i REGISTER\n"
           "Authorization: Digest %s\n"
           "Content-Length: 0\n\n",
           host, lip, lport, login, host, login, host, host, cseq, buffer2);

  cseq++;
  if (debug)
    hydra_report(stderr, "[INFO] C: %s\n", buffer);
  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 3;
  }
  try = 0;
  int32_t has_resp = 0;
  int32_t sip_code = 0;

  while (try < 2 && !has_resp) {
    try++;
    if (hydra_data_ready_timed(s, 5, 0) > 0) {
      memset(buf, 0, sizeof(buf));
      if ((i = hydra_recv(s, (char *)buf, sizeof(buf) - 1)) >= 0)
        buf[i] = 0;
      if (debug)
        hydra_report(stderr, "[INFO] S: %s\n", buf);
      sip_code = get_sip_code(buf);
      if (sip_code >= 200 && sip_code < 300) {
        hydra_report_found_host(port, ip, "sip", fp);
        hydra_completed_pair_found();
        has_resp = 1;
      }
      if (sip_code >= 400 && sip_code < 500) {
        has_resp = 1;
      }
    }
  }

  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 1;
}

void service_sip(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_SIP, mysslport = PORT_SIP_SSL;

  char *lip = get_iface_ip((int32_t) * (&ip[1]));

  hydra_register_socket(sp);

  // FIXME IPV6
  if (ip[0] != 4) {
    fprintf(stderr, "[ERROR] sip module is not ipv6 enabled yet, patches are "
                    "appreciated.\n");
    hydra_child_exit(2);
  }

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    run = 3;

  int32_t lport = 0;

  while (1) {
    switch (run) {
    case 1:
      if (sock < 0) {
        if (port != 0)
          myport = port;
        lport = rand() % (65535 - 1024) + 1024;
        hydra_set_srcport(lport);

        if ((options & OPTION_SSL) == 0) {
          if (port != 0)
            myport = port;
          sock = hydra_connect_udp(ip, myport);
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
          free(lip);
          hydra_child_exit(1);
        }
      }
      next_run = start_sip(sock, ip, lip, port, lport, options, miscptr, fp);
      break;
    case 2:
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      free(lip);
      hydra_child_exit(2);
      break;
    case 3:
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      free(lip);
      hydra_child_exit(2);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      free(lip);
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

char *get_iface_ip(uint64_t ip) {
  int32_t sfd;

  sfd = socket(AF_INET, SOCK_DGRAM, 0);

  struct sockaddr_in tparamet;

  tparamet.sin_family = AF_INET;
  tparamet.sin_port = htons(2000);
  tparamet.sin_addr.s_addr = ip;

  if (connect(sfd, (const struct sockaddr *)&tparamet, sizeof(struct sockaddr_in))) {
    perror("connect");
    close(sfd);
    return NULL;
  }
  struct sockaddr_in *local = malloc(sizeof(struct sockaddr_in));
  int32_t size = sizeof(struct sockaddr_in);

  if (getsockname(sfd, (void *)local, (socklen_t *)&size)) {
    perror("getsockname");
    close(sfd);
    free(local);
    return NULL;
  }
  close(sfd);

  char buff[32];

  if (!inet_ntop(AF_INET, (void *)&local->sin_addr, buff, 32)) {
    perror("inet_ntop");
    free(local);
    return NULL;
  }
  char *str = malloc(sizeof(char) * (strlen(buff) + 1));

  strcpy(str, buff);
  free(local);
  return str;
}

#endif

int32_t service_sip_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
