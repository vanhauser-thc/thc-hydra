/*
david:

PASSWORDS_LISTENER in listener.ora can be in clear or in plain mode,
this module support the 2 modes, use -m PLAIN or -m CLEAR on the cmd
line. Default is plain (oracle 10 uses it).

Thanks to Marcell for the plain mode analysis available
at http://marcellmajor.com/frame_listenerhash.html

*/

#include "hydra-mod.h"
#ifndef LIBOPENSSL
#include <stdio.h>
void dummy_oracle_listener() { printf("\n"); }
#else
#include "sasl.h"
#include <openssl/des.h>
#define HASHSIZE 17

extern char *HYDRA_EXIT;
char *buf;
unsigned char *hash;
int32_t sid_mechanism = AUTH_PLAIN;

int32_t initial_permutation(unsigned char **result, char *p_str, int32_t *sz) {
  int32_t k = 0;
  int32_t i = strlen(p_str);
  char *buff;

  // expand the string with zero so that length is a multiple of 4
  while ((i % 4) != 0) {
    i = i + 1;
  }
  *sz = 2 * i;

  if ((buff = malloc(i + 4)) == NULL) {
    hydra_report(stderr, "[ERROR] Can't allocate memory\n");
    return 1;
  }
  memset(buff, 0, i + 4);
  strcpy(buff, p_str);

  // swap the order of every byte pair
  for (k = 0; k < i; k += 2) {
    char bck = buff[k + 1];

    buff[k + 1] = buff[k];
    buff[k] = bck;
  }
  // convert to unicode
  if ((*result = malloc(2 * i)) == NULL) {
    hydra_report(stderr, "[ERROR] Can't allocate memory\n");
    free(buff);
    return 1;
  }
  memset(*result, 0, 2 * i);
  for (k = 0; k < i; k++) {
    (*result)[2 * k] = buff[k];
  }
  free(buff);

  return 0;
}

int32_t ora_hash(unsigned char **orahash, unsigned char *buf, int32_t len) {
  int32_t i;

  if ((*orahash = malloc(HASHSIZE)) == NULL) {
    hydra_report(stderr, "[ERROR] Can't allocate memory\n");
    return 1;
  }

  for (i = 0; i < 8; i++) {
    sprintf(((char *)*orahash) + i * 2, "%02X", buf[len - 8 + i]);
  }
  return 0;
}

int32_t convert_byteorder(unsigned char **result, int32_t size) {
  int32_t i = 0;
  char *buff;

  if ((buff = malloc(size)) == NULL) {
    hydra_report(stderr, "[ERROR] Can't allocate memory\n");
    return 1;
  }
  memcpy(buff, *result, size);

  while (i < size) {
    buff[i + 0] = (*result)[i + 3];
    buff[i + 1] = (*result)[i + 2];
    buff[i + 2] = (*result)[i + 1];
    buff[i + 3] = (*result)[i + 0];
    i += 4;
  }
  memcpy(*result, buff, size);
  free(buff);
  return 0;
}

int32_t ora_descrypt(unsigned char **rs, unsigned char *result, int32_t siz) {
  int32_t i = 0;
  char lastkey[8];
  DES_key_schedule ks1;
  unsigned char key1[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
  unsigned char ivec1[] = {0, 0, 0, 0, 0, 0, 0, 0};
  unsigned char *desresult;

  memset(ivec1, 0, sizeof(ivec1));
  if ((desresult = malloc(siz)) == NULL) {
    hydra_report(stderr, "[ERROR] Can't allocate memory\n");
    return 1;
  }
  DES_key_sched((const_DES_cblock *)key1, &ks1);
  DES_ncbc_encrypt(result, desresult, siz, &ks1, &ivec1, DES_ENCRYPT);

  for (i = 0; i < 8; i++) {
    lastkey[i] = desresult[siz - 8 + i];
  }

  DES_key_sched((const_DES_cblock *)lastkey, &ks1);
  memset(desresult, 0, siz);
  memset(ivec1, 0, sizeof(ivec1));
  DES_ncbc_encrypt(result, desresult, siz, &ks1, &ivec1, DES_ENCRYPT);

  if ((*rs = malloc(siz)) == NULL) {
    hydra_report(stderr, "[ERROR] Can't allocate memory\n");
    free(desresult);
    return 1;
  }
  memcpy(*rs, desresult, siz);

  return 0;
}

int32_t ora_hash_password(char *pass) {
  // secret hash function comes here, and written to char *hash
  int32_t siz = 0;
  unsigned char *desresult;
  unsigned char *result;
  char buff[strlen(pass) + 5];

  memset(buff, 0, sizeof(buff));

  // concatenate Arb string and convert the resulting string to uppercase
  snprintf(buff, sizeof(buff), "Arb%s", pass);
  strupper(buff);

  if (initial_permutation(&result, buff, &siz)) {
    hydra_report(stderr, "[ERROR] ora_hash_password: in initial_permutation\n");
    return 1;
  }

  if (convert_byteorder(&result, siz)) {
    hydra_report(stderr, "[ERROR] ora_hash_password: in convert_byteorder\n");
    free(result);
    return 1;
  }
  if (ora_descrypt(&desresult, result, siz)) {
    hydra_report(stderr, "[ERROR] ora_hash_password: in DES crypt\n");
    free(result);
    return 1;
  }
  free(result);
  if (ora_hash(&result, desresult, siz)) {
    hydra_report(stderr, "[ERROR] ora_hash_password: in extracting Oracle hash\n");
    free(desresult);
    return 1;
  }

  memcpy(hash, result, HASHSIZE);
  free(desresult);
  free(result);

  return 0;
}

int32_t start_oracle_listener(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  unsigned char tns_packet_begin[22] = {"\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00\x7f\xff\x86\x0e"
                                        "\x00\x00\x01\x00"};
  unsigned char tns_packet_end[32] = {"\x00\x3a\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                      "\x00\x00\x09\x94\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00"};

  char *empty = "";
  char *pass;
  char connect_string[200];
  char buffer2[260];
  int32_t siz = 0;

  memset(connect_string, 0, sizeof(connect_string));
  memset(buffer2, 0, sizeof(buffer2));

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  if (sid_mechanism == AUTH_PLAIN) {
    if ((hash = malloc(HASHSIZE)) == NULL) {
      hydra_report(stderr, "[ERROR] Can't allocate memory\n");
      return 1;
    }
    memset(hash, 0, HASHSIZE);
    if (ora_hash_password(pass)) {
      hydra_report(stderr, "[ERROR] generating Oracle hash\n");
      free(hash);
      return 1;
    }
    pass = (char *)hash;
  }
  snprintf(connect_string, sizeof(connect_string),
           "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)("
           "PASSWORD=%s)(SERVICE=)(VERSION=169869568)))",
           pass);

  if (hash != NULL)
    free(hash);
  if (verbose)
    hydra_report(stderr, "[VERBOSE] using connectiong string: %s\n", connect_string);

  siz = 2 + sizeof(tns_packet_begin) + 2 + sizeof(tns_packet_end) + strlen(connect_string);
  if (siz > 255) {
    buffer2[0] = 1;
    buffer2[1] = siz - 256;
  } else {
    buffer2[1] = siz;
  }
  memcpy(buffer2 + 2, (char *)tns_packet_begin, sizeof(tns_packet_begin));
  siz = strlen(connect_string);
  if (siz > 255) {
    buffer2[2 + sizeof(tns_packet_begin)] = 1;
    buffer2[1 + 2 + sizeof(tns_packet_begin)] = siz - 256;
  } else {
    buffer2[1 + 2 + sizeof(tns_packet_begin)] = siz;
  }
  memcpy(buffer2 + 2 + sizeof(tns_packet_begin) + 2, (char *)tns_packet_end, sizeof(tns_packet_end));
  memcpy(buffer2 + 2 + sizeof(tns_packet_begin) + 2 + sizeof(tns_packet_end), connect_string, strlen(connect_string));
  if (hydra_send(s, buffer2, 2 + sizeof(tns_packet_begin) + 2 + sizeof(tns_packet_end) + strlen(connect_string), 0) < 0) {
    return 1;
  }

  if ((buf = hydra_receive_line(s)) == NULL)
    return 1;
  if (verbose || debug)
    hydra_report(stderr, "[VERBOSE] Server answer: %s\n", buf);

  if (strstr(buf, "ERR=0") != NULL) {
    hydra_report_found_host(port, ip, "oracle-listener", fp);
    hydra_completed_pair_found();
  } else
    hydra_completed_pair();

  free(buf);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_oracle_listener(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_ORACLE, mysslport = PORT_ORACLE_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
    strupper(miscptr);
    if (strncmp(miscptr, "CLEAR", 5) == 0)
      sid_mechanism = AUTH_CLEAR;
  }
  if (verbose) {
    switch (sid_mechanism) {
    case AUTH_CLEAR:
      hydra_report(stderr, "[VERBOSE] using SID CLEAR mechanism\n");
      break;
    case AUTH_PLAIN:
      hydra_report(stderr, "[VERBOSE] using SID PLAIN mechanism\n");
      break;
    }
  }

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
      /* run the cracking function */
      next_run = start_oracle_listener(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    case 4:
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_oracle_listener_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_oracle_listener(const char *service) {
  printf("Module oracle-listener / tns is optionally taking the mode the "
         "password is stored as, could be PLAIN (default) or CLEAR\n\n");
}

#endif
