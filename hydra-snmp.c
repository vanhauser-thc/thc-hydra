#include "hydra-mod.h"
#ifdef LIBOPENSSL
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif

extern int32_t hydra_data_ready_timed(int32_t socket, long sec, long usec);

extern char *HYDRA_EXIT;
extern int32_t child_head_no;

char snmpv3buf[1024], *snmpv3info = NULL;
int32_t snmpv3infolen = 0, snmpversion = 1, snmpread = 1, hashtype = 1, enctype = 0;

unsigned char snmpv3_init[] = {0x30, 0x3e, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x08, 0x86, 0xdd, 0xf0, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x14, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0e, 0x02, 0x04, 0x3f, 0x44, 0x5c, 0xbc, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00};

unsigned char snmpv3_get1[] = {0x30, 0x77, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x08, 0x86, 0xdd, 0xef, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x05, 0x02, 0x01, 0x03};

unsigned char snmpv3_get2[] = {0x30, 0x2e, 0x04, 0x0c, 0x80, 0x00, 0x00, 0x09, 0x03, 0x00, 0x00, 0x1f, 0xca, 0x8d, 0x82, 0x1b, 0x04, 0x00, 0xa0, 0x1c, 0x02, 0x04, 0x3f, 0x44, 0x5c, 0xbb, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00};

unsigned char snmpv3_nouser[] = {0x04, 0x00, 0x04, 0x00, 0x04, 0x00};

struct SNMPV1_A {
  char ID;
  char len;
  char ver[3];
  char comid;
  char comlen;
};

struct SNMPV1_A snmpv1_a = {.ID = '\x30',
                            .len = '\x00',
                            .ver = "\x02\x01\x00", /* \x02\x01\x01 for snmpv2c, \x02\x01\x03 for snmpv3 */
                            .comid = '\x04',
                            .comlen = '\x00'};

struct SNMPV1_R {
  unsigned char type[2];
  unsigned char identid[2];
  unsigned char ident[4];
  unsigned char errstat[3];
  unsigned char errind[3];
  unsigned char objectid[2];
  unsigned char object[11];
  unsigned char value[3];
} snmpv1_r = {
    .type = "\xa0\x1b", /* GET */
    .identid = "\x02\x04",
    .ident = "\x1a\x5e\x97\x00", /* random crap :) */
    .errstat = "\x02\x01\x00",   /* no error */
    .errind = "\x02\x01\x00",    /* error index 0 */
    .objectid = "\x30\x0d",
    .object = "\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01", /* sysDescr */
    .value = "\x05\x00"                                       /* we just read, so value = 0 */
};

struct SNMPV1_W {
  unsigned char type[2];
  unsigned char identid[2];
  unsigned char ident[4];
  unsigned char errstat[3];
  unsigned char errind[3];
  unsigned char objectid[2];
  unsigned char object[12];
  unsigned char value[8];
} snmpv1_w = {
    .type = "\xa3\x21", /* SET */
    .identid = "\x02\x04",
    .ident = "\x1a\x5e\x97\x22", /* random crap :) */
    .errstat = "\x02\x01\x00",   /* no error */
    .errind = "\x02\x01\x00",    /* error index 0 */
    .objectid = "\x30\x13",      /* string */
    .object = "\x30\x11\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00",
    .value = "\x04\x05Hydra" /* writing hydra :-) */
};

#ifdef LIBOPENSSL
void password_to_key_md5(u_char *password,   /* IN */
                         u_int passwordlen,  /* IN */
                         u_char *engineID,   /* IN  - pointer to snmpEngineID  */
                         u_int engineLength, /* IN  - length of snmpEngineID */
                         u_char *key) {      /* OUT - pointer to caller 16-octet buffer */
  MD5_CTX MD;
  u_char *cp, password_buf[80], *mypass = password, bpass[17];
  u_long password_index = 0, count = 0, i, mylen, myelen = engineLength;

  if (strlen(password) > passwordlen)
    passwordlen = strlen(password);
  if (passwordlen > sizeof(bpass) - 1)
    passwordlen = sizeof(bpass) - 1;
  mylen = passwordlen;

  if (mylen < 8) {
    memset(bpass, 0, sizeof(bpass));
    strncpy(bpass, password, sizeof(bpass) - 1);
    while (mylen < 8) {
      strcat(bpass, password);
      mylen += passwordlen;
    }
    mypass = bpass;
  }
  if (myelen > 32)
    myelen = 32;

  MD5_Init(&MD); /* initialize MD5 */
  /* Use while loop until we've done 1 Megabyte */
  while (count < 1048576) {
    cp = password_buf;
    for (i = 0; i < 64; i++) {
      /* Take the next octet of the password, wrapping */
      /* to the beginning of the password as necessary. */
      *cp++ = mypass[password_index++ % mylen];
    }
    MD5_Update(&MD, password_buf, 64);
    count += 64;
  }
  MD5_Final(key, &MD); /* tell MD5 we're done */
  /* Now localize the key with the engineID and pass   */
  /* through MD5 to produce final key                  */
  /* May want to ensure that engineLength <= 32,       */
  /* otherwise need to use a buffer larger than 64     */
  memcpy(password_buf, key, 16);
  memcpy(password_buf + 16, engineID, myelen);
  memcpy(password_buf + 16 + myelen, key, 16);
  MD5_Init(&MD);
  MD5_Update(&MD, password_buf, 32 + myelen);
  MD5_Final(key, &MD);
  return;
}

void password_to_key_sha(u_char *password,   /* IN */
                         u_int passwordlen,  /* IN */
                         u_char *engineID,   /* IN  - pointer to snmpEngineID  */
                         u_int engineLength, /* IN  - length of snmpEngineID */
                         u_char *key) {      /* OUT - pointer to caller 20-octet buffer */
  SHA_CTX SH;
  u_char *cp, password_buf[80], *mypass = password, bpass[17];
  u_long password_index = 0, count = 0, i, mylen = passwordlen, myelen = engineLength;

  if (mylen < 8) {
    memset(bpass, 0, sizeof(bpass));
    strcpy(bpass, password);
    while (mylen < 8) {
      strcat(bpass, password);
      mylen += passwordlen;
    }
    mypass = bpass;
  }

  if (myelen > 32)
    myelen = 32;

  SHA1_Init(&SH); /* initialize SHA */
  /* Use while loop until we've done 1 Megabyte */
  while (count < 1048576) {
    cp = password_buf;
    for (i = 0; i < 64; i++) {
      /* Take the next octet of the password, wrapping */
      /* to the beginning of the password as necessary. */
      *cp++ = mypass[password_index++ % mylen];
    }
    SHA1_Update(&SH, password_buf, 64);
    count += 64;
  }
  SHA1_Final(key, &SH); /* tell SHA we're done */
  /* Now localize the key with the engineID and pass   */
  /* through SHA to produce final key                  */
  /* May want to ensure that engineLength <= 32,       */
  /* otherwise need to use a buffer larger than 72     */
  memcpy(password_buf, key, 20);
  memcpy(password_buf + 20, engineID, myelen);
  memcpy(password_buf + 20 + myelen, key, 20);
  SHA1_Init(&SH);
  SHA1_Update(&SH, password_buf, 40 + myelen);
  SHA1_Final(key, &SH);
  return;
}
#endif

int32_t start_snmp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "\"\"", *ptr, *login, *pass, buffer[1024], buf[1024], hash[64], key[256] = "", salt[8] = "";
  int32_t i, j, k, size, off = 0, off2 = 0;
  unsigned char initVect[8], privacy_params[8];
  int32_t engine_boots = 0;

#ifdef LIBOPENSSL
  DES_key_schedule symcbc;
#endif

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  if (snmpversion < 3) {
    /* do we attack snmp v1 or v2c? */
    if (snmpversion == 2) {
      snmpv1_a.ver[2] = '\x01';
    }

    if (snmpread) {
      size = sizeof(snmpv1_r);
    } else {
      size = sizeof(snmpv1_w);
    }

    snmpv1_a.comlen = (char)strlen(pass);
    snmpv1_a.len = snmpv1_a.comlen + size + sizeof(snmpv1_a) - 3;

    i = sizeof(snmpv1_a);
    memcpy(buffer, &snmpv1_a, i);
    strcpy(buffer + i, pass);
    i += strlen(pass);

    if (snmpread) {
      memcpy(buffer + i, &snmpv1_r, size);
      i += sizeof(snmpv1_r);
    } else {
      memcpy(buffer + i, &snmpv1_w, size);
      i += sizeof(snmpv1_w);
    }
  } else { // snmpv3
    if (enctype == 0) {
      memcpy(buffer, snmpv3_get1, sizeof(snmpv3_get1));
      i = sizeof(snmpv3_get1);
    } else {
      memcpy(buffer + 1, snmpv3_get1, sizeof(snmpv3_get1));
      buffer[0] = buffer[1];
      memset(buffer + 1, 0x81, 2);
      i = sizeof(snmpv3_get1) + 1;
      off2 = 1;
    }

    memcpy(buffer + i, snmpv3info, snmpv3infolen);

    if (hashtype > 0) {
      off = 12;
#ifdef LIBOPENSSL
      if (hashtype == 1) {
        password_to_key_md5(pass, strlen(pass), snmpv3info + 6, snmpv3info[5], key);
      } else {
        password_to_key_sha(pass, strlen(pass), snmpv3info + 6, snmpv3info[5], key);
      }
#endif
      if (enctype > 0) {
        off += 8;
        buffer[20 + off2] = 7;
      }
    } else {
      ptr = login;
      login = pass;
      pass = ptr;
      buffer[20] = 4;
    }

    buffer[i + 1] = 4 + snmpv3infolen + off + strlen(login);
    buffer[i + 3] = 2 + snmpv3infolen + off + strlen(login);
    if (enctype == 0)
      buffer[1] = 48 + sizeof(snmpv3_get1) + buffer[i + 1];
    i += snmpv3infolen;
    // printf("2 + %d + %d + %d = 0x%02x\n", off, snmpv3infolen, strlen(login),
    // buffer[1]);

    buffer[i] = 0x04;
    buffer[i + 1] = strlen(login);
    memcpy(buffer + i + 2, login, strlen(login));
    i += 2 + strlen(login);

    buffer[i] = 0x04;
    if (hashtype > 0) {
      buffer[i + 1] = 12;
      memset(buffer + i + 2, 0, 12);
      off = i + 2;
      i += 2 + 12;
    } else {
      buffer[i + 1] = 0;
      i += 2;
    }

    buffer[i] = 0x04;
    if (enctype == 0) {
      buffer[i + 1] = 0x00;
      i += 2;
    } else {
      buffer[i + 1] = 8;
      memcpy(buffer + i + 2, salt, 8); // uninitialized and we don't care
      i += 10;
    }

    if (enctype == 0) {
      memcpy(buffer + i, snmpv3_get2, sizeof(snmpv3_get2));
      i += sizeof(snmpv3_get2);
    } else {
      buffer[i] = 4;
      buffer[i + 1] = 0x30;

#ifdef LIBOPENSSL

      /*
      //PrivDES::encrypt(const unsigned char *key,
      //                 const uint32_t   key_len,
      //                 const unsigned char *buffer,
      //                 const uint32_t   buffer_len,
      //                 unsigned char       *out_buffer,
      //                 uint32_t        *out_buffer_len,
      //                 unsigned char       *privacy_params,
      //                 uint32_t        *privacy_params_len,
      //                 const unsigned long  engine_boots,
      //                 const unsigned long  engine_time)
      // last 8 bytes of key are used as base for initialization vector   */
      k = 0;
      memcpy((char *)initVect, key + 8, 8);
      // put salt in privacy_params
      j = htonl(engine_boots);
      memcpy(privacy_params, (char *)&j, 4);
      memcpy(privacy_params + 4, salt, 4); // ??? correct?
      // xor initVect with salt
      for (i = 0; i < 8; i++)
        initVect[i] ^= privacy_params[i];
      DES_key_sched((const_DES_cblock *)key, &symcbc);
      DES_ncbc_encrypt(snmpv3_get2 + 2, buf, sizeof(snmpv3_get2) - 2, &symcbc, (const_DES_cblock *)(initVect), DES_ENCRYPT);

#endif

      /*  for (i = 0; i <= sizeof(snmpv3_get2) - 8; i += 8) {
          DES_ncbc_encrypt(snmpv3_get2 + i, buf + i, 8,
        (const_DES_cblock*)(initVect), DES_ENCRYPT);
        }
        // last part of buffer
        if (buffer_len % 8) {
          unsigned char tmp_buf[8];
          unsigned char *tmp_buf_ptr = tmp_buf;
          int32_t start = buffer_len - (buffer_len % 8);
          memset(tmp_buf, 0, 8);
          for (uint32_t l = start; l < buffer_len; l++)
            *tmp_buf_ptr++ = buffer[l];
          DES_ncbc_encrypt(tmp_buf, buf + start, 1, &symcbc,
        (const_DES_cblock*)(initVect), DES_ENCRYPT); *out_buffer_len =
        buffer_len + 8 - (buffer_len % 8); } else *out_buffer_len = buffer_len;
      */
      // dummy
      k = ((sizeof(snmpv3_get2) - 2) / 8);
      if ((sizeof(snmpv3_get2) - 2) % 8 != 0)
        k++;
      memcpy(buffer + i + 2, buf, k * 8);
      i += k * 8 + 2;
    }

    i++; // just to conform with the snmpv1/2 code
#ifdef LIBOPENSSL
    if (hashtype == 1) {
      HMAC((EVP_MD *)EVP_md5(), key, 16, buffer, i - 1, hash, NULL);
      memcpy(buffer + off, hash, 12);
    } else if (hashtype == 2) {
      HMAC((EVP_MD *)EVP_sha1(), key, 20, buffer, i - 1, hash, NULL);
      memcpy(buffer + off, hash, 12);
    }
#endif
  }

  j = 0;
  do {
    if (hydra_send(s, buffer, i - 1, 0) < 0)
      return 3;
    j++;
  } while (hydra_data_ready_timed(s, 1, 0) <= 0 && j < 3);

  if (hydra_data_ready_timed(s, 5, 0) > 0) {
    i = hydra_recv(s, (char *)buf, sizeof(buf));

    if (snmpversion < 3) {
      /* stolen from ADMsnmp... :P */
      for (j = 0; j < i; j++) {
        if (buf[j] == '\x04') { /* community name */
          for (j = j + buf[j + 1]; j + 2 < i; j++) {
            if (buf[j] == '\xa2') { /* PDU Response */
              for (; j + 2 < i; j++) {
                if (buf[j] == '\x02') { /* ID */
                  for (j = j + (buf[j + 1]); j + 2 < i; j++) {
                    if (buf[j] == '\x02') {
                      if (buf[j + 1] == '\x01') { /* good ! */
                        hydra_report_found_host(port, ip, "snmp", fp);
                        hydra_completed_pair_found();
                        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
                          return 3;
                        return 1;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else { // snmpv3 reply
      off = 0;
      if (buf[0] == 0x30) {
        if (buf[4] == 0x03 && buf[5] == 0x30)
          off = 4;
        if (buf[5] == 0x03 && buf[6] == 0x30)
          off = 6;
        if (buf[6] == 0x03 && buf[7] == 0x30)
          off = 6;
      }
      if (off == 0)
        return 3;

      if (debug)
        printf("[DEBUG] buf[%d + 15] %d\n", off, buf[off + 15]);
      k = 3 + off + buf[2 + off];
      if ((j = hydra_memsearch(buf + k, buf[k + 3], snmpv3_nouser, sizeof(snmpv3_nouser))) < 0)
        if ((j = hydra_memsearch(buf + k, buf[k + 3], login, strlen(login))) >= 0) {
          if (snmpv3info[j - 2] == 0x04)
            j -= 2;
          else
            j = -1;
        }
      if (j >= 0) {
        i = buf[k + 3] + 4;
        if (i > sizeof(snmpv3info))
          i = sizeof(snmpv3info);
        memcpy(snmpv3info, buf + k, i);
        snmpv3infolen = j;
        if (debug)
          hydra_dump_asciihex(snmpv3info, snmpv3infolen);
      }

      if ((buf[off + 15] & 1) == 1) {
        if (hashtype == 0)
          hydra_report_found_host(port, ip, "snmp3", fp);
        else
          hydra_report_found_host(port, ip, "snmp", fp);
        hydra_completed_pair_found();
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
        return 1;
      } else if ((buf[off + 15] & 5) == 4 && hydra_memsearch(buf, i, snmpv3_nouser,
                                                             sizeof(snmpv3_nouser)) >= 0) { // user does not exist
        if (verbose)
          printf("[INFO] user %s does not exist, skipping\n", login);
        hydra_completed_pair_skip();
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
        return 1;
      }
    }
  }

  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_snmp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1, i = 0;
  int32_t myport = PORT_SNMP;
  char *lptr;

  if (miscptr != NULL) {
    lptr = strtok(miscptr, ":");
    while (lptr != NULL) {
      if (strcasecmp(lptr, "1") == 0)
        snmpversion = 1;
      else if (strcasecmp(lptr, "2") == 0)
        snmpversion = 2;
      else if (strcasecmp(lptr, "3") == 0)
        snmpversion = 3;
      else if (strcasecmp(lptr, "PLAIN") == 0)
        hashtype = 0;
      else if (strcasecmp(lptr, "MD5") == 0)
        hashtype = 1;
      else if (strncasecmp(lptr, "R", 1) == 0)
        snmpread = 1;
      else if (strncasecmp(lptr, "W", 1) == 0)
        snmpread = 0;
      else if (strncasecmp(lptr, "SHA", 3) == 0)
        hashtype = 2;
      else if (strcasecmp(lptr, "DES") == 0)
        enctype = 1;
      else if (strcasecmp(lptr, "AES") == 0)
        enctype = 2;
      else {
        fprintf(stderr, "[ERROR] unknown optional parameter: %s\n", lptr);
        hydra_child_exit(2);
      }
      lptr = strtok(NULL, ":");
    }
  }
  if (hashtype == 0)
    enctype = 0;

  if (port != 0)
    myport = port;
  sock = hydra_connect_udp(ip, myport);
  port = myport;

  if (debug)
    printf("[DEBUG] snmpv%d, isread %d, hashtype %d, enctype %d\n", snmpversion, snmpread, hashtype, enctype);

  hydra_register_socket(sp);

  if (sock < 0) {
    hydra_report(stderr, "[ERROR] Child with pid %d terminating, no socket available\n", (int32_t)getpid());
    hydra_child_exit(1);
  }

  if (snmpversion == 3) {
    next_run = 0;
    while (snmpv3info == NULL && next_run < 3) {
      hydra_send(sock, snmpv3_init, sizeof(snmpv3_init), 0);
      if (hydra_data_ready_timed(sock, 5, 0) > 0) {
        if ((i = hydra_recv(sock, (char *)snmpv3buf, sizeof(snmpv3buf))) > 30) {
          if (snmpv3buf[4] == 3 && snmpv3buf[5] == 0x30) {
            snmpv3info = snmpv3buf + 7 + snmpv3buf[6];
            snmpv3infolen = snmpv3info[3] + 4;
            if (snmpv3info + snmpv3infolen <= snmpv3buf + sizeof(snmpv3buf)) {
              while (snmpv3info[snmpv3infolen - 2] == 4 && snmpv3info[snmpv3infolen - 1] == 0 && snmpv3infolen > 1)
                snmpv3infolen -= 2;
              if (debug)
                hydra_dump_asciihex(snmpv3info, snmpv3infolen);
              if (snmpv3info[10] == 3 && child_head_no == 0)
                printf("[INFO] Remote device MAC address is "
                       "%02x:%02x:%02x:%02x:%02x:%02x\n",
                       (unsigned char)snmpv3info[12], (unsigned char)snmpv3info[13], (unsigned char)snmpv3info[14], (unsigned char)snmpv3info[15], (unsigned char)snmpv3info[16], (unsigned char)snmpv3info[12]);
            }
          }
        }
      }
      next_run++;
    }
    if (snmpv3info == NULL || i < snmpv3info + snmpv3infolen - snmpv3buf) {
      hydra_report(stderr, "No valid reply from snmp server, exiting!\n");
      hydra_child_exit(2);
    }
  }

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    run = 3;

  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      next_run = start_snmp(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_snmp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_snmp(const char *service) {
  printf("Module snmp is optionally taking the following parameters:\n"
         "   READ  perform read requests (default)\n"
         "   WRITE perform write requests\n"
         "   1     use SNMP version 1 (default)\n"
         "   2     use SNMP version 2\n"
         "   3     use SNMP version 3\n"
         "           Note that SNMP version 3 usually uses both login and "
         "passwords!\n"
         "           SNMP version 3 has the following optional sub parameters:\n"
         "             MD5   use MD5 authentication (default)\n"
         "             SHA   use SHA authentication\n"
         "             DES   use DES encryption\n"
         "             AES   use AES encryption\n"
         "           if no -p/-P parameter is given, SNMPv3 noauth is performed, "
         "which\n"
         "           only requires a password (or username) not both.\n"
         "To combine the options, use colons (\":\"), e.g.:\n"
         "   hydra -L user.txt -P pass.txt -m 3:SHA:AES:READ target.com snmp\n"
         "   hydra -P pass.txt -m 2 target.com snmp\n");
}
