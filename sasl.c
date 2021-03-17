#include "sasl.h"

extern int32_t selected_proxy;

/*
print_hex is used for debug
it displays the string buf hexa values of size len
*/
int32_t print_hex(unsigned char *buf, int32_t len) {
  int32_t i;
  int32_t n;

  for (i = 0, n = 0; i < len; i++) {
    if (n > 7) {
      printf("\n");
      n = 0;
    }
    printf("0x%02x, ", buf[i]);
    n++;
  }
  printf("\n");
  return (0);
}

/*
RFC 4013: SASLprep: Stringprep Profile for User Names and Passwords
code based on gsasl_saslprep from GSASL project
*/
int32_t sasl_saslprep(const char *in, sasl_saslprep_flags flags, char **out) {
#if LIBIDN
  int32_t rc;

  rc = stringprep_profile(in, out, "SASLprep", (flags & SASL_ALLOW_UNASSIGNED) ? STRINGPREP_NO_UNASSIGNED : 0);
  if (rc != STRINGPREP_OK) {
    *out = NULL;
    return -1;
  }
#if defined HAVE_PR29_H
  if (pr29_8z(*out) != PR29_SUCCESS) {
    free(*out);
    *out = NULL;
    return -1;
  }
#endif
#else
  size_t i, inlen = strlen(in);

  for (i = 0; i < inlen; i++) {
    if (in[i] & 0x80) {
      *out = NULL;
      hydra_report(stderr, "Error: Can't convert UTF-8, you should install libidn\n");
      return -1;
    }
  }
  *out = malloc(inlen + 1);
  if (!*out) {
    hydra_report(stderr, "Error: Can't allocate memory\n");
    return -1;
  }
  strcpy(*out, in);
#endif
  return 0;
}

/*
RFC 4616: The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
sasl_plain computes the plain authentication from strings login and password
and stored the value in variable result
the first parameter result must be able to hold at least 255 bytes!
*/
char *sasl_plain(char *result, char *login, char *pass) {
  char *preplogin;
  char *preppasswd;
  int32_t rc = sasl_saslprep(login, SASL_ALLOW_UNASSIGNED, &preplogin);

  if (rc) {
    result = NULL;
    return result;
  }
  rc = sasl_saslprep(pass, 0, &preppasswd);
  if (rc) {
    free(preplogin);
    result = NULL;
    return result;
  }
  if (2 * strlen(preplogin) + 3 + strlen(preppasswd) < 180) {
    strcpy(result, preplogin);
    strcpy(result + strlen(preplogin) + 1, preplogin);
    strcpy(result + 2 * strlen(preplogin) + 2, preppasswd);
    hydra_tobase64((unsigned char *)result, strlen(preplogin) * 2 + strlen(preppasswd) + 2, 250);
  }
  free(preplogin);
  free(preppasswd);
  return result;
}

#ifdef LIBOPENSSL

/*
RFC 2195: IMAP/POP AUTHorize Extension for Simple Challenge/Response
sasl_cram_md5 computes the cram-md5 authentication from password string
and the challenge sent by the server, and stored the value in variable
result
the parameter result must be able to hold at least 100 bytes!
*/
char *sasl_cram_md5(char *result, char *pass, char *challenge) {
  char ipad[64];
  char opad[64];
  unsigned char md5_raw[MD5_DIGEST_LENGTH];
  MD5_CTX md5c;
  int32_t i, rc;
  char *preppasswd;

  if (challenge == NULL) {
    result = NULL;
    return result;
  }
  rc = sasl_saslprep(pass, 0, &preppasswd);
  if (rc) {
    result = NULL;
    return result;
  }
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));
  if (strlen(preppasswd) >= 64) {
    MD5_Init(&md5c);
    MD5_Update(&md5c, preppasswd, strlen(preppasswd));
    MD5_Final(md5_raw, &md5c);
    memcpy(ipad, md5_raw, MD5_DIGEST_LENGTH);
    memcpy(opad, md5_raw, MD5_DIGEST_LENGTH);
  } else {
    strcpy(ipad, preppasswd); // safe
    strcpy(opad, preppasswd); // safe
  }
  for (i = 0; i < 64; i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }
  MD5_Init(&md5c);
  MD5_Update(&md5c, ipad, 64);
  MD5_Update(&md5c, challenge, strlen(challenge));
  MD5_Final(md5_raw, &md5c);
  MD5_Init(&md5c);
  MD5_Update(&md5c, opad, 64);
  MD5_Update(&md5c, md5_raw, MD5_DIGEST_LENGTH);
  MD5_Final(md5_raw, &md5c);
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(result, "%02x", md5_raw[i]);
    result += 2;
  }
  free(preppasswd);
  return result;
}

/*
sasl_cram_sha1 computes the cram-sha1 authentication from password string
and the challenge sent by the server, and stored the value in variable
result
the parameter result must be able to hold at least 100 bytes!
*/
char *sasl_cram_sha1(char *result, char *pass, char *challenge) {
  char ipad[64];
  char opad[64];
  unsigned char sha1_raw[SHA_DIGEST_LENGTH];
  SHA_CTX shac;
  int32_t i, rc;
  char *preppasswd;

  if (challenge == NULL) {
    result = NULL;
    return result;
  }
  rc = sasl_saslprep(pass, 0, &preppasswd);
  if (rc) {
    result = NULL;
    return result;
  }
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));
  if (strlen(preppasswd) >= 64) {
    SHA1_Init(&shac);
    SHA1_Update(&shac, preppasswd, strlen(preppasswd));
    SHA1_Final(sha1_raw, &shac);
    memcpy(ipad, sha1_raw, SHA_DIGEST_LENGTH);
    memcpy(opad, sha1_raw, SHA_DIGEST_LENGTH);
  } else {
    strcpy(ipad, preppasswd); // safe
    strcpy(opad, preppasswd); // safe
  }
  for (i = 0; i < 64; i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }
  SHA1_Init(&shac);
  SHA1_Update(&shac, ipad, 64);
  SHA1_Update(&shac, challenge, strlen(challenge));
  SHA1_Final(sha1_raw, &shac);
  SHA1_Init(&shac);
  SHA1_Update(&shac, opad, 64);
  SHA1_Update(&shac, sha1_raw, SHA_DIGEST_LENGTH);
  SHA1_Final(sha1_raw, &shac);
  for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
    sprintf(result, "%02x", sha1_raw[i]);
    result += 2;
  }
  free(preppasswd);
  return result;
}

/*
sasl_cram_sha256 computes the cram-sha256 authentication from password string
and the challenge sent by the server, and stored the value in variable
result
the parameter result must be able to hold at least 100 bytes!
*/
char *sasl_cram_sha256(char *result, char *pass, char *challenge) {
  char ipad[64];
  char opad[64];
  unsigned char sha256_raw[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256c;
  int32_t i, rc;
  char *preppasswd;

  if (challenge == NULL) {
    result = NULL;
    return result;
  }
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));
  rc = sasl_saslprep(pass, 0, &preppasswd);
  if (rc) {
    result = NULL;
    return result;
  }
  if (strlen(preppasswd) >= 64) {
    SHA256_Init(&sha256c);
    SHA256_Update(&sha256c, preppasswd, strlen(preppasswd));
    SHA256_Final(sha256_raw, &sha256c);
    memcpy(ipad, sha256_raw, SHA256_DIGEST_LENGTH);
    memcpy(opad, sha256_raw, SHA256_DIGEST_LENGTH);
  } else {
    strcpy(ipad, preppasswd); // safe
    strcpy(opad, preppasswd); // safe
  }
  for (i = 0; i < 64; i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }
  SHA256_Init(&sha256c);
  SHA256_Update(&sha256c, ipad, 64);
  SHA256_Update(&sha256c, challenge, strlen(challenge));
  SHA256_Final(sha256_raw, &sha256c);
  SHA256_Init(&sha256c);
  SHA256_Update(&sha256c, opad, 64);
  SHA256_Update(&sha256c, sha256_raw, SHA256_DIGEST_LENGTH);
  SHA256_Final(sha256_raw, &sha256c);
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(result, "%02x", sha256_raw[i]);
    result += 2;
  }
  free(preppasswd);
  return result;
}

/*
RFC 2831: Using Digest Authentication as a SASL Mechanism
the parameter result must be able to hold at least 500 bytes!!
*/
char *sasl_digest_md5(char *result, char *login, char *pass, char *buffer, char *miscptr, char *type, char *webtarget, int32_t webport, char *header) {
  char *pbuffer = NULL;
  int32_t array_size = 10;
  unsigned char response[MD5_DIGEST_LENGTH];
  char *array[array_size];
  char buffer2[500], buffer3[500], nonce[200], realm[200], algo[20];
  int32_t i = 0, ind = 0, lastpos = 0, currentpos = 0, intq = 0, auth_find = 0;
  MD5_CTX md5c;
  char *preplogin;
  char *preppasswd;
  int32_t rc = sasl_saslprep(login, SASL_ALLOW_UNASSIGNED, &preplogin);

  memset(realm, 0, sizeof(realm));
  if (rc) {
    result = NULL;
    return result;
  }
  rc = sasl_saslprep(pass, 0, &preppasswd);
  if (rc) {
    free(preplogin);
    result = NULL;
    return result;
  }
  // DEBUG S:
  // nonce="HB3HGAk+hxKpijy/ichq7Wob3Zo17LPM9rr4kMX7xRM=",realm="tida",qop="auth",maxbuf=4096,charset=utf-8,algorithm=md5-sess
  // DEBUG S:
  // nonce="1Mr6c8WjOd/x5r8GUnGeQIRNUtOVtItu3kQOGAmsZfM=",realm="test.com",qop="auth,auth-int32_t,auth-conf",cipher="rc4-40,rc4-56,rc4,des,3des",maxbuf=4096,charset=utf-8,algorithm=md5-sess
  // warning some not well configured xmpp server is sending no realm
  // DEBUG S: nonce="3448160828",qop="auth",charset=utf-8,algorithm=md5-sess
  pbuffer = buffer;
  do {
    currentpos++;
    if (pbuffer[0] == '"') {
      if (intq == 0)
        intq = 1;
      else {
        intq = 0;
      }
    }
    if ((pbuffer[0] == ',') && (intq == 0)) {
      array[ind] = malloc(currentpos);
      strncpy(array[ind], buffer + lastpos, currentpos - 1);
      array[ind][currentpos - 1] = '\0';
      ind++;
      lastpos += currentpos;
      currentpos = 0;
    }
    pbuffer++;
  } while ((pbuffer[0] > 31) && (ind < array_size));
  // save the latest one
  if (ind < array_size) {
    array[ind] = malloc(currentpos + 1);
    strncpy(array[ind], buffer + lastpos, currentpos);
    array[ind][currentpos] = '\0';
    ind++;
  }
  for (i = 0; i < ind; i++) {
    // removing space chars between comma separated value if any
    while ((array[i] != NULL) && (array[i][0] == ' ')) {
      char *tmp = strdup(array[i]);

      // memset(array[i], 0, sizeof(array[i]));
      strcpy(array[i], tmp + 1);
      free(tmp);
    }
    if (strstr(array[i], "nonce=") != NULL) {
      // check if it contains double-quote
      if (strstr(array[i], "\"") != NULL) {
        // assume last char is also a double-quote
        int32_t nonce_string_len = strlen(array[i]) - strlen("nonce=\"") - 1;

        if ((nonce_string_len > 0) && (nonce_string_len <= sizeof(nonce) - 1)) {
          strncpy(nonce, strstr(array[i], "nonce=") + strlen("nonce=") + 1, nonce_string_len);
          nonce[nonce_string_len] = '\0';
        } else {
          int32_t j;

          for (j = 0; j < ind; j++)
            if (array[j] != NULL)
              free(array[j]);
          hydra_report(stderr, "Error: DIGEST-MD5 nonce from server could not be extracted\n");
          result = NULL;
          return result;
        }
      } else {
        strncpy(nonce, strstr(array[i], "nonce=") + strlen("nonce="), sizeof(nonce) - 1);
        nonce[sizeof(nonce) - 1] = '\0';
      }
    }
    if (strstr(array[i], "realm=") != NULL) {
      if (strstr(array[i], "\"") != NULL) {
        // assume last char is also a double-quote
        int32_t realm_string_len = strlen(array[i]) - strlen("realm=\"") - 1;

        if ((realm_string_len > 0) && (realm_string_len <= sizeof(realm) - 1)) {
          strncpy(realm, strstr(array[i], "realm=") + strlen("realm=") + 1, realm_string_len);
          realm[realm_string_len] = '\0';
        } else {
          int32_t i;

          for (i = 0; i < ind; i++)
            if (array[i] != NULL)
              free(array[i]);
          hydra_report(stderr, "Error: DIGEST-MD5 realm from server could not be extracted\n");
          result = NULL;
          return result;
        }
      } else {
        strncpy(realm, strstr(array[i], "realm=") + strlen("realm="), sizeof(realm) - 1);
        realm[sizeof(realm) - 1] = '\0';
      }
    }
    if (strstr(array[i], "qop=") != NULL) {
      /*
      The value "auth" indicates authentication; the value "auth-int32_t"
      indicates authentication with integrity protection; the value "auth-conf"
      indicates authentication with integrity protection and encryption.
      */
      auth_find = 1;
      if ((strstr(array[i], "\"auth\"") == NULL) && (strstr(array[i], "\"auth,") == NULL) && (strstr(array[i], ",auth\"") == NULL)) {
        int32_t j;

        for (j = 0; j < ind; j++)
          if (array[j] != NULL)
            free(array[j]);
        hydra_report(stderr, "Error: DIGEST-MD5 quality of protection only "
                             "authentication is not supported by server\n");
        result = NULL;
        return result;
      }
    }
    if (strstr(array[i], "algorithm=") != NULL) {
      if (strstr(array[i], "\"") != NULL) {
        // assume last char is also a double-quote
        int32_t algo_string_len = strlen(array[i]) - strlen("algorithm=\"") - 1;

        if ((algo_string_len > 0) && (algo_string_len <= sizeof(algo) - 1)) {
          strncpy(algo, strstr(array[i], "algorithm=") + strlen("algorithm=") + 1, algo_string_len);
          algo[algo_string_len] = '\0';
        } else {
          int32_t j;

          for (j = 0; j < ind; j++)
            if (array[j] != NULL)
              free(array[j]);
          hydra_report(stderr, "Error: DIGEST-MD5 algorithm from server could "
                               "not be extracted\n");
          result = NULL;
          return result;
        }
      } else {
        strncpy(algo, strstr(array[i], "algorithm=") + strlen("algorithm="), sizeof(algo) - 1);
        algo[sizeof(algo) - 1] = '\0';
      }
      if ((strstr(algo, "MD5") == NULL) && (strstr(algo, "md5") == NULL)) {
        int32_t j;

        for (j = 0; j < ind; j++)
          if (array[j] != NULL)
            free(array[j]);
        hydra_report(stderr, "Error: DIGEST-MD5 algorithm not based on md5, based on %s\n", algo);
        result = NULL;
        return result;
      }
    }
    free(array[i]);
    array[i] = NULL;
  }
  if (!strlen(algo)) {
    // assuming by default algo is MD5
    memset(algo, 0, sizeof(algo));
    strcpy(algo, "MD5");
  }
  // xmpp case, some xmpp server is not sending the realm so we have to set it
  // up
  if ((strlen(realm) == 0) && (strstr(type, "xmpp") != NULL))
    snprintf(realm, sizeof(realm), "%s", miscptr);
  // compute ha1
  // support for algo = MD5
  snprintf(buffer, 500, "%s:%s:%s", preplogin, realm, preppasswd);
  MD5_Init(&md5c);
  MD5_Update(&md5c, buffer, strlen(buffer));
  MD5_Final(response, &md5c);
  // for MD5-sess
  if (strstr(algo, "5-sess") != NULL) {
    buffer[0] = 0; // memset(buffer, 0, sizeof(buffer)); => buffer is char*!

    /* per RFC 2617 Errata ID 1649 */
    if ((strstr(type, "proxy") != NULL) || (strstr(type, "GET") != NULL) || (strstr(type, "HEAD") != NULL)) {
      memset(buffer3, 0, sizeof(buffer3));
      pbuffer = buffer3;
      for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(pbuffer, "%02x", response[i]);
        pbuffer += 2;
      }
      snprintf(buffer, 500, "%s:%s:%s", buffer3, nonce, "hydra");
    } else {
      memcpy(buffer, response, sizeof(response));
      snprintf(buffer + sizeof(response), 50 - sizeof(response), ":%s:%s", nonce, "hydra");
    }
    MD5_Init(&md5c);
    MD5_Update(&md5c, buffer, strlen(buffer));
    MD5_Final(response, &md5c);
  }
  memset(buffer3, 0, sizeof(buffer3));
  pbuffer = buffer3;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(pbuffer, "%02x", response[i]);
    pbuffer += 2;
  }
  // compute ha2
  // proxy case
  if (strstr(type, "proxy") != NULL)
    snprintf(buffer, 500, "%s:%s", "HEAD", miscptr);
  else
      // http case
      if ((strstr(type, "GET") != NULL) || (strstr(type, "HEAD") != NULL))
    snprintf(buffer, 500, "%s:%s", type, miscptr);
  else
      // sip case
      if (strstr(type, "sip") != NULL)
    snprintf(buffer, 500, "REGISTER:%s:%s", type, miscptr);
  else
      // others
      if (strstr(type, "rtsp") != NULL)
    snprintf(buffer, 500, "DESCRIBE:%s://%s:%i", type, webtarget, port);
  else
    // others
    snprintf(buffer, 500, "AUTHENTICATE:%s/%s", type, realm);

  MD5_Init(&md5c);
  MD5_Update(&md5c, buffer, strlen(buffer));
  MD5_Final(response, &md5c);
  pbuffer = buffer2;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(pbuffer, "%02x", response[i]);
    pbuffer += 2;
  }
  // compute response
  if (!auth_find)
    snprintf(buffer, 500, "%s:%s", nonce, buffer2);
  else
    snprintf(buffer, 500, "%s:%s:%s:%s:%s", nonce, "00000001", "hydra", "auth", buffer2);
  MD5_Init(&md5c);
  MD5_Update(&md5c, buffer3, strlen(buffer3));
  MD5_Update(&md5c, ":", 1);
  MD5_Update(&md5c, buffer, strlen(buffer));
  MD5_Final(response, &md5c);
  pbuffer = buffer;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(pbuffer, "%02x", response[i]);
    pbuffer += 2;
  }
  // create the auth response
  if (strstr(type, "proxy") != NULL) {
    snprintf(result, 500,
             "HEAD %s HTTP/1.0\r\n%sProxy-Authorization: Digest username=\"%s\", "
             "realm=\"%s\", response=\"%s\", nonce=\"%s\", cnonce=\"hydra\", "
             "nc=00000001, algorithm=%s, qop=auth, uri=\"%s\"\r\nUser-Agent: "
             "Mozilla/4.0 (Hydra)\r\nConnection: keep-alive\r\n%s\r\n",
             miscptr, webtarget, preplogin, realm, buffer, nonce, algo, miscptr, header);
  } else {
    if ((strstr(type, "imap") != NULL) || (strstr(type, "pop") != NULL) || (strstr(type, "smtp") != NULL) || (strstr(type, "ldap") != NULL) || (strstr(type, "xmpp") != NULL) || (strstr(type, "nntp") != NULL)) {
      snprintf(result, 500,
               "username=\"%s\",realm=\"%s\",nonce=\"%s\",cnonce=\"hydra\",nc="
               "00000001,algorithm=%s,qop=\"auth\",digest-uri=\"%s/%s\",response=%s",
               preplogin, realm, nonce, algo, type, realm, buffer);
    } else {
      if (strstr(type, "sip") != NULL) {
        snprintf(result, 500,
                 "username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s:%s\","
                 "response=%s",
                 preplogin, realm, nonce, type, realm, buffer);
      } else {
        if (strstr(type, "rtsp") != NULL) {
          snprintf(result, 500,
                   "username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                   "uri=\"%s://%s:%i\", response=\"%s\"\r\n",
                   preplogin, realm, nonce, type, webtarget, port, buffer);
        } else {
          if (use_proxy == 1 && proxy_authentication[selected_proxy] != NULL)
            snprintf(result, 500,
                     "%s http://%s:%d%s HTTP/1.0\r\nHost: %s\r\nAuthorization: "
                     "Digest username=\"%s\", realm=\"%s\", response=\"%s\", "
                     "nonce=\"%s\", cnonce=\"hydra\", nc=00000001, algorithm=%s, "
                     "qop=auth, uri=\"%s\"\r\nProxy-Authorization: Basic "
                     "%s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\nConnection: "
                     "keep-alive\r\n%s\r\n",
                     type, webtarget, webport, miscptr, webtarget, preplogin, realm, buffer, nonce, algo, miscptr, proxy_authentication[selected_proxy], header);
          else {
            if (use_proxy == 1)
              snprintf(result, 500,
                       "%s http://%s:%d%s HTTP/1.0\r\nHost: %s\r\nAuthorization: "
                       "Digest username=\"%s\", realm=\"%s\", response=\"%s\", "
                       "nonce=\"%s\", cnonce=\"hydra\", nc=00000001, algorithm=%s, "
                       "qop=auth, uri=\"%s\"\r\nUser-Agent: Mozilla/4.0 "
                       "(Hydra)\r\nConnection: keep-alive\r\n%s\r\n",
                       type, webtarget, webport, miscptr, webtarget, preplogin, realm, buffer, nonce, algo, miscptr, header);
            else
              snprintf(result, 500,
                       "%s %s HTTP/1.0\r\nHost: %s\r\nAuthorization: Digest "
                       "username=\"%s\", realm=\"%s\", response=\"%s\", "
                       "nonce=\"%s\", cnonce=\"hydra\", nc=00000001, algorithm=%s, "
                       "qop=auth, uri=\"%s\"\r\nUser-Agent: Mozilla/4.0 "
                       "(Hydra)\r\nConnection: keep-alive\r\n%s\r\n",
                       type, miscptr, webtarget, preplogin, realm, buffer, nonce, algo, miscptr, header);
          }
        }
      }
    }
  }
  free(preplogin);
  free(preppasswd);
  return result;
}

/*
RFC 5802: Salted Challenge Response Authentication Mechanism
Note: SCRAM is a client-first SASL mechanism
I want to thx Simon Josefsson for his public server test,
and my girlfriend that let me work on that 2 whole nights ;)
clientfirstmessagebare must be at least 500 bytes in size!
*/
char *sasl_scram_sha1(char *result, char *pass, char *clientfirstmessagebare, char *serverfirstmessage) {
  int32_t saltlen = 0;
  int32_t iter = 4096;
  char *salt, *nonce, *ic;
  uint32_t resultlen = 0;
  char clientfinalmessagewithoutproof[200];
  char buffer[500];
  unsigned char SaltedPassword[SHA_DIGEST_LENGTH];
  unsigned char ClientKey[SHA_DIGEST_LENGTH];
  unsigned char StoredKey[SHA_DIGEST_LENGTH];
  unsigned char ClientSignature[SHA_DIGEST_LENGTH];
  char AuthMessage[1024];
  char ClientProof[SHA_DIGEST_LENGTH];
  unsigned char clientproof_b64[50];
  char *preppasswd;
  int32_t rc = sasl_saslprep(pass, 0, &preppasswd);

  if (rc) {
    result = NULL;
    return result;
  }

  /*client-final-message */
  if (debug)
    hydra_report(stderr, "DEBUG S: %s\n", serverfirstmessage);
  // r=hydra28Bo7kduPpAZLzhRQiLxc8Y9tiwgw+yP,s=ldDgevctH+Kg7b8RnnA3qA==,i=4096
  if (strstr(serverfirstmessage, "r=") == NULL) {
    hydra_report(stderr, "Error: Can't understand server message\n");
    free(preppasswd);
    result = NULL;
    return result;
  }
  strncpy(buffer, serverfirstmessage, sizeof(buffer) - 1);
  buffer[sizeof(buffer) - 1] = '\0';
  nonce = strtok(buffer, ",");
  // continue to search from the previous successful call
  salt = strtok(NULL, ",");
  ic = strtok(NULL, ",");
  iter = atoi(ic + 2);
  if (iter == 0) {
    hydra_report(stderr, "Error: Can't understand server response\n");
    free(preppasswd);
    result = NULL;
    return result;
  }
  if ((nonce != NULL) && (strlen(nonce) > 2))
    snprintf(clientfinalmessagewithoutproof, sizeof(clientfinalmessagewithoutproof), "c=biws,%s", nonce);
  else {
    hydra_report(stderr, "Error: Could not identify server nonce value\n");
    free(preppasswd);
    result = NULL;
    return result;
  }
  if ((salt != NULL) && (strlen(salt) > 2) && (strlen(salt) <= sizeof(buffer)))
    // s=ghgIAfLl1+yUy/Xl1WD5Tw== remove the header s=
    strcpy(buffer, salt + 2);
  else {
    hydra_report(stderr, "Error: Could not identify server salt value\n");
    free(preppasswd);
    result = NULL;
    return result;
  }

  /* SaltedPassword := Hi(Normalize(password), salt, i) */
  saltlen = from64tobits((char *)salt, buffer);
  if (PKCS5_PBKDF2_HMAC_SHA1(preppasswd, strlen(preppasswd), (unsigned char *)salt, saltlen, iter, SHA_DIGEST_LENGTH, SaltedPassword) != 1) {
    hydra_report(stderr, "Error: Failed to generate PBKDF2\n");
    free(preppasswd);
    result = NULL;
    return result;
  }

/* ClientKey := HMAC(SaltedPassword, "Client Key") */
#define CLIENT_KEY "Client Key"
  HMAC(EVP_sha1(), SaltedPassword, SHA_DIGEST_LENGTH, (const unsigned char *)CLIENT_KEY, strlen(CLIENT_KEY), ClientKey, &resultlen);

  /* StoredKey := H(ClientKey) */
  SHA1((const unsigned char *)ClientKey, SHA_DIGEST_LENGTH, StoredKey);

  /* ClientSignature := HMAC(StoredKey, AuthMessage) */
  snprintf(AuthMessage, 500, "%s,%s,%s", clientfirstmessagebare, serverfirstmessage, clientfinalmessagewithoutproof);
  HMAC(EVP_sha1(), StoredKey, SHA_DIGEST_LENGTH, (const unsigned char *)AuthMessage, strlen(AuthMessage), ClientSignature, &resultlen);

  /* ClientProof := ClientKey XOR ClientSignature */
  xor(ClientProof, (char *)ClientKey, (char *)ClientSignature, 20);
  to64frombits(clientproof_b64, (const unsigned char *)ClientProof, 20);
  snprintf(result, 500, "%s,p=%s", clientfinalmessagewithoutproof, clientproof_b64);
  if (debug)
    hydra_report(stderr, "DEBUG C: %s\n", result);
  free(preppasswd);
  return result;
}
#endif
