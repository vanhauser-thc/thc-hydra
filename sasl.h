
#include <stdio.h>
#include <string.h>
#include "ntlm.h"
#include "hydra-mod.h"

#define AUTH_ERROR -1
#define AUTH_CLEAR 0
#define AUTH_APOP 1
#define AUTH_LOGIN 2
#define AUTH_PLAIN 3
#define AUTH_CRAMMD5 4
#define AUTH_CRAMSHA1 5
#define AUTH_CRAMSHA256 6
#define AUTH_DIGESTMD5 7
#define AUTH_SCRAMSHA1 8
#define AUTH_NTLM 9
#define AUTH_NTLMv2 10
#define AUTH_BASIC 11
#define AUTH_LM 12
#define AUTH_LMv2 13

#if LIBIDN
#include <stringprep.h>
#if defined HAVE_PR29_H
#include <pr29.h>
#endif
#endif

typedef enum {
  SASL_ALLOW_UNASSIGNED = 1
} sasl_saslprep_flags;


int print_hex(unsigned char *buf, int len);

void sasl_plain(char *result, char *login, char *pass);
int sasl_saslprep(const char *in, sasl_saslprep_flags flags, char **out);

#ifdef LIBOPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

void sasl_cram_md5(char *result, char *pass, char *challenge);
void sasl_cram_sha1(char *result, char *pass, char *challenge);
void sasl_cram_sha256(char *result, char *pass, char *challenge);
void sasl_digest_md5(char *result, char *login, char *pass, char *buffer, char *miscptr, char *type, char *webtarget, int webport, char *header);
void sasl_scram_sha1(char *result, char *pass, char *clientfirstmessagebare, char *serverfirstmessage);
#endif
