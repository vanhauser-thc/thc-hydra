/* $Id$
   Single file NTLM system to create and parse authentication messages.

   http://www.reversing.org
   ilo-- ilo@reversing.org

   I did copy&paste&modify several files to leave independent NTLM code
   that compile in cygwin/linux environment. Most of the code was ripped
   from Samba implementation so I left the Copying statement. Samba core
   code was left unmodified from 1.9 version.

   Also libntlm was ripped but rewrote, due to fixed and useless interface.
   Copyright and licensing information is in ntlm.c file.

   NTLM Interface, just two functions:

   void BuildAuthRequest(tSmbNtlmAuthRequest *request, long flags, char *host,
   char *domain); if flags is 0 minimun security level is selected, otherwise
   new value superseeds. host and domain are optional, they may be NULLed.

   void buildAuthResponse(tSmbNtlmAuthChallenge *challenge, tSmbNtlmAuthResponse
   *response, long flags, char *user, char *password, char *domain, char *host);
   Given a challenge, generates a response for that user/passwd/host/domain.
   flags, host, and domain superseeds given by server. Leave 0 and NULL for
   server authentication


   This is an usage sample:


                ...
                //beware of fixed sized buffer, asserts may fail, don't use long
   strings :)
                //Yes, I Know, year 2k6 and still with this shit..
                unsigned char buf[4096];
                unsigned char buf2[4096];

                //send auth request: let the server send it's own hostname and
   domainname buildAuthRequest((tSmbNtlmAuthRequest*)buf2,0,NULL,NULL);
                to64frombits(buf, buf2, SmbLength((tSmbNtlmAuthRequest*)buf2));
                send_to_server(buf);

                //receive challenge
                receive_from_server(buf);

                //build response with hostname and domainname from server
                buildAuthResponse((tSmbNtlmAuthChallenge*)buf,(tSmbNtlmAuthResponse*)buf2,0,"username","password",NULL,NULL);
                to64frombits(buf, buf2, SmbLength((tSmbNtlmAuthResponse*)buf2));
                send_to_server(buf);

                //get reply and Check if ok
                ...


   included bonus!!:
   Base64 code
   int32_t  from64tobits(char *out, const char *in);
   void to64frombits(unsigned char *out, const unsigned char *in, int32_t
   inlen);




   You don't need to read the rest of the file.
*/

/*
 * These structures are byte-order dependant, and should not
 * be manipulated except by the use of the routines provided
 */
#ifdef __sun
#include <sys/int_types.h>
#elif defined(__FreeBSD__) || defined(__IBMCPP__) || defined(_AIX)
#include <inttypes.h>
#else
#include <stdint.h>
#endif

typedef unsigned short uint16;
typedef uint32_t uint32;
typedef unsigned char uint8;

typedef struct {
  uint16 len;
  uint16 maxlen;
  uint32 offset;
} tSmbStrHeader;

typedef struct {
  char ident[8];
  uint32 msgType;
  uint32 flags;
  tSmbStrHeader host;
  tSmbStrHeader domain;
  uint8 buffer[1024];
  uint32 bufIndex;
} tSmbNtlmAuthRequest;

typedef struct {
  char ident[8];
  uint32 msgType;
  tSmbStrHeader uDomain;
  uint32 flags;
  uint8 challengeData[8];
  uint8 reserved[8];
  tSmbStrHeader emptyString;
  uint8 buffer[1024];
  uint32 bufIndex;
} tSmbNtlmAuthChallenge;

typedef struct {
  char ident[8];
  uint32 msgType;
  tSmbStrHeader lmResponse;
  tSmbStrHeader ntResponse;
  tSmbStrHeader uDomain;
  tSmbStrHeader uUser;
  tSmbStrHeader uWks;
  tSmbStrHeader sessionKey;
  uint32 flags;
  uint8 buffer[1024];
  uint32 bufIndex;
} tSmbNtlmAuthResponse;

extern void buildAuthRequest(tSmbNtlmAuthRequest *request, long flags, char *host, char *domain);

/* reversing interface */

/* ntlm functions */
void BuildAuthRequest(tSmbNtlmAuthRequest *request, long flags, char *host, char *domain);

// if flags is 0 minimun security level is selected, otherwise new value
// superseeds. host and domain are optional, they may be NULLed.

void buildAuthResponse(tSmbNtlmAuthChallenge *challenge, tSmbNtlmAuthResponse *response, long flags, char *user, char *password, char *domain, char *host);

// Given a challenge, generates a response for that user/passwd/host/domain.
// flags, host, and domain superseeds given by server. Leave 0 and NULL for
// server authentication

/* Base64 code*/
int32_t from64tobits(char *out, const char *in);
void to64frombits(unsigned char *out, const unsigned char *in, int32_t inlen);

void xor (char *out, char *in1, char *in2, int32_t n);

// info functions
void dumpAuthRequest(FILE *fp, tSmbNtlmAuthRequest *request);
void dumpAuthChallenge(FILE *fp, tSmbNtlmAuthChallenge *challenge);
void dumpAuthResponse(FILE *fp, tSmbNtlmAuthResponse *response);

void strupper(char *s);

#define SmbLength(ptr) (((ptr)->buffer - (uint8 *)(ptr)) + (ptr)->bufIndex)
