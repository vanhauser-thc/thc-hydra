#include "hydra-mod.h"
#include <arpa/inet.h>
#include <unistd.h>
#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#endif

extern char *HYDRA_EXIT;

// RAdmin 2.x

struct rmessage {
  uint8_t magic;          // Indicates version, probably?
  uint32_t length;        // Total message size of data.
  uint32_t checksum;      // Checksum from type to end of data.
  uint8_t type;           // Command type, table below.
  unsigned char data[32]; // data to be sent.
};

/*
 * Usage: sum = checksum(message);
 * Function: Returns a 4 byte little endian sum of the messages typecode+data.
 * This data is zero padded for alignment. Example message (big endian):
 * [01][00000021][0f43d461] sum([1b6e779a f37189bb c1b22982 c80d1f4d 66678ff9
 * 4b10f0ce eabff6e8 f4fb8338 3b] + zeropad(3)]) Sum: is 0f43d461 (big endian)
 */
uint32_t checksum(struct rmessage *msg) {
  int32_t blen;
  uint8_t *stream;
  uint32_t sum;
  blen = msg->length; // Get the real length.
  blen += (4 - (blen % 4));

  // Allocate a worksapce.
  stream = calloc(blen, sizeof(uint8_t));
  memcpy(stream, &msg->type, sizeof(uint8_t));
  memcpy(stream + 1, msg->data, blen - 1);

  sum = 0;
  for (blen -= sizeof(uint32_t); blen > 0; blen -= sizeof(uint32_t)) {
    sum += *(uint32_t *)(stream + blen);
  }
  sum += *(uint32_t *)stream;

  // Free the workspace.
  free(stream);

  return sum;
}

/*
 * Usage: challenge_request(message);
 * Function: Modifies message to reflect a request for a challenge. Updates the
 * checksum as appropriate.
 */
void challenge_request(struct rmessage *msg) {
  msg->magic = 0x01;
  msg->length = 0x01;
  msg->type = 0x1b;
  msg->checksum = checksum(msg);
}

/*
 * Usage: challenge_request(message);
 * Function: Modifies message to reflect a response to a challenge. Updates the
 * checksum as appropriate.
 */
void challenge_response(struct rmessage *msg, unsigned char *solution) {
  msg->magic = 0x01;
  msg->length = 0x21;
  msg->type = 0x09;
  memcpy(msg->data, solution, 0x20);
  msg->checksum = checksum(msg);
}

/*
 * Usage: buffer = message2buffer(message); send(buffer, message->length + 10);
 * free(buffer) Function: Allocates a buffer for transmission and fills the
 * buffer with message data such that it is ready to transmit.
 */
// TODO: conver to a sendMessage() function?
char *message2buffer(struct rmessage *msg) {
  char *data;
  if (msg == NULL) {
    hydra_report(stderr, "rmessage is null\n");
    hydra_child_exit(0);
    return NULL;
  }

  switch (msg->type) {
  case 0x1b: // Challenge request
    data = (char *)calloc(10, sizeof(char));
    if (data == NULL) {
      hydra_report(stderr, "calloc failure\n");
      hydra_child_exit(0);
    }
    memcpy(data, &msg->magic, sizeof(char));
    *((int32_t *)(data + 1)) = htonl(msg->length);
    *((int32_t *)(data + 5)) = htonl(msg->checksum);
    memcpy((data + 9), &msg->type, sizeof(char));
    break;
  case 0x09:
    data = (char *)calloc(42, sizeof(char));
    if (data == NULL) {
      hydra_report(stderr, "calloc failure\n");
      hydra_child_exit(0);
    }
    memcpy(data, &msg->magic, sizeof(char));
    *((int32_t *)(data + 1)) = htonl(msg->length);
    *((int32_t *)(data + 5)) = htonl(msg->checksum);
    memcpy((data + 9), &msg->type, sizeof(char));
    memcpy((data + 10), msg->data, sizeof(char) * 32);
    break;
  default:
    hydra_report(stderr, "unknown rmessage type\n");
    hydra_child_exit(0);
    return NULL;
  }
  return data;
}

struct rmessage *buffer2message(char *buffer) {
  struct rmessage *msg;
  msg = calloc(1, sizeof(struct rmessage));
  if (msg == NULL) {
    hydra_report(stderr, "calloc failure\n");
    hydra_child_exit(0);
  }

  // Start parsing...
  msg->magic = buffer[0];
  buffer += sizeof(char);
  msg->length = ntohl(*((uint32_t *)(buffer)));
  buffer += sizeof(uint32_t);
  msg->checksum = ntohl(*((uint32_t *)(buffer)));
  buffer += sizeof(uint32_t);
  msg->type = buffer[0];
  buffer += sizeof(char);

  // Verify known fields...
  if (msg->magic != 0x01) {
    hydra_report(stderr, "Bad magic\n");
    hydra_child_exit(0);
    return NULL;
  }

  switch (msg->type) {
  case 0x1b:
    if (msg->length != 0x21) {
      hydra_report(stderr, "Bad length...%08x\n", msg->length);
      hydra_child_exit(0);
      return NULL;
    }
    memcpy(msg->data, buffer, 32);
    break;
  case 0x0a:
    // Win!
  case 0x0b:
    // Lose!
    break;
  default:
    hydra_report(stderr, "unknown rmessage type");
    hydra_child_exit(0);
    return NULL;
  }
  return msg;
}

int32_t start_radmin2(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) { return 0; }

void service_radmin2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
#ifdef HAVE_GCRYPT
  int32_t sock = -1;
  int32_t index;
  int32_t bytecount;
  char *request;
  struct rmessage *msg;
  int32_t myport = PORT_RADMIN2;
  char buffer[42];
  char password[101];
  uint8_t rawkey[16];
  uint8_t *IV = "\xFE\xDC\xBA\x98\x76\x54\x32\x10\xA3\x9D\x4A\x18\xF8\x5B\x4A\x52";
  uint8_t encrypted[32];
  gcry_error_t err;
  gcry_cipher_hd_t cipher;
  gcry_md_hd_t md;

  if (port != 0) {
    myport = port;
  }

  gcry_check_version(NULL);

  memset(buffer, 0x00, sizeof(buffer));

  // Phone the mother ship
  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
    return;
  }

  while (1) {
    /* Typical conversation goes as follows...
     0) connect to server
     1) request challenge
     2) receive 32 byte challenge response
     3) send 32 byte challenge solution
     4) receive 1 byte auth success/fail message
     */
    // 0) Connect to the server
    sock = hydra_connect_tcp(ip, myport);
    if (sock < 0) {
      hydra_report(stderr, "Error: Child with pid %d terminating, can not connect\n", (int32_t)getpid());
      hydra_child_exit(1);
    }

    // 1) request challenge (working)
    msg = calloc(1, sizeof(struct rmessage));
    challenge_request(msg);
    request = message2buffer(msg);
    hydra_send(sock, request, 10, 0);
    free(msg);
    free(request);

    // 2) receive response (working)
    index = 0;
    while (index < 42) { // We're always expecting back a 42 byte buffer from a
                         // challenge request.
      switch (hydra_data_ready(sock)) {
      case -1:
        hydra_report(stderr, "Error: Child with pid %d terminating, receive error\nerror:\t%s\n", (int32_t)getpid(), strerror(errno));
        hydra_child_exit(1);
        break;
      case 0:
        // keep waiting...
        break;
      default:
        bytecount = hydra_recv(sock, buffer + index, 42 - index);
        if (bytecount < 0) {
          hydra_report(stderr,
                       "Error: Child with pid %d terminating, receive "
                       "error\nerror:\t%s\n",
                       (int32_t)getpid(), strerror(errno));
          hydra_child_exit(1);
        }
        index += bytecount;
      }
    }

    // 3) Send challenge solution.

    // Get a password to work with.
    memset(password, 0x00, sizeof(password));
    memset(encrypted, 0x00, sizeof(encrypted));
    hydra_get_next_pair();
    strncpy(password, hydra_get_next_password(), sizeof(password) - 1);

    // MD5 the password to generate the password key, this is used with twofish
    // below.
    err = gcry_md_open(&md, GCRY_MD_MD5, 0);
    if (err) {
      hydra_report(stderr,
                   "Error: Child with pid %d terminating, gcry_md_open error "
                   "(%08x)\n%s/%s",
                   (int32_t)getpid(), index, gcry_strsource(err), gcry_strerror(err));
      hydra_child_exit(1);
    }
    gcry_md_reset(md);
    gcry_md_write(md, password, 100);
    if (gcry_md_read(md, 0) == NULL) {
      hydra_report(stderr, "Error: Child with pid %d terminating, gcry_md_read error (%08x)\n", (int32_t)getpid(), index);
      hydra_child_exit(1);
    }
    memcpy(rawkey, gcry_md_read(md, 0), 16);
    gcry_md_close(md);

    // 3.a) generate a new message from the buffer
    msg = buffer2message(buffer);

    // 3.b) encrypt data received using pkey & known IV
    err = gcry_cipher_open(&cipher, GCRY_CIPHER_TWOFISH128, GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
      hydra_report(stderr,
                   "Error: Child with pid %d terminating, gcry_cipher_open "
                   "error (%08x)\n%s/%s",
                   (int32_t)getpid(), index, gcry_strsource(err), gcry_strerror(err));
      hydra_child_exit(1);
    }

    err = gcry_cipher_setiv(cipher, IV, 16);
    if (err) {
      hydra_report(stderr,
                   "Error: Child with pid %d terminating, gcry_cipher_setiv "
                   "error (%08x)\n%s/%s",
                   (int32_t)getpid(), index, gcry_strsource(err), gcry_strerror(err));
      hydra_child_exit(1);
    }

    err = gcry_cipher_setkey(cipher, rawkey, 16);
    if (err) {
      hydra_report(stderr,
                   "Error: Child with pid %d terminating, gcry_cipher_setkey "
                   "error (%08x)\n%s/%s",
                   (int32_t)getpid(), index, gcry_strsource(err), gcry_strerror(err));
      hydra_child_exit(1);
    }

    err = gcry_cipher_encrypt(cipher, encrypted, 32, msg->data, 32);
    if (err) {
      hydra_report(stderr,
                   "Error: Child with pid %d terminating, gcry_cipher_encrypt "
                   "error (%08x)\n%s/%s",
                   (int32_t)getpid(), index, gcry_strsource(err), gcry_strerror(err));
      hydra_child_exit(1);
    }

    gcry_cipher_close(cipher);

    // 3.c) half sum - this is the solution to the challenge.
    for (index = 0; index < 16; index++) {
      *(encrypted + index) += *(encrypted + index + 16);
    }
    memset((encrypted + 16), 0x00, 16);

    // 3.d) send half sum
    challenge_response(msg, encrypted);
    request = message2buffer(msg);
    hydra_send(sock, request, 42, 0);
    free(msg);
    free(request);

    // 4) receive auth success/failure
    index = 0;
    while (index < 10) { // We're always expecting back a 42 byte buffer from a
                         // challenge request.
      switch (hydra_data_ready(sock)) {
      case -1:
        hydra_report(stderr, "Error: Child with pid %d terminating, receive error\nerror:\t%s\n", (int32_t)getpid(), strerror(errno));
        hydra_child_exit(1);
        break;
      case 0:
        // keep waiting...
        break;
      default:
        bytecount = hydra_recv(sock, buffer + index, 10 - index);
        if (bytecount < 0) {
          hydra_report(stderr,
                       "Error: Child with pid %d terminating, receive "
                       "error\nerror:\t%s\n",
                       (int32_t)getpid(), strerror(errno));
          hydra_child_exit(1);
        }
        index += bytecount;
      }
    }
    msg = buffer2message(buffer);
    switch (msg->type) {
    case 0x0a:
      hydra_completed_pair_found();
      break;
    case 0x0b:
      hydra_completed_pair();
      hydra_disconnect(sock);
      break;
    default:
      hydra_report(stderr, "Error: Child with pid %d terminating, protocol error\n", (int32_t)getpid());
      hydra_child_exit(2);
    }
    free(msg);
  }
#endif
}

int32_t service_radmin2_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  // 0 all OK
  // -1 error, hydra will exit, so print a good error message here

  return 0;
}
