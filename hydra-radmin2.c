#include "hydra-mod.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/md5.h>

extern char *HYDRA_EXIT;


//Twofish references
#include "twofish/aes.h"
extern int makeKey(keyInstance *key, BYTE direction, int keyLen,CONST char *keyMaterial);
extern int cipherInit(cipherInstance *cipher, BYTE mode,CONST char *IV);
extern int blockEncrypt(cipherInstance *cipher, keyInstance *key,CONST BYTE *input, int inputLen, BYTE *outBuffer);
extern int blockDecrypt(cipherInstance *cipher, keyInstance *key,CONST BYTE *input, int inputLen, BYTE *outBuffer);

//RAdmin 2.x

struct rmessage{
  char magic; //Indicates version, probably?
  unsigned int length; //Total message size of data.
  unsigned int checksum; //Checksum from type to end of data.
  char type; //Command type, table below.
  unsigned char data[32]; //data to be sent.
};

/*
* Usage:    sum = checksum(message);
* Function: Returns a 4 byte little endian sum of the messages typecode+data. This data is zero padded for alignment.
* Example message (big endian):
* [01][00000021][0f43d461] sum([1b6e779a f37189bb c1b22982 c80d1f4d 66678ff9 4b10f0ce eabff6e8 f4fb8338 3b] + zeropad(3)])
* Sum: is 0f43d461 (big endian)
*/
unsigned int checksum(struct rmessage *msg) {
  int blen;
  unsigned char *stream;
  unsigned int sum;
  blen = msg->length; //Get the real length.
  blen += (4 - (blen % 4));

  //Allocate a worksapce.
  stream = calloc(blen, sizeof(unsigned char));
  memcpy(stream, &msg->type, sizeof(unsigned char));
  memcpy(stream+1, msg->data, blen-1);

  sum = 0;
  for(blen -= sizeof(unsigned int); blen > 0; blen -= sizeof(unsigned int)) {
    sum += *(unsigned int *)(stream + blen);
  }
  sum += *(unsigned int *)stream;

  //Free the workspace.
  free(stream);

  return sum;
}

/*
* Usage:    challenge_request(message);
* Function: Modifies message to reflect a request for a challenge. Updates the checksum as appropriate.
*/
void challenge_request(struct rmessage *msg)  {
  msg->magic = 0x01;
  msg->length = 0x01;
  msg->type = 0x1b;
  msg->checksum = checksum(msg);
}

/*
* Usage:    challenge_request(message);
* Function: Modifies message to reflect a response to a challenge. Updates the checksum as appropriate.
*/
void challenge_response(struct rmessage *msg, unsigned char *solution) {
  msg->magic = 0x01;
  msg->length = 0x21;
  msg->type = 0x09;
  memcpy(msg->data, solution, 0x20);
  msg->checksum = checksum(msg);
}

/*
* Usage:    buffer = message2buffer(message); send(buffer, message->length + 10); free(buffer)
* Function: Allocates a buffer for transmission and fills the buffer with message data such that it is ready to transmit.
*/
//TODO: conver to a sendMessage() function?
char *message2buffer(struct rmessage *msg) {
  char *data;
  if(msg == NULL) {
    hydra_report(stderr, "rmessage is null\n");
    hydra_child_exit(0);
    return NULL;
  }

  switch(msg->type) {
    case 0x1b: //Challenge request
      data = calloc (10, sizeof(unsigned char)); //TODO: check return
      memcpy(data, &msg->magic, sizeof(char));
      *((int *)(data+1)) = htonl(msg->length);
      *((int *)(data+5)) = htonl(msg->checksum);
      memcpy((data+9), &msg->type, sizeof(char));
      break;
    case 0x09:
      data = calloc (42, sizeof(unsigned char)); //TODO: check return
      memcpy(data, &msg->magic, sizeof(char));
      *((int *)(data+1)) = htonl(msg->length);
      *((int *)(data+5)) = htonl(msg->checksum);
      memcpy((data+9), &msg->type, sizeof(char));
      memcpy((data+10), msg->data, sizeof(char) * 32);
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
  //TODO: check return

  //Start parsing...
  msg->magic = buffer[0];
  buffer += sizeof(char);
  msg->length = ntohl(*((unsigned int *)(buffer)));
  buffer += sizeof(unsigned int);
  msg->checksum = ntohl(*((unsigned int *)(buffer)));
  buffer += sizeof(unsigned int);
  msg->type = buffer[0];
  buffer += sizeof(char);

  //Verify known fields...
  if(msg->magic != 0x01) {
    hydra_report(stderr, "Bad magic\n");
    hydra_child_exit(0);
    return NULL;
  }

  switch(msg->type) {
    case 0x1b:
      if(msg->length != 0x21) {
        hydra_report(stderr, "Bad length...%08x\n", msg->length);
        hydra_child_exit(0);
        return NULL;
      }
      memcpy(msg->data, buffer, 32);
      break;
    case 0x0a:
      //Win!
    case 0x0b:
      //Lose!
      break;
    default:
      hydra_report(stderr, "unknown rmessage type");
      hydra_child_exit(0);
      return NULL;
  }
  return msg;
}


int start_radmin2(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp) {
  return 0;
}

void service_radmin2(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname) {
  int sock = -1;
  int index;
  int bytecount;
  char *request;
  struct rmessage *msg;
  int myport = PORT_RADMIN2;
  char buffer[42];
  char password[101];
  unsigned char rawkey[16];
  char pkey[33];
  char *IV = "FEDCBA9876543210A39D4A18F85B4A52";
  unsigned char encrypted[32];

  //Initialization nonsense.
  MD5_CTX md5c;
  keyInstance key;
  cipherInstance cipher;

  if(port != 0) {
    myport = port;
  }

  memset(buffer, 0x00, sizeof(buffer));
  memset(pkey, 0x00, 33); 
  memset(encrypted, 0x00, 32); 
  memset(password, 0x00, 100); 

  //Phone the mother ship
  hydra_register_socket(sp);
  if( memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
    return;
  }
  
  // Get a password to work with.  
  strncpy(password, hydra_get_next_password(), 101);
  MD5_Init(&md5c);
  MD5_Update(&md5c, password, 100);
  MD5_Final(rawkey, &md5c); 
  //Copy raw md5 data into ASCIIZ string
  for(index = 0; index < 16; index++) {
    count = sprintf((pkey+index*2), "%02x", rawkey[index]);
  }

  /* Typical conversation goes as follows...
  0) connect to server
  1) request challenge
  2) receive 32 byte challenge response
  3) send 32 byte challenge solution
  4) receive 1 byte auth success/fail message
  */
  // 0) Connect to the server
  sock = hydra_connect_tcp(ip, myport);
  if(sock < 0) {
    hydra_report(stderr, "Error: Child with pid %d terminating, can not connect\n", (int)getpid());
    hydra_child_exit(1);
  }

  // 1) request challenge (working)
  msg = calloc(1, sizeof(struct rmessage));
  challenge_request(msg);
  request = message2buffer(msg);
  hydra_send(sock, request, 10, 0);
  free(msg); 
  free(request);

  //2) receive response (working)
  index = 0;
  while(index < 42) { //We're always expecting back a 42 byte buffer from a challenge request.
    switch(hydra_data_ready(sock)) {
      case -1:
        hydra_report(stderr, "Error: Child with pid %d terminating, receive error\nerror:\t%s\n", (int)getpid(), strerror(errno));
        hydra_child_exit(1);
        break;
      case 0:
        //keep waiting...
        break;
      default:  
        bytecount = hydra_recv(sock, buffer+index, 42 - index);
        if(bytecount < 0) {
          hydra_report(stderr, "Error: Child with pid %d terminating, receive error\nerror:\t%s\n", (int)getpid(), strerror(errno));
          hydra_child_exit(1);
        }
        index += bytecount;
    }
  }
  
  //3) Send challenge solution.

  //3.a) generate a new message from the buffer
  msg = buffer2message(buffer);

  //3.b) encrypt data received using pkey & known IV
  index = makeKey(&key, DIR_ENCRYPT, 128, pkey);
  if(index != TRUE) {
    hydra_report(stderr, "Error: Child with pid %d terminating, make key error (%08x)\n", (int)getpid(), index);
    hydra_child_exit(1);
  }

  index = cipherInit(&cipher, MODE_CBC, IV);
  if(index != TRUE) {
    hydra_report(stderr, "Error: Child with pid %d terminating, cipher init error(%08x)\n", (int)getpid(), index);
    hydra_child_exit(1);
  }

  index = blockEncrypt(&cipher, &key, msg->data, 32 * 8, encrypted);
  if(index <= 0) {
    hydra_report(stderr, "Error: Child with pid %d terminating, encrypt error(%08x)\n", (int)getpid(), index);
    hydra_child_exit(1);
  }
  
  //3.c) half sum - this is the solution to the challenge.
  for(index=0; index < 16; index++) {
    *(encrypted+index) += *(encrypted+index+16);
  }
  memset((encrypted+16), 0x00, 16);

  //3.d) send half sum
  challenge_response(msg, encrypted);
  request = message2buffer(msg);
  hydra_send(sock, request, 42, 0);
  free(msg);
  free(request);

  //4) receive auth success/failure
  index = 0;
  while(index < 10) { //We're always expecting back a 42 byte buffer from a challenge request.
    switch(hydra_data_ready(sock)) {
      case -1:
          hydra_report(stderr, "Error: Child with pid %d terminating, receive error\nerror:\t%s\n", (int)getpid(), strerror(errno));
        hydra_child_exit(1);
        break;
      case 0:
        //keep waiting...
        break;
      default:  
        bytecount = hydra_recv(sock, buffer+index, 10 - index);
        if(bytecount < 0) {
          hydra_report(stderr, "Error: Child with pid %d terminating, receive error\nerror:\t%s\n", (int)getpid(), strerror(errno));
          hydra_child_exit(1);
        }
        index += bytecount;
    }
  }
  msg = buffer2message(buffer);
  if(msg->type == 0x0a) {
    hydra_completed_pair_found();
  }
  //5) Disconnect
  hydra_disconnect(sock); 
}

int service_radmin2_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname) {
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
