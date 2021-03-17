// This plugin was written by <david dot maciejak at kyxar dot fr>
//
// PC-Anywhere authentication protocol test on Symantec PC-Anywhere 10.5
//
// no memleaks found on 110425

#include "hydra-mod.h"

extern char *HYDRA_EXIT;

int32_t pcadebug = 0;

int32_t send_cstring(int32_t s, char *crypted_string) {
  char buffer2[100], *bptr = buffer2;
  char clientcryptheader[] = "\x06";

  memset(buffer2, 0, sizeof(clientcryptheader));
  bptr = buffer2;
  buffer2[0] = 6;
  bptr++;
  buffer2[1] = strlen(crypted_string);
  bptr++;
  strcpy(bptr, crypted_string);

  return hydra_send(s, buffer2, 2 + strlen(crypted_string), 0);
}

void show_buffer(char *buffer, int32_t size) {
  int32_t i;

  printf("size: %d, buffer:\n", size);
  for (i = 0; i < size; i++) {
    printf("%c", buffer[i]);
  }
  printf("\n");
}

void clean_buffer(char *buf, int32_t size) {
  int32_t i;

  for (i = 0; i < size; i++) {
    int32_t pos = buf[i];

    if (pos < 32 || pos > 126) {
      // . char
      buf[i] = 46;
    }
  }
}

void print_encrypted_str(char *str) {
  int32_t i;

  printf("encode string: ");
  for (i = 0; i < strlen(str); i++) {
    printf("%x ", str[i]);
  }
  printf("\n");
}

void pca_encrypt(char *cleartxt) {
  char passwd[128];
  int32_t i;

  strncpy(passwd, cleartxt, sizeof(passwd) - 1);
  passwd[sizeof(passwd) - 1] = 0;
  if (strlen(cleartxt) > 0) {
    passwd[0] = (passwd[0] ^ 0xab);
    for (i = 1; i < strlen(passwd); i++)
      passwd[i] = passwd[i - 1] ^ passwd[i] ^ (i - 1);
    passwd[strlen(passwd)] = '\0';
    strcpy(cleartxt, passwd);
  }
}

void pca_decrypt(char *password) {
  char cleartext[128];
  int32_t i;

  if (strlen(password) > 0) {
    cleartext[0] = password[0] ^ 0xab;
    for (i = 1; i < strlen(password); i++)
      cleartext[i] = password[i - 1] ^ password[i] ^ (i - 1);
    cleartext[strlen(password)] = '\0';
    strcpy(password, cleartext);
  }
}

void debugprintf(char *msg) {
  if (pcadebug)
    printf("debug: %s\n", msg);
}

int32_t start_pcanywhere(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;
  char buffer[2048] = "";
  char clogin[128] = "";
  char cpass[128] = "";
  int32_t ret, i;

  char *client[4];
  char *server[5];
  int32_t clientsize[4];

  client[0] = "\x00\x00\x00\x00";
  clientsize[0] = 4;
  client[1] = "\x6F\x06\xff";
  clientsize[1] = 3;
  client[2] = "\x6f\x61\x00\x09\x00\xfe\x00\x00\xff\xff\x00\x00\x00\x00";
  clientsize[2] = 14;
  client[3] = "\x6f\x62\x01\x02\x00\x00\x00";
  clientsize[3] = 7;

  server[0] = "nter";
  server[1] = "\x1B\x61";
  server[2] = "\0x1B\0x62";
  server[3] = "Enter login name";
  server[4] = "denying connection";

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  debugprintf("dans pcanywhere start");

  /*printf("testing %s:%s\n",login,pass); */

  strcpy(clogin, login);
  strcpy(cpass, pass);

  pca_encrypt(clogin);
  pca_encrypt(cpass);

  for (i = 0; i < 4; i++) {
    if (hydra_send(s, client[i], clientsize[i], 0) < 0) {
      return 1;
    }

    ret = hydra_recv(s, buffer, sizeof(buffer) - 1);
    if (ret == -1) {
      return 1;
    }

    if (i == 3) {
      if (ret == 3) {
        /*one more to get the login prompt */
        ret = hydra_recv(s, buffer, sizeof(buffer) - 1);
      }
    }

    if (ret >= 0)
      buffer[ret] = 0;

    if (i == 0 || i == 3)
      clean_buffer(buffer, ret);

    if (debug)
      show_buffer(buffer, ret);

    if (i == 2) {
      clean_buffer(buffer, ret);
      buffer[sizeof(buffer) - 1] = 0;
      if (strstr(buffer, server[i + 2]) != NULL) {
        fprintf(stderr, "[ERROR] PC Anywhere host denying connection because "
                        "you have requested a lower encrypt level\n");
        return 3;
      }
    }

    if (strstr(buffer, server[i]) == NULL) {
      if (i == 3) {
        debugprintf("problem receiving login banner");
      }
      return 1;
    }
  }

  if (send_cstring(s, clogin) < 0) {
    return 1;
  }
  ret = hydra_recv(s, buffer, sizeof(buffer) - 1);
  if (ret < 0) {
    return 1;
  }
  buffer[ret] = 0;
  clean_buffer(buffer, ret);
  /*show_buffer(buffer,ret); */
  if (strstr(buffer, "Enter password:") == NULL) {
    debugprintf("problem receiving password banner");
    return 1;
  }

  if (send_cstring(s, cpass) < 0) {
    return 1;
  }

  ret = hydra_recv(s, buffer, sizeof(buffer));
  if (ret < 0)
    return 1;
  else
    buffer[ret] = 0;

  clean_buffer(buffer, ret);
  /*show_buffer(buffer,ret); */

  if ((strstr(buffer, "Invalid login") != NULL) || (strstr(buffer, "Enter password") != NULL)) {
    debugprintf("login/passwd wrong");

    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 2;
  } else {
    debugprintf("cool find login/passwd");

    hydra_report_found_host(port, ip, "pcanywhere", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 2;
  }
  return 1;
}

void service_pcanywhere(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_PCANYWHERE, mysslport = PORT_PCANYWHERE_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      usleepn(275);
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
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }

      next_run = 2;
      break;

    case 2:

      next_run = start_pcanywhere(sock, ip, port, options, miscptr, fp);
      break;
    case 3:

      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;

    default:

      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_pcanywhere_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
