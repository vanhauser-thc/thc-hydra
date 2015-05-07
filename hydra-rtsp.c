//
//  hydra-rtsp.c
//  hydra-rtsp
//
//  Created by Javier Sánchez on 18/04/15.
//
//

#include <stdio.h>
#include "hydra-mod.h"
#include <string.h>
#include "sasl.h"

extern char *HYDRA_EXIT;
char *buf;
char packet[500];
char packet2[500];

int is_Unauthorized(char *s) {

  if (strstr(s, "401 Unauthorized") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

int is_NotFound(char *s) {

  if (strstr(s, "404 Stream Not Found") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

int is_Authorized(char *s) {

  if (strstr(s, "200 OK") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

int use_Basic_Auth(char *s) {

  if (strstr(s, "WWW-Authenticate: Basic") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

int use_Digest_Auth(char *s) {

  if (strstr(s, "WWW-Authenticate: Digest") != NULL) {
    return 1;
  } else {
    return 0;
  }
}



void create_core_packet(int control, char *ip, int port) {

  char buffer[500];
  char *target = hydra_address2string(ip);

  if (control == 0) {
    if (strlen(packet) <= 0) {
      sprintf(packet, "DESCRIBE rtsp://%.260s:%i RTSP/1.0\r\nCSeq: 2\r\n\r\n", target, port);
    }
  } else {
    if (strlen(packet2) <= 0) {
      sprintf(packet2, "DESCRIBE rtsp://%s.260:%i RTSP/1.0\r\nCSeq: 3\r\n", target, port);
    }
  }
}
int start_rtsp(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp) {
  char *empty = "";
  char *login, *pass, buffer[500], buffer2[500];

  char *lresp;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  create_core_packet(0, ip, port);

  if (hydra_send(s, packet, strlen(packet), 0) < 0) {
    return 1;
  }
  lresp = hydra_receive_line(s);

  if (lresp == NULL) {
    fprintf(stderr, "[ERROR] no server reply");
    return 1;
  }

  if (is_NotFound(lresp)) {
    printf("[INFO] Server does not need credentials\n");
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
      return 3;
    }
    return 1;
  } else {

    create_core_packet(1, ip, port);

    if (use_Basic_Auth(lresp) == 1) {

      sprintf(buffer2, "%.260s:%.260s", login, pass);
      hydra_tobase64((unsigned char *) buffer2, strlen(buffer2), sizeof(buffer2));

      sprintf(buffer, "%sAuthorization: : Basic %s\r\n\r\n", packet2, buffer2);

      if (debug) {
        hydra_report(stderr, "C:%s\n", buffer);
      }
    }

    if (use_Digest_Auth(lresp) == 1) {
      char *dbuf;
      char dbuffer[500] = "";
      char aux[500] = "";

      char *pbuffer = hydra_strcasestr(lresp, "WWW-Authenticate: Digest ");

      strncpy(aux, pbuffer + strlen("WWW-Authenticate: Digest "), sizeof(buffer));
      aux[sizeof(aux) - 1] = '\0';
#ifdef LIBOPENSSL
      sasl_digest_md5(dbuf, login, pass, aux, miscptr, "rtsp", hydra_address2string(ip), port, "");
#else
      printf("[ERROR] Digest auth required but compiled without OpenSSL/MD5 support\n");
      return 3;
#endif

      if (dbuf == NULL) {
        fprintf(stderr, "[ERROR] digest generation failed\n");
        return 3;
      }
      sprintf(buffer, "%sAuthorization: Digest %s\r\n\r\n", packet2, dbuf);

      if (debug) {
        hydra_report(stderr, "C:%s\n", buffer);
      }
    }

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }

    lresp = NULL;

    lresp = hydra_receive_line(s);

    if ((is_NotFound(lresp))) {

      hydra_completed_pair_found();

      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
        return 3;
      }
      return 1;


    }
    hydra_completed_pair();
  }

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

//not rechead
  return 2;
}

void service_rtsp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  int run = 1, next_run = 1, sock = -1;
  int myport = PORT_RTSP, mysslport = PORT_RTSP_SSL;
  char *ptr, *ptr2;

  hydra_register_socket(sp);

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  while (1) {

    switch (run) {
    case 1:                    /* connect and service init function */
      if (sock >= 0) {
        sock = hydra_disconnect(sock);
      }
      if ((options & OPTION_SSL) == 0) {
        if (port != 0) {
          myport = port;
        }
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      }
      if (sock < 0) {
        if (verbose || debug)
          hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int) getpid());
        hydra_child_exit(1);
      }

      next_run = 2;
      break;
    case 2:                    /* run the cracking function */
      next_run = start_rtsp(sock, ip, port, options, miscptr, fp);
      break;
    case 3:                    /* clean exit */
      if (sock >= 0) {
        sock = hydra_disconnect(sock);
      }
      hydra_child_exit(0);
      break;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int service_rtsp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
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
