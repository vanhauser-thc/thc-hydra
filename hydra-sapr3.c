#include "hydra-mod.h"
// checked for memleaks on 110425, none found
#ifndef LIBSAPR3
void dummy_sapr3() { printf("\n"); }
#else

#include <ctype.h>
#include <saprfc.h>

/* temporary workaround fix */
const int32_t *__ctype_tolower;
const int32_t *__ctype_toupper;
const int32_t *__ctype_b;

extern void flood(); /* for -lm */

extern char *HYDRA_EXIT;
RFC_ERROR_INFO_EX error_info;

int32_t start_sapr3(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  RFC_HANDLE handle;
  char *empty = "";
  char *login, *pass, buffer[1024];
  char *buf;
  int32_t i;
  int32_t sysnr = port % 100;
  char opts[] = "RFCINI=N RFCTRACE=N BALANCE=N DEBUG=N TRACE=0 ABAP_DEBUG=0";

  //  char opts[] = "RFCINI=N RFCTRACE=Y BALANCE=N DEBUG=Y TRACE=Y
  //  ABAP_DEBUG=Y";

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  if (strlen(login) > 0)
    for (i = 0; i < strlen(login); i++)
      login[i] = (char)toupper(login[i]);
  if (strlen(pass) > 0)
    for (i = 0; i < strlen(pass); i++)
      pass[i] = (char)toupper(pass[i]);

  memset(buffer, 0, sizeof(buffer));
  memset(&error_info, 0, sizeof(error_info));

  // strcpy(buf, "mvse001");
  snprintf(buffer, sizeof(buffer), "ASHOST=%s SYSNR=%02d CLIENT=%03d USER=\"%s\" PASSWD=\"%s\" LANG=DE %s", hydra_address2string(ip), sysnr, atoi(miscptr), login, pass, opts);

  /*
    USER=SAPCPIC PASSWORD=admin
    USER=SAP*    PASSWORD=PASS

    ## do we need these options?
    SAPSYS=3 SNC_MODE=N SAPGUI=N INVISIBLE=N GUIATOPEN=Y NRCALL=00001 CLOSE=N

    ASHOST= //  IP
    SYSNR=  // port - 3200, scale 2
    CLIENT= // miscptr, scale 2
    ABAP_DEBUG=0
    USER=
    PASSWD=
    LANG=DE
  */
  // printf ("DEBUG: %d Connectstring \"%s\"\n",sizeof(error_info),buffer);
  handle = RfcOpenEx(buffer, &error_info);

  // printf("DEBUG: handle %d, key %s, message %s\n", handle, error_info.key,
  // error_info.message);

  if (handle <= RFC_HANDLE_NULL)
    return 3;

  if (strstr(error_info.message, "sapgui") != NULL || strlen(error_info.message) == 0) {
    hydra_report_found_host(port, ip, "sapr3", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 2;
    return 1;
  } else {
    if (strstr(error_info.key, "ERROR_COMMUNICATION") != NULL) {
      /* sysnr does not exist, report as port closed */
      return 3;
    }
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 2;
  }
  return 1;
}

void service_sapr3(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      next_run = start_sapr3(sock, ip, port, options, miscptr, fp);
      break;
    case 2:
      hydra_child_exit(0);
    case 3: /* clean exit */
      fprintf(stderr, "[ERROR] could not connect to target port %d\n", port);
      hydra_child_exit(1);
    case 4:
      hydra_child_exit(2);
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

#endif

int32_t service_sapr3_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_sapr3(const char *service) { printf("Module sapr3 requires the client id, a number between 0 and 99\n\n"); }
