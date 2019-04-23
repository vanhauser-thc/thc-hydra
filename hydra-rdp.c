/*
   david: this module is heavily based on rdesktop v 1.7.0

   rdesktop: A Remote Desktop Protocol client.
   Protocol services - RDP layer
   Copyright (C) Matthew Chapman <matthewc.unsw.edu.au> 1999-2008
   Copyright 2003-2011 Peter Astrand <astrand@cendio.se> for Cendio AB

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

note:

this module was tested on w2k, xp, w2k3, w2k8

in terminal services configuration, in rdp-tcp properties
in Logon Settings tab, if 'Always prompt for password' is checked,
the password can't be passed interactively so there is no way
to test the credential (unless manually).

it's advised to lower the number of parallel tasks as RDP server
can't handle multiple connections at the same time.
It's particularly true on windows XP

*/

#include "hydra-mod.h"

extern char *HYDRA_EXIT;
#ifndef LIBFREERDP2
void dummy_rdp() {
  printf("\n");
}
#else

#include <freerdp/freerdp.h>
freerdp * instance;
BOOL rdp_connect(char *server, int32_t port, char *domain, char *login, char *password) {
  instance->settings->Username = login;
  instance->settings->Password = password;
  int32_t ret = 0;
  instance->settings->IgnoreCertificate = TRUE;
  instance->settings->AuthenticationOnly = TRUE;
  instance->settings->ServerHostname = server;
  instance->settings->ServerPort = port;
  instance->settings->Domain = domain;
  ret = freerdp_connect(instance);
  return ret==1? True : False;
}

/* Client program */
int32_t start_rdp(char *ip, int32_t port, unsigned char options, char *miscptr, FILE * fp) {
  char *empty = "";
  char *login, *pass;
  char server[64];
  char domain[256];
  
  BOOL login_result = False;
  memset(domain, 0, sizeof(domain));

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  strcpy(server, hydra_address2string(ip));

  if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
    strncpy(domain, miscptr, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = 0;
  }

  login_result = rdp_connect(server, port, domain, login, pass);
  
  int x = 0;
  x = freerdp_get_last_error(instance->context);
  int err = freerdp_get_last_error(instance->context);
  if ( err != 0 && err != 0x00020014) { //0x00020014 == logon failed
    return 3;
  }

  if (login_result == True) {
    hydra_report_found_host(port, ip, "rdp", fp);
    hydra_completed_pair_found();
  } else {
    hydra_completed_pair();
  }

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 2;
  return 1;

}

void service_rdp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE * fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1;
  int32_t myport = PORT_RDP;

  if (port != 0)
    myport = port;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    next_run = 0;
    switch (run) {
    case 1:                    /* run the cracking function */
      next_run = start_rdp(ip, port, options, miscptr, fp);
      break;
    case 2:                    /* clean exit */
      freerdp_disconnect(instance);
      hydra_child_exit(0);
      return;
    case 3:                    /* connection error case */
      hydra_report(stderr, "[ERROR] freerdp: %s\n", freerdp_get_last_error_string(freerdp_get_last_error(instance->context)));
      hydra_child_exit(1);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_rdp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE * fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  // 
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here

  // Disable freerdp output
  wLog* root = WLog_GetRoot();
  WLog_SetStringLogLevel(root, "OFF"); 

  // Init freerdp instance
  instance = freerdp_new();
  freerdp_context_new(instance);
  return 0;
}

void usage_rdp(const char* service) {
  printf("Module rdp is optionally taking the windows domain name.\n" "For example:\nhydra rdp://192.168.0.1/firstdomainname -l john -p doe\n\n");
}
#endif