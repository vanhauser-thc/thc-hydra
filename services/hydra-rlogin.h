#ifndef _HYDRA_SERVICE_RLOGIN_H_
#define _HYDRA_SERVICE_RLOGIN_H_

void service_rlogin(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_rlogin_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_RLOGIN { \
    "rlogin", \
    service_rlogin_init, \
    service_rlogin, \
    NULL \
}

#endif /* _HYDRA_SERVICE_RLOGIN_H_ */
