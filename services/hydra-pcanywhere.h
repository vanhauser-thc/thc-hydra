#ifndef _HYDRA_SERVICE_PCANYWHERE_H_
#define _HYDRA_SERVICE_PCANYWHERE_H_

void service_pcanywhere(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_pcanywhere_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_PCANYWHERE { \
    "pcanywhere", \
    service_pcanywhere_init, \
    service_pcanywhere, \
    NULL \
}

#endif /* _HYDRA_SERVICE_PCANYWHERE_H_ */
