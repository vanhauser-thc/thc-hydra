#ifndef _HYDRA_SERVICE_REXEC_H_
#define _HYDRA_SERVICE_REXEC_H_

void service_rexec(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_rexec_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_REXEC { \
    "rexec", \
    service_rexec_init, \
    service_rexec, \
    NULL \
}

#endif /* _HYDRA_SERVICE_REXEC_H_ */
