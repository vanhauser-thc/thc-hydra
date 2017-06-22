#ifndef _HYDRA_SERVICE_RSH_H_
#define _HYDRA_SERVICE_RSH_H_

void service_rsh(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_rsh_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_RSH { \
    "rsh", \
    service_rsh_init, \
    service_rsh, \
    NULL \
}

#endif /* _HYDRA_SERVICE_RSH_H_ */
