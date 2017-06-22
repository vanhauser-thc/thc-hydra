#ifndef _HYDRA_SERVICE_ICQ_H_
#define _HYDRA_SERVICE_ICQ_H_

void service_icq(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_icq_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_ICQ { \
    "icq", \
    service_icq_init, \
    service_icq, \
    NULL \
}

#endif /* _HYDRA_SERVICE_ICQ_H_ */
