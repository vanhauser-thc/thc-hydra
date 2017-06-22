#ifndef _HYDRA_SERVICE_SAPR3_H_
#define _HYDRA_SERVICE_SAPR3_H_

void service_sapr3(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_sapr3_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_sapr3(const char* service);

#define SERVICE_SAPR3 { \
    "sapr3", \
    service_sapr3_init, \
    service_sapr3, \
    usage_sapr3 \
}

#endif /* _HYDRA_SERVICE_SAPR3_H_ */
