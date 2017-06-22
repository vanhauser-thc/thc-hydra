#ifndef _HYDRA_SERVICE_SAPR3_H_
#define _HYDRA_SERVICE_SAPR3_H_

void service_sapr3(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_sapr3_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_sapr3(const char* service);

#endif /* _HYDRA_SERVICE_SAPR3_H_ */
