#ifndef _HYDRA_SERVICE_S7_300_H_
#define _HYDRA_SERVICE_S7_300_H_

void service_s7_300(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_s7_300_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_s7_300(const char* service);

#endif /* _HYDRA_SERVICE_S7_300_H_ */
