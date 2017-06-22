#ifndef _HYDRA_SERVICE_CISCO_H_
#define _HYDRA_SERVICE_CISCO_H_

void service_cisco(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_cisco_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_cisco(const char* service);

#endif /* _HYDRA_SERVICE_CISCO_H_ */
