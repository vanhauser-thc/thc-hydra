#ifndef _HYDRA_SERVICE_POP3_H_
#define _HYDRA_SERVICE_POP3_H_

void service_pop3(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_pop3_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_pop3(const char* service);

#endif /* _HYDRA_SERVICE_POP3_H_ */
