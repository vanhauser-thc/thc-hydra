#ifndef _HYDRA_SERVICE_SMTP_H_
#define _HYDRA_SERVICE_SMTP_H_

void service_smtp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_smtp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_smtp(const char* service);

#endif /* _HYDRA_SERVICE_SMTP_H_ */
