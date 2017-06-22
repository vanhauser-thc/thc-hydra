#ifndef _HYDRA_SERVICE_ADAM6500_H_
#define _HYDRA_SERVICE_ADAM6500_H_

void service_adam6500(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_adam6500_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_adam6500(const char* service);

#endif /* _HYDRA_SERVICE_ADAM6500_H_ */
