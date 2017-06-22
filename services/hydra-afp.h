#ifndef _HYDRA_SERVICE_AFP_H_
#define _HYDRA_SERVICE_AFP_H_

void service_afp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_afp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_afp(const char* service);

#endif /* _HYDRA_SERVICE_AFP_H_ */
