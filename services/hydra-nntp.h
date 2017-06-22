#ifndef _HYDRA_SERVICE_NNTP_H_
#define _HYDRA_SERVICE_NNTP_H_

void service_nntp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_nntp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_nntp(const char* service);

#endif /* _HYDRA_SERVICE_NNTP_H_ */
