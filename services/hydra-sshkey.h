#ifndef _HYDRA_SERVICE_SSHKEY_H_
#define _HYDRA_SERVICE_SSHKEY_H_

void service_sshkey(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_sshkey_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_sshkey(const char* service);

#endif /* _HYDRA_SERVICE_SSHKEY_H_ */
