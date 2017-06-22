#ifndef _HYDRA_SERVICE_PCNFS_H_
#define _HYDRA_SERVICE_PCNFS_H_

void service_pcnfs(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_pcnfs_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_pcnfs(const char* service);

#endif /* _HYDRA_SERVICE_PCNFS_H_ */
