#ifndef _HYDRA_SERVICE_SMB_H_
#define _HYDRA_SERVICE_SMB_H_

void service_smb(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_smb_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_smb(const char* service);

#endif /* _HYDRA_SERVICE_SMB_H_ */
