#ifndef _HYDRA_SERVICE_SMB_H_
#define _HYDRA_SERVICE_SMB_H_

void service_smb(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_smb_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_smb(const char* service);

#define SERVICE_SMB { \
    "smb", \
    service_smb_init, \
    service_smb, \
    usage_smb \
}

#define SERVICE_SMBNT { \
    "smbnt", \
    service_smb_init, \
    service_smb, \
    usage_smb \
}

#endif /* _HYDRA_SERVICE_SMB_H_ */
