#ifndef _HYDRA_SERVICE_ORACLE_SID_H_
#define _HYDRA_SERVICE_ORACLE_SID_H_

void service_oracle_sid(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_oracle_sid_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_oracle_sid(const char* service);

#endif /* _HYDRA_SERVICE_ORACLE_SID_H_ */
