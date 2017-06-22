#ifndef _HYDRA_SERVICE_MSSQL_H_
#define _HYDRA_SERVICE_MSSQL_H_

void service_mssql(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_mssql_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_mssql(const char* service);

#endif /* _HYDRA_SERVICE_MSSQL_H_ */
