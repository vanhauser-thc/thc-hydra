#ifndef _HYDRA_SERVICE_MYSQL_H_
#define _HYDRA_SERVICE_MYSQL_H_

void service_mysql(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_mysql_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_mysql(const char* service);

#endif /* _HYDRA_SERVICE_MYSQL_H_ */
