#ifndef _HYDRA_SERVICE_POSTGRES_H_
#define _HYDRA_SERVICE_POSTGRES_H_

void service_postgres(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_postgres_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_postgres(const char* service);

#define SERVICE_POSTGRES { \
    "postgres", \
    service_postgres_init, \
    service_postgres, \
    usage_postgres \
}

#endif /* _HYDRA_SERVICE_POSTGRES_H_ */
