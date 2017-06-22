#ifndef _HYDRA_SERVICE_SMTP_ENUM_H_
#define _HYDRA_SERVICE_SMTP_ENUM_H_

void service_smtp_enum(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_smtp_enum_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_smtp_enum(const char* service);

#define SERVICE_SMTP_ENUM { \
    "smtp-enum", \
    service_smtp_enum_init, \
    service_smtp_enum, \
    usage_smtp_enum \
}

#endif /* _HYDRA_SERVICE_SMTP_ENUM_H_ */
