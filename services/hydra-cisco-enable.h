#ifndef _HYDRA_SERVICE_CISCO_ENABLE_H_
#define _HYDRA_SERVICE_CISCO_ENABLE_H_

void service_cisco_enable(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_cisco_enable_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_cisco_enable(const char* service);

#define SERVICE_CISCO_ENABLE { "cisco-enable", service_cisco_enable_init, service_cisco_enable, usage_cisco_enable }

#endif /* _HYDRA_SERVICE_CISCO_ENABLE_H_ */
