#ifndef _HYDRA_SERVICE_HTTP_H_
#define _HYDRA_SERVICE_HTTP_H_

void service_http_get(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void service_http_head(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void service_http_post(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_http_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_http(const char* service);

#endif /* _HYDRA_SERVICE_HTTP_H_ */
