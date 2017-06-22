#ifndef _HYDRA_SERVICE_HTTP_PROXY_H_
#define _HYDRA_SERVICE_HTTP_PROXY_H_

void service_http_proxy(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_http_proxy_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_http_proxy(const char* service);

#define SERVICE_HTTP_PROXY { \
    "http-proxy", \
    service_http_proxy_init, \
    service_http_proxy, \
    usage_http_proxy \
}

#endif /* _HYDRA_SERVICE_HTTP_PROXY_H_ */
