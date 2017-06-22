#ifndef _HYDRA_SERVICE_RTSP_H_
#define _HYDRA_SERVICE_RTSP_H_

void service_rtsp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_rtsp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_rtsp(const char* service);

#endif /* _HYDRA_SERVICE_RTSP_H_ */
