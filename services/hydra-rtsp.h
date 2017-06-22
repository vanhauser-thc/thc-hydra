#ifndef _HYDRA_SERVICE_RTSP_H_
#define _HYDRA_SERVICE_RTSP_H_

void service_rtsp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_rtsp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_RTSP { \
    "rtsp", \
    service_rtsp_init, \
    service_rtsp, \
    NULL \
}

#endif /* _HYDRA_SERVICE_RTSP_H_ */
