#ifndef _HYDRA_H

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <errno.h>

#ifdef HAVE_OPENSSL
#define HYDRA_SSL
#endif
#ifdef HAVE_SSL
#ifndef HYDRA_SSL
#define HYDRA_SSL
#endif
#endif

#ifdef LIBSSH
#include <libssh/libssh.h>
#endif

#define OPTION_SSL 1

#define PORT_NOPORT     -1
#define PORT_FTP	21
#define PORT_FTP_SSL	990
#define PORT_TELNET	23
#define PORT_TELNET_SSL	992
#define PORT_HTTP	80
#define PORT_HTTP_SSL	443
#define PORT_HTTP_PROXY 3128
#define PORT_HTTP_PROXY_SSL 3128
#define PORT_POP3	110
#define PORT_POP3_SSL	995
#define PORT_NNTP	119
#define PORT_NNTP_SSL	563
#define PORT_SMB	139
#define PORT_SMB_SSL    139
#define PORT_SMBNT	445
#define PORT_SMBNT_SSL  445
#define PORT_IMAP	143
#define PORT_IMAP_SSL	993
#define PORT_LDAP	389
#define PORT_LDAP_SSL   636
#define PORT_REXEC	512
#define PORT_REXEC_SSL	512
#define PORT_RLOGIN	513
#define PORT_RLOGIN_SSL	513
#define PORT_RSH	514
#define PORT_RSH_SSL	514
#define PORT_SOCKS5     1080
#define PORT_SOCKS5_SSL 1080
#define PORT_ICQ	4000
#define PORT_ICQ_SSL	-1
#define PORT_VNC	5900
#define PORT_VNC_SSL	5901
#define PORT_PCNFS	0
#define PORT_PCNFS_SSL	-1
#define PORT_MYSQL      3306
#define PORT_MYSQL_SSL  3306
#define PORT_MSSQL	1433
#define PORT_MSSQL_SSL	1433
#define PORT_POSTGRES	5432
#define PORT_POSTGRES_SSL 5432
#define PORT_ORACLE     1521
#define PORT_ORACLE_SSL 1521
#define PORT_PCANYWHERE 5631
#define PORT_PCANYWHERE_SSL 5631
#define PORT_SAPR3      -1
#define PORT_SAPR3_SSL  -1
#define PORT_SSH        22
#define PORT_SSH_SSL    22
#define PORT_SNMP       161
#define PORT_SNMP_SSL   1993
#define PORT_CVS        2401
#define PORT_CVS_SSL    2401
#define PORT_FIREBIRD   3050
#define PORT_FIREBIRD_SSL 3050
#define PORT_AFP	548
#define PORT_AFP_SSL	548
#define PORT_NCP        524
#define PORT_NCP_SSL    524
#define PORT_SVN        3690
#define PORT_SVN_SSL    3690
#define PORT_SMTP   25
#define PORT_SMTP_SSL 465
#define PORT_TEAMSPEAK  8767
#define PORT_TEAMSPEAK_SSL 8767
#define PORT_SIP	5060
#define PORT_SIP_SSL	5061
#define PORT_VMAUTHD	902
#define PORT_VMAUTHD_SSL	902
#define PORT_XMPP       5222
#define PORT_XMPP_SSL   5223
#define PORT_IRC        6667
#define PORT_IRC_SSL    6697
#define PORT_RDP        3389
#define PORT_RDP_SSL    3389
#define PORT_ASTERISK   5038 
#define PORT_ASTERISK_SSL  5038 
#define PORT_S7_300      102
#define PORT_S7_300_SSL  102
#define PORT_REDIS      6379
#define PORT_REDIS_SSL   6379

#define False 0
#define True  1

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#define _HYDRA_H
#endif
