LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CFLAGS:= -O3 -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DHAVE_PCRE \
               -DLIBNCP -DLIBPOSTGRES -DLIBSVN -DLIBSSH -DNO_RINDEX \
               -DHAVE_MATH_H -DOPENSSL_NO_DEPRECATED -DNO_RSA_LEGACY \
               -fdata-sections -ffunction-sections          

LOCAL_LDFLAGS:=-Wl,--gc-sections

LOCAL_C_INCLUDES:= \
	$(LOCAL_PATH)\
	external/openssl/include\
	external/libssh/include\
	external/libidn/lib\
	external/subversion/subversion/include\
	external/apr/include\
	external/libncp/include\
	external/libpcre
	
LOCAL_SRC_FILES:= \
	bfg.c\
	crc32.c\
	d3des.c\
	hmacmd5.c\
	hydra-afp.c\
	hydra-asterisk.c\
	hydra.c\
	hydra-cisco.c\
	hydra-cisco-enable.c\
	hydra-cvs.c\
	hydra-firebird.c\
	hydra-ftp.c\
	hydra-http.c\
	hydra-http-form.c\
	hydra-http-proxy.c\
	hydra-http-proxy-urlenum.c\
	hydra-icq.c\
	hydra-imap.c\
	hydra-irc.c\
	hydra-ldap.c\
	hydra-mod.c\
	hydra-memcached.c\
	hydra-mongodb.c\
	hydra-mssql.c\
	hydra-mysql.c\
	hydra-ncp.c\
	hydra-nntp.c\
	hydra-oracle.c\
	hydra-oracle-listener.c\
	hydra-oracle-sid.c\
	hydra-pcanywhere.c\
	hydra-pcnfs.c\
	hydra-pop3.c\
	hydra-postgres.c\
	hydra-rdp.c\
	hydra-redis.c\
	hydra-rexec.c\
	hydra-rlogin.c\
	hydra-rsh.c\
	hydra-rtsp.c\
	hydra-s7-300.c\
	hydra-sapr3.c\
	hydra-sip.c\
	hydra-smb.c\
	hydra-smtp.c\
	hydra-smtp-enum.c\
	hydra-snmp.c\
	hydra-socks5.c\
	hydra-ssh.c\
	hydra-sshkey.c\
	hydra-svn.c\
	hydra-teamspeak.c\
	hydra-telnet.c\
	hydra-vmauthd.c\
	hydra-vnc.c\
	hydra-xmpp.c\
	ntlm.c\
	sasl.c

LOCAL_STATIC_LIBRARIES := \
	libidn \
	libncp \
	libpcre \
	libpcrecpp \
	libpcreposix \
	libpq \
	libssh \
	libsvn_client-1 \
	libapr-1 \
	libaprutil-1 \
	libiconv\
	libneon\
	libssl_static\
	libcrypto_static\
	libmemcached
						
LOCAL_SHARED_LIBRARIES := \
	libsqlite\
	libexpat
					
LOCAL_MODULE:= hydra

include $(BUILD_EXECUTABLE)
