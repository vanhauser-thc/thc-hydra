#
# Makefile for Hydra - (c) 2001-2017 by van Hauser / THC <vh@thc.org>
#
OPTS=-I. -O3
# -Wall -g -pedantic
LIBS=-lm
BINDIR = /bin
MANDIR ?= /man/man1/
DATADIR ?= /etc
DESTDIR ?=

SRC = services/hydra-vnc.c services/hydra-pcnfs.c services/hydra-rexec.c \
      services/hydra-nntp.c services/hydra-socks5.c services/hydra-telnet.c \
      services/hydra-cisco.c services/hydra-http.c services/hydra-ftp.c \
      services/hydra-imap.c services/hydra-pop3.c services/hydra-smb.c \
      services/hydra-icq.c services/hydra-cisco-enable.c services/hydra-ldap.c \
      services/hydra-mysql.c services/hydra-mssql.c services/hydra-xmpp.c \
      services/hydra-http-proxy-urlenum.c services/hydra-snmp.c \
      services/hydra-cvs.c services/hydra-smtp.c services/hydra-smtp-enum.c \
      services/hydra-sapr3.c services/hydra-ssh.c services/hydra-sshkey.c \
      services/hydra-teamspeak.c services/hydra-postgres.c services/hydra-rsh.c \
      services/hydra-rlogin.c services/hydra-oracle-listener.c services/hydra-svn.c \
      services/hydra-pcanywhere.c services/hydra-sip.c services/hydra-oracle.c \
      services/hydra-vmauthd.c services/hydra-asterisk.c services/hydra-firebird.c \
      services/hydra-afp.c services/hydra-ncp.c services/hydra-oracle-sid.c \
      services/hydra-http-proxy.c services/hydra-http-form.c services/hydra-irc.c \
      services/hydra-rdp.c services/hydra-s7-300.c services/hydra-redis.c \
      services/hydra-adam6500.c services/hydra-rtsp.c services/hydra-rpcap.c \
      crc32.c d3des.c bfg.c ntlm.c sasl.c hmacmd5.c hydra-mod.c hydra-time.c
OBJ = services/hydra-vnc.o services/hydra-pcnfs.o services/hydra-rexec.o \
      services/hydra-nntp.o services/hydra-socks5.o services/hydra-telnet.o \
      services/hydra-cisco.o services/hydra-http.o services/hydra-ftp.o \
      services/hydra-imap.o services/hydra-pop3.o services/hydra-smb.o \
      services/hydra-icq.o services/hydra-cisco-enable.o services/hydra-ldap.o \
      services/hydra-mysql.o services/hydra-mssql.o services/hydra-xmpp.o \
      services/hydra-http-proxy-urlenum.o services/hydra-snmp.o \
      services/hydra-cvs.o services/hydra-smtp.o services/hydra-smtp-enum.o \
      services/hydra-sapr3.o services/hydra-ssh.o services/hydra-sshkey.o \
      services/hydra-teamspeak.o services/hydra-postgres.o services/hydra-rsh.o \
      services/hydra-rlogin.o services/hydra-oracle-listener.o services/hydra-svn.o \
      services/hydra-pcanywhere.o services/hydra-sip.o services/hydra-oracle-sid.o \
      services/hydra-oracle.o services/hydra-vmauthd.o services/hydra-asterisk.o \
      services/hydra-firebird.o services/hydra-afp.o services/hydra-ncp.o \
      services/hydra-http-proxy.o services/hydra-http-form.o services/hydra-irc.o \
      services/hydra-redis.o services/hydra-rdp.o services/hydra-s7-300.c \
      services/hydra-adam6500.o services/hydra-rtsp.o services/hydra-rpcap.o \
      crc32.o d3des.o bfg.o ntlm.o sasl.o hmacmd5.o hydra-mod.o hydra-time.o
BINS = hydra pw-inspector

EXTRA_DIST = README README.arm README.palm CHANGES TODO INSTALL LICENSE \
             hydra-mod.h hydra.h crc32.h d3des.h

all:	pw-inspector hydra $(XHYDRA_SUPPORT) 
	@echo
	@echo Now type "make install"

hydra:	hydra.c $(OBJ)
	$(CC) $(OPTS) $(SEC) $(LIBS) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o hydra $(HYDRA_LOGO) hydra.c $(OBJ) $(LIBS) $(XLIBS) $(XLIBPATHS) $(XIPATHS) $(XDEFINES)
	@echo
	@echo If men could get pregnant, abortion would be a sacrament
	@echo

xhydra:	
	-cd hydra-gtk && sh ./make_xhydra.sh

pw-inspector: pw-inspector.c
	-$(CC) $(OPTS) $(SEC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o pw-inspector $(PWI_LOGO) pw-inspector.c

.c.o:	
	$(CC) $(OPTS) $(SEC) $(CFLAGS) $(CPPFLAGS) -c $< $(XDEFINES) $(XIPATHS) -o $@

strip:	all
	strip $(BINS)
	-echo OK > /dev/null && test -x xhydra && strip xhydra || echo OK > /dev/null

install:	strip
	-mkdir -p $(DESTDIR)$(PREFIX)$(BINDIR)
	cp -f hydra-wizard.sh $(BINS) $(DESTDIR)$(PREFIX)$(BINDIR) && cd $(DESTDIR)$(PREFIX)$(BINDIR) && chmod 755 hydra-wizard.sh $(BINS)
	-echo OK > /dev/null && test -x xhydra && cp xhydra $(DESTDIR)$(PREFIX)$(BINDIR) && cd $(DESTDIR)$(PREFIX)$(BINDIR) && chmod 755 xhydra || echo OK > /dev/null
	-sed -e "s|^INSTALLDIR=.*|INSTALLDIR="$(PREFIX)"|" dpl4hydra.sh | sed -e "s|^LOCATION=.*|LOCATION="$(DATADIR)"|" > $(DESTDIR)$(PREFIX)$(BINDIR)/dpl4hydra.sh
	-chmod 755 $(DESTDIR)$(PREFIX)$(BINDIR)/dpl4hydra.sh
	-mkdir -p $(DESTDIR)$(PREFIX)$(DATADIR)
	-cp -f *.csv $(DESTDIR)$(PREFIX)$(DATADIR)
	-mkdir -p $(DESTDIR)$(PREFIX)$(MANDIR)
	-cp -f hydra.1 xhydra.1 pw-inspector.1 $(DESTDIR)$(PREFIX)$(MANDIR)

clean:
	rm -rf xhydra pw-inspector hydra *.o core *.core *.stackdump *~ Makefile.in Makefile dev_rfc hydra.restore arm/*.ipk arm/ipkg/usr/bin/* hydra-gtk/src/*.o hydra-gtk/src/xhydra hydra-gtk/stamp-h hydra-gtk/config.status hydra-gtk/errors hydra-gtk/config.log hydra-gtk/src/.deps hydra-gtk/src/Makefile hydra-gtk/Makefile
	cp -f Makefile.orig Makefile

