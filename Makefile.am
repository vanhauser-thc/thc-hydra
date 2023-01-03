#
# Makefile for Hydra - (c) 2001-2023 by van Hauser / THC <vh@thc.org>
#
WARN_CLANG=-Wformat-nonliteral -Wstrncat-size -Wformat-security -Wsign-conversion -Wconversion -Wfloat-conversion -Wshorten-64-to-32 -Wuninitialized -Wmissing-variable-declarations  -Wmissing-declarations
WARN_GCC=-Wformat=2 -Wformat-overflow=2 -Wformat-nonliteral -Wformat-truncation=2 -Wnull-dereference -Wstrict-overflow=2 -Wstringop-overflow=4 -Walloca-larger-than=4096 -Wtype-limits -Wconversion -Wtrampolines -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -fno-common -Wcast-align
CFLAGS ?= -g
OPTS=-I. -O3 $(CFLAGS) -fcommon
CPPFLAGS += -D_GNU_SOURCE
# -Wall -g -pedantic
LIBS=-lm
DESTDIR ?=
BINDIR = /bin
MANDIR = /man/man1/
DATADIR = /etc
PIXDIR = /share/pixmaps
APPDIR = /share/applications

SRC = hydra-vnc.c hydra-pcnfs.c hydra-rexec.c hydra-nntp.c hydra-socks5.c \
      hydra-telnet.c hydra-cisco.c hydra-http.c hydra-ftp.c hydra-imap.c \
      hydra-pop3.c hydra-smb.c hydra-icq.c hydra-cisco-enable.c hydra-ldap.c \
      hydra-memcached.c hydra-mongodb.c hydra-mysql.c hydra-mssql.c hydra-xmpp.c \
      hydra-http-proxy-urlenum.c hydra-snmp.c hydra-cvs.c hydra-smtp.c \
      hydra-smtp-enum.c hydra-sapr3.c hydra-ssh.c hydra-sshkey.c hydra-teamspeak.c \
      hydra-postgres.c hydra-rsh.c hydra-rlogin.c hydra-oracle-listener.c \
      hydra-svn.c hydra-pcanywhere.c hydra-sip.c hydra-oracle.c hydra-vmauthd.c \
      hydra-asterisk.c hydra-firebird.c hydra-afp.c hydra-ncp.c hydra-rdp.c \
      hydra-oracle-sid.c hydra-http-proxy.c hydra-http-form.c hydra-irc.c \
      hydra-s7-300.c hydra-redis.c hydra-adam6500.c hydra-rtsp.c \
      hydra-rpcap.c hydra-radmin2.c hydra-cobaltstrike.c \
      hydra-time.c crc32.c d3des.c bfg.c ntlm.c sasl.c hmacmd5.c hydra-mod.c \
      hydra-smb2.c
OBJ = hydra-vnc.o hydra-pcnfs.o hydra-rexec.o hydra-nntp.o hydra-socks5.o \
      hydra-telnet.o hydra-cisco.o hydra-http.o hydra-ftp.o hydra-imap.o \
      hydra-pop3.o hydra-smb.o hydra-icq.o hydra-cisco-enable.o hydra-ldap.o \
      hydra-memcached.o hydra-mongodb.o hydra-mysql.o hydra-mssql.o hydra-cobaltstrike.o hydra-xmpp.o \
      hydra-http-proxy-urlenum.o hydra-snmp.o hydra-cvs.o hydra-smtp.o \
      hydra-smtp-enum.o hydra-sapr3.o hydra-ssh.o hydra-sshkey.o hydra-teamspeak.o \
      hydra-postgres.o hydra-rsh.o hydra-rlogin.o hydra-oracle-listener.o \
      hydra-svn.o hydra-pcanywhere.o hydra-sip.o hydra-oracle-sid.o hydra-oracle.o \
      hydra-vmauthd.o hydra-asterisk.o hydra-firebird.o hydra-afp.o \
      hydra-ncp.o hydra-http-proxy.o hydra-http-form.o hydra-irc.o \
      hydra-redis.o hydra-rdp.o hydra-s7-300.c hydra-adam6500.o hydra-rtsp.o \
      hydra-rpcap.o hydra-radmin2.o \
      crc32.o d3des.o bfg.o ntlm.o sasl.o hmacmd5.o hydra-mod.o hydra-time.o \
      hydra-smb2.o
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
	$(CC) $(OPTS) $(SEC) $(CFLAGS) $(CPPFLAGS) -c $< $(XDEFINES) $(XIPATHS)

strip:	all
	-strip $(BINS)
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
	-mkdir -p $(DESTDIR)$(PREFIX)$(PIXDIR)
	-cp -f xhydra.png $(DESTDIR)$(PREFIX)$(PIXDIR)/
	-mkdir -p $(DESTDIR)$(PREFIX)$(APPDIR)
	-desktop-file-install --dir $(DESTDIR)$(PREFIX)$(APPDIR) xhydra.desktop

clean:
	rm -rf xhydra pw-inspector hydra *.o core *.core *.stackdump *~ Makefile.in Makefile dev_rfc hydra.restore arm/*.ipk arm/ipkg/usr/bin/* hydra-gtk/src/*.o hydra-gtk/src/xhydra hydra-gtk/stamp-h hydra-gtk/config.status hydra-gtk/errors hydra-gtk/config.log hydra-gtk/src/.deps hydra-gtk/src/Makefile hydra-gtk/Makefile
	cp -f Makefile.orig Makefile

uninstall:
	-rm -f $(DESTDIR)$(PREFIX)$(BINDIR)/xhydra $(DESTDIR)$(PREFIX)$(BINDIR)/hydra $(DESTDIR)$(PREFIX)$(BINDIR)/pw-inspector $(DESTDIR)$(PREFIX)$(BINDIR)/hydra-wizard.sh $(DESTDIR)$(PREFIX)$(BINDIR)/dpl4hydra.sh
	-rm -f $(DESTDIR)$(PREFIX)$(DATADIR)/dpl4hydra_full.csv $(DESTDIR)$(PREFIX)$(DATADIR)/dpl4hydra_local.csv
	-rm -f $(DESTDIR)$(PREFIX)$(MANDIR)/hydra.1 $(DESTDIR)$(PREFIX)$(MANDIR)/xhydra.1 $(DESTDIR)$(PREFIX)$(MANDIR)/pw-inspector.1
	-rm -f $(DESTDIR)$(PREFIX)$(PIXDIR)/xhydra.png
	-rm -f $(DESTDIR)$(PREFIX)$(APPDIR)/xhydra.desktop
