## Process this file with automake to produce Makefile.in

# Note: Use no-deprecated-declarations until someone finishes the Gtk3 port,
# ie. move from GtkTable to GtkGrid, and a few other details.

AM_CPPFLAGS = \
	-Wno-deprecated-declarations \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	@PACKAGE_CFLAGS@

bin_PROGRAMS = xhydra

xhydra_SOURCES = \
	main.c \
	support.c support.h \
	interface.c interface.h \
	callbacks.c callbacks.h

xhydra_LDADD = @PACKAGE_LIBS@

