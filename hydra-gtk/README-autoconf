Installation Instructions
*************************

Basic Installation
==================

   The following shell commands:

     test -f configure || ./bootstrap
     ./configure
     make
     make install

should configure, build, and install this package.  The first line,
which bootstraps, is intended for developers; when building from
distribution tarballs it does nothing and can be skipped.  A package
might name the bootstrapping script differently; if the name is
‘autogen.sh’, for example, the first line should say ‘./autogen.sh’
instead of ‘./bootstrap’.

   The following more-detailed instructions are generic; see the
‘README’ file for instructions specific to this package.  Some packages
provide this ‘INSTALL’ file but do not implement all of the features
documented below.  The lack of an optional feature in a given package is
not necessarily a bug.  More recommendations for GNU packages can be
found in the GNU Coding Standards.

   Many packages have scripts meant for developers instead of ordinary
builders, as they may use developer tools that are less commonly
installed, or they may access the network, which has privacy
implications.  These scripts attempt to bootstrap by building the
‘configure’ script and related files, possibly using developer tools or
the network.  Because the output of bootstrapping is system-independent,
it is normally run by a package developer so that its output can be put
into the distribution tarball and ordinary builders and users need not
bootstrap.  Some packages have commands like ‘./autopull.sh’ and
‘./autogen.sh’ that you can run instead of ‘./bootstrap’, for more
fine-grained control over bootstrapping.

   The ‘configure’ script attempts to guess correct values for various
system-dependent variables used during compilation.  It uses those
values to create a ‘Makefile’ in each directory of the package.  It may
also create one or more ‘.h’ files containing system-dependent
definitions.  Finally, it creates a script ‘config.status’ that you can
run in the future to recreate the current configuration, and a file
‘config.log’ containing output useful for debugging ‘configure’.

   It can also use an optional file (typically called ‘config.cache’ and
enabled with ‘--cache-file=config.cache’ or simply ‘-C’) that saves the
results of its tests to speed up reconfiguring.  Caching is disabled by
default to prevent problems with accidental use of stale cache files.

   If you need to do unusual things to compile the package, please try
to figure out how ‘configure’ could check whether to do them, and mail
diffs or instructions to the address given in the ‘README’ so they can
be considered for the next release.  If you are using the cache, and at
some point ‘config.cache’ contains results you don’t want to keep, you
may remove or edit it.

   The ‘autoconf’ program generates ‘configure’ from the file
‘configure.ac’.  Normally you should edit ‘configure.ac’ instead of
editing ‘configure’ directly.

   The simplest way to compile this package is:

  1. ‘cd’ to the directory containing the package’s source code.

  2. If this is a developer checkout and file ‘configure’ does not yet
     exist, run the bootstrapping script (typically ‘./bootstrap’ or
     ‘./autogen.sh’) to bootstrap and create the file.  You may need
     special developer tools and network access to bootstrap, and the
     network access may have privacy implications.

  3. Type ‘./configure’ to configure the package for your system.  This
     might take a while.  While running, ‘configure’ prints messages
     telling which features it is checking for.

  4. Type ‘make’ to compile the package.

  5. Optionally, type ‘make check’ to run any self-tests that come with
     the package, generally using the just-built uninstalled binaries.

  6. Type ‘make install’ to install the programs and any data files and
     documentation.  When installing into a prefix owned by root, it is
     recommended that the package be configured and built as a regular
     user, and only the ‘make install’ phase executed with root
     privileges.

  7. Optionally, type ‘make installcheck’ to repeat any self-tests, but
     this time using the binaries in their final installed location.
     This target does not install anything.  Running this target as a
     regular user, particularly if the prior ‘make install’ required
     root privileges, verifies that the installation completed
     correctly.

  8. You can remove the program binaries and object files from the
     source code directory by typing ‘make clean’.  To also remove the
     files that ‘configure’ created (so you can compile the package for
     a different kind of computer), type ‘make distclean’.  There is
     also a ‘make maintainer-clean’ target, but that is intended mainly
     for the package’s developers.  If you use it, you may have to
     bootstrap again.

  9. If the package follows the GNU Coding Standards, you can type ‘make
     uninstall’ to remove the installed files.

Installation Prerequisites
==========================

   Installation requires a POSIX-like environment with a shell and at
least the following standard utilities:

     awk cat cp diff echo expr false ls mkdir mv printf pwd rm rmdir sed
     sort test tr

This package’s installation may need other standard utilities such as
‘grep’, ‘make’, ‘sleep’ and ‘touch’, along with compilers like ‘gcc’.

Compilers and Options
=====================

   Some systems require unusual options for compilation or linking that
the ‘configure’ script does not know about.  Run ‘./configure --help’
for details on some of the pertinent environment variables.

   You can give ‘configure’ initial values for configuration parameters
by setting variables in the command line or in the environment.  Here is
an example:

     ./configure CC=gcc CFLAGS=-g LIBS=-lposix

   See “Defining Variables” for more details.

Compiling For Multiple Architectures
====================================

   You can compile the package for more than one kind of computer at the
same time, by placing the object files for each system in their own
directory.  To do this, you can use GNU ‘make’.  ‘cd’ to the directory
where you want the object files and executables to go and run the
‘configure’ script.  ‘configure’ automatically checks for the source
code in the directory that ‘configure’ is in and in ‘..’.  This is known
as a “VPATH” build.

   With a non-GNU ‘make’, it is safer to compile the package for one
system at a time in the source code directory.  After you have installed
the package for one system, use ‘make distclean’ before reconfiguring
for another system.

   Some platforms, notably macOS, support “fat” or “universal” binaries,
where a single binary can execute on different architectures.  On these
platforms you can configure and compile just once, with options specific
to that platform.

Installation Names
==================

   By default, ‘make install’ installs the package’s commands under
‘/usr/local/bin’, include files under ‘/usr/local/include’, etc.  You
can specify an installation prefix other than ‘/usr/local’ by giving
‘configure’ the option ‘--prefix=PREFIX’, where PREFIX must be an
absolute file name.

   You can specify separate installation prefixes for
architecture-specific files and architecture-independent files.  If you
pass the option ‘--exec-prefix=PREFIX’ to ‘configure’, the package uses
PREFIX as the prefix for installing programs and libraries.
Documentation and other data files still use the regular prefix.

   In addition, if you use an unusual directory layout you can give
options like ‘--bindir=DIR’ to specify different values for particular
kinds of files.  Run ‘configure --help’ for a list of the directories
you can set and what kinds of files go in them.  In general, the default
for these options is expressed in terms of ‘${prefix}’, so that
specifying just ‘--prefix’ will affect all of the other directory
specifications that were not explicitly provided.

   The most portable way to affect installation locations is to pass the
correct locations to ‘configure’; however, many packages provide one or
both of the following shortcuts of passing variable assignments to the
‘make install’ command line to change installation locations without
having to reconfigure or recompile.

   The first method involves providing an override variable for each
affected directory.  For example, ‘make install
prefix=/alternate/directory’ will choose an alternate location for all
directory configuration variables that were expressed in terms of
‘${prefix}’.  Any directories that were specified during ‘configure’,
but not in terms of ‘${prefix}’, must each be overridden at install time
for the entire installation to be relocated.  The approach of makefile
variable overrides for each directory variable is required by the GNU
Coding Standards, and ideally causes no recompilation.  However, some
platforms have known limitations with the semantics of shared libraries
that end up requiring recompilation when using this method, particularly
noticeable in packages that use GNU Libtool.

   The second method involves providing the ‘DESTDIR’ variable.  For
example, ‘make install DESTDIR=/alternate/directory’ will prepend
‘/alternate/directory’ before all installation names.  The approach of
‘DESTDIR’ overrides is not required by the GNU Coding Standards, and
does not work on platforms that have drive letters.  On the other hand,
it does better at avoiding recompilation issues, and works well even
when some directory options were not specified in terms of ‘${prefix}’
at ‘configure’ time.

Optional Features
=================

   If the package supports it, you can cause programs to be installed
with an extra prefix or suffix on their names by giving ‘configure’ the
option ‘--program-prefix=PREFIX’ or ‘--program-suffix=SUFFIX’.

   Some packages pay attention to ‘--enable-FEATURE’ and
‘--disable-FEATURE’ options to ‘configure’, where FEATURE indicates an
optional part of the package.  They may also pay attention to
‘--with-PACKAGE’ and ‘--without-PACKAGE’ options, where PACKAGE is
something like ‘gnu-ld’.  ‘./configure --help’ should mention the
‘--enable-...’ and ‘--with-...’ options that the package recognizes.

   Some packages offer the ability to configure how verbose the
execution of ‘make’ will be.  For these packages, running ‘./configure
--enable-silent-rules’ sets the default to minimal output, which can be
overridden with ‘make V=1’; while running ‘./configure
--disable-silent-rules’ sets the default to verbose, which can be
overridden with ‘make V=0’.

Specifying a System Type
========================

   By default ‘configure’ builds for the current system.  To create
binaries that can run on a different system type, specify a
‘--host=TYPE’ option along with compiler variables that specify how to
generate object code for TYPE.  For example, to create binaries intended
to run on a 64-bit ARM processor:

     ./configure --host=aarch64-linux-gnu \
        CC=aarch64-linux-gnu-gcc \
        CXX=aarch64-linux-gnu-g++

If done on a machine that can execute these binaries (e.g., via
‘qemu-aarch64’, ‘$QEMU_LD_PREFIX’, and Linux’s ‘binfmt_misc’
capability), the build behaves like a native build.  Otherwise it is a
cross-build: ‘configure’ will make cross-compilation guesses instead of
running test programs, and ‘make check’ will not work.

   A system type can either be a short name like ‘mingw64’, or a
canonical name like ‘x86_64-pc-linux-gnu’.  Canonical names have the
form CPU-COMPANY-SYSTEM where SYSTEM is either OS or KERNEL-OS.  To
canonicalize and validate a system type, you can run the command
‘config.sub’, which is often squirreled away in a subdirectory like
‘build-aux’.  For example:

     $ build-aux/config.sub arm64-linux
     aarch64-unknown-linux-gnu
     $ build-aux/config.sub riscv-lnx
     Invalid configuration 'riscv-lnx': OS 'lnx' not recognized

You can look at the ‘config.sub’ file to see which types are recognized.
If the file is absent, this package does not need the system type.

   If ‘configure’ fails with the diagnostic “cannot guess build type”.
‘config.sub’ did not recognize your system’s type.  In this case, first
fetch the newest versions of these files from the GNU config package
(https://savannah.gnu.org/projects/config).  If that fixes things,
please report it to the maintainers of the package containing
‘configure’.  Otherwise, you can try the configure option ‘--build=TYPE’
where TYPE comes close to your system type; also, please report the
problem to <config-patches@gnu.org>.

   For more details about configuring system types, see the Autoconf
documentation.

Sharing Defaults
================

   If you want to set default values for ‘configure’ scripts to share,
you can create a site shell script called ‘config.site’ that gives
default values for variables like ‘CC’, ‘cache_file’, and ‘prefix’.
‘configure’ looks for ‘PREFIX/share/config.site’ if it exists, then
‘PREFIX/etc/config.site’ if it exists.  Or, you can set the
‘CONFIG_SITE’ environment variable to the location of the site script.
A warning: not all ‘configure’ scripts look for a site script.

Defining Variables
==================

   Variables not defined in a site shell script can be set in the
environment passed to ‘configure’.  However, some packages may run
configure again during the build, and the customized values of these
variables may be lost.  In order to avoid this problem, you should set
them in the ‘configure’ command line, using ‘VAR=value’.  For example:

     ./configure CC=/usr/local2/bin/gcc

causes the specified ‘gcc’ to be used as the C compiler (unless it is
overridden in the site shell script).

Unfortunately, this technique does not work for ‘CONFIG_SHELL’ due to an
Autoconf limitation.  Until the limitation is lifted, you can use this
workaround:

     CONFIG_SHELL=/bin/bash ./configure CONFIG_SHELL=/bin/bash

‘configure’ Invocation
======================

   ‘configure’ recognizes the following options to control how it
operates.

‘--help’
‘-h’
     Print a summary of all of the options to ‘configure’, and exit.

‘--help=short’
‘--help=recursive’
     Print a summary of the options unique to this package’s
     ‘configure’, and exit.  The ‘short’ variant lists options used only
     in the top level, while the ‘recursive’ variant lists options also
     present in any nested packages.

‘--version’
‘-V’
     Print the version of Autoconf used to generate the ‘configure’
     script, and exit.

‘--cache-file=FILE’
     Enable the cache: use and save the results of the tests in FILE,
     traditionally ‘config.cache’.  FILE defaults to ‘/dev/null’ to
     disable caching.

‘--config-cache’
‘-C’
     Alias for ‘--cache-file=config.cache’.

‘--srcdir=DIR’
     Look for the package’s source code in directory DIR.  Usually
     ‘configure’ can determine that directory automatically.

‘--prefix=DIR’
     Use DIR as the installation prefix.  See “Installation Names” for
     more details, including other options available for fine-tuning the
     installation locations.

‘--host=TYPE’
     Build binaries for system TYPE.  See “Specifying a System Type”.

‘--enable-FEATURE’
‘--disable-FEATURE’
     Enable or disable the optional FEATURE.  See “Optional Features”.

‘--with-PACKAGE’
‘--without-PACKAGE’
     Use or omit PACKAGE when building.  See “Optional Features”.

‘--quiet’
‘--silent’
‘-q’
     Do not print messages saying which checks are being made.  To
     suppress all normal output, redirect it to ‘/dev/null’ (any error
     messages will still be shown).

‘--no-create’
‘-n’
     Run the configure checks, but stop before creating any output
     files.

‘configure’ also recognizes several environment variables, and accepts
some other, less widely useful, options.  Run ‘configure --help’ for
more details.

Copyright notice
================

   Copyright © 1994–1996, 1999–2002, 2004–2017, 2020–2025 Free Software
Foundation, Inc.

   Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind.
