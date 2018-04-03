#ifndef __HIREDIS_FMACRO_H
#define __HIREDIS_FMACRO_H

#if defined(__linux__)
#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#endif

#if defined(__CYGWIN__)
#include <sys/cdefs.h>
#endif

#if defined(__linux__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define _XOPEN_SOURCE 600
#elif defined(__APPLE__) && defined(__MACH__)
#define _XOPEN_SOURCE
#elif defined(__FreeBSD__)
// intentionally left blank, don't define _XOPEN_SOURCE
#elif defined(AIX)
// intentionally left blank, don't define _XOPEN_SOURCE
#else
#define _XOPEN_SOURCE
#endif

#if defined(__sun__)
#define _POSIX_C_SOURCE 200112L
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define _OSX
#endif

#ifndef AIX
# define _XOPEN_SOURCE_EXTENDED 1
# define _ALL_SOURCE
#endif

#endif
