#ifndef CRC32_H
#define CRC32_H

#include <sys/types.h>

#ifndef HAVE_ZLIB
unsigned int crc32(const void *buf, unsigned int size);
#endif

#endif
