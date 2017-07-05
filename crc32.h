#ifndef CRC32_H
#define CRC32_H

#include <sys/types.h>

#ifndef HAVE_ZLIB
uint32_t crc32(const void *buf, uint32_t size);
#endif

#endif
