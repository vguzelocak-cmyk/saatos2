/* Reproduce const-preserving strchr headers on older build toolchains too. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>

static inline const char *driverlab_const_strchr(const char *text, int character)
{
    return (strchr)(text, character);
}

#undef strchr
#define strchr(text, character) _Generic((text), \
    const char *: driverlab_const_strchr, default: (strchr))((text), (character))
