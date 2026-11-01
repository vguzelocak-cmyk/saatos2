#ifndef DRIVERLAB_NTCOMPAT_H
#define DRIVERLAB_NTCOMPAT_H

#include <stddef.h>
#include <stdint.h>

#define NTAPI __attribute__((ms_abi))

typedef struct {
    uint16_t length, maximum_length;
    uint16_t *buffer;
} unicode_string;

void *driverlab_resolve(const char *module, const char *symbol);
size_t driverlab_export_count(void);
void driverlab_set_image(void *base, size_t size);

#endif
