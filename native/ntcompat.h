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

typedef struct { const char *module, *name; void *address; } nt_export;
extern const nt_export driverlab_io_exports[], driverlab_crypto_exports[], driverlab_memory_exports[];
extern const size_t driverlab_io_count, driverlab_crypto_count, driverlab_memory_count;
uint32_t driverlab_io_initialize(const char *directory);

typedef struct {
    uint32_t length;
    void *root_directory;
    unicode_string *object_name;
    uint32_t attributes;
    void *security_descriptor, *security_qos;
} nt_object_attributes;
typedef struct { uintptr_t status, information; } nt_io_status;

#define NT_SUCCESS_STATUS UINT32_C(0)
#define NT_INVALID_HANDLE UINT32_C(0xc0000008)
#define NT_INVALID_PARAMETER UINT32_C(0xc000000d)
#define NT_NO_MEMORY UINT32_C(0xc0000017)
#define NT_ACCESS_DENIED UINT32_C(0xc0000022)
#define NT_BUFFER_TOO_SMALL UINT32_C(0xc0000023)
#define NT_NOT_FOUND UINT32_C(0xc0000034)
#define NT_NOT_SUPPORTED UINT32_C(0xc00000bb)
#define NT_UNSUCCESSFUL UINT32_C(0xc0000001)

#endif
