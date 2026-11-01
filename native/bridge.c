/* A Windows x64 ABI call bridge, NOT an NT kernel implementation. */
#include <stddef.h>
#include <stdint.h>
#include <uchar.h>
#include "ntcompat.h"

typedef struct {
    int16_t type, size;
    void *device_object;
    uint32_t flags;
    void *driver_start;
    uint32_t driver_size;
    void *driver_section, *driver_extension;
    unicode_string driver_name;
    void *hardware_database, *fast_io_dispatch;
    void *driver_init, *driver_start_io, *driver_unload;
    void *major_function[28];
} driver_object;

_Static_assert(sizeof(void *) == 8, "x64 required");
_Static_assert(sizeof(unicode_string) == 16, "UNICODE_STRING layout");
_Static_assert(sizeof(driver_object) == 0x150, "DRIVER_OBJECT layout");
_Static_assert(offsetof(driver_object, driver_start) == 0x18, "DriverStart offset");
_Static_assert(offsetof(driver_object, major_function) == 0x70, "MajorFunction offset");

typedef uint32_t (__attribute__((ms_abi)) *entry_fn)(driver_object *, unicode_string *);

uint32_t driverlab_call(void *entry, void *base, uint32_t image_size)
{
    driverlab_set_image(base, image_size);
    char16_t registry_text[] = u"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\DriverLabTest";
    char16_t name_text[] = u"\\Driver\\DriverLabTest";
    unicode_string registry = {
        sizeof(registry_text) - 2, sizeof(registry_text), (uint16_t *)registry_text
    };
    driver_object object = {0};
    object.type = 4;
    object.size = sizeof(object);
    object.driver_start = base;
    object.driver_size = image_size;
    object.driver_init = entry;
    object.driver_name = (unicode_string){
        sizeof(name_text) - 2, sizeof(name_text), (uint16_t *)name_text
    };
    return ((entry_fn)entry)(&object, &registry);
}
