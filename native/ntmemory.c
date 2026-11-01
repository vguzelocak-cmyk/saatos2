#define _GNU_SOURCE
#include "ntcompat.h"
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

/* These MDLs describe host virtual memory. They never claim physical PFNs. */
typedef struct mdl {
    struct mdl *next;
    int16_t size, flags;
    void *process, *mapped_system_va, *start_va;
    uint32_t byte_count, byte_offset;
} mdl;
_Static_assert(sizeof(mdl) == 48, "x64 MDL prefix layout");
typedef struct record {
    mdl *descriptor; void *buffer; uintptr_t start; uint32_t length;
    size_t pages; int pinned, mapped, nonpaged; struct record *next;
} record;
typedef struct pin { uintptr_t page; size_t references; struct pin *next; } pin;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static record *records;
static pin *pins;

static void fatal(const char *message)
{
    fprintf(stderr, "driverlab memory contract violation: %s\n", message); abort();
}
static record *find(mdl *descriptor)
{
    for (record *p = records; p; p = p->next) if (p->descriptor == descriptor) {
        if ((uintptr_t)descriptor->start_va != p->start || descriptor->byte_count != p->length ||
            descriptor->byte_offset != (uintptr_t)p->buffer - p->start)
            fatal("MDL range changed after allocation");
        return p;
    }
    return NULL;
}
static void unpin_page(uintptr_t page, size_t page_size)
{
    pin **slot = &pins;
    while (*slot && (*slot)->page != page) slot = &(*slot)->next;
    if (!*slot || !(*slot)->references) fatal("unbalanced page unpin");
    if (!--(*slot)->references) {
        pin *p = *slot;
        *slot = p->next;
        if (munlock((void *)page, page_size)) fatal("host munlock failed");
        free(p);
    }
}
static int pin_pages(record *p)
{
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE), completed = 0;
    uintptr_t start = p->start;
    for (; completed < p->pages; ++completed) {
        uintptr_t page = start + completed * page_size;
        pin *existing = pins;
        while (existing && existing->page != page) existing = existing->next;
        if (existing) { ++existing->references; continue; }
        pin *entry = calloc(1, sizeof(*entry));
        if (!entry) break;
        if (mlock((void *)page, page_size)) { free(entry); break; }
        *entry = (pin){page, 1, pins}; pins = entry;
    }
    if (completed == p->pages) return 1;
    while (completed) unpin_page(start + --completed * page_size, page_size);
    return 0;
}
static void unpin_pages(record *p)
{
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    for (size_t i = 0; i < p->pages; ++i)
        unpin_page(p->start + i * page_size, page_size);
    p->pinned = 0;
}
int driverlab_probe_range(const void *buffer, size_t length, int writing)
{
    uintptr_t position = (uintptr_t)buffer;
    if (!length) return 1;
    if (!buffer || length > UINTPTR_MAX - position) return 0;
    uintptr_t end = position + length;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512], permissions[5];
    while (position < end && fgets(line, sizeof(line), maps)) {
        unsigned long start, stop;
        if (sscanf(line, "%lx-%lx %4s", &start, &stop, permissions) != 3 || stop <= position) continue;
        if (start > position || permissions[0] != 'r' || (writing && permissions[1] != 'w')) break;
        position = stop < end ? stop : end;
    }
    fclose(maps); return position == end;
}

static mdl *NTAPI m_IoAllocateMdl(void *buffer, uint32_t length, uint8_t secondary, uint8_t quota, void *irp)
{
    if (!buffer || !length || secondary || quota || irp) return NULL;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t address = (uintptr_t)buffer;
    if (address > UINTPTR_MAX - length) return NULL;
    size_t offset = address % page_size, pages = (offset + length + page_size - 1) / page_size;
    if (pages > (INT16_MAX - sizeof(mdl)) / sizeof(uintptr_t)) return NULL;
    mdl *descriptor = calloc(1, sizeof(*descriptor) + pages * sizeof(uintptr_t));
    record *p = calloc(1, sizeof(*p));
    if (!descriptor || !p) { free(descriptor); free(p); return NULL; }
    descriptor->size = sizeof(*descriptor) + pages * sizeof(uintptr_t);
    uintptr_t *pfns = (uintptr_t *)(descriptor + 1);
    for (size_t i = 0; i < pages; ++i) pfns[i] = UINTPTR_MAX; /* Unavailable, not invented physical PFNs. */
    descriptor->start_va = (void *)(address - offset);
    descriptor->byte_count = length; descriptor->byte_offset = offset;
    p->descriptor = descriptor; p->buffer = buffer; p->pages = pages;
    p->start = address - offset; p->length = length;
    pthread_mutex_lock(&mutex); p->next = records; records = p; pthread_mutex_unlock(&mutex);
    return descriptor;
}
static void NTAPI m_MmBuildMdlForNonPagedPool(mdl *descriptor)
{
    pthread_mutex_lock(&mutex);
    record *p = find(descriptor);
    if (!p || p->pinned) fatal("invalid or already built MDL");
    if (!pin_pages(p)) fatal("host page locking failed; no kernel-memory fallback is available");
    p->pinned = 1; p->nonpaged = 1;
    descriptor->flags = 4; /* SOURCE_IS_NONPAGED_POOL, in this process-local model only. */
    descriptor->mapped_system_va = p->buffer;
    pthread_mutex_unlock(&mutex);
}
static void NTAPI m_MmProbeAndLockPages(mdl *descriptor, int mode, int operation)
{
    pthread_mutex_lock(&mutex);
    record *p = find(descriptor);
    if (!p || p->pinned || (mode != 0 && mode != 1) || operation < 0 || operation > 2)
        fatal("invalid MDL probe request");
    if (!driverlab_probe_range(p->buffer, p->length, operation != 0) || !pin_pages(p))
        fatal("MDL access probe or host page locking failed; Windows SEH is not implemented");
    p->pinned = 1; p->nonpaged = 0;
    descriptor->flags = 2; /* PAGES_LOCKED; physical PFNs remain unavailable. */
    pthread_mutex_unlock(&mutex);
}
static void NTAPI m_MmUnlockPages(mdl *descriptor)
{
    pthread_mutex_lock(&mutex);
    record *p = find(descriptor);
    if (!p || !p->pinned || p->nonpaged) fatal("invalid MDL unlock");
    p->mapped = 0; descriptor->mapped_system_va = NULL; descriptor->flags = 0;
    unpin_pages(p);
    pthread_mutex_unlock(&mutex);
}
static void *NTAPI m_MmMapLockedPagesSpecifyCache(mdl *descriptor, int mode, int cache, void *requested,
                                                 uint32_t bugcheck, uint32_t priority)
{
    /* No uncached/write-combined mappings, physical aliasing or protection flags. */
    pthread_mutex_lock(&mutex);
    record *p = find(descriptor);
    void *result = NULL;
    if (p && p->pinned && !p->nonpaged && mode == 0 && cache == 1 && (!requested || requested == p->buffer) && !(priority & 0xFFFF0000)) {
        p->mapped = 1; result = p->buffer;
        descriptor->mapped_system_va = result; descriptor->flags |= 1;
    }
    pthread_mutex_unlock(&mutex);
    if (!result && bugcheck) fatal("requested bugcheck after unsupported MDL mapping");
    return result;
}
static void NTAPI m_MmUnmapLockedPages(void *base, mdl *descriptor)
{
    pthread_mutex_lock(&mutex);
    record *p = find(descriptor);
    if (!p || !p->mapped || base != p->buffer) fatal("invalid MDL unmap");
    p->mapped = 0; descriptor->flags &= ~1;
    pthread_mutex_unlock(&mutex);
}
static void NTAPI m_IoFreeMdl(mdl *descriptor)
{
    pthread_mutex_lock(&mutex);
    record **slot = &records;
    while (*slot && (*slot)->descriptor != descriptor) slot = &(*slot)->next;
    if (!*slot) fatal("unknown or already freed MDL");
    record *p = *slot;
    if (p->mapped) fatal("MDL freed while explicitly mapped");
    if (p->pinned && !p->nonpaged) fatal("unlock probed MDL before freeing it");
    if (p->pinned) {
        unpin_pages(p);
    }
    *slot = p->next;
    free(descriptor); free(p);
    pthread_mutex_unlock(&mutex);
}
#define M(name) {"ntoskrnl.exe", #name, (void *)m_##name}
const nt_export driverlab_memory_exports[] = {
    M(IoAllocateMdl), M(IoFreeMdl), M(MmBuildMdlForNonPagedPool), M(MmMapLockedPagesSpecifyCache), M(MmUnmapLockedPages),
    M(MmProbeAndLockPages), M(MmUnlockPages),
};
const size_t driverlab_memory_count = sizeof(driverlab_memory_exports) / sizeof(driverlab_memory_exports[0]);
