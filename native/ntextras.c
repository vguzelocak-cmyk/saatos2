#define _GNU_SOURCE
#include "ntcompat.h"
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wctype.h>

static void fatal(const char *message)
{
    fprintf(stderr, "driverlab NT extension contract violation: %s\n", message); abort();
}

static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t first = (uintptr_t)a, second = (uintptr_t)b;
    return first <= second ? second - first < an : first - second < bn;
}
static size_t u16_length(const uint16_t *text, size_t capacity)
{
    size_t count = 0;
    while (count < capacity && text[count]) ++count;
    return count;
}
static int NTAPI x_strcpy_s(char *destination, size_t capacity, const char *source)
{
    if (!destination || !capacity) return EINVAL;
    if (!source) { destination[0] = 0; return EINVAL; }
    size_t length = strnlen(source, capacity);
    if (length == capacity) { destination[0] = 0; return ERANGE; }
    if (overlap(destination, length + 1, source, length + 1)) { destination[0] = 0; return EINVAL; }
    memcpy(destination, source, length + 1); return 0;
}
static int NTAPI x_strncpy_s(char *destination, size_t capacity, const char *source, size_t count)
{
    if (!count && !destination && !capacity) return 0;
    if (!destination || !capacity) return EINVAL;
    if (!count) { destination[0] = 0; return 0; }
    if (!source) { destination[0] = 0; return EINVAL; }
    int truncate = count == SIZE_MAX;
    size_t limit = truncate || count >= capacity ? capacity : count;
    size_t length = strnlen(source, limit);
    int result = 0;
    if (length == capacity) {
        if (!truncate) { destination[0] = 0; return ERANGE; }
        length = capacity - 1; result = 80; /* STRUNCATE */
    }
    if (overlap(destination, length + 1, source, length ? length : 1)) { destination[0] = 0; return EINVAL; }
    memcpy(destination, source, length); destination[length] = 0; return result;
}
static int NTAPI x_wcscpy_s(uint16_t *destination, size_t capacity, const uint16_t *source)
{
    if (!destination || !capacity || capacity > SIZE_MAX / 2) return EINVAL;
    if (!source) { destination[0] = 0; return EINVAL; }
    size_t length = u16_length(source, capacity);
    if (length == capacity) { destination[0] = 0; return ERANGE; }
    if (overlap(destination, (length + 1) * 2, source, (length + 1) * 2)) { destination[0] = 0; return EINVAL; }
    memcpy(destination, source, (length + 1) * 2); return 0;
}
static int NTAPI x_wcscat_s(uint16_t *destination, size_t capacity, const uint16_t *source)
{
    if (!destination || !capacity || capacity > SIZE_MAX / 2) return EINVAL;
    if (!source) { destination[0] = 0; return EINVAL; }
    size_t used = u16_length(destination, capacity);
    if (used == capacity) { destination[0] = 0; return EINVAL; }
    size_t length = u16_length(source, capacity - used);
    if (length == capacity - used) { destination[0] = 0; return ERANGE; }
    if (overlap(destination, (used + length + 1) * 2, source, (length + 1) * 2)) { destination[0] = 0; return EINVAL; }
    memcpy(destination + used, source, (length + 1) * 2); return 0;
}

static locale_t unicode_locale;
static pthread_once_t locale_once = PTHREAD_ONCE_INIT;
static void initialize_locale(void) { unicode_locale = newlocale(LC_CTYPE_MASK, "C.UTF-8", (locale_t)0); }
static uint16_t uppercase(uint16_t c)
{
    if (c >= 0xD800 && c <= 0xDFFF) return c;
    pthread_once(&locale_once, initialize_locale);
    if (!unicode_locale) {
        if (c > 127) fatal("Unicode case conversion locale unavailable");
        return c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c;
    }
    wint_t result = towupper_l(c, unicode_locale);
    return result <= UINT16_MAX ? (uint16_t)result : c;
}
static uint8_t NTAPI x_RtlPrefixUnicodeString(const unicode_string *prefix, const unicode_string *string, uint8_t ignore_case)
{
    if (!prefix || !string || prefix->length % 2 || string->length % 2 ||
        prefix->length > prefix->maximum_length || string->length > string->maximum_length ||
        (prefix->length && !prefix->buffer) || (string->length && !string->buffer)) fatal("invalid Unicode prefix arguments");
    if (prefix->length > string->length) return 0;
    for (size_t i = 0; i < prefix->length / 2; ++i) {
        uint16_t left = prefix->buffer[i], right = string->buffer[i];
        if (ignore_case) { left = uppercase(left); right = uppercase(right); }
        if (left != right) return 0;
    }
    return 1;
}
static uint32_t NTAPI x_RtlMultiByteToUnicodeN(uint16_t *output, uint32_t capacity, uint32_t *written,
                                             const unsigned char *input, uint32_t size)
{
    static const uint16_t cp1252[32] = {
        0x20AC,0x0081,0x201A,0x0192,0x201E,0x2026,0x2020,0x2021,0x02C6,0x2030,0x0160,0x2039,0x0152,0x008D,0x017D,0x008F,
        0x0090,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x02DC,0x2122,0x0161,0x203A,0x0153,0x009D,0x017E,0x0178
    };
    if ((!output && capacity) || (!input && size)) return NT_INVALID_PARAMETER;
    uint32_t count = size < capacity / 2 ? size : capacity / 2;
    for (uint32_t i = 0; i < count; ++i) output[i] = input[i] >= 0x80 && input[i] < 0xA0 ? cp1252[input[i] - 0x80] : input[i];
    if (written) *written = count * 2;
    return 0;
}

typedef struct { int16_t year, month, day, hour, minute, second, milliseconds, weekday; } time_fields;
static time_t seconds_for(int64_t ticks, int64_t *fraction)
{
    int64_t seconds = ticks / 10000000 - INT64_C(11644473600);
    *fraction = ticks % 10000000;
    if (*fraction < 0) { --seconds; *fraction += 10000000; }
    return (time_t)seconds;
}
static void NTAPI x_RtlTimeToTimeFields(const int64_t *ticks, time_fields *fields)
{
    int64_t fraction;
    time_t seconds = seconds_for(*ticks, &fraction);
    struct tm calendar;
    if (!gmtime_r(&seconds, &calendar) || calendar.tm_year + 1900 < INT16_MIN || calendar.tm_year + 1900 > INT16_MAX)
        fatal("time outside TIME_FIELDS range");
    *fields = (time_fields){calendar.tm_year + 1900, calendar.tm_mon + 1, calendar.tm_mday, calendar.tm_hour,
                           calendar.tm_min, calendar.tm_sec, fraction / 10000, calendar.tm_wday};
}
static void NTAPI x_ExSystemTimeToLocalTime(const int64_t *system, int64_t *local)
{
    int64_t fraction;
    time_t seconds = seconds_for(*system, &fraction);
    struct tm calendar;
    if (!localtime_r(&seconds, &calendar) || __builtin_add_overflow(*system, (int64_t)calendar.tm_gmtoff * 10000000, local))
        fatal("local time outside signed NT time range");
}
static void probe(const void *buffer, size_t size, uint32_t alignment, int writing)
{
    if (!size) return;
    if (!alignment || (alignment & (alignment - 1)) || alignment > 16 || (uintptr_t)buffer % alignment)
        fatal("STATUS_DATATYPE_MISALIGNMENT (Windows SEH unavailable)");
    if (!driverlab_probe_range(buffer, size, writing)) fatal("STATUS_ACCESS_VIOLATION (Windows SEH unavailable)");
}
static void NTAPI x_ProbeForRead(const void *buffer, size_t size, uint32_t alignment) { probe(buffer, size, alignment, 0); }
static void NTAPI x_ProbeForWrite(void *buffer, size_t size, uint32_t alignment) { probe(buffer, size, alignment, 1); }

typedef struct reader { pthread_t thread; struct reader *next; } reader;
typedef struct push_lock {
    _Atomic uintptr_t *address;
    pthread_rwlock_t rw;
    pthread_mutex_t state;
    pthread_t writer;
    int has_writer;
    size_t count, waiting;
    reader *readers;
    struct push_lock *next;
} push_lock;
static pthread_mutex_t push_mutex = PTHREAD_MUTEX_INITIALIZER;
static push_lock *push_locks;
static push_lock *get_push(_Atomic uintptr_t *address, int initialize)
{
    if (!address || (uintptr_t)address % sizeof(uintptr_t)) fatal("unaligned pushlock");
    pthread_mutex_lock(&push_mutex);
    push_lock *p = push_locks;
    while (p && p->address != address) p = p->next;
    if (!p) {
        if (!initialize) fatal("uninitialized pushlock");
        p = calloc(1, sizeof(*p));
        if (!p || pthread_rwlock_init(&p->rw, NULL) || pthread_mutex_init(&p->state, NULL)) fatal("pushlock host allocation failed");
        p->address = address; p->next = push_locks; push_locks = p;
    }
    pthread_mutex_unlock(&push_mutex);
    return p;
}
static void NTAPI x_ExInitializePushLock(_Atomic uintptr_t *address)
{
    push_lock *p = get_push(address, 1);
    pthread_mutex_lock(&p->state);
    if (p->count || p->has_writer || p->waiting) fatal("reinitializing busy pushlock");
    atomic_store(address, 0);
    pthread_mutex_unlock(&p->state);
}
static reader **reader_slot(push_lock *p)
{
    reader **slot = &p->readers;
    while (*slot && !pthread_equal((*slot)->thread, pthread_self())) slot = &(*slot)->next;
    return slot;
}
static void acquire_push(_Atomic uintptr_t *address, uint32_t flags, int exclusive)
{
    if (flags || !driverlab_normal_apcs_disabled() || driverlab_current_irql() > 1)
        fatal("pushlock requires zero flags, IRQL <= APC_LEVEL and normal APCs disabled");
    push_lock *p = get_push(address, 0);
    pthread_mutex_lock(&p->state);
    if ((p->has_writer && pthread_equal(p->writer, pthread_self())) || *reader_slot(p)) fatal("recursive pushlock acquire");
    ++p->waiting;
    pthread_mutex_unlock(&p->state);
    int error = exclusive ? pthread_rwlock_wrlock(&p->rw) : pthread_rwlock_rdlock(&p->rw);
    if (error) fatal("host pushlock acquire failed");
    pthread_mutex_lock(&p->state); --p->waiting;
    if (exclusive) { p->writer = pthread_self(); p->has_writer = 1; atomic_store(address, 1); }
    else {
        reader *r = malloc(sizeof(*r)); if (!r) fatal("pushlock reader allocation failed");
        *r = (reader){pthread_self(), p->readers}; p->readers = r; ++p->count;
        atomic_store(address, (p->count << 4) | 1 | (p->count > 1 ? 8 : 0));
    }
    pthread_mutex_unlock(&p->state);
}
static void release_push(_Atomic uintptr_t *address, uint32_t flags, int exclusive)
{
    if (flags || !driverlab_normal_apcs_disabled() || driverlab_current_irql() > 1) fatal("pushlock release contract");
    push_lock *p = get_push(address, 0);
    pthread_mutex_lock(&p->state);
    if (exclusive) {
        if (!p->has_writer || !pthread_equal(p->writer, pthread_self())) fatal("pushlock writer released by non-owner");
        p->has_writer = 0; atomic_store(address, 0);
    } else {
        reader **slot = reader_slot(p);
        if (!*slot || !p->count) fatal("pushlock reader released by non-owner");
        reader *r = *slot; *slot = r->next; free(r); --p->count;
        atomic_store(address, p->count ? (p->count << 4) | 1 | (p->count > 1 ? 8 : 0) : 0);
    }
    pthread_mutex_unlock(&p->state);
    if (pthread_rwlock_unlock(&p->rw)) fatal("host pushlock release failed");
}
static void NTAPI x_ExAcquirePushLockExclusiveEx(_Atomic uintptr_t *p, uint32_t flags) { acquire_push(p, flags, 1); }
static void NTAPI x_ExReleasePushLockExclusiveEx(_Atomic uintptr_t *p, uint32_t flags) { release_push(p, flags, 1); }
static void NTAPI x_ExAcquirePushLockSharedEx(_Atomic uintptr_t *p, uint32_t flags) { acquire_push(p, flags, 0); }
static void NTAPI x_ExReleasePushLockSharedEx(_Atomic uintptr_t *p, uint32_t flags) { release_push(p, flags, 0); }

typedef struct cached_rundown {
    uint64_t references;
    size_t waiters;
    int closed;
    uint32_t pool;
    pthread_cond_t drained;
    struct cached_rundown *next;
} cached_rundown;
static pthread_mutex_t rundown_mutex = PTHREAD_MUTEX_INITIALIZER;
static cached_rundown *rundowns;
static cached_rundown *find_rundown(void *pointer)
{
    for (cached_rundown *p = rundowns; p; p = p->next) if (p == pointer) return p;
    fatal("invalid cache-aware rundown handle"); return NULL;
}
static void *NTAPI x_ExAllocateCacheAwareRundownProtection(uint32_t pool, uint32_t tag)
{
    (void)tag;
    if (pool != 0 && pool != 1 && pool != 512) return NULL;
    if (driverlab_current_irql() > 2 || (pool == 1 && driverlab_current_irql() > 1)) fatal("cache-aware rundown allocation IRQL");
    cached_rundown *p = NULL;
    if (posix_memalign((void **)&p, 64, sizeof(*p))) return NULL;
    memset(p, 0, sizeof(*p)); p->pool = pool;
    if (pthread_cond_init(&p->drained, NULL)) { free(p); return NULL; }
    pthread_mutex_lock(&rundown_mutex); p->next = rundowns; rundowns = p; pthread_mutex_unlock(&rundown_mutex);
    return p;
}
static uint8_t NTAPI x_ExAcquireRundownProtectionCacheAwareEx(void *pointer, uint32_t count)
{
    if (!count || driverlab_current_irql() > 2) fatal("invalid rundown acquire count or IRQL");
    pthread_mutex_lock(&rundown_mutex); cached_rundown *p = find_rundown(pointer);
    uint8_t result = !p->closed;
    if (result) { if (p->references > UINT64_MAX - count) fatal("rundown counter overflow"); p->references += count; }
    pthread_mutex_unlock(&rundown_mutex); return result;
}
static void NTAPI x_ExReleaseRundownProtectionCacheAwareEx(void *pointer, uint32_t count)
{
    pthread_mutex_lock(&rundown_mutex); cached_rundown *p = find_rundown(pointer);
    if (!count || count > p->references || driverlab_current_irql() > 2) fatal("unbalanced cache-aware rundown release");
    p->references -= count;
    if (!p->references && p->closed) pthread_cond_broadcast(&p->drained);
    pthread_mutex_unlock(&rundown_mutex);
}
static void NTAPI x_ExWaitForRundownProtectionReleaseCacheAware(void *pointer)
{
    if (driverlab_current_irql() > 1) fatal("cache-aware rundown wait above APC_LEVEL");
    pthread_mutex_lock(&rundown_mutex); cached_rundown *p = find_rundown(pointer);
    p->closed = 1; ++p->waiters;
    while (p->references) if (pthread_cond_wait(&p->drained, &rundown_mutex)) fatal("rundown host wait failed");
    --p->waiters; pthread_mutex_unlock(&rundown_mutex);
}
static void NTAPI x_ExFreeCacheAwareRundownProtection(void *pointer)
{
    pthread_mutex_lock(&rundown_mutex); cached_rundown *p = find_rundown(pointer);
    if (p->references || p->waiters) fatal("freeing active cache-aware rundown");
    if (driverlab_current_irql() > 2 || (p->pool == 1 && driverlab_current_irql() > 1)) fatal("cache-aware rundown free IRQL");
    cached_rundown **slot = &rundowns;
    while (*slot != p) slot = &(*slot)->next;
    *slot = p->next; pthread_cond_destroy(&p->drained); free(p); pthread_mutex_unlock(&rundown_mutex);
}

static cpu_set_t *active_cpus;
static size_t active_bytes, active_capacity;
static uint32_t active_count;
static uint8_t number_processors;
static void __attribute__((constructor)) initialize_cpus(void)
{
    long count = sysconf(_SC_NPROCESSORS_CONF);
    active_capacity = count > 0 ? (size_t)count : CPU_SETSIZE;
    for (int attempt = 0; attempt < 8; ++attempt) {
        active_bytes = CPU_ALLOC_SIZE(active_capacity); active_cpus = CPU_ALLOC(active_capacity);
        if (!active_cpus) fatal("CPU affinity allocation failed");
        CPU_ZERO_S(active_bytes, active_cpus);
        if (!sched_getaffinity(0, active_bytes, active_cpus)) break;
        CPU_FREE(active_cpus); active_cpus = NULL; active_capacity *= 2;
    }
    if (!active_cpus) fatal("CPU affinity snapshot unavailable");
    active_count = CPU_COUNT_S(active_bytes, active_cpus);
    number_processors = active_count < 64 ? active_count : 64;
}
static uint32_t NTAPI x_KeQueryActiveProcessorCountEx(uint16_t group)
{
    if (!active_cpus) fatal("CPU affinity snapshot unavailable");
    if (group == UINT16_MAX) return active_count;
    uint32_t start = (uint32_t)group * 64;
    return start >= active_count ? 0 : active_count - start < 64 ? active_count - start : 64;
}
typedef struct { uint16_t group; uint8_t number, reserved; } processor_number;
static uint32_t NTAPI x_KeGetCurrentProcessorNumberEx(processor_number *number)
{
    int cpu = sched_getcpu();
    if (cpu < 0 || (size_t)cpu >= active_capacity || !CPU_ISSET_S(cpu, active_bytes, active_cpus))
        fatal("current host CPU outside initial affinity snapshot");
    uint32_t index = 0;
    for (int i = 0; i < cpu; ++i) if (CPU_ISSET_S(i, active_bytes, active_cpus)) ++index;
    if (number) *number = (processor_number){index / 64, index % 64, 0};
    return index % 64;
}
extern void driverlab_chkstk(void);
#define X(name) {"ntoskrnl.exe", #name, (void *)x_##name}
const nt_export driverlab_extras_exports[] = {
    X(strcpy_s), X(strncpy_s), X(wcscpy_s), X(wcscat_s), X(RtlPrefixUnicodeString), X(RtlMultiByteToUnicodeN),
    X(RtlTimeToTimeFields), X(ExSystemTimeToLocalTime), X(ProbeForRead), X(ProbeForWrite),
    X(ExInitializePushLock), X(ExAcquirePushLockExclusiveEx), X(ExReleasePushLockExclusiveEx),
    X(ExAcquirePushLockSharedEx), X(ExReleasePushLockSharedEx),
    X(ExAllocateCacheAwareRundownProtection), X(ExFreeCacheAwareRundownProtection),
    X(ExAcquireRundownProtectionCacheAwareEx), X(ExReleaseRundownProtectionCacheAwareEx), X(ExWaitForRundownProtectionReleaseCacheAware),
    X(KeQueryActiveProcessorCountEx), X(KeGetCurrentProcessorNumberEx),
    {"ntoskrnl.exe", "KeNumberProcessors", &number_processors}, {"ntoskrnl.exe", "__chkstk", (void *)driverlab_chkstk},
};
const size_t driverlab_extras_count = sizeof(driverlab_extras_exports) / sizeof(driverlab_extras_exports[0]);
