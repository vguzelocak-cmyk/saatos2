#define _GNU_SOURCE
#include "ntcompat.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <uchar.h>
#include <unistd.h>

#define W(s) ((const uint16_t *)u##s)
#define IMPORT(name, result, ...) static result (NTAPI *p_##name)(__VA_ARGS__)
#define BIND(name) do { p_##name = (__typeof__(p_##name))driverlab_resolve("ntoskrnl.exe", #name); assert(p_##name); } while (0)
IMPORT(strcpy_s, int, char *, size_t, const char *);
IMPORT(strncpy_s, int, char *, size_t, const char *, size_t);
IMPORT(wcscpy_s, int, uint16_t *, size_t, const uint16_t *);
IMPORT(wcscat_s, int, uint16_t *, size_t, const uint16_t *);
IMPORT(RtlPrefixUnicodeString, uint8_t, const unicode_string *, const unicode_string *, uint8_t);
IMPORT(RtlMultiByteToUnicodeN, uint32_t, uint16_t *, uint32_t, uint32_t *, const unsigned char *, uint32_t);
typedef struct { int16_t year, month, day, hour, minute, second, milliseconds, weekday; } time_fields;
IMPORT(RtlTimeToTimeFields, void, const int64_t *, time_fields *);
IMPORT(ExSystemTimeToLocalTime, void, const int64_t *, int64_t *);
IMPORT(ProbeForRead, void, const void *, size_t, uint32_t);
IMPORT(ProbeForWrite, void, void *, size_t, uint32_t);
IMPORT(ExInitializePushLock, void, _Atomic uintptr_t *);
IMPORT(ExAcquirePushLockExclusiveEx, void, _Atomic uintptr_t *, uint32_t);
IMPORT(ExReleasePushLockExclusiveEx, void, _Atomic uintptr_t *, uint32_t);
IMPORT(ExAcquirePushLockSharedEx, void, _Atomic uintptr_t *, uint32_t);
IMPORT(ExReleasePushLockSharedEx, void, _Atomic uintptr_t *, uint32_t);
IMPORT(KeEnterCriticalRegion, void, void);
IMPORT(KeLeaveCriticalRegion, void, void);
IMPORT(KeInitializeMutex, void, void *, uint32_t);
IMPORT(KeWaitForSingleObject, uint32_t, void *, int, int, uint8_t, const int64_t *);
IMPORT(KeReleaseMutex, int32_t, void *, uint8_t);
IMPORT(ExAllocateCacheAwareRundownProtection, void *, uint32_t, uint32_t);
IMPORT(ExFreeCacheAwareRundownProtection, void, void *);
IMPORT(ExAcquireRundownProtectionCacheAwareEx, uint8_t, void *, uint32_t);
IMPORT(ExReleaseRundownProtectionCacheAwareEx, void, void *, uint32_t);
IMPORT(ExWaitForRundownProtectionReleaseCacheAware, void, void *);
IMPORT(KeQueryActiveProcessorCountEx, uint32_t, uint16_t);
typedef struct { uint16_t group; uint8_t number, reserved; } processor_number;
IMPORT(KeGetCurrentProcessorNumberEx, uint32_t, processor_number *);

static unicode_string string(const uint16_t *s)
{
    size_t n = 0; while (s && s[n]) ++n;
    return (unicode_string){n * 2, s ? n * 2 + 2 : 0, (uint16_t *)s};
}
static void test_strings(void)
{
    char text[8];
    assert(!p_strcpy_s(text, sizeof(text), "abc") && !strcmp(text, "abc"));
    assert(p_strcpy_s(text, sizeof(text), "abcdefgh") == ERANGE && !text[0]);
    assert(p_strcpy_s(text, sizeof(text), NULL) == EINVAL && !text[0]);
    assert(!p_strncpy_s(text, sizeof(text), "abcdef", 3) && !strcmp(text, "abc"));
    assert(p_strncpy_s(text, sizeof(text), "abcdefghij", SIZE_MAX) == 80 && !strcmp(text, "abcdefg"));
    assert(p_strncpy_s(text, 3, "abc", 3) == ERANGE && !text[0]);
    assert(!p_strncpy_s(NULL, 0, NULL, 0));
    assert(!p_strcpy_s(text, sizeof(text), "abc"));
    assert(p_strcpy_s(text, sizeof(text), text) == EINVAL && !text[0]);
    uint16_t wide[8];
    assert(!p_wcscpy_s(wide, 8, W("A€")));
    assert(!p_wcscat_s(wide, 8, W("😀")));
    assert(wide[0] == 'A' && wide[1] == 0x20AC && wide[2] == 0xD83D && wide[3] == 0xDE00 && !wide[4]);
    assert(p_wcscpy_s(wide, 2, W("AB")) == ERANGE && !wide[0]);
    assert(!p_wcscpy_s(wide, 8, W("AB")));
    assert(p_wcscat_s(wide, 3, W("C")) == ERANGE && !wide[0]);
}
static void test_unicode(void)
{
    unicode_string prefix = string(W("\\Driver\\é")), full = string(W("\\DRIVER\\Émore"));
    assert(!p_RtlPrefixUnicodeString(&prefix, &full, 0));
    assert(p_RtlPrefixUnicodeString(&prefix, &full, 1));
    assert(!p_RtlPrefixUnicodeString(&full, &prefix, 1));
    unicode_string empty = {0}; assert(p_RtlPrefixUnicodeString(&empty, &full, 0));
    unsigned char bytes[] = {0x80, 0x8A, 0xE9, 0};
    uint16_t output[5] = {0, 0, 0, 0, 0xAAAA}; uint32_t written = 99;
    assert(!p_RtlMultiByteToUnicodeN(output, 8, &written, bytes, 4) && written == 8);
    assert(output[0] == 0x20AC && output[1] == 0x0160 && output[2] == 0x00E9 && !output[3] && output[4] == 0xAAAA);
    output[1] = 0xBBBB;
    assert(!p_RtlMultiByteToUnicodeN(output, 3, &written, bytes, 4) && written == 2 && output[1] == 0xBBBB);
    assert(!p_RtlMultiByteToUnicodeN(NULL, 0, &written, NULL, 0) && !written);
}
static void test_time(void)
{
    time_fields fields;
    int64_t ticks = 0;
    p_RtlTimeToTimeFields(&ticks, &fields);
    assert(fields.year == 1601 && fields.month == 1 && fields.day == 1 && fields.weekday == 1);
    ticks = -1; p_RtlTimeToTimeFields(&ticks, &fields);
    assert(fields.year == 1600 && fields.month == 12 && fields.day == 31 && fields.hour == 23 && fields.second == 59 && fields.milliseconds == 999);
    ticks = INT64_C(116444736000000000) + INT64_C(1709210096) * 10000000 + 7890000;
    p_RtlTimeToTimeFields(&ticks, &fields);
    assert(fields.year == 2024 && fields.month == 2 && fields.day == 29 && fields.hour == 12 && fields.minute == 34 &&
           fields.second == 56 && fields.milliseconds == 789 && fields.weekday == 4);
    setenv("TZ", "UTC0", 1); tzset(); int64_t local;
    p_ExSystemTimeToLocalTime(&ticks, &local); assert(local == ticks);
    setenv("TZ", "UTC-3", 1); tzset();
    p_ExSystemTimeToLocalTime(&ticks, &local); assert(local == ticks + INT64_C(10800) * 10000000);
    setenv("TZ", "EST5EDT,M3.2.0/2,M11.1.0/2", 1); tzset();
    ticks = INT64_C(116444736000000000) + INT64_C(1720000000) * 10000000;
    p_ExSystemTimeToLocalTime(&ticks, &ticks);
    assert(ticks == INT64_C(116444736000000000) + INT64_C(1719985600) * 10000000);
}

static _Atomic uintptr_t push;
static unsigned counter;
static _Atomic unsigned active_readers;
static pthread_barrier_t readers_ready, readers_release;
static void *writer_loop(void *unused)
{
    (void)unused;
    p_KeEnterCriticalRegion();
    for (int i = 0; i < 1000; ++i) {
        p_ExAcquirePushLockExclusiveEx(&push, 0); ++counter; p_ExReleasePushLockExclusiveEx(&push, 0);
    }
    p_KeLeaveCriticalRegion(); return NULL;
}
static void *shared_reader(void *unused)
{
    (void)unused;
    p_KeEnterCriticalRegion(); p_ExAcquirePushLockSharedEx(&push, 0);
    atomic_fetch_add(&active_readers, 1);
    pthread_barrier_wait(&readers_ready); pthread_barrier_wait(&readers_release);
    atomic_fetch_sub(&active_readers, 1);
    p_ExReleasePushLockSharedEx(&push, 0); p_KeLeaveCriticalRegion(); return NULL;
}
static void *exclusive_after_readers(void *unused)
{
    (void)unused;
    p_KeEnterCriticalRegion(); p_ExAcquirePushLockExclusiveEx(&push, 0);
    assert(!atomic_load(&active_readers));
    p_ExReleasePushLockExclusiveEx(&push, 0); p_KeLeaveCriticalRegion(); return NULL;
}
static void test_push(void)
{
    p_ExInitializePushLock(&push);
    pthread_t threads[4];
    for (int i = 0; i < 4; ++i) assert(!pthread_create(&threads[i], NULL, writer_loop, NULL));
    for (int i = 0; i < 4; ++i) pthread_join(threads[i], NULL);
    assert(counter == 4000 && !atomic_load(&push));
    assert(!pthread_barrier_init(&readers_ready, NULL, 3)); assert(!pthread_barrier_init(&readers_release, NULL, 3));
    assert(!pthread_create(&threads[0], NULL, shared_reader, NULL)); assert(!pthread_create(&threads[1], NULL, shared_reader, NULL));
    pthread_barrier_wait(&readers_ready); assert(atomic_load(&active_readers) == 2);
    assert(!pthread_create(&threads[2], NULL, exclusive_after_readers, NULL));
    pthread_barrier_wait(&readers_release);
    for (int i = 0; i < 3; ++i) pthread_join(threads[i], NULL);
    pthread_barrier_destroy(&readers_ready); pthread_barrier_destroy(&readers_release);
    _Alignas(8) unsigned char mutex[56]; int64_t zero = 0;
    p_KeInitializeMutex(mutex, 0); assert(!p_KeWaitForSingleObject(mutex, 0, 0, 0, &zero));
    assert(driverlab_normal_apcs_disabled());
    p_ExAcquirePushLockExclusiveEx(&push, 0); p_ExReleasePushLockExclusiveEx(&push, 0);
    p_KeReleaseMutex(mutex, 0); assert(!driverlab_normal_apcs_disabled());
}

static void *cached;
static _Atomic unsigned drained;
static void *rundown_waiter(void *unused)
{
    (void)unused; p_ExWaitForRundownProtectionReleaseCacheAware(cached); atomic_store(&drained, 1); return NULL;
}
static void test_cached(void)
{
    cached = p_ExAllocateCacheAwareRundownProtection(512, 123);
    assert(cached && (uintptr_t)cached % 64 == 0);
    assert(p_ExAcquireRundownProtectionCacheAwareEx(cached, 3)); assert(p_ExAcquireRundownProtectionCacheAwareEx(cached, 2));
    pthread_t thread; assert(!pthread_create(&thread, NULL, rundown_waiter, NULL));
    while (p_ExAcquireRundownProtectionCacheAwareEx(cached, 1)) { p_ExReleaseRundownProtectionCacheAwareEx(cached, 1); sched_yield(); }
    p_ExReleaseRundownProtectionCacheAwareEx(cached, 3); assert(!atomic_load(&drained));
    p_ExReleaseRundownProtectionCacheAwareEx(cached, 2); pthread_join(thread, NULL);
    assert(atomic_load(&drained) && !p_ExAcquireRundownProtectionCacheAwareEx(cached, 1));
    p_ExFreeCacheAwareRundownProtection(cached);
}
static void test_cpu(void)
{
    size_t capacity = (size_t)sysconf(_SC_NPROCESSORS_CONF), bytes;
    cpu_set_t *original = NULL;
    for (;;) {
        bytes = CPU_ALLOC_SIZE(capacity); original = CPU_ALLOC(capacity); assert(original);
        if (!sched_getaffinity(0, bytes, original)) break;
        assert(errno == EINVAL); CPU_FREE(original); capacity *= 2;
    }
    unsigned total = CPU_COUNT_S(bytes, original);
    assert(p_KeQueryActiveProcessorCountEx(UINT16_MAX) == total);
    assert(*(uint8_t *)driverlab_resolve("ntoskrnl.exe", "KeNumberProcessors") == (total < 64 ? total : 64));
    unsigned sum = 0;
    for (unsigned i = 0; i <= total / 64; ++i) sum += p_KeQueryActiveProcessorCountEx(i);
    assert(sum == total && !p_KeQueryActiveProcessorCountEx(UINT16_MAX - 1));
    cpu_set_t *single = CPU_ALLOC(capacity); assert(single); CPU_ZERO_S(bytes, single);
    size_t first = 0; while (!CPU_ISSET_S(first, bytes, original)) ++first;
    CPU_SET_S(first, bytes, single); assert(!sched_setaffinity(0, bytes, single));
    processor_number number = {99, 99, 99};
    assert(!p_KeGetCurrentProcessorNumberEx(&number) && !number.group && !number.number && !number.reserved);
    assert(sched_getcpu() == (int)first);
    assert(!sched_setaffinity(0, bytes, original)); CPU_FREE(single); CPU_FREE(original);
}
extern int driverlab_test_chkstk(void *function, size_t count);
static void *overflow_probe(void *unused)
{
    (void)unused; driverlab_test_chkstk(driverlab_resolve("ntoskrnl.exe", "__chkstk"), 2 * 1024 * 1024); return NULL;
}
static void bind_all(void)
{
    BIND(strcpy_s); BIND(strncpy_s); BIND(wcscpy_s); BIND(wcscat_s);
    BIND(RtlPrefixUnicodeString); BIND(RtlMultiByteToUnicodeN); BIND(RtlTimeToTimeFields); BIND(ExSystemTimeToLocalTime);
    BIND(ProbeForRead); BIND(ProbeForWrite);
    BIND(ExInitializePushLock); BIND(ExAcquirePushLockExclusiveEx); BIND(ExReleasePushLockExclusiveEx);
    BIND(ExAcquirePushLockSharedEx); BIND(ExReleasePushLockSharedEx); BIND(KeEnterCriticalRegion); BIND(KeLeaveCriticalRegion);
    BIND(KeInitializeMutex); BIND(KeWaitForSingleObject); BIND(KeReleaseMutex);
    BIND(ExAllocateCacheAwareRundownProtection); BIND(ExFreeCacheAwareRundownProtection);
    BIND(ExAcquireRundownProtectionCacheAwareEx); BIND(ExReleaseRundownProtectionCacheAwareEx); BIND(ExWaitForRundownProtectionReleaseCacheAware);
    BIND(KeQueryActiveProcessorCountEx); BIND(KeGetCurrentProcessorNumberEx);
}
int main(int argc, char **argv)
{
    struct rlimit limit = {0, 0}; setrlimit(RLIMIT_CORE, &limit); assert(argc == 2); bind_all();
    if (!strcmp(argv[1], "strings")) test_strings();
    else if (!strcmp(argv[1], "unicode")) test_unicode();
    else if (!strcmp(argv[1], "time")) test_time();
    else if (!strcmp(argv[1], "push")) test_push();
    else if (!strcmp(argv[1], "cached")) test_cached();
    else if (!strcmp(argv[1], "cpu")) test_cpu();
    else if (!strcmp(argv[1], "stack")) {
        const size_t counts[] = {0, 1, 4095, 4096, 4097, 12288};
        for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i)
            assert(driverlab_test_chkstk(driverlab_resolve("ntoskrnl.exe", "__chkstk"), counts[i]));
    } else if (!strcmp(argv[1], "probe")) {
        _Alignas(16) unsigned char buffer[32] = {0xA5};
        p_ProbeForRead(buffer, sizeof(buffer), 16); p_ProbeForWrite(buffer, sizeof(buffer), 16);
        p_ProbeForWrite(NULL, 0, 0); assert(buffer[0] == 0xA5);
    } else if (!strcmp(argv[1], "bad-probe")) {
        void *buffer = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); assert(buffer != MAP_FAILED);
        p_ProbeForWrite(buffer, 16, 1); return 9;
    } else if (!strcmp(argv[1], "bad-align")) {
        _Alignas(8) unsigned char buffer[16]; p_ProbeForRead(buffer + 1, 1, 4); return 9;
    } else if (!strcmp(argv[1], "bad-push")) {
        p_ExInitializePushLock(&push); p_ExAcquirePushLockExclusiveEx(&push, 0); return 9;
    } else if (!strcmp(argv[1], "bad-cached")) {
        void *p = p_ExAllocateCacheAwareRundownProtection(0, 0); assert(p);
        assert(p_ExAcquireRundownProtectionCacheAwareEx(p, 1)); p_ExFreeCacheAwareRundownProtection(p); return 9;
    } else if (!strcmp(argv[1], "stack-guard")) {
        pthread_attr_t attr; pthread_t thread;
        assert(!pthread_attr_init(&attr)); assert(!pthread_attr_setstacksize(&attr, 65536)); assert(!pthread_attr_setguardsize(&attr, 4096));
        assert(!pthread_create(&thread, &attr, overflow_probe, NULL)); pthread_join(thread, NULL); pthread_attr_destroy(&attr);
    } else return 2;
    printf("%s: PASS\n", argv[1]); return 0;
}
