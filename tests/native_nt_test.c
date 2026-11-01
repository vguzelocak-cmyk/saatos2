#define _GNU_SOURCE
#include "ntcompat.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <uchar.h>
#include <unistd.h>

#define IMPORT(name, result, ...) static result (NTAPI *p_##name)(__VA_ARGS__)
#define BIND(name) do { p_##name = (__typeof__(p_##name))driverlab_resolve("ntoskrnl.exe", #name); assert(p_##name); } while (0)
IMPORT(ExAllocatePoolWithTag, void *, uint32_t, size_t, uint32_t);
IMPORT(ExFreePoolWithTag, void, void *, uint32_t);
IMPORT(RtlInitUnicodeString, void, unicode_string *, const uint16_t *);
IMPORT(RtlDuplicateUnicodeString, uint32_t, uint32_t, const unicode_string *, unicode_string *);
IMPORT(RtlFreeUnicodeString, void, unicode_string *);
IMPORT(RtlCompareMemory, size_t, const void *, const void *, size_t);
IMPORT(KeInitializeEvent, void, void *, int, uint8_t);
IMPORT(KeSetEvent, int32_t, void *, int32_t, uint8_t);
IMPORT(KeResetEvent, int32_t, void *);
IMPORT(KeReadStateEvent, int32_t, void *);
IMPORT(KeWaitForSingleObject, uint32_t, void *, int, int, uint8_t, const int64_t *);
IMPORT(KeInitializeMutex, void, void *, uint32_t);
IMPORT(KeReleaseMutex, int32_t, void *, uint8_t);
IMPORT(KeInitializeGuardedMutex, void, void *);
IMPORT(KeAcquireGuardedMutex, void, void *);
IMPORT(KeReleaseGuardedMutex, void, void *);
IMPORT(KeAreAllApcsDisabled, uint8_t, void);
IMPORT(KeInitializeSpinLock, void, _Atomic uintptr_t *);
IMPORT(KeAcquireSpinLockRaiseToDpc, uint8_t, _Atomic uintptr_t *);
IMPORT(KeReleaseSpinLock, void, _Atomic uintptr_t *, uint8_t);
IMPORT(KeGetCurrentIrql, uint8_t, void);
IMPORT(KfRaiseIrql, uint8_t, uint8_t);
IMPORT(KeLowerIrql, void, uint8_t);
IMPORT(ExInitializeRundownProtection, void, _Atomic uintptr_t *);
IMPORT(ExAcquireRundownProtection, uint8_t, _Atomic uintptr_t *);
IMPORT(ExReleaseRundownProtection, void, _Atomic uintptr_t *);
IMPORT(ExWaitForRundownProtectionRelease, void, _Atomic uintptr_t *);
IMPORT(KeQuerySystemTimePrecise, void, int64_t *);
IMPORT(KeQueryPerformanceCounter, int64_t, int64_t *);
IMPORT(KeDelayExecutionThread, uint32_t, int, uint8_t, const int64_t *);
IMPORT(RtlPcToFileHeader, void *, void *, void **);
IMPORT(MmGetSystemRoutineAddress, void *, const unicode_string *);

static void bind_all(void)
{
    BIND(ExAllocatePoolWithTag); BIND(ExFreePoolWithTag);
    BIND(RtlInitUnicodeString); BIND(RtlDuplicateUnicodeString); BIND(RtlFreeUnicodeString); BIND(RtlCompareMemory);
    BIND(KeInitializeEvent); BIND(KeSetEvent); BIND(KeResetEvent); BIND(KeReadStateEvent); BIND(KeWaitForSingleObject);
    BIND(KeInitializeMutex); BIND(KeReleaseMutex);
    BIND(KeInitializeGuardedMutex); BIND(KeAcquireGuardedMutex); BIND(KeReleaseGuardedMutex); BIND(KeAreAllApcsDisabled);
    BIND(KeInitializeSpinLock); BIND(KeAcquireSpinLockRaiseToDpc); BIND(KeReleaseSpinLock); BIND(KeGetCurrentIrql);
    BIND(KfRaiseIrql); BIND(KeLowerIrql);
    BIND(ExInitializeRundownProtection); BIND(ExAcquireRundownProtection);
    BIND(ExReleaseRundownProtection); BIND(ExWaitForRundownProtectionRelease);
    BIND(KeQuerySystemTimePrecise); BIND(KeQueryPerformanceCounter); BIND(KeDelayExecutionThread);
    BIND(RtlPcToFileHeader); BIND(MmGetSystemRoutineAddress);
}

static void test_pool(void)
{
    unsigned char *memory = p_ExAllocatePoolWithTag(512, 65, 1234);
    assert(memory && (uintptr_t)memory % 16 == 0);
    memset(memory, 0xA5, 65);
    assert(memory[64] == 0xA5);
    p_ExFreePoolWithTag(memory, 1234);
    memory = p_ExAllocatePoolWithTag(1, 0, 0);
    assert(memory);
    p_ExFreePoolWithTag(memory, 0);
}
static void test_unicode(void)
{
    uint16_t text[] = {0x41, 0x20AC, 0xD83D, 0xDE00, 0};
    unicode_string source, copy;
    p_RtlInitUnicodeString(&source, text);
    assert(source.length == 8 && source.maximum_length == 10 && source.buffer == text);
    assert(!p_RtlDuplicateUnicodeString(3, &source, &copy));
    assert(copy.length == 8 && copy.maximum_length == 10 && copy.buffer != text);
    assert(!memcmp(copy.buffer, text, 10));
    text[0] = 0x42;
    assert(copy.buffer[0] == 0x41);
    p_RtlFreeUnicodeString(&copy);
    assert(!copy.buffer && !copy.length && !copy.maximum_length);
    assert(p_RtlDuplicateUnicodeString(2, &source, &copy) == 0xC000000D);
    p_RtlInitUnicodeString(&source, NULL);
    assert(!source.length && !source.maximum_length && !source.buffer);
    assert(!p_RtlDuplicateUnicodeString(3, &source, &copy));
    assert(copy.buffer && copy.maximum_length == 2 && copy.buffer[0] == 0);
    p_RtlFreeUnicodeString(&copy);
    uint16_t *long_text = calloc(32770, 2);
    assert(long_text);
    for (int i = 0; i < 32769; ++i) long_text[i] = 0x41;
    p_RtlInitUnicodeString(&source, long_text);
    assert(source.length == 65532 && source.maximum_length == 65534);
    free(long_text);
    assert(p_RtlCompareMemory("abcX", "abcY", 4) == 3);
    assert(p_RtlCompareMemory("abc", "abc", 3) == 3);
}

typedef struct { void *object; uint32_t result; int release_mutex; } wait_context;
static void *wait_thread(void *argument)
{
    wait_context *context = argument;
    int64_t timeout = -INT64_C(2000000); /* 200 ms */
    context->result = p_KeWaitForSingleObject(context->object, 0, 0, 0, &timeout);
    if (!context->result && context->release_mutex) p_KeReleaseMutex(context->object, 0);
    return NULL;
}
static void test_events(void)
{
    _Alignas(8) unsigned char event[24];
    int64_t zero = 0, short_wait = -10000;
    p_KeInitializeEvent(event, 0, 0);
    assert(p_KeWaitForSingleObject(event, 0, 0, 0, &zero) == 0x102);
    assert(p_KeWaitForSingleObject(event, 0, 0, 0, &short_wait) == 0x102);
    assert(p_KeSetEvent(event, 0, 0) == 0);
    assert(p_KeReadStateEvent(event) == 1);
    assert(!p_KeWaitForSingleObject(event, 0, 0, 0, &zero));
    assert(!p_KeWaitForSingleObject(event, 0, 0, 0, &zero));
    assert(p_KeResetEvent(event) == 1);
    assert(!p_KeReadStateEvent(event));
    for (int type = 0; type <= 1; ++type) {
        p_KeInitializeEvent(event, type, 0);
        wait_context a = {event, 99, 0}, b = {event, 99, 0};
        pthread_t first, second;
        assert(!pthread_create(&first, NULL, wait_thread, &a));
        assert(!pthread_create(&second, NULL, wait_thread, &b));
        usleep(10000);
        p_KeSetEvent(event, 0, 0);
        pthread_join(first, NULL); pthread_join(second, NULL);
        if (!type) assert(a.result == 0 && b.result == 0);
        else assert((a.result == 0 && b.result == 0x102) || (b.result == 0 && a.result == 0x102));
    }
    assert(p_KeWaitForSingleObject(event, 0, 0, 1, &zero) == 0xC00000BB);
    uint8_t previous = p_KfRaiseIrql(2);
    p_KeSetEvent(event, 0, 0);
    assert(!p_KeWaitForSingleObject(event, 0, 0, 0, &zero));
    assert(p_KeWaitForSingleObject(event, 0, 0, 0, &short_wait) == 0xC0000184);
    p_KeLowerIrql(previous);
}
static void test_mutex(void)
{
    _Alignas(8) unsigned char mutex[56];
    int64_t zero = 0;
    p_KeInitializeMutex(mutex, 0);
    assert(!p_KeWaitForSingleObject(mutex, 0, 0, 0, &zero));
    assert(!p_KeWaitForSingleObject(mutex, 0, 0, 0, &zero));
    assert(p_KeReleaseMutex(mutex, 0) == -1);
    wait_context context = {mutex, 99, 1};
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, wait_thread, &context));
    usleep(10000);
    assert(p_KeReleaseMutex(mutex, 0) == 0);
    pthread_join(thread, NULL);
    assert(!context.result);
}

static _Alignas(8) unsigned char guarded[56];
static _Atomic uintptr_t spinlock;
static unsigned counter;
static void *guarded_thread(void *unused)
{
    (void)unused;
    for (int i = 0; i < 1000; ++i) {
        p_KeAcquireGuardedMutex(guarded);
        assert(p_KeAreAllApcsDisabled());
        ++counter;
        p_KeReleaseGuardedMutex(guarded);
        assert(!p_KeAreAllApcsDisabled());
    }
    return NULL;
}
static void *spin_thread(void *unused)
{
    (void)unused;
    for (int i = 0; i < 10000; ++i) {
        uint8_t previous = p_KeAcquireSpinLockRaiseToDpc(&spinlock);
        assert(previous == 0 && p_KeGetCurrentIrql() == 2);
        ++counter;
        p_KeReleaseSpinLock(&spinlock, previous);
        assert(!p_KeGetCurrentIrql());
    }
    return NULL;
}
static void test_locks(void)
{
    p_KeInitializeGuardedMutex(guarded);
    p_KeInitializeSpinLock(&spinlock);
    for (int kind = 0; kind < 2; ++kind) {
        pthread_t threads[4];
        counter = 0;
        for (int i = 0; i < 4; ++i)
            assert(!pthread_create(&threads[i], NULL, kind ? spin_thread : guarded_thread, NULL));
        for (int i = 0; i < 4; ++i) pthread_join(threads[i], NULL);
        assert(counter == (kind ? 40000u : 4000u));
    }
}
static _Atomic uintptr_t rundown;
static void *rundown_thread(void *unused)
{
    (void)unused;
    p_ExWaitForRundownProtectionRelease(&rundown);
    return NULL;
}
static void test_rundown(void)
{
    p_ExInitializeRundownProtection(&rundown);
    assert(p_ExAcquireRundownProtection(&rundown));
    assert(p_ExAcquireRundownProtection(&rundown));
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, rundown_thread, NULL));
    while (!(atomic_load(&rundown) & 1)) sched_yield();
    assert(!p_ExAcquireRundownProtection(&rundown));
    p_ExReleaseRundownProtection(&rundown);
    assert((atomic_load(&rundown) & ~(uintptr_t)1) == 2);
    p_ExReleaseRundownProtection(&rundown);
    pthread_join(thread, NULL);
    assert(!p_ExAcquireRundownProtection(&rundown));
}
static void test_time_and_lookup(void)
{
    int64_t ticks, frequency, interval = -200000;
    p_KeQuerySystemTimePrecise(&ticks);
    assert(llabs(ticks - (time(NULL) * INT64_C(10000000) + INT64_C(116444736000000000))) < 10000000);
    int64_t before = p_KeQueryPerformanceCounter(&frequency);
    assert(frequency == 1000000000);
    assert(!p_KeDelayExecutionThread(0, 0, &interval));
    assert(p_KeQueryPerformanceCounter(NULL) - before >= 15000000);
    assert(p_KeDelayExecutionThread(0, 1, &interval) == 0xC00000BB);
    int64_t distant_past = 1;
    assert(!p_KeDelayExecutionThread(0, 0, &distant_past));
    assert(driverlab_resolve("HAL.dll", "KeQueryPerformanceCounter") == (void *)p_KeQueryPerformanceCounter);
    unicode_string name;
    p_RtlInitUnicodeString(&name, (const uint16_t *)u"KeSetEvent");
    assert(p_MmGetSystemRoutineAddress(&name) == (void *)p_KeSetEvent);
    p_RtlInitUnicodeString(&name, (const uint16_t *)u"MissingRoutine");
    assert(!p_MmGetSystemRoutineAddress(&name));
    unsigned char image[20];
    void *base = NULL;
    driverlab_set_image(image, sizeof(image));
    assert(p_RtlPcToFileHeader(image + 3, &base) == image && base == image);
    assert(!p_RtlPcToFileHeader(image + 20, &base) && !base);
    assert(!driverlab_resolve("cng.sys", "KeSetEvent"));
    assert(!driverlab_resolve("ntoskrnl.exe", "kesetevent"));
}

int main(int argc, char **argv)
{
    struct rlimit limit = {0, 0};
    setrlimit(RLIMIT_CORE, &limit);
    assert(argc == 2);
    bind_all();
    if (!strcmp(argv[1], "pool")) test_pool();
    else if (!strcmp(argv[1], "unicode")) test_unicode();
    else if (!strcmp(argv[1], "events")) test_events();
    else if (!strcmp(argv[1], "mutex")) test_mutex();
    else if (!strcmp(argv[1], "locks")) test_locks();
    else if (!strcmp(argv[1], "rundown")) test_rundown();
    else if (!strcmp(argv[1], "time")) test_time_and_lookup();
    else if (!strcmp(argv[1], "bad-free")) {
        unsigned char local;
        p_ExFreePoolWithTag(&local, 0);
        return 9;
    } else return 2;
    printf("%s: PASS\n", argv[1]);
    return 0;
}
