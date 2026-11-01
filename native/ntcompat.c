#define _GNU_SOURCE
#include "ntcompat.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define SUCCESS UINT32_C(0)
#define TIMEOUT UINT32_C(0x102)
#define INVALID_PARAMETER UINT32_C(0xc000000d)
#define NO_MEMORY UINT32_C(0xc0000017)
#define NOT_SUPPORTED UINT32_C(0xc00000bb)
#define INVALID_DEVICE_STATE UINT32_C(0xc0000184)
#define WINDOWS_EPOCH INT64_C(116444736000000000)

static _Thread_local uint8_t irql;
static _Thread_local unsigned critical_depth, guarded_depth;
static void *image_base;
static size_t image_size;

static void fatal(const char *message)
{
    fprintf(stderr, "driverlab NT contract violation: %s\n", message);
    abort();
}

/* Pool pages are host process memory, not physical nonpaged Windows memory. */
typedef struct allocation {
    void *pointer;
    uint32_t tag;
    struct allocation *next;
} allocation;
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static allocation *allocations;

static void *NTAPI nt_ExAllocatePoolWithTag(uint32_t type, size_t size, uint32_t tag)
{
    if (type != 0 && type != 1 && type != 512) {
        fprintf(stderr, "driverlab: unsupported pool type %u\n", type);
        return NULL;
    }
    if (irql > 2 || (type == 1 && irql > 1))
        fatal("pool allocation at invalid virtual IRQL");
    void *pointer = NULL;
    if (posix_memalign(&pointer, 16, size ? size : 1))
        return NULL;
    allocation *record = malloc(sizeof(*record));
    if (!record) {
        free(pointer);
        return NULL;
    }
    *record = (allocation){pointer, tag, NULL};
    pthread_mutex_lock(&pool_mutex);
    record->next = allocations;
    allocations = record;
    pthread_mutex_unlock(&pool_mutex);
    return pointer;
}

static void NTAPI nt_ExFreePoolWithTag(void *pointer, uint32_t tag)
{
    pthread_mutex_lock(&pool_mutex);
    allocation **slot = &allocations;
    while (*slot && (*slot)->pointer != pointer)
        slot = &(*slot)->next;
    if (!*slot)
        fatal("pool free of unknown or already freed pointer");
    allocation *record = *slot;
    if (tag && tag != record->tag)
        fatal("pool tag mismatch");
    *slot = record->next;
    pthread_mutex_unlock(&pool_mutex);
    free(pointer);
    free(record);
}

static void NTAPI nt_ExFreePool(void *pointer) { nt_ExFreePoolWithTag(pointer, 0); }

static size_t NTAPI nt_wcslen(const uint16_t *text)
{
    const uint16_t *end = text;
    while (*end) ++end;
    return (size_t)(end - text);
}

static void NTAPI nt_RtlInitUnicodeString(unicode_string *destination, const uint16_t *source)
{
    size_t length = source ? nt_wcslen(source) : 0;
    if (length > 32766) length = 32766;
    *destination = (unicode_string){length * 2, source ? length * 2 + 2 : 0, (uint16_t *)source};
}

static uint32_t NTAPI nt_RtlDuplicateUnicodeString(uint32_t flags, const unicode_string *source,
                                                 unicode_string *destination)
{
    if (!source || !destination || source == destination || flags > 3 || flags == 2 ||
        source->length % 2 || source->length > source->maximum_length ||
        (source->length && !source->buffer))
        return INVALID_PARAMETER;
    *destination = (unicode_string){0};
    size_t bytes = source->length + ((flags & 1) ? 2 : 0);
    if (!source->length && (!source->buffer || !bytes) && flags != 3)
        return SUCCESS;
    if (bytes > UINT16_MAX)
        return INVALID_PARAMETER;
    uint16_t *buffer = nt_ExAllocatePoolWithTag(1, bytes, UINT32_C(0x44556c52));
    if (!buffer) return NO_MEMORY;
    if (source->length) memcpy(buffer, source->buffer, source->length);
    if (flags & 1) buffer[source->length / 2] = 0;
    *destination = (unicode_string){source->length, bytes, buffer};
    return SUCCESS;
}

static void NTAPI nt_RtlFreeUnicodeString(unicode_string *string)
{
    if (string->buffer) nt_ExFreePool(string->buffer);
    *string = (unicode_string){0};
}

static size_t NTAPI nt_RtlCompareMemory(const void *a, const void *b, size_t size)
{
    const unsigned char *left = a, *right = b;
    size_t count = 0;
    while (count < size && left[count] == right[count]) ++count;
    return count;
}

static void *NTAPI nt_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
static void *NTAPI nt_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
static void *NTAPI nt_memset(void *d, int c, size_t n) { return memset(d, c, n); }
static int NTAPI nt_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
static size_t NTAPI nt_strlen(const char *s) { return strlen(s); }
static size_t NTAPI nt_strnlen(const char *s, size_t n) { return strnlen(s, n); }
static int NTAPI nt_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static char *NTAPI nt_strchr(const char *s, int c)
{
    /* Keep the Windows CRT ABI even when host headers preserve input constness. */
    return (char *)strchr(s, c);
}

/* Virtual IRQL/APC state is local to this runtime, not Linux IRQ masking. */
static uint8_t NTAPI nt_KeGetCurrentIrql(void) { return irql; }
static uint8_t NTAPI nt_KfRaiseIrql(uint8_t level)
{
    if (level < irql || level > 31) fatal("invalid IRQL raise");
    uint8_t previous = irql;
    irql = level;
    return previous;
}
static void NTAPI nt_KeLowerIrql(uint8_t level)
{
    if (level > irql) fatal("invalid IRQL lower");
    irql = level;
}
static void NTAPI nt_KeEnterCriticalRegion(void) { ++critical_depth; }
static void NTAPI nt_KeLeaveCriticalRegion(void)
{
    if (!critical_depth) fatal("unbalanced critical region");
    --critical_depth;
}
static uint8_t NTAPI nt_KeAreAllApcsDisabled(void) { return guarded_depth != 0 || irql >= 1; }

static void NTAPI nt_KeInitializeSpinLock(_Atomic uintptr_t *lock) { atomic_init(lock, 0); }
static void NTAPI nt_KeAcquireSpinLockAtDpcLevel(_Atomic uintptr_t *lock)
{
    if (irql < 2) fatal("DPC spinlock acquire below DISPATCH_LEVEL");
    while (atomic_exchange_explicit(lock, 1, memory_order_acquire)) sched_yield();
}
static void NTAPI nt_KeReleaseSpinLockFromDpcLevel(_Atomic uintptr_t *lock)
{
    if (irql < 2 || !atomic_load(lock)) fatal("invalid DPC spinlock release");
    atomic_store_explicit(lock, 0, memory_order_release);
}
static uint8_t NTAPI nt_KeAcquireSpinLockRaiseToDpc(_Atomic uintptr_t *lock)
{
    if (irql > 2) fatal("spinlock acquire above DISPATCH_LEVEL");
    uint8_t previous = nt_KfRaiseIrql(2);
    nt_KeAcquireSpinLockAtDpcLevel(lock);
    return previous;
}
static void NTAPI nt_KeReleaseSpinLock(_Atomic uintptr_t *lock, uint8_t previous)
{
    nt_KeReleaseSpinLockFromDpcLevel(lock);
    nt_KeLowerIrql(previous);
}

/* Dispatcher objects retain host state for the lifetime of the worker. */
enum { EVENT = 1, MUTEX, GUARDED };
typedef struct object_state {
    void *key;
    int kind, notification, signaled;
    unsigned depth, waiters;
    pthread_t owner;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    struct object_state *next;
} object_state;
static pthread_mutex_t objects_mutex = PTHREAD_MUTEX_INITIALIZER;
static object_state *objects;

static object_state *lock_object(void *key, int kind, int initialize)
{
    pthread_mutex_lock(&objects_mutex);
    object_state *object = objects;
    while (object && object->key != key) object = object->next;
    if (!object) {
        if (!initialize) fatal("uninitialized dispatcher object");
        object = calloc(1, sizeof(*object));
        if (!object) fatal("dispatcher allocation failed");
        object->key = key;
        if (pthread_mutex_init(&object->mutex, NULL) || pthread_cond_init(&object->changed, NULL))
            fatal("dispatcher host initialization failed");
        object->next = objects;
        objects = object;
    }
    pthread_mutex_unlock(&objects_mutex);
    pthread_mutex_lock(&object->mutex);
    if (initialize) {
        if (object->waiters || object->depth) fatal("reinitializing busy dispatcher object");
        object->kind = kind;
    } else if (object->kind != kind && kind) {
        fatal("dispatcher object type mismatch");
    }
    return object;
}

static void write_signal(object_state *object, int32_t value)
{
    memcpy((unsigned char *)object->key + 4, &value, sizeof(value));
}

static void NTAPI nt_KeInitializeEvent(void *event, int type, uint8_t state)
{
    if (type != 0 && type != 1) fatal("invalid event type");
    object_state *object = lock_object(event, EVENT, 1);
    object->notification = type == 0;
    object->signaled = state != 0;
    memset(event, 0, 24);
    ((uint8_t *)event)[0] = type;
    ((uint8_t *)event)[2] = 6;
    write_signal(object, object->signaled);
    pthread_mutex_unlock(&object->mutex);
}

static int32_t NTAPI nt_KeSetEvent(void *event, int32_t increment, uint8_t wait)
{
    (void)increment;
    if (wait) fatal("KeSetEvent Wait=TRUE is not implemented");
    object_state *object = lock_object(event, EVENT, 0);
    int32_t previous = object->signaled;
    object->signaled = 1;
    write_signal(object, 1);
    if (object->notification) pthread_cond_broadcast(&object->changed);
    else pthread_cond_signal(&object->changed);
    pthread_mutex_unlock(&object->mutex);
    return previous;
}

static int32_t NTAPI nt_KeResetEvent(void *event)
{
    object_state *object = lock_object(event, EVENT, 0);
    int32_t previous = object->signaled;
    object->signaled = 0;
    write_signal(object, 0);
    pthread_mutex_unlock(&object->mutex);
    return previous;
}
static void NTAPI nt_KeClearEvent(void *event) { (void)nt_KeResetEvent(event); }
static int32_t NTAPI nt_KeReadStateEvent(void *event)
{
    object_state *object = lock_object(event, EVENT, 0);
    int32_t value = object->signaled;
    pthread_mutex_unlock(&object->mutex);
    return value;
}

static struct timespec deadline_for(int64_t ticks)
{
    struct timespec deadline;
    if (ticks <= 0) {
        clock_gettime(CLOCK_REALTIME, &deadline);
        uint64_t relative = ticks ? (uint64_t)(-(ticks + 1)) + 1 : 0;
        deadline.tv_sec += relative / 10000000;
        deadline.tv_nsec += (relative % 10000000) * 100;
        if (deadline.tv_nsec >= 1000000000) {
            ++deadline.tv_sec;
            deadline.tv_nsec -= 1000000000;
        }
    } else {
        int64_t unix_ticks = ticks - WINDOWS_EPOCH;
        deadline.tv_sec = unix_ticks / 10000000;
        deadline.tv_nsec = (unix_ticks % 10000000) * 100;
        if (deadline.tv_nsec < 0) {
            --deadline.tv_sec;
            deadline.tv_nsec += 1000000000;
        }
    }
    return deadline;
}

static void NTAPI nt_KeInitializeMutex(void *mutex, uint32_t level)
{
    if (level) fatal("mutex level must be zero");
    object_state *object = lock_object(mutex, MUTEX, 1);
    object->depth = 0;
    memset(mutex, 0, 56);
    ((uint8_t *)mutex)[0] = 2;
    ((uint8_t *)mutex)[2] = 14;
    write_signal(object, 1);
    pthread_mutex_unlock(&object->mutex);
}

static uint32_t NTAPI nt_KeWaitForSingleObject(void *key, int reason, int mode,
                                             uint8_t alertable, const int64_t *timeout)
{
    (void)reason;
    if (alertable) return NOT_SUPPORTED;
    if (mode != 0 && mode != 1) return INVALID_PARAMETER;
    if (irql > 2 || (irql == 2 && (!timeout || *timeout != 0))) return INVALID_DEVICE_STATE;
    struct timespec deadline = {0};
    if (timeout) deadline = deadline_for(*timeout);
    object_state *object = lock_object(key, 0, 0);
    if (object->kind != EVENT && object->kind != MUTEX)
        fatal("unsupported wait object type");
    if (object->kind == MUTEX && irql > 1) {
        pthread_mutex_unlock(&object->mutex);
        return INVALID_DEVICE_STATE;
    }
    for (;;) {
        if (object->kind == EVENT && object->signaled) {
            if (!object->notification) {
                object->signaled = 0;
                write_signal(object, 0);
            }
            break;
        }
        if (object->kind == MUTEX && (!object->depth || pthread_equal(object->owner, pthread_self()))) {
            object->owner = pthread_self();
            ++object->depth;
            write_signal(object, 1 - (int32_t)object->depth);
            break;
        }
        if (timeout && !*timeout) {
            pthread_mutex_unlock(&object->mutex);
            return TIMEOUT;
        }
        ++object->waiters;
        int error = timeout ? pthread_cond_timedwait(&object->changed, &object->mutex, &deadline)
                            : pthread_cond_wait(&object->changed, &object->mutex);
        --object->waiters;
        if (error) {
            pthread_mutex_unlock(&object->mutex);
            return error == ETIMEDOUT ? TIMEOUT : INVALID_PARAMETER;
        }
    }
    pthread_mutex_unlock(&object->mutex);
    return SUCCESS;
}

static int32_t NTAPI nt_KeReleaseMutex(void *mutex, uint8_t wait)
{
    if (wait) fatal("KeReleaseMutex Wait=TRUE is not implemented");
    object_state *object = lock_object(mutex, MUTEX, 0);
    if (!object->depth || !pthread_equal(object->owner, pthread_self()))
        fatal("mutex released by non-owner");
    int32_t previous = 1 - (int32_t)object->depth;
    --object->depth;
    write_signal(object, 1 - (int32_t)object->depth);
    if (!object->depth) pthread_cond_signal(&object->changed);
    pthread_mutex_unlock(&object->mutex);
    return previous;
}

static void NTAPI nt_KeInitializeGuardedMutex(void *mutex)
{
    object_state *object = lock_object(mutex, GUARDED, 1);
    memset(mutex, 0, 56);
    int32_t count = 1;
    memcpy(mutex, &count, sizeof(count));
    pthread_mutex_unlock(&object->mutex);
}
static void NTAPI nt_KeAcquireGuardedMutex(void *mutex)
{
    if (irql > 1) fatal("guarded mutex acquire above APC_LEVEL");
    object_state *object = lock_object(mutex, GUARDED, 0);
    if (object->depth && pthread_equal(object->owner, pthread_self()))
        fatal("recursive guarded mutex acquire");
    while (object->depth) {
        ++object->waiters;
        if (pthread_cond_wait(&object->changed, &object->mutex)) fatal("guarded mutex host wait failed");
        --object->waiters;
    }
    object->owner = pthread_self();
    object->depth = 1;
    ++guarded_depth;
    pthread_mutex_unlock(&object->mutex);
}
static void NTAPI nt_KeReleaseGuardedMutex(void *mutex)
{
    object_state *object = lock_object(mutex, GUARDED, 0);
    if (!object->depth || !pthread_equal(object->owner, pthread_self()) || !guarded_depth)
        fatal("guarded mutex released by non-owner");
    object->depth = 0;
    --guarded_depth;
    pthread_cond_signal(&object->changed);
    pthread_mutex_unlock(&object->mutex);
}

static void NTAPI nt_ExInitializeRundownProtection(_Atomic uintptr_t *state) { atomic_init(state, 0); }
static uint8_t NTAPI nt_ExAcquireRundownProtection(_Atomic uintptr_t *state)
{
    uintptr_t value = atomic_load(state);
    for (;;) {
        if (value & 1) return 0;
        if (value > UINTPTR_MAX - 2) fatal("rundown counter overflow");
        if (atomic_compare_exchange_weak(state, &value, value + 2)) return 1;
    }
}
static void NTAPI nt_ExReleaseRundownProtection(_Atomic uintptr_t *state)
{
    uintptr_t value = atomic_load(state);
    for (;;) {
        if ((value & ~(uintptr_t)1) < 2) fatal("unbalanced rundown release");
        if (atomic_compare_exchange_weak(state, &value, value - 2)) return;
    }
}
static void NTAPI nt_ExWaitForRundownProtectionRelease(_Atomic uintptr_t *state)
{
    if (irql > 1) fatal("rundown wait above APC_LEVEL");
    atomic_fetch_or(state, 1);
    while (atomic_load(state) & ~(uintptr_t)1) sched_yield();
}

static void NTAPI nt_KeQuerySystemTimePrecise(int64_t *value)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    *value = now.tv_sec * INT64_C(10000000) + now.tv_nsec / 100 + WINDOWS_EPOCH;
}
static int64_t NTAPI nt_KeQueryPerformanceCounter(int64_t *frequency)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (frequency) *frequency = INT64_C(1000000000);
    return now.tv_sec * INT64_C(1000000000) + now.tv_nsec;
}
static uint32_t NTAPI nt_KeDelayExecutionThread(int mode, uint8_t alertable, const int64_t *interval)
{
    if (!interval || (mode != 0 && mode != 1)) return INVALID_PARAMETER;
    if (alertable) return NOT_SUPPORTED;
    if (irql > 1) return INVALID_DEVICE_STATE;
    struct timespec deadline = deadline_for(*interval);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    if (deadline.tv_sec < now.tv_sec || (deadline.tv_sec == now.tv_sec && deadline.tv_nsec <= now.tv_nsec))
        return SUCCESS;
    int error;
    do { error = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &deadline, NULL); }
    while (error == EINTR);
    return error ? INVALID_PARAMETER : SUCCESS;
}

static void *NTAPI nt_PsGetCurrentProcessId(void) { return (void *)(uintptr_t)getpid(); }
static void *NTAPI nt_PsGetCurrentThreadId(void) { return (void *)(uintptr_t)syscall(SYS_gettid); }

static void *NTAPI nt_RtlPcToFileHeader(void *pc, void **base)
{
    uintptr_t address = (uintptr_t)pc, start = (uintptr_t)image_base;
    void *result = address >= start && address - start < image_size ? image_base : NULL;
    if (base) *base = result;
    return result;
}
static void *NTAPI nt_MmGetSystemRoutineAddress(const unicode_string *name)
{
    if (!name || !name->buffer || name->length % 2 || name->length > name->maximum_length || name->length > 510)
        return NULL;
    char ascii[256];
    size_t count = name->length / 2;
    for (size_t i = 0; i < count; ++i) {
        if (!name->buffer[i] || name->buffer[i] > 127) return NULL;
        ascii[i] = name->buffer[i];
    }
    ascii[count] = 0;
    void *result = driverlab_resolve("ntoskrnl.exe", ascii);
    return result ? result : driverlab_resolve("hal.dll", ascii);
}

static void NTAPI nt_KeBugCheckEx(uint32_t code, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    fprintf(stderr, "driverlab: virtual bugcheck 0x%08x (%zx, %zx, %zx, %zx)\n", code, a, b, c, d);
    abort();
}

#define NT(name) {"ntoskrnl.exe", #name, (void *)nt_##name}
static const nt_export exports[] = {
    NT(ExAllocatePoolWithTag), NT(ExFreePoolWithTag), NT(ExFreePool),
    NT(RtlInitUnicodeString), NT(RtlDuplicateUnicodeString), NT(RtlFreeUnicodeString), NT(RtlCompareMemory),
    NT(memcpy), NT(memmove), NT(memset), NT(memcmp), NT(strlen), NT(strnlen), NT(strcmp), NT(strchr), NT(wcslen),
    NT(KeGetCurrentIrql), NT(KfRaiseIrql), NT(KeLowerIrql),
    NT(KeEnterCriticalRegion), NT(KeLeaveCriticalRegion), NT(KeAreAllApcsDisabled),
    NT(KeInitializeSpinLock), NT(KeAcquireSpinLockRaiseToDpc), NT(KeReleaseSpinLock),
    NT(KeAcquireSpinLockAtDpcLevel), NT(KeReleaseSpinLockFromDpcLevel),
    NT(KeInitializeEvent), NT(KeSetEvent), NT(KeResetEvent), NT(KeClearEvent), NT(KeReadStateEvent),
    NT(KeWaitForSingleObject), NT(KeInitializeMutex), NT(KeReleaseMutex),
    NT(KeInitializeGuardedMutex), NT(KeAcquireGuardedMutex), NT(KeReleaseGuardedMutex),
    NT(ExInitializeRundownProtection), NT(ExAcquireRundownProtection),
    NT(ExReleaseRundownProtection), NT(ExWaitForRundownProtectionRelease),
    NT(KeQuerySystemTimePrecise), NT(KeDelayExecutionThread),
    NT(PsGetCurrentProcessId), NT(PsGetCurrentThreadId), NT(RtlPcToFileHeader), NT(MmGetSystemRoutineAddress),
    NT(KeBugCheckEx), {"hal.dll", "KeQueryPerformanceCounter", (void *)nt_KeQueryPerformanceCounter},
    NT(KeQueryPerformanceCounter),
};

void *driverlab_resolve(const char *module, const char *symbol)
{
    if (!module || !symbol) return NULL;
    if (!strcasecmp(module, "ntkrnlmp.exe")) module = "ntoskrnl.exe";
    for (size_t i = 0; i < sizeof(exports) / sizeof(exports[0]); ++i)
        if (!strcasecmp(module, exports[i].module) && !strcmp(symbol, exports[i].name))
            return exports[i].address;
    const nt_export *tables[] = {driverlab_io_exports, driverlab_crypto_exports, driverlab_memory_exports};
    const size_t counts[] = {driverlab_io_count, driverlab_crypto_count, driverlab_memory_count};
    for (size_t table = 0; table < 3; ++table)
        for (size_t i = 0; i < counts[table]; ++i)
            if (!strcasecmp(module, tables[table][i].module) && !strcmp(symbol, tables[table][i].name))
                return tables[table][i].address;
    return NULL;
}
size_t driverlab_export_count(void)
{
    return sizeof(exports) / sizeof(exports[0]) + driverlab_io_count + driverlab_crypto_count + driverlab_memory_count;
}
void driverlab_set_image(void *base, size_t size) { image_base = base; image_size = size; }
