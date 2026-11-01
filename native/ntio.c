#define _GNU_SOURCE
#include "ntcompat.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_DELETED UINT32_C(0xc000017c)
#define COLLISION UINT32_C(0xc0000035)
#define BUFFER_OVERFLOW UINT32_C(0x80000005)
enum { FILE_HANDLE = 1, KEY_HANDLE };
typedef struct value { char *name; uint32_t type, size; void *data; struct value *next; } value;
typedef struct key { char *path; int deleted; value *values; struct key *next; } key;
typedef struct handle {
    uintptr_t id;
    int kind, fd, read, write, append;
    uint32_t access, share;
    dev_t device; ino_t inode;
    key *registry;
    struct handle *next;
} handle;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static handle *handles;
static key *keys;
static uintptr_t next_id = 0x10000;
static int files = -1;
_Static_assert(sizeof(nt_object_attributes) == 48, "x64 OBJECT_ATTRIBUTES");
_Static_assert(sizeof(nt_io_status) == 16, "x64 IO_STATUS_BLOCK");

static uint32_t error_status(int error)
{
    switch (error) {
    case ENOENT: return NT_NOT_FOUND;
    case EEXIST: return COLLISION;
    case EACCES: case EPERM: case ELOOP: return NT_ACCESS_DENIED;
    case ENOMEM: return NT_NO_MEMORY;
    case ENOTDIR: return 0xc0000103;
    case EISDIR: return 0xc00000ba;
    case ENOSPC: return 0xc000007f;
    default: return NT_UNSUCCESSFUL;
    }
}
static uint32_t io_result(nt_io_status *io, uint32_t status, uintptr_t information)
{
    if (io) { io->status = status; io->information = information; }
    return status;
}
static handle *find(void *id, int kind)
{
    for (handle *h = handles; h; h = h->next)
        if (h->id == (uintptr_t)id && (!kind || kind == h->kind)) return h;
    return NULL;
}
static void publish(handle *h, void **output)
{
    h->id = next_id; next_id += 4; h->next = handles; handles = h; *output = (void *)h->id;
}
static char *utf8(const unicode_string *s)
{
    if (!s || s->length % 2 || s->length > s->maximum_length || (s->length && !s->buffer) || s->length > 4096)
        return NULL;
    char *result = malloc((size_t)s->length * 2 + 1);
    if (!result) return NULL;
    size_t used = 0;
    for (size_t i = 0; i < s->length / 2; ++i) {
        uint32_t c = s->buffer[i];
        if (!c) { free(result); return NULL; }
        if (c >= 0xD800 && c <= 0xDBFF) {
            if (++i >= s->length / 2 || s->buffer[i] < 0xDC00 || s->buffer[i] > 0xDFFF) { free(result); return NULL; }
            c = 0x10000 + ((c - 0xD800) << 10) + s->buffer[i] - 0xDC00;
        } else if (c >= 0xDC00 && c <= 0xDFFF) { free(result); return NULL; }
        if (c < 0x80) result[used++] = c;
        else if (c < 0x800) { result[used++] = 0xC0 | (c >> 6); result[used++] = 0x80 | (c & 63); }
        else if (c < 0x10000) { result[used++] = 0xE0 | (c >> 12); result[used++] = 0x80 | ((c >> 6) & 63); result[used++] = 0x80 | (c & 63); }
        else { result[used++] = 0xF0 | (c >> 18); result[used++] = 0x80 | ((c >> 12) & 63); result[used++] = 0x80 | ((c >> 6) & 63); result[used++] = 0x80 | (c & 63); }
    }
    result[used] = 0; return result;
}
static int valid_attributes(const nt_object_attributes *a)
{
    return a && a->length == sizeof(*a) && !a->security_descriptor && !a->security_qos && !(a->attributes & ~0x240u);
}
static void fold(char *text) { for (; *text; ++text) if (*text >= 'A' && *text <= 'Z') *text += 'a' - 'A'; }
static key *find_key(const char *path)
{
    for (key *p = keys; p; p = p->next) if (!p->deleted && !strcmp(p->path, path)) return p;
    return NULL;
}
static key *new_key(const char *path)
{
    key *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->path = strdup(path);
    if (!p->path) { free(p); return NULL; }
    p->next = keys; keys = p; return p;
}
uint32_t driverlab_io_initialize(const char *directory)
{
    if (!directory) return NT_INVALID_PARAMETER;
    pthread_mutex_lock(&mutex);
    if (files >= 0) { pthread_mutex_unlock(&mutex); return NT_INVALID_PARAMETER; }
    if (mkdir(directory, 0700) && errno != EEXIST) { pthread_mutex_unlock(&mutex); return error_status(errno); }
    int root = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (root < 0) { pthread_mutex_unlock(&mutex); return error_status(errno); }
    int error = 0;
    if (mkdirat(root, "files", 0700) && errno != EEXIST) error = errno;
    if (!error) { files = openat(root, "files", O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW); if (files < 0) error = errno; }
    if (!error && mkdirat(files, "C", 0700) && errno != EEXIST) error = errno;
    close(root);
    if (error) { if (files >= 0) close(files); files = -1; pthread_mutex_unlock(&mutex); return error_status(error); }
    const char *seeds[] = {"\\registry", "\\registry\\machine", "\\registry\\user", "\\registry\\machine\\software",
        "\\registry\\machine\\system", "\\registry\\machine\\system\\currentcontrolset",
        "\\registry\\machine\\system\\currentcontrolset\\services"};
    for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); ++i)
        if (!new_key(seeds[i])) { pthread_mutex_unlock(&mutex); return NT_NO_MEMORY; }
    pthread_mutex_unlock(&mutex); return 0;
}

/* Walk beneath the private root one component at a time without symlinks. */
static uint32_t file_parent(const nt_object_attributes *a, int *parent, char **name, char **allocation)
{
    if (!valid_attributes(a)) return NT_NOT_SUPPORTED;
    char *path = utf8(a->object_name);
    if (!path) return NT_INVALID_PARAMETER;
    *allocation = path;
    int root;
    if (a->root_directory) {
        handle *h = find(a->root_directory, FILE_HANDLE);
        if (!h) return NT_INVALID_HANDLE;
        if (*path == '\\' || *path == '/') return NT_INVALID_PARAMETER;
        root = dup(h->fd);
    } else {
        if (strncmp(path, "\\??\\", 4) || !((path[4] >= 'A' && path[4] <= 'Z') || (path[4] >= 'a' && path[4] <= 'z')) ||
            path[5] != ':' || (path[6] != '\\' && path[6] != '/')) return NT_NOT_SUPPORTED;
        path += 4;
        if (*path >= 'a' && *path <= 'z') *path -= 'a' - 'A';
        memmove(path + 1, path + 2, strlen(path + 2) + 1);
        if (files < 0) return NT_INVALID_PARAMETER;
        root = dup(files);
    }
    if (root < 0) return error_status(errno);
    for (char *p = path; *p; ++p) if (*p == '\\') *p = '/';
    size_t length = strlen(path);
    while (length && path[length - 1] == '/') path[--length] = 0;
    if (!length) { close(root); return NT_INVALID_PARAMETER; }
    char *component = path;
    for (;;) {
        char *slash = strchr(component, '/');
        if (slash) *slash = 0;
        if (!*component || !strcmp(component, ".") || !strcmp(component, "..") || strpbrk(component, ":*?<>|\"")) {
            close(root); return NT_ACCESS_DENIED;
        }
        if (!slash) { *parent = root; *name = component; return 0; }
        int next = openat(root, component, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        int error = errno; close(root);
        if (next < 0) return error_status(error);
        root = next; component = slash + 1;
    }
}
static uint32_t NTAPI i_ZwCreateFile(void **output, uint32_t access, nt_object_attributes *a, nt_io_status *io,
                                    const int64_t *allocation_size, uint32_t attributes, uint32_t share,
                                    uint32_t disposition, uint32_t options, void *ea, uint32_t ea_length)
{
    if (!output || !io || disposition > 5 || (share & ~7u) || ((options & 0x41) == 0x41)) return io_result(io, NT_INVALID_PARAMETER, 0);
    if (!(options & 0x20) || (options & ~0x865u) || (attributes && attributes != 0x80) ||
        (allocation_size && *allocation_size) || ea_length || ea || !disposition || (access & 0x02010000))
        return io_result(io, NT_NOT_SUPPORTED, 0);
    pthread_mutex_lock(&mutex);
    int parent = -1, fd = -1, created = 0;
    char *name = NULL, *path = NULL;
    uint32_t status = file_parent(a, &parent, &name, &path);
    if (status) goto done;
    int read = (access & (0x90000000u | 1)) != 0, write = (access & (0x50000000u | 6)) != 0;
    int directory = options & 1;
    if (directory && disposition > 3) { status = NT_NOT_SUPPORTED; goto done; }
    if ((disposition == 4 || disposition == 5) && !write) { status = NT_ACCESS_DENIED; goto done; }
    int flags = O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (directory ? O_DIRECTORY | O_RDONLY : read && write ? O_RDWR : write ? O_WRONLY : O_RDONLY);
    if (directory && (disposition == 2 || disposition == 3)) {
        if (!mkdirat(parent, name, 0700)) created = 1;
        else if (errno != EEXIST || disposition == 2) { status = error_status(errno); goto done; }
    }
    if (!directory && (disposition == 2 || disposition == 3 || disposition == 5)) {
        fd = openat(parent, name, flags | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) created = 1;
        else if (errno != EEXIST || disposition == 2) { status = error_status(errno); goto done; }
    }
    if (fd < 0) fd = openat(parent, name, flags);
    if (fd < 0) { status = error_status(errno); goto done; }
    struct stat st;
    if (fstat(fd, &st)) { status = error_status(errno); goto done; }
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) { status = NT_NOT_SUPPORTED; goto done; }
    if ((directory && !S_ISDIR(st.st_mode)) || ((options & 0x40) && S_ISDIR(st.st_mode))) { status = NT_INVALID_PARAMETER; goto done; }
    for (handle *h = handles; h; h = h->next) {
        if (h->kind != FILE_HANDLE || h->device != st.st_dev || h->inode != st.st_ino) continue;
        if ((read && !(h->share & 1)) || (write && !(h->share & 2)) || (h->read && !(share & 1)) || (h->write && !(share & 2))) {
            status = 0xc0000043; goto done;
        }
    }
    if (!directory && !created && (disposition == 4 || disposition == 5) && ftruncate(fd, 0)) { status = error_status(errno); goto done; }
    handle *h = calloc(1, sizeof(*h));
    if (!h) { status = NT_NO_MEMORY; goto done; }
    h->kind = FILE_HANDLE; h->fd = fd; h->access = access; h->read = read; h->write = write; h->share = share;
    h->append = (access & 4) && !(access & (0x50000000u | 2)); h->device = st.st_dev; h->inode = st.st_ino;
    publish(h, output); fd = -1;
    status = 0;
done:
    if (parent >= 0) close(parent);
    if (fd >= 0) close(fd);
    free(path); pthread_mutex_unlock(&mutex);
    return io_result(io, status, status ? 0 : created ? 2 : (disposition == 4 || disposition == 5) ? 3 : 1);
}
static uint32_t NTAPI i_ZwOpenFile(void **output, uint32_t access, nt_object_attributes *a, nt_io_status *io, uint32_t share, uint32_t options)
{
    return i_ZwCreateFile(output, access, a, io, NULL, 0, share, 1, options, NULL, 0);
}
static uint32_t NTAPI i_IoCreateFileEx(void **output, uint32_t access, nt_object_attributes *a, nt_io_status *io,
    const int64_t *allocation, uint32_t attributes, uint32_t share, uint32_t disposition, uint32_t options,
    void *ea, uint32_t ea_length, int file_type, void *internal, uint32_t extra, void *context)
{
    if (file_type || internal || extra || context) return io_result(io, NT_NOT_SUPPORTED, 0);
    return i_ZwCreateFile(output, access, a, io, allocation, attributes, share, disposition, options, ea, ea_length);
}
static uint32_t transfer(void *id, void *event, void *apc, void *context, nt_io_status *io, void *buffer,
                          uint32_t size, const int64_t *offset, uint32_t *key_pointer, int writing)
{
    if (!io || (!buffer && size)) return io_result(io, NT_INVALID_PARAMETER, 0);
    if (event || apc || context || key_pointer) return io_result(io, NT_NOT_SUPPORTED, 0);
    pthread_mutex_lock(&mutex);
    handle *h = find(id, FILE_HANDLE);
    uint32_t status = NT_INVALID_HANDLE; ssize_t count = 0;
    if (!h) goto done;
    if (writing ? !h->write : !h->read) { status = NT_ACCESS_DENIED; goto done; }
    int64_t position = offset ? *offset : -2;
    if ((writing && h->append) || (writing && position == -1)) {
        if (lseek(h->fd, 0, SEEK_END) < 0) { status = error_status(errno); goto done; }
        position = -2;
    }
    if (position < 0 && position != -2) { status = NT_INVALID_PARAMETER; goto done; }
    if (position >= 0 && position > INT64_MAX - size) { status = NT_INVALID_PARAMETER; goto done; }
    do {
        if (writing) count = position == -2 ? write(h->fd, buffer, size) : pwrite(h->fd, buffer, size, position);
        else count = position == -2 ? read(h->fd, buffer, size) : pread(h->fd, buffer, size, position);
    } while (count < 0 && errno == EINTR);
    if (count < 0) { status = error_status(errno); goto done; }
    if (position >= 0 && lseek(h->fd, position + count, SEEK_SET) < 0) { status = error_status(errno); goto done; }
    status = !writing && size && !count ? 0xc0000011 : 0;
done:
    pthread_mutex_unlock(&mutex); return io_result(io, status, count > 0 ? (uintptr_t)count : 0);
}
static uint32_t NTAPI i_ZwReadFile(void *h, void *e, void *a, void *c, nt_io_status *io, void *b, uint32_t n, const int64_t *o, uint32_t *k)
{ return transfer(h, e, a, c, io, b, n, o, k, 0); }
static uint32_t NTAPI i_ZwWriteFile(void *h, void *e, void *a, void *c, nt_io_status *io, void *b, uint32_t n, const int64_t *o, uint32_t *k)
{ return transfer(h, e, a, c, io, b, n, o, k, 1); }
static uint32_t NTAPI i_ZwFlushBuffersFile(void *id, nt_io_status *io)
{
    if (!io) return NT_INVALID_PARAMETER;
    pthread_mutex_lock(&mutex); handle *h = find(id, FILE_HANDLE);
    uint32_t status = !h ? NT_INVALID_HANDLE : fsync(h->fd) ? error_status(errno) : 0;
    pthread_mutex_unlock(&mutex); return io_result(io, status, 0);
}
static uint32_t NTAPI i_ZwQueryInformationFile(void *id, nt_io_status *io, void *output, uint32_t capacity, int info_class)
{
    if (!io || (!output && capacity)) return io_result(io, NT_INVALID_PARAMETER, 0);
    pthread_mutex_lock(&mutex); handle *h = find(id, FILE_HANDLE);
    uint32_t status = NT_INVALID_HANDLE, size = info_class == 5 ? 24 : 8;
    unsigned char result[24] = {0};
    if (!h) goto done;
    if (!(h->access & (0x90000000u | 0x80))) { status = NT_ACCESS_DENIED; goto done; }
    if (info_class == 5) {
        struct stat st;
        if (fstat(h->fd, &st)) { status = error_status(errno); goto done; }
        int64_t allocation = st.st_blocks * 512, length = st.st_size;
        uint32_t links = st.st_nlink;
        memcpy(result, &allocation, 8); memcpy(result + 8, &length, 8); memcpy(result + 16, &links, 4);
        result[21] = S_ISDIR(st.st_mode);
    } else if (info_class == 14) {
        int64_t position = lseek(h->fd, 0, SEEK_CUR);
        if (position < 0) { status = error_status(errno); goto done; }
        memcpy(result, &position, 8);
    } else { status = NT_NOT_SUPPORTED; goto done; }
    status = capacity < size ? NT_BUFFER_TOO_SMALL : 0;
    if (!status) memcpy(output, result, size);
done:
    pthread_mutex_unlock(&mutex); return io_result(io, status, status ? 0 : size);
}
static uint32_t NTAPI i_ZwSetInformationFile(void *id, nt_io_status *io, void *input, uint32_t size, int info_class)
{
    if (!io || !input || size != 8) return io_result(io, NT_INVALID_PARAMETER, 0);
    int64_t value; memcpy(&value, input, 8);
    if (value < 0) return io_result(io, NT_INVALID_PARAMETER, 0);
    pthread_mutex_lock(&mutex); handle *h = find(id, FILE_HANDLE);
    uint32_t status = NT_INVALID_HANDLE;
    if (h) {
        if (info_class == 14) status = lseek(h->fd, value, SEEK_SET) < 0 ? error_status(errno) : 0;
        else if (info_class == 20) status = !h->write ? NT_ACCESS_DENIED : ftruncate(h->fd, value) ? error_status(errno) : 0;
        else status = NT_NOT_SUPPORTED;
    }
    pthread_mutex_unlock(&mutex); return io_result(io, status, 0);
}

static uint32_t key_path(const nt_object_attributes *a, char **output, int creating)
{
    if (!valid_attributes(a)) return NT_NOT_SUPPORTED;
    char *name = utf8(a->object_name);
    if (!name) return NT_INVALID_PARAMETER;
    if (a->root_directory) {
        handle *h = find(a->root_directory, KEY_HANDLE);
        if (!h) { free(name); return NT_INVALID_HANDLE; }
        if (h->registry->deleted) { free(name); return KEY_DELETED; }
        if (creating && !(h->access & 4)) { free(name); return NT_ACCESS_DENIED; }
        if (*name == '\\') { free(name); return NT_INVALID_PARAMETER; }
        size_t size = strlen(h->registry->path) + strlen(name) + 2;
        char *joined = malloc(size);
        if (!joined) { free(name); return NT_NO_MEMORY; }
        strcpy(joined, h->registry->path);
        if (*name) strcat(joined, "\\");
        strcat(joined, name); free(name); name = joined;
    }
    fold(name);
    if (strncmp(name, "\\registry", 9) || (name[9] && name[9] != '\\') || strstr(name, "\\\\")) { free(name); return NT_NOT_SUPPORTED; }
    size_t length = strlen(name);
    if (length > 1 && name[length - 1] == '\\') name[length - 1] = 0;
    *output = name; return 0;
}
static uint32_t key_open(void **output, uint32_t access, nt_object_attributes *a, int create, uint32_t *disposition)
{
    if (!output) return NT_INVALID_PARAMETER;
    if (access & 0x02000000) return NT_NOT_SUPPORTED;
    pthread_mutex_lock(&mutex);
    char *path = NULL;
    uint32_t status = key_path(a, &path, create);
    if (status) goto done;
    key *p = find_key(path);
    int created = 0;
    if (!p && create) {
        char *separator = strrchr(path, '\\');
        *separator = 0;
        int parent_exists = find_key(path) != NULL;
        *separator = '\\';
        if (!parent_exists) { status = 0xc000003a; goto done; }
        p = new_key(path); created = 1;
        if (!p) { status = NT_NO_MEMORY; goto done; }
    }
    if (!p) { status = NT_NOT_FOUND; goto done; }
    handle *h = calloc(1, sizeof(*h));
    if (!h) { status = NT_NO_MEMORY; goto done; }
    if (access & 0x10000000u) access |= 0xf003f;
    if (access & 0x80000000u) access |= 0x19;
    if (access & 0x40000000u) access |= 6;
    h->kind = KEY_HANDLE; h->registry = p; h->access = access;
    publish(h, output);
    if (disposition) *disposition = created ? 1 : 2;
done:
    free(path); pthread_mutex_unlock(&mutex); return status;
}
static uint32_t NTAPI i_ZwCreateKey(void **output, uint32_t access, nt_object_attributes *a, uint32_t title,
                                   unicode_string *class_name, uint32_t options, uint32_t *disposition)
{
    if (title || class_name || options != 1) return NT_NOT_SUPPORTED; /* REG_OPTION_VOLATILE only. */
    return key_open(output, access, a, 1, disposition);
}
static uint32_t NTAPI i_ZwOpenKey(void **output, uint32_t access, nt_object_attributes *a)
{ return key_open(output, access, a, 0, NULL); }
static uint32_t NTAPI i_ZwSetValueKey(void *id, unicode_string *name, uint32_t title, uint32_t type, void *data, uint32_t size)
{
    if (title || (!data && size) || size > 64 * 1024 * 1024) return NT_INVALID_PARAMETER;
    char *text = utf8(name);
    if (!text) return NT_INVALID_PARAMETER;
    fold(text); pthread_mutex_lock(&mutex);
    handle *h = find(id, KEY_HANDLE);
    uint32_t status = !h ? NT_INVALID_HANDLE : h->registry->deleted ? KEY_DELETED : !(h->access & 2) ? NT_ACCESS_DENIED : 0;
    if (!status) {
        value *v = h->registry->values;
        while (v && strcmp(v->name, text)) v = v->next;
        void *copy = size ? malloc(size) : NULL;
        if (size && !copy) { status = NT_NO_MEMORY; goto done; }
        if (!v) {
            v = calloc(1, sizeof(*v));
            if (!v) { free(copy); status = NT_NO_MEMORY; goto done; }
            v->name = text; text = NULL; v->next = h->registry->values; h->registry->values = v;
        }
        if (size) memcpy(copy, data, size);
        free(v->data); v->data = copy; v->size = size; v->type = type;
    }
done:
    free(text); pthread_mutex_unlock(&mutex); return status;
}
static uint32_t NTAPI i_ZwQueryValueKey(void *id, unicode_string *name, int info_class, void *output, uint32_t capacity, uint32_t *required)
{
    if (!required || (!output && capacity)) return NT_INVALID_PARAMETER;
    if (info_class != 2 && info_class != 4) return NT_NOT_SUPPORTED;
    char *text = utf8(name);
    if (!text) return NT_INVALID_PARAMETER;
    fold(text); pthread_mutex_lock(&mutex);
    handle *h = find(id, KEY_HANDLE);
    uint32_t status = !h ? NT_INVALID_HANDLE : h->registry->deleted ? KEY_DELETED : !(h->access & 1) ? NT_ACCESS_DENIED : 0;
    if (!status) {
        value *v = h->registry->values;
        while (v && strcmp(v->name, text)) v = v->next;
        if (!v) { status = NT_NOT_FOUND; goto done; }
        uint32_t header = info_class == 2 ? 12 : 8;
        *required = header + v->size;
        if (capacity < header) status = NT_BUFFER_TOO_SMALL;
        else {
            unsigned char *bytes = output;
            if (header == 12) { memset(bytes, 0, 4); bytes += 4; }
            memcpy(bytes, &v->type, 4); memcpy(bytes + 4, &v->size, 4);
            uint32_t available = capacity - header;
            if (available > v->size) available = v->size;
            if (available) memcpy((unsigned char *)output + header, v->data, available);
            status = available < v->size ? BUFFER_OVERFLOW : 0;
        }
    }
done:
    free(text); pthread_mutex_unlock(&mutex); return status;
}
static uint32_t NTAPI i_ZwDeleteValueKey(void *id, unicode_string *name)
{
    char *text = utf8(name);
    if (!text) return NT_INVALID_PARAMETER;
    fold(text); pthread_mutex_lock(&mutex);
    handle *h = find(id, KEY_HANDLE);
    uint32_t status = !h ? NT_INVALID_HANDLE : h->registry->deleted ? KEY_DELETED : !(h->access & 2) ? NT_ACCESS_DENIED : 0;
    if (!status) {
        value **slot = &h->registry->values;
        while (*slot && strcmp((*slot)->name, text)) slot = &(*slot)->next;
        if (!*slot) status = NT_NOT_FOUND;
        else { value *v = *slot; *slot = v->next; free(v->name); free(v->data); free(v); }
    }
    free(text); pthread_mutex_unlock(&mutex); return status;
}
static uint32_t NTAPI i_ZwDeleteKey(void *id)
{
    pthread_mutex_lock(&mutex); handle *h = find(id, KEY_HANDLE);
    uint32_t status = !h ? NT_INVALID_HANDLE : h->registry->deleted ? KEY_DELETED : !(h->access & 0x10000) ? NT_ACCESS_DENIED : 0;
    if (!status) {
        size_t length = strlen(h->registry->path);
        for (key *p = keys; p; p = p->next)
            if (!p->deleted && !strncmp(p->path, h->registry->path, length) && p->path[length] == '\\') { status = 0xc0000121; break; }
        if (!status) h->registry->deleted = 1;
    }
    pthread_mutex_unlock(&mutex); return status;
}
static uint32_t NTAPI i_ZwClose(void *id)
{
    pthread_mutex_lock(&mutex); handle **slot = &handles;
    while (*slot && (*slot)->id != (uintptr_t)id) slot = &(*slot)->next;
    if (!*slot) { pthread_mutex_unlock(&mutex); return NT_INVALID_HANDLE; }
    handle *h = *slot; *slot = h->next;
    if (h->kind == FILE_HANDLE) close(h->fd);
    free(h); pthread_mutex_unlock(&mutex); return 0;
}

#define I(name) {"ntoskrnl.exe", #name, (void *)i_##name}
const nt_export driverlab_io_exports[] = {
    I(ZwCreateFile), I(ZwOpenFile), I(IoCreateFileEx), I(ZwReadFile), I(ZwWriteFile), I(ZwFlushBuffersFile),
    I(ZwQueryInformationFile), I(ZwSetInformationFile), I(ZwClose),
    I(ZwCreateKey), I(ZwOpenKey), I(ZwSetValueKey), I(ZwQueryValueKey), I(ZwDeleteValueKey), I(ZwDeleteKey),
};
const size_t driverlab_io_count = sizeof(driverlab_io_exports) / sizeof(driverlab_io_exports[0]);
