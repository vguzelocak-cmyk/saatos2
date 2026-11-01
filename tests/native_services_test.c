#define _GNU_SOURCE
#include "ntcompat.h"
#include <assert.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <uchar.h>
#include <unistd.h>

#define DECLARE(name, result, ...) static result (NTAPI *p_##name)(__VA_ARGS__)
#define BIND(module, name) do { p_##name = (__typeof__(p_##name))driverlab_resolve(module, #name); assert(p_##name); } while (0)
DECLARE(ZwCreateFile, uint32_t, void **, uint32_t, nt_object_attributes *, nt_io_status *, const int64_t *, uint32_t, uint32_t, uint32_t, uint32_t, void *, uint32_t);
DECLARE(ZwOpenFile, uint32_t, void **, uint32_t, nt_object_attributes *, nt_io_status *, uint32_t, uint32_t);
DECLARE(ZwReadFile, uint32_t, void *, void *, void *, void *, nt_io_status *, void *, uint32_t, const int64_t *, uint32_t *);
DECLARE(ZwWriteFile, uint32_t, void *, void *, void *, void *, nt_io_status *, void *, uint32_t, const int64_t *, uint32_t *);
DECLARE(ZwQueryInformationFile, uint32_t, void *, nt_io_status *, void *, uint32_t, int);
DECLARE(ZwSetInformationFile, uint32_t, void *, nt_io_status *, void *, uint32_t, int);
DECLARE(ZwFlushBuffersFile, uint32_t, void *, nt_io_status *);
DECLARE(ZwClose, uint32_t, void *);
DECLARE(ZwCreateKey, uint32_t, void **, uint32_t, nt_object_attributes *, uint32_t, unicode_string *, uint32_t, uint32_t *);
DECLARE(ZwOpenKey, uint32_t, void **, uint32_t, nt_object_attributes *);
DECLARE(ZwSetValueKey, uint32_t, void *, unicode_string *, uint32_t, uint32_t, void *, uint32_t);
DECLARE(ZwQueryValueKey, uint32_t, void *, unicode_string *, int, void *, uint32_t, uint32_t *);
DECLARE(ZwDeleteValueKey, uint32_t, void *, unicode_string *);
DECLARE(ZwDeleteKey, uint32_t, void *);
DECLARE(BCryptOpenAlgorithmProvider, uint32_t, void **, const uint16_t *, const uint16_t *, uint32_t);
DECLARE(BCryptCloseAlgorithmProvider, uint32_t, void *, uint32_t);
DECLARE(BCryptGetProperty, uint32_t, void *, const uint16_t *, unsigned char *, uint32_t, uint32_t *, uint32_t);
DECLARE(BCryptCreateHash, uint32_t, void *, void **, unsigned char *, uint32_t, unsigned char *, uint32_t, uint32_t);
DECLARE(BCryptHashData, uint32_t, void *, unsigned char *, uint32_t, uint32_t);
DECLARE(BCryptFinishHash, uint32_t, void *, unsigned char *, uint32_t, uint32_t);
DECLARE(BCryptDestroyHash, uint32_t, void *);
DECLARE(BCryptImportKeyPair, uint32_t, void *, void *, const uint16_t *, void **, unsigned char *, uint32_t, uint32_t);
DECLARE(BCryptVerifySignature, uint32_t, void *, void *, unsigned char *, uint32_t, unsigned char *, uint32_t, uint32_t);
DECLARE(BCryptDestroyKey, uint32_t, void *);
DECLARE(BCryptGenRandom, uint32_t, void *, unsigned char *, uint32_t, uint32_t);
typedef struct mdl {
    struct mdl *next; int16_t size, flags; void *process, *mapped, *start;
    uint32_t count, offset;
} mdl;
DECLARE(IoAllocateMdl, mdl *, void *, uint32_t, uint8_t, uint8_t, void *);
DECLARE(IoFreeMdl, void, mdl *);
DECLARE(MmBuildMdlForNonPagedPool, void, mdl *);
DECLARE(MmProbeAndLockPages, void, mdl *, int, int);
DECLARE(MmUnlockPages, void, mdl *);
DECLARE(MmMapLockedPagesSpecifyCache, void *, mdl *, int, int, void *, uint32_t, uint32_t);
DECLARE(MmUnmapLockedPages, void, void *, mdl *);
#define W(text) ((const uint16_t *)u##text)

static unicode_string string(const uint16_t *text)
{
    size_t count = 0;
    while (text && text[count]) ++count;
    return (unicode_string){count * 2, text ? count * 2 + 2 : 0, (uint16_t *)text};
}
static nt_object_attributes attributes(unicode_string *name, void *root)
{
    return (nt_object_attributes){sizeof(nt_object_attributes), root, name, 0x40, NULL, NULL};
}
static uint32_t get32(const unsigned char *p) { uint32_t value; memcpy(&value, p, 4); return value; }

static void test_files(const char *state)
{
    unicode_string path = string(W("\\??\\C:\\roundtrip.bin"));
    nt_object_attributes a = attributes(&path, NULL);
    void *file = NULL, *second = NULL;
    nt_io_status io;
    assert(!p_ZwCreateFile(&file, 0xc0000000, &a, &io, NULL, 0x80, 3, 2, 0x60, NULL, 0));
    assert(io.status == 0 && io.information == 2);
    unsigned char message[] = {'a', 0, 'b', 0xff, 'c'}, output[32] = {0};
    int64_t offset = 0;
    assert(!p_ZwWriteFile(file, NULL, NULL, NULL, &io, message, sizeof(message), &offset, NULL));
    assert(io.information == sizeof(message));
    assert(!p_ZwFlushBuffersFile(file, &io));
    assert(!p_ZwQueryInformationFile(file, &io, output, sizeof(output), 14));
    int64_t position; memcpy(&position, output, 8); assert(position == 5);
    assert(!p_ZwReadFile(file, NULL, NULL, NULL, &io, output, sizeof(output), &offset, NULL));
    assert(io.information == 5 && !memcmp(output, message, 5));
    assert(p_ZwReadFile(file, NULL, NULL, NULL, &io, output, 1, NULL, NULL) == 0xc0000011);
    int64_t size = 3;
    assert(!p_ZwSetInformationFile(file, &io, &size, 8, 20));
    assert(p_ZwCreateFile(&second, 0xc0000000, &a, &io, NULL, 0x80, 0, 4, 0x60, NULL, 0) == 0xc0000043);
    assert(!p_ZwQueryInformationFile(file, &io, output, sizeof(output), 5));
    memcpy(&size, output + 8, 8); assert(size == 3); /* Denied overwrite did not truncate. */
    assert(!p_ZwClose(file));
    assert(p_ZwClose(file) == NT_INVALID_HANDLE);
    assert(!p_ZwOpenFile(&second, 0x80000000, &a, &io, 3, 0x60));
    assert(p_ZwWriteFile(second, NULL, NULL, NULL, &io, message, 1, NULL, NULL) == NT_ACCESS_DENIED);
    assert(!p_ZwClose(second));

    path = string(W("\\??\\C:\\Sub"));
    assert(!p_ZwCreateFile(&file, 0x80000000, &a, &io, NULL, 0, 3, 2, 0x21, NULL, 0));
    unicode_string relative = string(W("child.bin"));
    nt_object_attributes child = attributes(&relative, file);
    assert(!p_ZwCreateFile(&second, 0xc0000000, &child, &io, NULL, 0, 3, 2, 0x60, NULL, 0));
    assert(!p_ZwClose(second));
    relative = string(W("..\\escape.bin"));
    assert(p_ZwOpenFile(&second, 0x80000000, &child, &io, 3, 0x60) == NT_ACCESS_DENIED);
    assert(!p_ZwClose(file));
    path = string(W("\\??\\C:\\..\\escape.bin"));
    assert(p_ZwOpenFile(&second, 0x80000000, &a, &io, 3, 0x60) == NT_ACCESS_DENIED);
    char link[PATH_MAX];
    assert(snprintf(link, sizeof(link), "%s/files/C/Link", state) < (int)sizeof(link));
    assert(!symlink("/etc", link));
    path = string(W("\\??\\C:\\Link\\passwd"));
    assert(p_ZwOpenFile(&second, 0x80000000, &a, &io, 3, 0x60) != 0);
    path = string(W("\\??\\C:\\€😀.bin"));
    assert(!p_ZwCreateFile(&file, 0xc0000000, &a, &io, NULL, 0, 3, 2, 0x60, NULL, 0));
    assert(!p_ZwClose(file));
}
static void test_registry(void)
{
    unicode_string path = string(W("\\Registry\\Machine\\Software\\DriverLab")), value = string(W("Settings"));
    nt_object_attributes a = attributes(&path, NULL);
    void *key = NULL, *read_only = NULL, *child_key = NULL;
    uint32_t disposition, data = 0x12345678, required = 0;
    assert(p_ZwCreateKey(&key, 0x10000000, &a, 0, NULL, 0, &disposition) == NT_NOT_SUPPORTED);
    assert(!p_ZwCreateKey(&key, 0x10000000, &a, 0, NULL, 1, &disposition) && disposition == 1);
    assert(!p_ZwOpenKey(&read_only, 1, &a));
    assert(!p_ZwSetValueKey(key, &value, 0, 4, &data, 4));
    assert(p_ZwSetValueKey(read_only, &value, 0, 4, &data, 4) == NT_ACCESS_DENIED);
    value = string(W("sETTINGS"));
    assert(p_ZwQueryValueKey(key, &value, 2, NULL, 0, &required) == NT_BUFFER_TOO_SMALL && required == 16);
    unsigned char output[32]; memset(output, 0xCC, sizeof(output));
    assert(p_ZwQueryValueKey(key, &value, 2, output, 14, &required) == 0x80000005 && output[14] == 0xCC);
    assert(!p_ZwQueryValueKey(key, &value, 2, output, sizeof(output), &required));
    assert(get32(output + 4) == 4 && get32(output + 8) == 4 && get32(output + 12) == data);
    assert(!p_ZwDeleteValueKey(key, &value));
    assert(p_ZwQueryValueKey(key, &value, 2, output, sizeof(output), &required) == NT_NOT_FOUND);
    unicode_string empty = {0};
    assert(!p_ZwSetValueKey(key, &empty, 0, 3, NULL, 0));
    assert(!p_ZwQueryValueKey(key, &empty, 2, output, sizeof(output), &required) && required == 12);
    unicode_string child_name = string(W("Child"));
    nt_object_attributes child = attributes(&child_name, read_only);
    assert(p_ZwCreateKey(&child_key, 0x10000000, &child, 0, NULL, 1, &disposition) == NT_ACCESS_DENIED);
    child.root_directory = key;
    assert(!p_ZwCreateKey(&child_key, 0x10000000, &child, 0, NULL, 1, &disposition));
    assert(p_ZwDeleteKey(key) == 0xc0000121);
    assert(!p_ZwDeleteKey(child_key));
    assert(p_ZwSetValueKey(child_key, &value, 0, 4, &data, 4) == 0xc000017c);
    assert(!p_ZwClose(child_key)); assert(!p_ZwClose(read_only));
    assert(!p_ZwDeleteKey(key)); assert(!p_ZwClose(key));
    assert(p_ZwOpenKey(&key, 1, &a) == NT_NOT_FOUND);
}

static void unhex(const char *hex, unsigned char *output)
{
    for (size_t i = 0; i < strlen(hex) / 2; ++i) { unsigned value; assert(sscanf(hex + i * 2, "%2x", &value) == 1); output[i] = value; }
}
static void test_hash(int hmac)
{
    void *algorithm = NULL, *hash = NULL;
    assert(!p_BCryptOpenAlgorithmProvider(&algorithm, W("SHA256"), NULL, hmac ? 8 : 0));
    uint32_t required = 0, length = 0;
    assert(p_BCryptGetProperty(algorithm, W("HashDigestLength"), NULL, 0, &required, 0) == NT_BUFFER_TOO_SMALL && required == 4);
    assert(!p_BCryptGetProperty(algorithm, W("HashDigestLength"), (unsigned char *)&length, 4, &required, 0) && length == 32);
    assert(!p_BCryptCreateHash(algorithm, &hash, NULL, 0, hmac ? (unsigned char *)"key" : NULL, hmac ? 3 : 0, 0));
    unsigned char output[32], expected[32];
    if (hmac) {
        unsigned char message[] = "The quick brown fox jumps over the lazy dog";
        assert(!p_BCryptHashData(hash, message, sizeof(message) - 1, 0));
        unhex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", expected);
    } else {
        assert(!p_BCryptHashData(hash, (unsigned char *)"a", 1, 0));
        assert(!p_BCryptHashData(hash, (unsigned char *)"bc", 2, 0));
        unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected);
    }
    assert(p_BCryptFinishHash(hash, output, 31, 0) == NT_INVALID_PARAMETER);
    assert(!p_BCryptFinishHash(hash, output, 32, 0)); assert(!memcmp(output, expected, 32));
    assert(p_BCryptHashData(hash, (unsigned char *)"x", 1, 0) != 0);
    assert(!p_BCryptDestroyHash(hash)); assert(p_BCryptDestroyHash(hash) == NT_INVALID_HANDLE);
    assert(!p_BCryptCloseAlgorithmProvider(algorithm, 0));
    assert(p_BCryptCloseAlgorithmProvider(algorithm, 0) == NT_INVALID_HANDLE);
    unsigned char random[32]; assert(!p_BCryptGenRandom(NULL, random, sizeof(random), 2));
}
static void test_rsa(void)
{
    EVP_PKEY_CTX *generator = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *key = NULL;
    assert(generator && EVP_PKEY_keygen_init(generator) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(generator, 2048) > 0);
    assert(EVP_PKEY_generate(generator, &key) > 0); EVP_PKEY_CTX_free(generator);
    BIGNUM *n = NULL, *e = NULL;
    assert(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) && EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e));
    uint32_t header[] = {0x31415352, 2048, BN_num_bytes(e), BN_num_bytes(n), 0, 0};
    unsigned char blob[1024]; memcpy(blob, header, 24);
    assert(BN_bn2bin(e, blob + 24) == (int)header[2]);
    assert(BN_bn2bin(n, blob + 24 + header[2]) == (int)header[3]); BN_free(n); BN_free(e);
    void *algorithm = NULL, *public_key = NULL;
    assert(!p_BCryptOpenAlgorithmProvider(&algorithm, W("RSA"), NULL, 0));
    assert(!p_BCryptImportKeyPair(algorithm, NULL, W("RSAPUBLICBLOB"), &public_key, blob, 24 + header[2] + header[3], 0));
    unsigned char digest[32]; unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digest);
    for (int pss = 0; pss < 2; ++pss) {
        EVP_PKEY_CTX *signer = EVP_PKEY_CTX_new(key, NULL);
        assert(signer && EVP_PKEY_sign_init(signer) > 0);
        assert(EVP_PKEY_CTX_set_rsa_padding(signer, pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING) > 0);
        assert(EVP_PKEY_CTX_set_signature_md(signer, EVP_sha256()) > 0);
        if (pss) assert(EVP_PKEY_CTX_set_rsa_pss_saltlen(signer, 32) > 0);
        unsigned char signature[512]; size_t size = sizeof(signature);
        assert(EVP_PKEY_sign(signer, signature, &size, digest, 32) > 0);
        struct { const uint16_t *algorithm; uint32_t salt; } padding = {W("SHA256"), 32};
        assert(!p_BCryptVerifySignature(public_key, &padding, digest, 32, signature, size, pss ? 8 : 2));
        signature[0] ^= 0x80;
        assert(p_BCryptVerifySignature(public_key, &padding, digest, 32, signature, size, pss ? 8 : 2) == 0xc000a000);
        EVP_PKEY_CTX_free(signer);
    }
    assert(!p_BCryptDestroyKey(public_key)); assert(!p_BCryptCloseAlgorithmProvider(algorithm, 0)); EVP_PKEY_free(key);
}
static void test_ec(void)
{
    EVP_PKEY_CTX *generator = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    assert(generator && EVP_PKEY_keygen_init(generator) > 0 && EVP_PKEY_CTX_set_group_name(generator, "prime256v1") > 0);
    assert(EVP_PKEY_generate(generator, &key) > 0); EVP_PKEY_CTX_free(generator);
    unsigned char point[65]; size_t length = sizeof(point);
    assert(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point), &length) && length == 65);
    unsigned char blob[72]; uint32_t header[] = {0x31534345, 32};
    memcpy(blob, header, 8); memcpy(blob + 8, point + 1, 64);
    void *algorithm = NULL, *public_key = NULL;
    assert(!p_BCryptOpenAlgorithmProvider(&algorithm, W("ECDSA_P256"), NULL, 0));
    assert(!p_BCryptImportKeyPair(algorithm, NULL, W("ECCPUBLICBLOB"), &public_key, blob, sizeof(blob), 0));
    unsigned char digest[32] = {1}, der[256], signature[64]; size_t size = sizeof(der);
    EVP_PKEY_CTX *signer = EVP_PKEY_CTX_new(key, NULL);
    assert(signer && EVP_PKEY_sign_init(signer) > 0 && EVP_PKEY_sign(signer, der, &size, digest, 32) > 0);
    const unsigned char *cursor = der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &cursor, size);
    assert(sig); const BIGNUM *r, *s; ECDSA_SIG_get0(sig, &r, &s);
    assert(BN_bn2binpad(r, signature, 32) == 32 && BN_bn2binpad(s, signature + 32, 32) == 32);
    assert(!p_BCryptVerifySignature(public_key, NULL, digest, 32, signature, 64, 0));
    signature[0] ^= 0x80;
    assert(p_BCryptVerifySignature(public_key, NULL, digest, 32, signature, 64, 0) == 0xc000a000);
    memset(blob + 8, 0, 64);
    void *bad = NULL;
    assert(p_BCryptImportKeyPair(algorithm, NULL, W("ECCPUBLICBLOB"), &bad, blob, sizeof(blob), 0) != 0);
    ECDSA_SIG_free(sig); EVP_PKEY_CTX_free(signer); EVP_PKEY_free(key);
    assert(!p_BCryptDestroyKey(public_key)); assert(!p_BCryptCloseAlgorithmProvider(algorithm, 0));
}
static void test_memory(void)
{
    unsigned char *buffer = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(buffer != MAP_FAILED);
    mdl *first = p_IoAllocateMdl(buffer + 13, 5000, 0, 0, NULL);
    mdl *second = p_IoAllocateMdl(buffer + 16, 100, 0, 0, NULL);
    assert(first && second && first->start == buffer && first->offset == 13 && first->count == 5000);
    assert(*(uintptr_t *)(first + 1) == UINTPTR_MAX); /* Physical PFNs are explicitly unavailable. */
    p_MmProbeAndLockPages(first, 0, 2); p_MmProbeAndLockPages(second, 0, 2);
    assert(first->flags & 2);
    assert(!p_MmMapLockedPagesSpecifyCache(first, 1, 1, NULL, 0, 16));
    assert(!p_MmMapLockedPagesSpecifyCache(first, 0, 0, NULL, 0, 16));
    unsigned char *alias = p_MmMapLockedPagesSpecifyCache(first, 0, 1, NULL, 0, 16);
    assert(alias == buffer + 13); alias[4999] = 0xA5; assert(buffer[5012] == 0xA5);
    p_MmUnlockPages(second); p_IoFreeMdl(second); /* Shared page remains pinned for the first MDL. */
    p_MmUnmapLockedPages(alias, first); p_MmUnlockPages(first); p_IoFreeMdl(first);
    mdl *nonpaged = p_IoAllocateMdl(buffer, 16, 0, 0, NULL);
    assert(nonpaged); p_MmBuildMdlForNonPagedPool(nonpaged);
    assert(nonpaged->flags == 4 && nonpaged->mapped == buffer);
    assert(!p_MmMapLockedPagesSpecifyCache(nonpaged, 0, 1, NULL, 0, 16));
    p_IoFreeMdl(nonpaged);
    assert(!driverlab_resolve("ntoskrnl.exe", "MmGetPhysicalAddress"));
    assert(!munmap(buffer, 8192));
}
static void test_bad_probe(void)
{
    void *buffer = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(buffer != MAP_FAILED);
    mdl *descriptor = p_IoAllocateMdl(buffer, 64, 0, 0, NULL);
    assert(descriptor);
    p_MmProbeAndLockPages(descriptor, 0, 2); /* Write probe must fail on read-only memory. */
    abort();
}
static void test_bad_mdl(void)
{
    unsigned char buffer[64];
    mdl *descriptor = p_IoAllocateMdl(buffer, sizeof(buffer), 0, 0, NULL);
    assert(descriptor); descriptor->count = UINT32_MAX;
    p_MmProbeAndLockPages(descriptor, 0, 0);
    abort();
}
static void bind_all(void)
{
    BIND("ntoskrnl.exe", ZwCreateFile); BIND("ntoskrnl.exe", ZwOpenFile); BIND("ntoskrnl.exe", ZwReadFile); BIND("ntoskrnl.exe", ZwWriteFile);
    BIND("ntoskrnl.exe", ZwQueryInformationFile); BIND("ntoskrnl.exe", ZwSetInformationFile); BIND("ntoskrnl.exe", ZwFlushBuffersFile); BIND("ntoskrnl.exe", ZwClose);
    BIND("ntoskrnl.exe", ZwCreateKey); BIND("ntoskrnl.exe", ZwOpenKey); BIND("ntoskrnl.exe", ZwSetValueKey); BIND("ntoskrnl.exe", ZwQueryValueKey);
    BIND("ntoskrnl.exe", ZwDeleteValueKey); BIND("ntoskrnl.exe", ZwDeleteKey);
    BIND("cng.sys", BCryptOpenAlgorithmProvider); BIND("cng.sys", BCryptCloseAlgorithmProvider); BIND("cng.sys", BCryptGetProperty);
    BIND("cng.sys", BCryptCreateHash); BIND("cng.sys", BCryptHashData); BIND("cng.sys", BCryptFinishHash); BIND("cng.sys", BCryptDestroyHash);
    BIND("cng.sys", BCryptImportKeyPair); BIND("cng.sys", BCryptVerifySignature); BIND("cng.sys", BCryptDestroyKey); BIND("cng.sys", BCryptGenRandom);
    BIND("ntoskrnl.exe", IoAllocateMdl); BIND("ntoskrnl.exe", IoFreeMdl); BIND("ntoskrnl.exe", MmBuildMdlForNonPagedPool);
    BIND("ntoskrnl.exe", MmMapLockedPagesSpecifyCache); BIND("ntoskrnl.exe", MmUnmapLockedPages);
    BIND("ntoskrnl.exe", MmProbeAndLockPages); BIND("ntoskrnl.exe", MmUnlockPages);
}
int main(int argc, char **argv)
{
    struct rlimit limit = {0, 0}; setrlimit(RLIMIT_CORE, &limit);
    assert(argc == 3); bind_all();
    assert(!driverlab_io_initialize(argv[2]));
    if (!strcmp(argv[1], "files")) test_files(argv[2]);
    else if (!strcmp(argv[1], "registry")) test_registry();
    else if (!strcmp(argv[1], "sha256")) test_hash(0);
    else if (!strcmp(argv[1], "hmac")) test_hash(1);
    else if (!strcmp(argv[1], "rsa")) test_rsa();
    else if (!strcmp(argv[1], "ecdsa")) test_ec();
    else if (!strcmp(argv[1], "memory")) test_memory();
    else if (!strcmp(argv[1], "bad-probe")) test_bad_probe();
    else if (!strcmp(argv[1], "bad-mdl")) test_bad_mdl();
    else return 2;
    printf("%s: PASS\n", argv[1]); return 0;
}
