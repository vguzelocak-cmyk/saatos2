#include "ntcompat.h"
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#define INVALID_SIGNATURE UINT32_C(0xc000a000)
enum { ALGORITHM = 1, HASH, KEY };
typedef struct crypto_object {
    uintptr_t id;
    int type, hmac, finished, bits;
    char algorithm[24];
    const EVP_MD *digest;
    EVP_MD_CTX *hash;
    EVP_MAC_CTX *mac;
    EVP_PKEY *key;
    struct crypto_object *next;
} crypto_object;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static crypto_object *objects;
static uintptr_t next_id = 0xC0000000;

static crypto_object *find(void *handle, int type)
{
    for (crypto_object *p = objects; p; p = p->next)
        if (p->id == (uintptr_t)handle && (!type || p->type == type)) return p;
    return NULL;
}
static void publish(crypto_object *p, void **handle)
{
    p->id = next_id;
    next_id += 4;
    p->next = objects;
    objects = p;
    *handle = (void *)p->id;
}
static uint32_t destroy(void *handle, int type)
{
    pthread_mutex_lock(&mutex);
    crypto_object **slot = &objects;
    while (*slot && ((*slot)->id != (uintptr_t)handle || (*slot)->type != type)) slot = &(*slot)->next;
    if (!*slot) { pthread_mutex_unlock(&mutex); return NT_INVALID_HANDLE; }
    crypto_object *p = *slot;
    *slot = p->next;
    EVP_MD_CTX_free(p->hash); EVP_MAC_CTX_free(p->mac); EVP_PKEY_free(p->key);
    free(p);
    pthread_mutex_unlock(&mutex);
    return 0;
}
static int ascii(const uint16_t *text, char *output, size_t capacity)
{
    if (!text) return 0;
    for (size_t i = 0; i < capacity; ++i) {
        if (text[i] > 127) return 0;
        output[i] = text[i];
        if (!text[i]) return 1;
    }
    return 0;
}
static const EVP_MD *digest_for(const char *name)
{
    if (!strcmp(name, "SHA256")) return EVP_sha256();
    if (!strcmp(name, "SHA384")) return EVP_sha384();
    if (!strcmp(name, "SHA512")) return EVP_sha512();
    if (!strcmp(name, "SHA1")) return EVP_sha1();
    return NULL;
}
static uint32_t NTAPI c_BCryptOpenAlgorithmProvider(void **output, const uint16_t *name,
                                                    const uint16_t *implementation, uint32_t flags)
{
    char algorithm[24], provider[64];
    if (!output || !ascii(name, algorithm, sizeof(algorithm))) return NT_INVALID_PARAMETER;
    if (implementation && (!ascii(implementation, provider, sizeof(provider)) || strcmp(provider, "Microsoft Primitive Provider")))
        return NT_NOT_SUPPORTED;
    const EVP_MD *digest = digest_for(algorithm);
    if (!digest && strcmp(algorithm, "RSA") && strcmp(algorithm, "ECDSA_P256") &&
        strcmp(algorithm, "ECDSA_P384") && strcmp(algorithm, "ECDSA_P521") && strcmp(algorithm, "RNG"))
        return NT_NOT_SUPPORTED;
    if (flags && (flags != 8 || !digest)) return NT_NOT_SUPPORTED;
    crypto_object *p = calloc(1, sizeof(*p));
    if (!p) return NT_NO_MEMORY;
    p->type = ALGORITHM; p->digest = digest; p->hmac = flags == 8;
    strcpy(p->algorithm, algorithm);
    pthread_mutex_lock(&mutex); publish(p, output); pthread_mutex_unlock(&mutex);
    return 0;
}
static uint32_t NTAPI c_BCryptCloseAlgorithmProvider(void *handle, uint32_t flags)
{
    return flags ? NT_INVALID_PARAMETER : destroy(handle, ALGORITHM);
}
static uint32_t NTAPI c_BCryptCreateHash(void *algorithm, void **output, unsigned char *storage,
                                       uint32_t storage_length, unsigned char *secret,
                                       uint32_t secret_length, uint32_t flags)
{
    if (!output || (!storage && storage_length) || (!secret && secret_length) || flags) return NT_INVALID_PARAMETER;
    pthread_mutex_lock(&mutex);
    crypto_object *a = find(algorithm, ALGORITHM);
    uint32_t status = NT_INVALID_HANDLE;
    if (!a) goto done;
    if (!a->digest || (!a->hmac && secret_length)) { status = NT_INVALID_PARAMETER; goto done; }
    crypto_object *p = calloc(1, sizeof(*p));
    if (!p) { status = NT_NO_MEMORY; goto done; }
    p->type = HASH; p->digest = a->digest; p->hmac = a->hmac;
    strcpy(p->algorithm, a->algorithm);
    int ok;
    if (p->hmac) {
        EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        p->mac = mac ? EVP_MAC_CTX_new(mac) : NULL;
        EVP_MAC_free(mac);
        const char *digest_name = EVP_MD_get0_name(p->digest);
        OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)digest_name, 0),
                               OSSL_PARAM_construct_end()};
        ok = p->mac && EVP_MAC_init(p->mac, secret ? secret : (const unsigned char *)"", secret_length, params);
    } else {
        p->hash = EVP_MD_CTX_new();
        ok = p->hash && EVP_DigestInit_ex(p->hash, p->digest, NULL);
    }
    if (!ok) { EVP_MD_CTX_free(p->hash); EVP_MAC_CTX_free(p->mac); free(p); status = NT_UNSUCCESSFUL; goto done; }
    publish(p, output); status = 0;
done:
    pthread_mutex_unlock(&mutex);
    return status;
}
static uint32_t NTAPI c_BCryptHashData(void *handle, unsigned char *input, uint32_t length, uint32_t flags)
{
    if (flags || (!input && length)) return NT_INVALID_PARAMETER;
    pthread_mutex_lock(&mutex);
    crypto_object *p = find(handle, HASH);
    uint32_t status = NT_INVALID_HANDLE;
    if (p) {
        if (p->finished) status = NT_INVALID_PARAMETER;
        else if (!length) status = 0;
        else status = (p->hmac ? EVP_MAC_update(p->mac, input, length) : EVP_DigestUpdate(p->hash, input, length)) ? 0 : NT_UNSUCCESSFUL;
    }
    pthread_mutex_unlock(&mutex); return status;
}
static uint32_t NTAPI c_BCryptFinishHash(void *handle, unsigned char *output, uint32_t length, uint32_t flags)
{
    if (flags || !output) return NT_INVALID_PARAMETER;
    pthread_mutex_lock(&mutex);
    crypto_object *p = find(handle, HASH);
    uint32_t status = NT_INVALID_HANDLE;
    if (p) {
        if (p->finished || length != (uint32_t)EVP_MD_get_size(p->digest)) status = NT_INVALID_PARAMETER;
        else {
            unsigned int count = 0;
            size_t mac_count = 0;
            int ok = p->hmac ? EVP_MAC_final(p->mac, output, &mac_count, length) : EVP_DigestFinal_ex(p->hash, output, &count);
            p->finished = 1;
            status = ok && (p->hmac ? mac_count == length : count == length) ? 0 : NT_UNSUCCESSFUL;
        }
    }
    pthread_mutex_unlock(&mutex); return status;
}
static uint32_t NTAPI c_BCryptDestroyHash(void *handle) { return destroy(handle, HASH); }
static uint32_t NTAPI c_BCryptDestroyKey(void *handle) { return destroy(handle, KEY); }

static uint32_t NTAPI c_BCryptGetProperty(void *handle, const uint16_t *property, unsigned char *output,
                                        uint32_t capacity, uint32_t *required, uint32_t flags)
{
    char name[40];
    if (!required || flags || (!output && capacity) || !ascii(property, name, sizeof(name))) return NT_INVALID_PARAMETER;
    pthread_mutex_lock(&mutex);
    crypto_object *p = find(handle, 0);
    if (!p) { pthread_mutex_unlock(&mutex); return NT_INVALID_HANDLE; }
    unsigned char bytes[64]; uint32_t size = 4, value = 0;
    if (!strcmp(name, "ObjectLength") && p->digest) value = 0; /* Opaque state is allocated internally. */
    else if (!strcmp(name, "HashDigestLength") && p->digest) value = EVP_MD_get_size(p->digest);
    else if (!strcmp(name, "BlockLength") && p->digest) value = EVP_MD_get_block_size(p->digest);
    else if (!strcmp(name, "KeyLength") && p->type == KEY) value = p->bits;
    else if (!strcmp(name, "AlgorithmName")) {
        size = (strlen(p->algorithm) + 1) * 2;
        for (uint32_t i = 0; i < size / 2; ++i) { bytes[i * 2] = p->algorithm[i]; bytes[i * 2 + 1] = 0; }
    } else { pthread_mutex_unlock(&mutex); return NT_NOT_SUPPORTED; }
    if (strcmp(name, "AlgorithmName")) memcpy(bytes, &value, 4);
    *required = size;
    uint32_t status = capacity < size ? NT_BUFFER_TOO_SMALL : 0;
    if (!status) memcpy(output, bytes, size);
    pthread_mutex_unlock(&mutex); return status;
}

static uint32_t u32(const unsigned char *p) { uint32_t value; memcpy(&value, p, 4); return value; }
static EVP_PKEY *import_rsa(const unsigned char *blob, size_t size)
{
    if (size < 24 || u32(blob) != 0x31415352 || u32(blob + 16) || u32(blob + 20)) return NULL;
    uint32_t bits = u32(blob + 4), exponent_size = u32(blob + 8), modulus_size = u32(blob + 12);
    if (bits < 512 || bits > 16384 || !exponent_size || exponent_size > 8 || modulus_size != (bits + 7) / 8 ||
        size != 24 + (size_t)exponent_size + modulus_size) return NULL;
    BIGNUM *e = BN_bin2bn(blob + 24, exponent_size, NULL);
    BIGNUM *n = BN_bin2bn(blob + 24 + exponent_size, modulus_size, NULL);
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    if (e && n && builder && BN_is_odd(e) && BN_cmp(e, BN_value_one()) > 0 && BN_is_odd(n) &&
        BN_num_bits(n) == (int)bits && OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, n) &&
        OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E, e)) {
        params = OSSL_PARAM_BLD_to_param(builder);
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (params && ctx && EVP_PKEY_fromdata_init(ctx) > 0)
            if (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0) { EVP_PKEY_free(key); key = NULL; }
    }
    EVP_PKEY_CTX_free(ctx); OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(builder); BN_free(n); BN_free(e);
    return key;
}
static EVP_PKEY *import_ec(const char *algorithm, const unsigned char *blob, size_t size)
{
    unsigned bytes; uint32_t magic; const char *group;
    if (!strcmp(algorithm, "ECDSA_P256")) { bytes = 32; magic = 0x31534345; group = "prime256v1"; }
    else if (!strcmp(algorithm, "ECDSA_P384")) { bytes = 48; magic = 0x33534345; group = "secp384r1"; }
    else if (!strcmp(algorithm, "ECDSA_P521")) { bytes = 66; magic = 0x35534345; group = "secp521r1"; }
    else return NULL;
    if (size != 8 + 2 * bytes || u32(blob) != magic || u32(blob + 4) != bytes) return NULL;
    unsigned char point[133]; point[0] = 4; memcpy(point + 1, blob + 8, 2 * bytes);
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0),
                           OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point, 1 + 2 * bytes),
                           OSSL_PARAM_construct_end()};
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    if (ctx && EVP_PKEY_fromdata_init(ctx) > 0)
        if (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0) { EVP_PKEY_free(key); key = NULL; }
    EVP_PKEY_CTX_free(ctx); return key;
}
static uint32_t NTAPI c_BCryptImportKeyPair(void *algorithm, void *import_key, const uint16_t *blob_type,
                                          void **output, unsigned char *input, uint32_t size, uint32_t flags)
{
    char type[32];
    if (!output || !input || !ascii(blob_type, type, sizeof(type))) return NT_INVALID_PARAMETER;
    if (flags || import_key) return NT_NOT_SUPPORTED;
    pthread_mutex_lock(&mutex);
    crypto_object *a = find(algorithm, ALGORITHM);
    uint32_t status = NT_INVALID_HANDLE;
    if (!a) goto done;
    EVP_PKEY *key = NULL;
    if (!strcmp(a->algorithm, "RSA") && (!strcmp(type, "RSAPUBLICBLOB") || !strcmp(type, "PUBLICBLOB"))) key = import_rsa(input, size);
    else if (!strncmp(a->algorithm, "ECDSA_", 6) && (!strcmp(type, "ECCPUBLICBLOB") || !strcmp(type, "PUBLICBLOB"))) key = import_ec(a->algorithm, input, size);
    else { status = NT_NOT_SUPPORTED; goto done; }
    if (!key) { status = NT_INVALID_PARAMETER; goto done; }
    EVP_PKEY_CTX *check = EVP_PKEY_CTX_new(key, NULL);
    int valid = check && EVP_PKEY_public_check(check) == 1;
    EVP_PKEY_CTX_free(check);
    if (!valid) { EVP_PKEY_free(key); status = NT_INVALID_PARAMETER; goto done; }
    crypto_object *p = calloc(1, sizeof(*p));
    if (!p) { EVP_PKEY_free(key); status = NT_NO_MEMORY; goto done; }
    p->type = KEY; p->key = key; p->bits = EVP_PKEY_get_bits(key); strcpy(p->algorithm, a->algorithm);
    publish(p, output); status = 0;
done:
    pthread_mutex_unlock(&mutex); return status;
}

static uint32_t NTAPI c_BCryptVerifySignature(void *handle, void *padding, unsigned char *hash, uint32_t hash_size,
                                             unsigned char *signature, uint32_t signature_size, uint32_t flags)
{
    if (!hash || !hash_size || !signature) return NT_INVALID_PARAMETER;
    pthread_mutex_lock(&mutex);
    crypto_object *p = find(handle, KEY);
    uint32_t status = NT_INVALID_HANDLE;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *der = NULL;
    if (!p) goto done;
    ctx = EVP_PKEY_CTX_new(p->key, NULL);
    if (!ctx || EVP_PKEY_verify_init(ctx) <= 0) { status = NT_UNSUCCESSFUL; goto done; }
    if (!strcmp(p->algorithm, "RSA")) {
        if (!padding || (flags != 2 && flags != 8)) { status = NT_NOT_SUPPORTED; goto done; }
        const uint16_t *algorithm = *(const uint16_t **)padding;
        char name[24];
        const EVP_MD *digest = ascii(algorithm, name, sizeof(name)) ? digest_for(name) : NULL;
        if (!digest || hash_size != (uint32_t)EVP_MD_get_size(digest)) { status = NT_INVALID_PARAMETER; goto done; }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, flags == 2 ? RSA_PKCS1_PADDING : RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_signature_md(ctx, digest) <= 0) { status = NT_UNSUCCESSFUL; goto done; }
        if (flags == 8) {
            uint32_t salt; memcpy(&salt, (unsigned char *)padding + sizeof(void *), 4);
            if (salt > INT_MAX || EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, salt) <= 0) { status = NT_INVALID_PARAMETER; goto done; }
        }
    } else {
        if (flags || padding) { status = NT_NOT_SUPPORTED; goto done; }
        size_t bytes = (p->bits + 7) / 8;
        if (signature_size != 2 * bytes) { status = INVALID_SIGNATURE; goto done; }
        BIGNUM *r = BN_bin2bn(signature, bytes, NULL), *s = BN_bin2bn(signature + bytes, bytes, NULL);
        ECDSA_SIG *sig = ECDSA_SIG_new();
        if (!r || !s || !sig || !ECDSA_SIG_set0(sig, r, s)) {
            BN_free(r); BN_free(s); ECDSA_SIG_free(sig); status = NT_NO_MEMORY; goto done;
        }
        int length = i2d_ECDSA_SIG(sig, &der);
        ECDSA_SIG_free(sig);
        if (length <= 0) { status = NT_UNSUCCESSFUL; goto done; }
        signature = der; signature_size = length;
    }
    int result = EVP_PKEY_verify(ctx, signature, signature_size, hash, hash_size);
    status = result == 1 ? 0 : INVALID_SIGNATURE;
done:
    OPENSSL_free(der); EVP_PKEY_CTX_free(ctx); pthread_mutex_unlock(&mutex); return status;
}
static uint32_t NTAPI c_BCryptGenRandom(void *algorithm, unsigned char *output, uint32_t length, uint32_t flags)
{
    if ((!output && length) || length > INT_MAX) return NT_INVALID_PARAMETER;
    if (flags == 2 && !algorithm) return RAND_bytes(output, length) == 1 ? 0 : NT_UNSUCCESSFUL;
    if (flags) return NT_NOT_SUPPORTED;
    pthread_mutex_lock(&mutex);
    crypto_object *p = find(algorithm, ALGORITHM);
    uint32_t status = !p ? NT_INVALID_HANDLE : strcmp(p->algorithm, "RNG") ? NT_INVALID_PARAMETER :
        RAND_bytes(output, length) == 1 ? 0 : NT_UNSUCCESSFUL;
    pthread_mutex_unlock(&mutex); return status;
}

#define C(name) {"cng.sys", #name, (void *)c_##name}
const nt_export driverlab_crypto_exports[] = {
    C(BCryptOpenAlgorithmProvider), C(BCryptCloseAlgorithmProvider), C(BCryptCreateHash), C(BCryptHashData),
    C(BCryptFinishHash), C(BCryptDestroyHash), C(BCryptGetProperty), C(BCryptImportKeyPair),
    C(BCryptVerifySignature), C(BCryptDestroyKey), C(BCryptGenRandom),
};
const size_t driverlab_crypto_count = sizeof(driverlab_crypto_exports) / sizeof(driverlab_crypto_exports[0]);
