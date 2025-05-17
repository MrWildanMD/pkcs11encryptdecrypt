#include "encrypt_service.h"
#include "key_manager.h"
#include "pkcs11_wrapper.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    KeyManager *key_manager;
    CK_MECHANISM mech;
} EncryptionServiceContext;

static bool encrypt(EncryptionService *service, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    EncryptionServiceContext *ctx = (EncryptionServiceContext *)service->context;
    return pkcs11_encrypt(ctx->key_manager->session, &ctx->mech, ctx->key_manager->hKey, input, input_len, output, output_len);
}

static bool decrypt(EncryptionService *service, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    EncryptionServiceContext *ctx = (EncryptionServiceContext *)service->context;
    return pkcs11_decrypt(ctx->key_manager->session, &ctx->mech, ctx->key_manager->hKey, input, input_len, output, output_len);
}

static void destroy(EncryptionService *service) {
    if (service) {
        EncryptionServiceContext *ctx = (EncryptionServiceContext *)service->context;
        key_manager_destroy(ctx->key_manager);
        free(ctx);
        free(service);
    }
}

EncryptionService *create_encryption_service(void *key_manager, CK_MECHANISM mech) {
    EncryptionService *service = malloc(sizeof(EncryptionService));
    EncryptionServiceContext *ctx = malloc(sizeof(EncryptionServiceContext));

    ctx->key_manager = key_manager;
    ctx->mech = mech;

    service->encrypt = encrypt;
    service->decrypt = decrypt;
    service->destroy = destroy;
    service->context = ctx;

    return service;
}