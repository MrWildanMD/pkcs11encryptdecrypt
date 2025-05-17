#include "encrypt_service.h"
#include "key_manager.h"
#include "pkcs11_wrapper.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    KeyManager *key_manager;
} AESServiceContext;

static bool aes_encrypt(EncryptionService *service, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    AESServiceContext *ctx = (AESServiceContext *)service->context;
    return pkcs11_encrypt(ctx->key_manager->session, ctx->key_manager->hKey, input, input_len, output, output_len);
}

static bool aes_decrypt(EncryptionService *service, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    AESServiceContext *ctx = (AESServiceContext *)service->context;
    return pkcs11_decrypt(ctx->key_manager->session, ctx->key_manager->hKey, input, input_len, output, output_len);
}

static void aes_destroy(EncryptionService *service) {
    if (service) {
        AESServiceContext *ctx = (AESServiceContext *)service->context;
        key_manager_destroy(ctx->key_manager);
        free(ctx);
        free(service);
    }
}

EncryptionService *create_aes_encryption_service(void *key_manager) {
    EncryptionService *service = malloc(sizeof(EncryptionService));
    AESServiceContext *ctx = malloc(sizeof(AESServiceContext));

    ctx->key_manager = key_manager;

    service->encrypt = aes_encrypt;
    service->decrypt = aes_decrypt;
    service->destroy = aes_destroy;
    service->context = ctx;

    return service;
}