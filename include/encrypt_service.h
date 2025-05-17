#ifndef ENCRYPT_SERVICE_H
#define ENCRYPT_SERVICE_H

#include <stddef.h>
#include <stdbool.h>
#include <softhsm/pkcs11.h>

typedef struct EncryptionService {
    bool (*encrypt)(struct EncryptionService *, const unsigned char *, size_t, unsigned char *, size_t *);
    bool (*decrypt)(struct EncryptionService *, const unsigned char *, size_t, unsigned char *, size_t *);
    void (*destroy)(struct EncryptionService *);
    void *context;
} EncryptionService;

EncryptionService *create_encryption_service(void *key_manager, CK_MECHANISM mech);

#endif // ENCRYPT_SERVICE_H