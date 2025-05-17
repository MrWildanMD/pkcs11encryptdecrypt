#include "encrypt_service.h"
#include "pkcs11_wrapper.h"
#include "key_manager.h"
#include <stdio.h>
#include <string.h>

int main() {
    if (!pkcs11_initialize("/usr/lib/softhsm/libsofthsm2.so")) {
        fprintf(stderr, "Failed to initialize PKCS#11.\n");
        return 1;
    }

    CK_SESSION_HANDLE session = pkcs11_open_session();
    if (!session) {
        fprintf(stderr, "Failed to open PKCS#11 session.\n");
        return 1;
    }

    KeyManager *key_manager = key_manager_create(session);
    EncryptionService *aes_service = create_aes_encryption_service(key_manager);

    const char *plaintext = "Hello, Wildan";
    unsigned char ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);

    if (aes_service->encrypt(aes_service, (unsigned char *)plaintext, strlen(plaintext), ciphertext, &ciphertext_len)) {
        printf("Encryption successful. Ciphertext length: %zu\n", ciphertext_len);
    } else {
        fprintf(stderr, "Encryption failed.\n");
    }

    unsigned char decrypted[256];
    size_t decrypted_len = sizeof(decrypted);

    if (aes_service->decrypt(aes_service, ciphertext, ciphertext_len, decrypted, &decrypted_len)) {
        decrypted[decrypted_len] = '\0';
        printf("Decrypted: %s\n", decrypted);
    } else {
        fprintf(stderr, "Decryption failed.\n");
    }

    aes_service->destroy(aes_service);
    pkcs11_close_session(session);
    pkcs11_finalize();

    return 0;
}