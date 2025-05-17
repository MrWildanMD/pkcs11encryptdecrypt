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

    CK_SLOT_ID slot_id = pkcs11_get_first_slot();
    if (slot_id == CK_INVALID_HANDLE) {
        fprintf(stderr, "Failed to get a valid slot.\n");
        pkcs11_finalize();
        return 1;
    }

    CK_BYTE pin[] = "12345678";

    CK_SESSION_HANDLE session = pkcs11_open_session(slot_id, pin);
    if (session == CK_INVALID_HANDLE) {
        fprintf(stderr, "Failed to open PKCS#11 session.\n");
        pkcs11_finalize();
        return 1;
    }

    // List supported mechanisms for the slot
    printf("Listing supported mechanisms for slot %lu:\n", slot_id);
    pkcs11_list_mechanisms(slot_id);

    // Define AES key generation mechanism and template for a token object
    CK_MECHANISM key_gen_mech = {CKM_AES_KEY_GEN, NULL_PTR, 0};
    CK_ATTRIBUTE key_template[] = {
        {CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY}, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE)},
        {CKA_VALUE_LEN, &(CK_ULONG){32}, sizeof(CK_ULONG)}, // 256-bit key
        {CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
        {CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)}, // Make it a token object
        {CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)}, // Mark as sensitive
        {CKA_EXTRACTABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL)} // Prevent extraction
    };

    KeyManager *key_manager = key_manager_create(session, &key_gen_mech, key_template, sizeof(key_template) / sizeof(CK_ATTRIBUTE));
    if (!key_manager || key_manager->hKey == CK_INVALID_HANDLE) {
        fprintf(stderr, "Failed to generate AES key. Key handle is invalid.\n");
        pkcs11_close_session(session);
        pkcs11_finalize();
        return 1;
    }
    printf("AES key generated successfully. Key handle: 0x%lX\n", key_manager->hKey);

     // Encrypt using AES-CBC
    CK_BYTE iv[16] = {0};  // Initialization vector
    CK_MECHANISM encMech = {CKM_AES_CBC_PAD, iv, sizeof(iv)};
    CK_BYTE plaintext[] = "hello world!";
    CK_BYTE ciphertext[256];
    CK_ULONG outLen = sizeof(ciphertext);
    EncryptionService *service = create_encryption_service(key_manager, encMech);

    // Perform encryption
    if (service->encrypt(service, plaintext, strlen((char *)plaintext), ciphertext, &outLen)) {
        printf("Encryption successful. Ciphertext length: %zu\n", outLen);
    } else {
        fprintf(stderr, "Encryption failed.\n");
        service->destroy(service);
        pkcs11_close_session(session);
        pkcs11_finalize();
        return 1;
    }

    // Perform decryption
    unsigned char decrypted[256];
    size_t decrypted_len = sizeof(decrypted);
    if (service->decrypt(service, ciphertext, outLen, decrypted, &decrypted_len)) {
        printf("Decryption successful. Decrypted text: %.*s\n", (int)decrypted_len, decrypted);
    } else {
        fprintf(stderr, "Decryption failed.\n");
    }

    // Clean up
    service->destroy(service);
    pkcs11_close_session(session);
    pkcs11_finalize();

    return 0;
}