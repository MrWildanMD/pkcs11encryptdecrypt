#include "encrypt_service.h"
#include "key_manager.h"
#include "pkcs11_wrapper.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

// Mock implementations for PKCS#11 functions
static int mock_encrypt(EncryptionService *service, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len) {
    if (plaintext == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return 0; // Simulate failure
    }
    memcpy(ciphertext, plaintext, plaintext_len); // Mock encryption (identity operation)
    *ciphertext_len = plaintext_len;
    return 1; // Simulate success
}

static int mock_decrypt(EncryptionService *service, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len) {
    if (ciphertext == NULL || plaintext == NULL || plaintext_len == NULL) {
        return 0; // Simulate failure
    }
    memcpy(plaintext, ciphertext, ciphertext_len); // Mock decryption (identity operation)
    *plaintext_len = ciphertext_len;
    return 1; // Simulate success
}

static void mock_destroy(EncryptionService *service) {
    // Mock destroy function
    free(service);
}

// Test cases
void test_encrypt_valid() {
    EncryptionService service = {mock_encrypt, mock_decrypt, mock_destroy};
    unsigned char plaintext[] = "test data";
    unsigned char ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);

    int result = service.encrypt(&service, plaintext, strlen((char *)plaintext), ciphertext, &ciphertext_len);
    assert(result == 1);
    assert(ciphertext_len == strlen((char *)plaintext));
    assert(memcmp(plaintext, ciphertext, ciphertext_len) == 0);
    printf("test_encrypt_valid passed.\n");
}

void test_encrypt_invalid() {
    EncryptionService service = {mock_encrypt, mock_decrypt, mock_destroy};
    unsigned char *plaintext = NULL;
    unsigned char ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);

    int result = service.encrypt(&service, plaintext, 0, ciphertext, &ciphertext_len);
    assert(result == 0);
    printf("test_encrypt_invalid passed.\n");
}

void test_decrypt_valid() {
    EncryptionService service = {mock_encrypt, mock_decrypt, mock_destroy};
    unsigned char ciphertext[] = "test data";
    unsigned char plaintext[256];
    size_t plaintext_len = sizeof(plaintext);

    int result = service.decrypt(&service, ciphertext, strlen((char *)ciphertext), plaintext, &plaintext_len);
    assert(result == 1);
    assert(plaintext_len == strlen((char *)ciphertext));
    assert(memcmp(plaintext, ciphertext, plaintext_len) == 0);
    printf("test_decrypt_valid passed.\n");
}

void test_decrypt_invalid() {
    EncryptionService service = {mock_encrypt, mock_decrypt, mock_destroy};
    unsigned char *ciphertext = NULL;
    unsigned char plaintext[256];
    size_t plaintext_len = sizeof(plaintext);

    int result = service.decrypt(&service, ciphertext, 0, plaintext, &plaintext_len);
    assert(result == 0);
    printf("test_decrypt_invalid passed.\n");
}

int main() {
    test_encrypt_valid();
    test_encrypt_invalid();
    test_decrypt_valid();
    test_decrypt_invalid();
    printf("All tests passed.\n");
    return 0;
}
