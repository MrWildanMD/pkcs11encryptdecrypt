#ifndef PKCS11_WRAPPER_H
#define PKCS11_WRAPPER_H

#include <softhsm/pkcs11.h>
#include <stdbool.h>

bool pkcs11_initialize(const char *module_path);
void pkcs11_finalize();
CK_SESSION_HANDLE pkcs11_open_session();
void pkcs11_close_session(CK_SESSION_HANDLE session);
CK_OBJECT_HANDLE pkcs11_generate_aes_key(CK_SESSION_HANDLE session);
bool pkcs11_encrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len);
bool pkcs11_decrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len);

#endif // PKCS11_WRAPPER_H