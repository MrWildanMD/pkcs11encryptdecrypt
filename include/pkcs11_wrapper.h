#ifndef PKCS11_WRAPPER_H
#define PKCS11_WRAPPER_H

#include <softhsm/pkcs11.h>
#include <stdbool.h>

bool pkcs11_initialize(const char *module_path);
void pkcs11_finalize();
CK_SESSION_HANDLE pkcs11_open_session(CK_SLOT_ID slotID, CK_BYTE pin[]);
void pkcs11_close_session(CK_SESSION_HANDLE session);
bool pkcs11_encrypt(CK_SESSION_HANDLE session, CK_MECHANISM *mech, CK_OBJECT_HANDLE key, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len);
bool pkcs11_decrypt(CK_SESSION_HANDLE session, CK_MECHANISM *mech, CK_OBJECT_HANDLE key, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len);
CK_OBJECT_HANDLE pkcs11_generate_key(CK_SESSION_HANDLE session, CK_MECHANISM *mech, CK_ATTRIBUTE *template, size_t template_len);
CK_SLOT_ID pkcs11_get_first_slot();

#endif // PKCS11_WRAPPER_H