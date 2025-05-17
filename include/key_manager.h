#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <softhsm/pkcs11.h>

typedef struct {
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE hKey;
} KeyManager;

KeyManager *key_manager_create(CK_SESSION_HANDLE session);
void key_manager_destroy(KeyManager *key_manager);
CK_OBJECT_HANDLE key_manager_get_key(KeyManager *key_manager);

#endif // KEY_MANAGER_H