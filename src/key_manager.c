#include "key_manager.h"
#include "pkcs11_wrapper.h"
#include <stdlib.h>

KeyManager *key_manager_create(CK_SESSION_HANDLE session) {
    KeyManager *key_manager = malloc(sizeof(KeyManager));
    if (!key_manager) return NULL;

    key_manager->session = session;
    key_manager->hKey = pkcs11_generate_aes_key(session);
    return key_manager;
}

void key_manager_destroy(KeyManager *key_manager) {
    if (key_manager) free(key_manager);
}

CK_OBJECT_HANDLE key_manager_get_key(KeyManager *key_manager) {
    return key_manager->hKey;
}