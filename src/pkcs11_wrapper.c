#include "pkcs11_wrapper.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static CK_FUNCTION_LIST_PTR p11 = NULL;
static void *module_handle = NULL;

bool pkcs11_initialize(const char *module_path) {
    module_handle = dlopen(module_path, RTLD_NOW);
    if (!module_handle) {
        fprintf(stderr, "Failed to load PKCS#11 module: %s\n", dlerror());
        return false;
    }

    CK_C_GetFunctionList get_func_list = (CK_C_GetFunctionList)dlsym(module_handle, "C_GetFunctionList");
    if (!get_func_list || get_func_list(&p11) != CKR_OK) {
        fprintf(stderr, "Failed to get function list symbol.\n");
        return false;   
    }

    return (p11->C_Initialize(NULL_PTR) == CKR_OK);
}

void pkcs11_finalize() {
    if (p11) p11->C_Finalize(NULL_PTR);
    if (module_handle) dlclose(module_handle);
}

CK_SESSION_HANDLE pkcs11_open_session(CK_UTF8CHAR_PTR pin) {
    CK_SLOT_ID slot;
    CK_ULONG slot_count = 1;
    if (p11->C_GetSlotList(CK_TRUE, &slot, &slot_count) != CKR_OK || slot_count == 0) {
        fprintf(stderr, "No slots available.\n");
        return CK_INVALID_HANDLE;
    }

    CK_SESSION_HANDLE session;
    if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session) != CKR_OK) {
        fprintf(stderr, "Failed to open session.\n");
        return CK_INVALID_HANDLE;
    }

    if (p11->C_Login(session, CKU_USER, pin, sizeof(pin)) != CKR_OK) {
        fprintf(stderr, "Failed to login to session.\n");
        p11->C_CloseSession(session);
        return CK_INVALID_HANDLE;
    }

    return session;
}

void pkcs11_close_session(CK_SESSION_HANDLE session) {
    p11->C_Logout(session);
    p11->C_CloseSession(session);
}

CK_OBJECT_HANDLE pkcs11_generate_aes_key(CK_SESSION_HANDLE session) {
    CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL_PTR, 0};
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_BBOOL true_val = CK_TRUE;
    CK_UTF8CHAR_PTR key_label = (CK_UTF8CHAR_PTR)"AES Key";

    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_ENCRYPT, &true_val, sizeof(true_val)},
        {CKA_DECRYPT, &true_val, sizeof(true_val)},
        {CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG)},
        {CKA_TOKEN, &true_val, sizeof(true_val)},
        {CKA_LABEL, key_label, strlen((char *)key_label)},
    };

    CK_OBJECT_HANDLE key_handle;
    if(p11->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), &key_handle) != CKR_OK) {
        fprintf(stderr, "Failed to generate AES key.\n");
        return CK_INVALID_HANDLE;
    }

    return key_handle;
}

bool pkcs11_encrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len) {
    CK_MECHANISM mech = {CKM_AES_ECB, NULL_PTR, 0};
    if (p11->C_EncryptInit(session, &mech, key) != CKR_OK) {
        fprintf(stderr, "Failed to initialize encryption.\n");
        return false;
    }

    return (p11->C_Encrypt(session, plaintext, plaintext_len, ciphertext, ciphertext_len) == CKR_OK);
}

bool pkcs11_decrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len) {
    CK_MECHANISM mech = {CKM_AES_ECB, NULL_PTR, 0};
    if (p11->C_DecryptInit(session, &mech, key) != CKR_OK) {
        fprintf(stderr, "Failed to initialize decryption.\n");
        return false;
    }

    return (p11->C_Decrypt(session, ciphertext, ciphertext_len, plaintext, plaintext_len) == CKR_OK);
}