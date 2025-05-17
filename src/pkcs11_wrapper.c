#include "pkcs11_wrapper.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static CK_FUNCTION_LIST_PTR p11 = NULL;
static void *module_handle = NULL;

bool pkcs11_initialize(const char *module_path)
{
    module_handle = dlopen(module_path, RTLD_NOW);
    if (!module_handle)
    {
        fprintf(stderr, "Failed to load PKCS#11 module: %s\n", dlerror());
        return false;
    }

    CK_C_GetFunctionList get_func_list = (CK_C_GetFunctionList)dlsym(module_handle, "C_GetFunctionList");
    if (!get_func_list || get_func_list(&p11) != CKR_OK)
    {
        fprintf(stderr, "Failed to get function list symbol.\n");
        return false;
    }

    return (p11->C_Initialize(NULL_PTR) == CKR_OK);
}

void pkcs11_finalize()
{
    if (p11)
        p11->C_Finalize(NULL_PTR);
    if (module_handle)
        dlclose(module_handle);
}

CK_SESSION_HANDLE pkcs11_open_session(CK_SLOT_ID slotId, CK_BYTE pin[])
{
    CK_SESSION_HANDLE session;
    if (p11->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session) != CKR_OK)
    {
        fprintf(stderr, "Failed to open session.\n");
        return CK_INVALID_HANDLE;
    }

    // Calculate the length of the PIN
    CK_ULONG pin_len = (CK_ULONG)strlen((char *)pin);

    if (p11->C_Login(session, CKU_USER, pin, pin_len) != CKR_OK)
    {
        fprintf(stderr, "Failed to login to session.\n");
        p11->C_CloseSession(session);
        return CK_INVALID_HANDLE;
    }

    return session;
}

void pkcs11_close_session(CK_SESSION_HANDLE session)
{
    p11->C_Logout(session);
    p11->C_CloseSession(session);
}

CK_OBJECT_HANDLE pkcs11_generate_key(CK_SESSION_HANDLE session, CK_MECHANISM *mech, CK_ATTRIBUTE *template, size_t template_len)
{
    CK_OBJECT_HANDLE key_handle;
    CK_RV rv = p11->C_GenerateKey(session, mech, template, template_len, &key_handle);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "Key generation failed. CK_RV: 0x%lX\n", rv);
        return CK_INVALID_HANDLE;
    }
    return key_handle;
}

bool pkcs11_encrypt(CK_SESSION_HANDLE session, CK_MECHANISM *mech, CK_OBJECT_HANDLE key, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len)
{
    printf("Initializing encryption with mechanism: 0x%lX, key handle: 0x%lX\n", mech->mechanism, key);

    CK_RV rv = p11->C_EncryptInit(session, mech, key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "EncryptInit failed. CK_RV: 0x%lX\n", rv);
        return false;
    }

    rv = p11->C_Encrypt(session, plaintext, plaintext_len, ciphertext, ciphertext_len);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "Encrypt failed. CK_RV: 0x%lX\n", rv);
        return false;
    }

    return true;
}

bool pkcs11_decrypt(CK_SESSION_HANDLE session, CK_MECHANISM *mech, CK_OBJECT_HANDLE key, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len)
{
    CK_RV rv = p11->C_DecryptInit(session, mech, key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "DecryptInit failed. CK_RV: 0x%lX\n", rv);
        return false;
    }

    rv = p11->C_Decrypt(session, ciphertext, ciphertext_len, plaintext, plaintext_len);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "Decrypt failed. CK_RV: 0x%lX\n", rv);
        return false;
    }

    return true;
}

CK_SLOT_ID pkcs11_get_first_slot()
{
    CK_SLOT_ID slots[10];
    CK_ULONG slot_count = sizeof(slots) / sizeof(CK_SLOT_ID);

    if (p11->C_GetSlotList(CK_TRUE, slots, &slot_count) != CKR_OK || slot_count == 0)
    {
        fprintf(stderr, "No available slots.\n");
        return CK_INVALID_HANDLE;
    }

    return slots[0]; // Return the first available slot
}

void pkcs11_list_mechanisms(CK_SLOT_ID slot_id)
{
    CK_MECHANISM_TYPE mechanisms[128];
    CK_ULONG mech_count = sizeof(mechanisms) / sizeof(CK_MECHANISM_TYPE);

    if (p11->C_GetMechanismList(slot_id, mechanisms, &mech_count) != CKR_OK)
    {
        fprintf(stderr, "Failed to get mechanism list.\n");
        return;
    }

    printf("Supported mechanisms for slot %lu:\n", slot_id);
    for (CK_ULONG i = 0; i < mech_count; i++)
    {
        printf("  0x%lX\n", mechanisms[i]);
    }
}