/*
	Creative Commons Attribution-NonCommercial-NoDerivs (CC-BY-NC-ND)
	https://creativecommons.org/licenses/by-nc-nd/4.0/
	The most restrictive creative commons license.
	This only allows people to download and share your work for no commercial gain and for no other purposes.
*/

#include "pkcs11-client.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define CHECK_STATE_FIX(handle, st) \
	do { \
        if ((handle) == NULL) return PKCS11_ERR_NULL_PTR; \
        if ((handle)->state != (st)) return PKCS11_ERR_WRONG_STATE; \
    } while (0)

#define CHECK_STATE_LESS(handle, st) \
	do { \
		if ((handle) == NULL) return PKCS11_ERR_NULL_PTR; \
		if ((handle)->state < (st)) return PKCS11_ERR_WRONG_STATE; \
	} while (0)

static const CK_BBOOL yes = CK_TRUE;
static const CK_BBOOL no = CK_FALSE;

enum
{
	PKCS11_STATE_NONE,
	PKCS11_STATE_LIB_LOADED,
	PKCS11_STATE_FUNCS_LOADED,
	PKCS11_STATE_INITIALIZED,
	PKCS11_STATE_HAS_SESSION,
	PKCS11_STATE_LOGGED_IN,
};

typedef struct pkcs11_handle_t
{
	void * lib_handle;
	CK_FUNCTION_LIST * func_list;
	CK_SESSION_HANDLE session;
	CK_RV pkcs_error;
	CK_OBJECT_HANDLE last_object_handle;
	CK_OBJECT_HANDLE last_object_public;
	CK_OBJECT_HANDLE last_object_private;
	int state;
} pkcs11_handle;

int pkcs11_free(pkcs11_handle * handle)
{
	if (handle == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (handle->lib_handle == NULL)
	{
		if (handle->session != 0 || handle->state != PKCS11_STATE_NONE)
		{
			return PKCS11_ERR_WRONG_STATE;
		}

		return PKCS11_OK;
	}

	if (handle->state >= PKCS11_STATE_HAS_SESSION && handle->session == 0)
	{
		return PKCS11_ERR_WRONG_STATE;
	}

	if (handle->state == PKCS11_STATE_LOGGED_IN)
	{
		handle->pkcs_error = handle->func_list->C_Logout(handle->session);
		if (handle->pkcs_error != CKR_OK)
		{
			return PKCS11_ERR_PKCS11;
		}

		handle->state = PKCS11_STATE_HAS_SESSION;
	}

	if (handle->state == PKCS11_STATE_HAS_SESSION)
	{
		handle->pkcs_error = handle->func_list->C_CloseSession(handle->session);
		if (handle->pkcs_error != CKR_OK)
		{
			return PKCS11_ERR_PKCS11;
		}

		handle->session = 0;
		handle->state = PKCS11_STATE_INITIALIZED;
	}

	if (handle->state == PKCS11_STATE_INITIALIZED)
	{
		handle->pkcs_error = handle->func_list->C_Finalize(NULL);
		if (handle->pkcs_error != CKR_OK)
		{
			return PKCS11_ERR_PKCS11;
		}

		handle->state = PKCS11_STATE_FUNCS_LOADED;
	}

	if (handle->state == PKCS11_STATE_FUNCS_LOADED)
	{
		handle->func_list = NULL;
		handle->state = PKCS11_STATE_LIB_LOADED;
	}

	if (handle->state == PKCS11_STATE_LIB_LOADED)
	{
		if (dlclose(handle->lib_handle) != 0)
		{
			return PKCS11_ERR_UNLOAD_LIBRARY;
		}

		handle->state = PKCS11_STATE_NONE;
	}

	free(handle);
	return PKCS11_OK;
}

pkcs11_handle * pkcs11_load_library(const char * path, int flags)
{
	pkcs11_handle * handle = calloc(sizeof(pkcs11_handle), 1);
	if (handle == NULL)
	{
		return NULL;
	}

	handle->lib_handle = dlopen(path, flags);
	if (handle->lib_handle == NULL)
	{
		free(handle);
		return NULL;
	}

	handle->state = PKCS11_STATE_LIB_LOADED;
	return handle;
}

int pkcs11_load_functions(pkcs11_handle * handle)
{
	if (handle == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (handle->state != PKCS11_STATE_FUNCS_LOADED && handle->state != PKCS11_STATE_LIB_LOADED)
	{
		return PKCS11_ERR_WRONG_STATE;
	}

	CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList) dlsym(handle->lib_handle, "C_GetFunctionList");

	if (C_GetFunctionList == NULL)
	{
		return PKCS11_ERR_LIB_FUNC_NOT_FOUND;
	}

	handle->pkcs_error = C_GetFunctionList(&handle->func_list);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	handle->state = PKCS11_STATE_FUNCS_LOADED;
	return PKCS11_OK;
}

int pkcs11_init_library(pkcs11_handle * handle)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_FUNCS_LOADED);

	handle->pkcs_error = handle->func_list->C_Initialize(NULL);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	handle->state = PKCS11_STATE_INITIALIZED;
	return PKCS11_OK;
}

int pkcs11_get_slot_list(pkcs11_handle * handle, int has_token, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR slot_count)
{
	CHECK_STATE_LESS(handle, PKCS11_STATE_INITIALIZED);

	handle->pkcs_error = handle->func_list->C_GetSlotList(has_token, slot_list, slot_count);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_get_slot_info(pkcs11_handle * handle, CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	CHECK_STATE_LESS(handle, PKCS11_STATE_INITIALIZED);

	handle->pkcs_error = handle->func_list->C_GetSlotInfo(slot, info);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_get_token_info(pkcs11_handle * handle, CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	CHECK_STATE_LESS(handle, PKCS11_STATE_INITIALIZED);

	handle->pkcs_error = handle->func_list->C_GetTokenInfo(slot, info);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_open_session(pkcs11_handle * handle, CK_SLOT_ID slot, CK_FLAGS flags)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_INITIALIZED);

	handle->pkcs_error = handle->func_list->C_OpenSession(slot, flags, NULL, NULL, &handle->session);
	if (handle->pkcs_error != CKR_OK)
	{
		handle->session = 0;
		return PKCS11_ERR_PKCS11;
	}

	handle->state = PKCS11_STATE_HAS_SESSION;
	return PKCS11_OK;
}

int pkcs11_login(pkcs11_handle * handle, int user, const char * pin)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_HAS_SESSION);

	if (pin == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	size_t len = strlen(pin);
	if (len > MAX_PIN_LEN || len < MIN_PIN_LEN)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	handle->pkcs_error = handle->func_list->C_Login(handle->session, user, pin, len);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	handle->state = PKCS11_STATE_LOGGED_IN;
	return PKCS11_OK;
}

int pkcs11_generate_3des(pkcs11_handle * handle, const char * label)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN);

	if (label == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (strlen(label) > MAX_LABEL_LEN)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	CK_MECHANISM mech = {CKM_DES3_KEY_GEN};
	CK_ATTRIBUTE attrib[] =
	{
		{CKA_TOKEN,         &yes,       sizeof(CK_BBOOL)},
		{CKA_PRIVATE,       &yes,       sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,     &yes,       sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,   &no,        sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,    &no,        sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,       &yes,       sizeof(CK_BBOOL)},
		{CKA_DECRYPT,       &yes,       sizeof(CK_BBOOL)},
		{CKA_LABEL,         label,      strlen(label)}
	};

	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
	handle->pkcs_error = handle->func_list->C_GenerateKey(handle->session, &mech, attrib,
														  attribLen, &handle->last_object_handle);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_generate_aes(pkcs11_handle * handle, const char * label, size_t size)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN);

	if (label == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (strlen(label) > MAX_LABEL_LEN)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	if (size != 128 && size != 192 && size != 256)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	CK_MECHANISM mech = {CKM_AES_KEY_GEN};
	size /= 8;

	CK_ATTRIBUTE attrib[] =
	{
		{CKA_TOKEN,         &yes,       sizeof(CK_BBOOL)},
		{CKA_PRIVATE,       &yes,       sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,     &yes,       sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,   &yes,       sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,    &yes,       sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,       &yes,       sizeof(CK_BBOOL)},
		{CKA_DECRYPT,       &yes,       sizeof(CK_BBOOL)},
		{CKA_LABEL,         label,      strlen(label)},
		{CKA_VALUE_LEN,	    &size,		sizeof(size)}
	};

	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
	handle->pkcs_error = handle->func_list->C_GenerateKey(handle->session, &mech, attrib, attribLen, &handle->last_object_handle);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_generate_rsa(pkcs11_handle * handle, const char * label, CK_ULONG size, const char * expo, size_t expo_len)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN);

	if (label == NULL || expo == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (strlen(label) > MAX_LABEL_LEN || expo_len == 0 || expo_len > (4096 / 8))
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN};
	CK_UTF8CHAR pubLabel[MAX_LABEL_LEN + 20];
	CK_UTF8CHAR priLabel[MAX_LABEL_LEN + 20];
	sprintf(pubLabel, "%s" PUBLIC_OBJECT_POST_FIX, label);
	sprintf(priLabel, "%s" PRIVATE_OBJECT_POST_FIX, label);

	CK_ATTRIBUTE attribPub[] =
	{
		{CKA_TOKEN,             &yes,               sizeof(CK_BBOOL)},
		{CKA_PRIVATE,           &no,                sizeof(CK_BBOOL)},
		{CKA_VERIFY,            &yes,               sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,           &yes,               sizeof(CK_BBOOL)},
		{CKA_MODULUS_BITS,      &size,          	sizeof(CK_ULONG)},
		{CKA_PUBLIC_EXPONENT,   expo,    			expo_len}, // TODO, check reference
		{CKA_LABEL,             &pubLabel,          strlen(pubLabel)}
	};
	CK_ULONG attribLenPub = sizeof(attribPub) / sizeof(*attribPub);

	CK_ATTRIBUTE attribPri[] =
	{
		{CKA_TOKEN,             &yes,               sizeof(CK_BBOOL)},
		{CKA_PRIVATE,           &yes,               sizeof(CK_BBOOL)},
		{CKA_SIGN,              &yes,               sizeof(CK_BBOOL)},
		{CKA_DECRYPT,           &yes,               sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,         &yes,               sizeof(CK_BBOOL)},
		{CKA_LABEL,             &priLabel,          strlen(priLabel)}
	};
	CK_ULONG attribLenPri = sizeof(attribPri) / sizeof(*attribPri);

	handle->pkcs_error = handle->func_list->C_GenerateKeyPair(handle->session, &mech, attribPub, attribLenPub,
															  attribPri, attribLenPri, &handle->last_object_public, &handle->last_object_private);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_generate_ecdsa(pkcs11_handle * handle, const char * label, const char * curve, size_t size)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN);

	if (label == NULL || curve == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (strlen(label) > MAX_LABEL_LEN || size == 0 || size > 10)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	CK_MECHANISM mech = {CKM_ECDSA_KEY_PAIR_GEN};
	CK_UTF8CHAR pubLabel[MAX_LABEL_LEN + 20];
	CK_UTF8CHAR priLabel[MAX_LABEL_LEN + 20];
	sprintf(pubLabel, "%s" PUBLIC_OBJECT_POST_FIX, label);
	sprintf(priLabel, "%s" PRIVATE_OBJECT_POST_FIX, label);

	CK_ATTRIBUTE attribPub[] =
	{
		{CKA_TOKEN,             &yes,               sizeof(CK_BBOOL)},
		{CKA_PRIVATE,           &no,                sizeof(CK_BBOOL)},
		{CKA_VERIFY,            &yes,               sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,           &yes,               sizeof(CK_BBOOL)},
		{CKA_EC_PARAMS,			curve,		 		size},
		{CKA_LABEL,             &pubLabel,          strlen(pubLabel)}
	};
	CK_ULONG attribLenPub = sizeof(attribPub) / sizeof(*attribPub);

	CK_ATTRIBUTE attribPri[] =
	{
		{CKA_TOKEN,             &yes,               sizeof(CK_BBOOL)},
		{CKA_PRIVATE,           &yes,               sizeof(CK_BBOOL)},
		{CKA_SIGN,              &yes,               sizeof(CK_BBOOL)},
		{CKA_DECRYPT,           &yes,               sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,         &yes,               sizeof(CK_BBOOL)},
		{CKA_LABEL,             &priLabel,          strlen(priLabel)}
	};
	CK_ULONG attribLenPri = sizeof(attribPri) / sizeof(*attribPri);

	handle->pkcs_error = handle->func_list->C_GenerateKeyPair(handle->session, &mech, attribPub, attribLenPub, attribPri, attribLenPri,
															  &handle->last_object_public, &handle->last_object_private);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_create_data(pkcs11_handle * handle, const char * label, const char * value, size_t len)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN);

	if (label == NULL || value == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (strlen(label) > MAX_LABEL_LEN || len == 0)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	CK_OBJECT_CLASS objClass = CKO_DATA;
	CK_ATTRIBUTE attrib[] =
	{
		{CKA_CLASS,	    	&objClass,		sizeof(objClass)},
		{CKA_TOKEN,         &yes,       	sizeof(CK_BBOOL)},
		{CKA_PRIVATE,       &yes,       	sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,    &no,        	sizeof(CK_BBOOL)},
		{CKA_VALUE,	   		value,			len},
		{CKA_LABEL,         label,    		strlen(label)}
	};
	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

	handle->pkcs_error = handle->func_list->C_CreateObject(handle->session, attrib, attribLen, &handle->last_object_handle);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

/*
int seed_random(CK_SESSION_HANDLE session, CK_BYTE_PTR data_ptr, CK_ULONG size)
{
	CK_RV rv;
	rv = pkcs11->C_SeedRandom(session, data_ptr, size);
	if (rv != CKR_OK)
	{
		printf("C_SeedRandom failed: %s\n", ckr_text(rv));
		return -1;
	}

	return 0;
}

int generate_random(CK_SESSION_HANDLE session, CK_BYTE_PTR data_ptr, CK_ULONG size)
{
	CK_RV rv;
	rv = pkcs11->C_GenerateRandom(session, data_ptr, size);
	if (rv != CKR_OK)
	{
		printf("C_GenerateRandom failed: %s\n", ckr_text(rv));
		return -1;
	}

	return 0;
}
*/

void pkcs11_print_slot_info(CK_SLOT_INFO_PTR slot_info)
{
	printf("\\_ Description:      %.*s\n", sizeof(slot_info->slotDescription), slot_info->slotDescription);
	printf("\\_ Manufacture:      %.*s\n", sizeof(slot_info->manufacturerID), slot_info->manufacturerID);
	printf("\\_ Firmware Version: %u.%u\n", slot_info->firmwareVersion.major, slot_info->firmwareVersion.minor);
	printf("\\_ Hardware Version: %u.%u\n", slot_info->hardwareVersion.major, slot_info->hardwareVersion.minor);
	printf("\\_ Flags:            0x%X\n", slot_info->flags);
}

void pkcs11_print_token_info(CK_TOKEN_INFO_PTR token_info)
{
	printf("\\_ Label:            %.*s\n", sizeof(token_info->label), token_info->label);
	printf("\\_ Manufacture ID:   %.*s\n", sizeof(token_info->manufacturerID), token_info->manufacturerID);
	printf("\\_ Model:            %.*s\n", sizeof(token_info->model), token_info->model);
	printf("\\_ Firmware Version: %u.%u\n", token_info->firmwareVersion.major, token_info->firmwareVersion.minor);
	printf("\\_ Hardware Version: %u.%u\n", token_info->hardwareVersion.major, token_info->hardwareVersion.minor);
	printf("\\_ Serial Number:    %.*s\n", sizeof(token_info->serialNumber), token_info->serialNumber);
	printf("\\_ UTC Time:         %.*s\n", sizeof(token_info->utcTime), token_info->utcTime);
	printf("\\_ Flags:            0x%X\n", token_info->flags);
	printf("\\_ Session:          %lu / %lu\n", token_info->ulSessionCount, token_info->ulMaxSessionCount);
	printf("\\_ Private Memory:   %lu / %lu\n", token_info->ulFreePrivateMemory, token_info->ulTotalPrivateMemory);
	printf("\\_ Free Public:      %lu / %lu\n", token_info->ulFreePublicMemory, token_info->ulTotalPublicMemory);
	printf("\\_ Pin Length:       %lu / %lu\n", token_info->ulMinPinLen, token_info->ulMaxPinLen);
	printf("\\_ RW Session:       %lu / %lu\n", token_info->ulRwSessionCount, token_info->ulMaxRwSessionCount);
}

const char * pkcs11_pkcs11_get_last_error_str_internal(CK_RV code)
{
	if (code == CKR_OK) return "CKR_OK";
	else if (code == CKR_CANCEL) return "CKR_CANCEL";
	else if (code == CKR_HOST_MEMORY) return "CKR_HOST_MEMORY";
	else if (code == CKR_SLOT_ID_INVALID) return "CKR_SLOT_ID_INVALID";
	else if (code == CKR_GENERAL_ERROR) return "CKR_GENERAL_ERROR";
	else if (code == CKR_FUNCTION_FAILED) return "CKR_FUNCTION_FAILED";
	else if (code == CKR_ARGUMENTS_BAD) return "CKR_ARGUMENTS_BAD";
	else if (code == CKR_NO_EVENT) return "CKR_NO_EVENT";
	else if (code == CKR_NEED_TO_CREATE_THREADS) return "CKR_NEED_TO_CREATE_THREADS";
	else if (code == CKR_CANT_LOCK) return "CKR_CANT_LOCK";
	else if (code == CKR_ATTRIBUTE_READ_ONLY) return "CKR_ATTRIBUTE_READ_ONLY";
	else if (code == CKR_ATTRIBUTE_SENSITIVE) return "CKR_ATTRIBUTE_SENSITIVE";
	else if (code == CKR_ATTRIBUTE_TYPE_INVALID) return "CKR_ATTRIBUTE_TYPE_INVALID";
	else if (code == CKR_ATTRIBUTE_VALUE_INVALID) return "CKR_ATTRIBUTE_VALUE_INVALID";
	else if (code == CKR_ACTION_PROHIBITED) return "CKR_ACTION_PROHIBITED";
	else if (code == CKR_DATA_INVALID) return "CKR_DATA_INVALID";
	else if (code == CKR_DATA_LEN_RANGE) return "CKR_DATA_LEN_RANGE";
	else if (code == CKR_DEVICE_ERROR) return "CKR_DEVICE_ERROR";
	else if (code == CKR_DEVICE_MEMORY) return "CKR_DEVICE_MEMORY";
	else if (code == CKR_DEVICE_REMOVED) return "CKR_DEVICE_REMOVED";
	else if (code == CKR_ENCRYPTED_DATA_INVALID) return "CKR_ENCRYPTED_DATA_INVALID";
	else if (code == CKR_ENCRYPTED_DATA_LEN_RANGE) return "CKR_ENCRYPTED_DATA_LEN_RANGE";
	else if (code == CKR_FUNCTION_CANCELED) return "CKR_FUNCTION_CANCELED";
	else if (code == CKR_FUNCTION_NOT_PARALLEL) return "CKR_FUNCTION_NOT_PARALLEL";
	else if (code == CKR_FUNCTION_NOT_SUPPORTED) return "CKR_FUNCTION_NOT_SUPPORTED";
	else if (code == CKR_KEY_HANDLE_INVALID) return "CKR_KEY_HANDLE_INVALID";
	else if (code == CKR_KEY_SIZE_RANGE) return "CKR_KEY_SIZE_RANGE";
	else if (code == CKR_KEY_TYPE_INCONSISTENT) return "CKR_KEY_TYPE_INCONSISTENT";
	else if (code == CKR_KEY_NOT_NEEDED) return "CKR_KEY_NOT_NEEDED";
	else if (code == CKR_KEY_CHANGED) return "CKR_KEY_CHANGED";
	else if (code == CKR_KEY_NEEDED) return "CKR_KEY_NEEDED";
	else if (code == CKR_KEY_INDIGESTIBLE) return "CKR_KEY_INDIGESTIBLE";
	else if (code == CKR_KEY_FUNCTION_NOT_PERMITTED) return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	else if (code == CKR_KEY_NOT_WRAPPABLE) return "CKR_KEY_NOT_WRAPPABLE";
	else if (code == CKR_KEY_UNEXTRACTABLE) return "CKR_KEY_UNEXTRACTABLE";
	else if (code == CKR_MECHANISM_INVALID) return "CKR_MECHANISM_INVALID";
	else if (code == CKR_MECHANISM_PARAM_INVALID) return "CKR_MECHANISM_PARAM_INVALID";
	else if (code == CKR_OBJECT_HANDLE_INVALID) return "CKR_OBJECT_HANDLE_INVALID";
	else if (code == CKR_OPERATION_ACTIVE) return "CKR_OPERATION_ACTIVE";
	else if (code == CKR_OPERATION_NOT_INITIALIZED) return "CKR_OPERATION_NOT_INITIALIZED";
	else if (code == CKR_PIN_INCORRECT) return "CKR_PIN_INCORRECT";
	else if (code == CKR_PIN_INVALID) return "CKR_PIN_INVALID";
	else if (code == CKR_PIN_LEN_RANGE) return "CKR_PIN_LEN_RANGE";
	else if (code == CKR_PIN_EXPIRED) return "CKR_PIN_EXPIRED";
	else if (code == CKR_PIN_LOCKED) return "CKR_PIN_LOCKED";
	else if (code == CKR_SESSION_CLOSED) return "CKR_SESSION_CLOSED";
	else if (code == CKR_SESSION_COUNT) return "CKR_SESSION_COUNT";
	else if (code == CKR_SESSION_HANDLE_INVALID) return "CKR_SESSION_HANDLE_INVALID";
	else if (code == CKR_SESSION_PARALLEL_NOT_SUPPORTED) return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
	else if (code == CKR_SESSION_READ_ONLY) return "CKR_SESSION_READ_ONLY";
	else if (code == CKR_SESSION_EXISTS) return "CKR_SESSION_EXISTS";
	else if (code == CKR_SESSION_READ_ONLY_EXISTS) return "CKR_SESSION_READ_ONLY_EXISTS";
	else if (code == CKR_SESSION_READ_WRITE_SO_EXISTS) return "CKR_SESSION_READ_WRITE_SO_EXISTS";
	else if (code == CKR_SIGNATURE_INVALID) return "CKR_SIGNATURE_INVALID";
	else if (code == CKR_SIGNATURE_LEN_RANGE) return "CKR_SIGNATURE_LEN_RANGE";
	else if (code == CKR_TEMPLATE_INCOMPLETE) return "CKR_TEMPLATE_INCOMPLETE";
	else if (code == CKR_TEMPLATE_INCONSISTENT) return "CKR_TEMPLATE_INCONSISTENT";
	else if (code == CKR_TOKEN_NOT_PRESENT) return "CKR_TOKEN_NOT_PRESENT";
	else if (code == CKR_TOKEN_NOT_RECOGNIZED) return "CKR_TOKEN_NOT_RECOGNIZED";
	else if (code == CKR_TOKEN_WRITE_PROTECTED) return "CKR_TOKEN_WRITE_PROTECTED";
	else if (code == CKR_UNWRAPPING_KEY_HANDLE_INVALID) return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
	else if (code == CKR_UNWRAPPING_KEY_SIZE_RANGE) return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
	else if (code == CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT) return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
	else if (code == CKR_USER_ALREADY_LOGGED_IN) return "CKR_USER_ALREADY_LOGGED_IN";
	else if (code == CKR_USER_NOT_LOGGED_IN) return "CKR_USER_NOT_LOGGED_IN";
	else if (code == CKR_USER_PIN_NOT_INITIALIZED) return "CKR_USER_PIN_NOT_INITIALIZED";
	else if (code == CKR_USER_TYPE_INVALID) return "CKR_USER_TYPE_INVALID";
	else if (code == CKR_USER_ANOTHER_ALREADY_LOGGED_IN) return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	else if (code == CKR_USER_TOO_MANY_TYPES) return "CKR_USER_TOO_MANY_TYPES";
	else if (code == CKR_WRAPPED_KEY_INVALID) return "CKR_WRAPPED_KEY_INVALID";
	else if (code == CKR_WRAPPED_KEY_LEN_RANGE) return "CKR_WRAPPED_KEY_LEN_RANGE";
	else if (code == CKR_WRAPPING_KEY_HANDLE_INVALID) return "CKR_WRAPPING_KEY_HANDLE_INVALID";
	else if (code == CKR_WRAPPING_KEY_SIZE_RANGE) return "CKR_WRAPPING_KEY_SIZE_RANGE";
	else if (code == CKR_WRAPPING_KEY_TYPE_INCONSISTENT) return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
	else if (code == CKR_RANDOM_SEED_NOT_SUPPORTED) return "CKR_RANDOM_SEED_NOT_SUPPORTED";
	else if (code == CKR_RANDOM_NO_RNG) return "CKR_RANDOM_NO_RNG";
	else if (code == CKR_DOMAIN_PARAMS_INVALID) return "CKR_DOMAIN_PARAMS_INVALID";
	else if (code == CKR_BUFFER_TOO_SMALL) return "CKR_BUFFER_TOO_SMALL";
	else if (code == CKR_SAVED_STATE_INVALID) return "CKR_SAVED_STATE_INVALID";
	else if (code == CKR_INFORMATION_SENSITIVE) return "CKR_INFORMATION_SENSITIVE";
	else if (code == CKR_STATE_UNSAVEABLE) return "CKR_STATE_UNSAVEABLE";
	else if (code == CKR_CRYPTOKI_NOT_INITIALIZED) return "CKR_CRYPTOKI_NOT_INITIALIZED";
	else if (code == CKR_CRYPTOKI_ALREADY_INITIALIZED) return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
	else if (code == CKR_MUTEX_BAD) return "CKR_MUTEX_BAD";
	else if (code == CKR_MUTEX_NOT_LOCKED) return "CKR_MUTEX_NOT_LOCKED";
	else if (code == CKR_NEW_PIN_MODE) return "CKR_NEW_PIN_MODE";
	else if (code == CKR_NEXT_OTP) return "CKR_NEXT_OTP";
	else if (code == CKR_EXCEEDED_MAX_ITERATIONS) return "CKR_EXCEEDED_MAX_ITERATIONS";
	else if (code == CKR_FIPS_SELF_TEST_FAILED) return "CKR_FIPS_SELF_TEST_FAILED";
	else if (code == CKR_LIBRARY_LOAD_FAILED) return "CKR_LIBRARY_LOAD_FAILED";
	else if (code == CKR_PIN_TOO_WEAK) return "CKR_PIN_TOO_WEAK";
	else if (code == CKR_PUBLIC_KEY_INVALID) return "CKR_PUBLIC_KEY_INVALID";
	else if (code == CKR_FUNCTION_REJECTED) return "CKR_FUNCTION_REJECTED";
	else if (code & CKR_VENDOR_DEFINED) return "CKR_VENDOR_DEFINED";
	else return "CKR_UN_DEFINED";
}

const char * pkcs11_get_last_error_str(pkcs11_handle * handle)
{
	return handle == NULL ? NULL : pkcs11_pkcs11_get_last_error_str_internal(handle->pkcs_error);
}