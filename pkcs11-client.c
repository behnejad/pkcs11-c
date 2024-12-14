/*
	Creative Commons Attribution-NonCommercial-NoDerivs (CC-BY-NC-ND)
	https://creativecommons.org/licenses/by-nc-nd/4.0/
	The most restrictive creative commons license.
	This only allows people to download and share your work for no commercial gain and for no other purposes.
*/

#include "pkcs11-client.h"
#include "pkcs11-util.h"

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
	int last_digest_mech;
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

int pkcs11_seed_random(pkcs11_handle * handle, char * buffer, size_t size)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN);

	if (buffer == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (size == 0)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	handle->pkcs_error = handle->func_list->C_SeedRandom(handle->session, buffer, size);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_generate_random(pkcs11_handle * handle, char * buffer, size_t size)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN);

	if (buffer == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (size == 0)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	handle->pkcs_error = handle->func_list->C_GenerateRandom(handle->session, buffer, size);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_digest(pkcs11_handle * handle, int mode,
				  const char * buffer, size_t buffer_size,
				  char * out, size_t * out_size)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN); // TODO, check for login required

	if (buffer == NULL)
	{
		return PKCS11_ERR_NULL_PTR;
	}

	if (buffer_size == 0)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	if (out_size == NULL)
	{
		return PKCS11_ERR_WRONG_LEN;
	}

	CK_MECHANISM mech = {mode};
	handle->pkcs_error = handle->func_list->C_DigestInit(handle->session, &mech);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	handle->pkcs_error = handle->func_list->C_Digest(handle->session, buffer, buffer_size, out, out_size);
	if (handle->pkcs_error != CKR_OK)
	{
		return PKCS11_ERR_PKCS11;
	}

	return PKCS11_OK;
}

int pkcs11_digest_parted(pkcs11_handle * handle, int mode, int state, char * buffer, size_t * size)
{
	CHECK_STATE_FIX(handle, PKCS11_STATE_LOGGED_IN); // TODO, check for login required

	if (state < PKCS11_START || state > PKCS11_FINISH)
	{
		return PKCS11_ERR_WRONG_STATE;
	}

	if (state == PKCS11_START)
	{
		CK_MECHANISM mech = {mode};
		handle->pkcs_error = handle->func_list->C_DigestInit(handle->session, &mech);
		if (handle->pkcs_error != CKR_OK)
		{
			return PKCS11_ERR_PKCS11;
		}

		handle->last_digest_mech = mode;
	}
	else if (handle->last_digest_mech != mode)
	{
		return PKCS11_ERR_WRONG_PARAMETER;
	}
	else if (state == PKCS11_UPDATE)
	{
		if (buffer == NULL || size == NULL)
		{
			return PKCS11_ERR_NULL_PTR;
		}

		if (*size == 0)
		{
			return PKCS11_ERR_WRONG_LEN;
		}

		handle->pkcs_error = handle->func_list->C_DigestUpdate(handle->session, buffer, *size);
		if (handle->pkcs_error != CKR_OK)
		{
			return PKCS11_ERR_PKCS11;
		}
	}
	else // if (state == PKCS11_FINISH)
	{
		if (size == NULL)
		{
			return PKCS11_ERR_NULL_PTR;
		}

		handle->pkcs_error = handle->func_list->C_DigestFinal(handle->session, buffer, size);
		if (handle->pkcs_error != CKR_OK)
		{
			return PKCS11_ERR_PKCS11;
		}

		if (buffer != NULL)
		{
			handle->last_digest_mech = 0;
		}
	}

	return PKCS11_OK;
}

const char * pkcs11_get_last_error_str(pkcs11_handle * handle)
{
	return handle == NULL ? NULL : pkcs11_ckr_to_str(handle->pkcs_error);
}