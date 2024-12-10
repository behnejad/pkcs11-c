/*
	Creative Commons Attribution-NonCommercial-NoDerivs (CC-BY-NC-ND)
	https://creativecommons.org/licenses/by-nc-nd/4.0/
	The most restrictive creative commons license.
	This only allows people to download and share your work for no commercial gain and for no other purposes.
*/

#include "pkcs11-impl.h"

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

static void * libHandle = NULL;

static CK_BBOOL yes = CK_TRUE;
static CK_BBOOL no = CK_FALSE;

static CK_FUNCTION_LIST * pkcs11 = NULL;

const char * ckr_text(CK_RV code)
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
	else if (code == CKR_ACTION_PROHIBITED) return "CKR_?ACTION_PROHIBITED";
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

int load_library(const char * path)
{
	libHandle = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
	if (libHandle == NULL)
	{
		printf("dlopen failed\n");
		return -1;
	}

	return 0;
}

int init_pkcs_library()
{
	CK_RV rv;
	CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList) dlsym(libHandle, "C_GetFunctionList");
	rv = C_GetFunctionList(&pkcs11);
	if (rv != CKR_OK)
	{
		printf("C_GetFunctionList failed: %s\n", ckr_text(rv));
		return -1;
	}

	return 0;
}

int init_pkcs()
{
	CK_RV rv;
//	printf("%x - %x\n", pkcs11->C_Initialize, &C_Initialize);
	rv = pkcs11->C_Initialize(NULL);
	if (rv != CKR_OK)
	{
		printf("C_Initialize failed: %s\n", ckr_text(rv));
		return -1;
	}

//	printf("initialized\n");
	return 0;
}

int get_slot_count(CK_ULONG_PTR count)
{
	CK_RV rv;
	rv = pkcs11->C_GetSlotList(CK_TRUE, NULL, count);
	if (rv != CKR_OK)
	{
		printf("C_GetSlotList failed: %s\n", ckr_text(rv));
		return -1;
	}

	if (*count == 0)
	{
		printf("no slot are available\n");
		return -1;
	}

	return 0;
}

int get_slot(CK_SLOT_ID_PTR list, CK_ULONG_PTR slot_count)
{
	CK_RV rv;
	rv = pkcs11->C_GetSlotList(CK_TRUE, list, slot_count);
	if (rv != CKR_OK)
	{
		printf("C_GetSlotList failed: %s\n", ckr_text(rv));
		return -1;
	}

	return 0;
}

int get_slot_info(CK_SLOT_ID slot)
{
	CK_RV rv;
	CK_SLOT_INFO slot_info;

	printf("available slot: %lu - 0x%X\n", slot, slot);
	rv = pkcs11->C_GetSlotInfo(slot, &slot_info);
	if (rv != CKR_OK)
	{
		printf("C_GetSlotInfo %lu failed %s\n", slot, ckr_text(rv));
	}
	else
	{
		printf("\\_ Description:      %.*s\n", sizeof(slot_info.slotDescription), slot_info.slotDescription);
		printf("\\_ Manufacture:      %.*s\n", sizeof(slot_info.manufacturerID), slot_info.manufacturerID);
		printf("\\_ Firmware Version: %u.%u\n", slot_info.firmwareVersion.major, slot_info.firmwareVersion.minor);
		printf("\\_ Hardware Version: %u.%u\n", slot_info.hardwareVersion.major, slot_info.hardwareVersion.minor);
		printf("\\_ Flags:            0x%X\n", slot_info.flags);
	}

	CK_TOKEN_INFO token_nfo;
	rv = pkcs11->C_GetTokenInfo(slot, &token_nfo);
	if (rv != CKR_OK)
	{
		printf("C_GetTokenInfo %lu failed %s\n", slot, ckr_text(rv));
	}
	else
	{
		printf("\\____\n");
		printf("\\_ Label:            %.*s\n", sizeof(token_nfo.label), token_nfo.label);
		printf("\\_ Manufacture ID:   %.*s\n", sizeof(token_nfo.manufacturerID), token_nfo.manufacturerID);
		printf("\\_ Model:            %.*s\n", sizeof(token_nfo.model), token_nfo.model);
		printf("\\_ Firmware Version: %u.%u\n", token_nfo.firmwareVersion.major, token_nfo.firmwareVersion.minor);
		printf("\\_ Hardware Version: %u.%u\n", token_nfo.hardwareVersion.major, token_nfo.hardwareVersion.minor);
		printf("\\_ Serial Number:    %.*s\n", sizeof(token_nfo.serialNumber), token_nfo.serialNumber);
		printf("\\_ UTC Time:         %.*s\n", sizeof(token_nfo.utcTime), token_nfo.utcTime);
		printf("\\_ Flags:            0x%X\n", token_nfo.flags);
		printf("\\_ Session:          %lu / %lu\n", token_nfo.ulSessionCount, token_nfo.ulMaxSessionCount);
		printf("\\_ Private Memory:   %lu / %lu\n", token_nfo.ulFreePrivateMemory, token_nfo.ulTotalPrivateMemory);
		printf("\\_ Free Public:      %lu / %lu\n", token_nfo.ulFreePublicMemory, token_nfo.ulTotalPublicMemory);
		printf("\\_ Pin Length:       %lu / %lu\n", token_nfo.ulMinPinLen, token_nfo.ulMaxPinLen);
		printf("\\_ RW Session:       %lu / %lu\n", token_nfo.ulRwSessionCount, token_nfo.ulMaxRwSessionCount);
	}

	printf("\n");

	return 0;
}

int open_session(CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR session)
{
	CK_RV rv;
	rv = pkcs11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, session);
	if (rv != CKR_OK)
	{
		printf("C_OpenSession failed: %s\n", ckr_text(rv));
		return -1;
	}

	printf("Session id: %lu\n", *session);
	return 0;
}

int login(CK_SESSION_HANDLE session, int user, const char * pin)
{
	CK_RV rv;
	rv = pkcs11->C_Login(session, user, pin, strlen(pin));
	if (rv != CKR_OK)
	{
		printf("C_Login failed: %s\n", ckr_text(rv));
		return -1;
	}

//	printf("logged in\n");
	return 0;
}

int logout(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	rv = pkcs11->C_Logout(session);
	if (rv != CKR_OK)
	{
		printf("C_Logout failed: %s\n", ckr_text(rv));
		return -1;
	}

//	printf("logged out\n");
	return 0;
}

int close_session(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	rv = pkcs11->C_CloseSession(session);
	if (rv != CKR_OK)
	{
		printf("C_CloseSession failed: %s\n", ckr_text(rv));
		return -1;
	}

//	printf("session closed %lu\n", session);
	return 0;
}

int finalize()
{
	CK_RV rv;
	rv = pkcs11->C_Finalize(NULL);
	if (rv != CKR_OK)
	{
		printf("C_Finalize failed: %s\n", ckr_text(rv));
		return -1;
	}

//	printf("finalized\n");
	return 0;
}

int unload_library()
{
	if (libHandle != NULL)
	{
		if (dlclose(libHandle) != 0)
		{
			printf("dlclose failed: %d - %s\n", errno, strerror(errno));
			return -1;
		}
	}

	return 0;
}

int generate_3des(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_OBJECT_HANDLE_PTR objHandle)
{
	CK_RV rv;
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
	rv = pkcs11->C_GenerateKey(session, &mech, attrib, attribLen, objHandle);
	if (rv != CKR_OK)
	{
		printf("C_GenerateKey failed: %s\n", ckr_text(rv));
		return -1;
	}

	printf("%s 3des key handle: %lu\n", label, *objHandle);
	return 0;
}

int generate_aes(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_ULONG size, CK_OBJECT_HANDLE_PTR objHandle)
{
	CK_RV rv;
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
	rv = pkcs11->C_GenerateKey(session, &mech, attrib, attribLen, objHandle);
	if (rv != CKR_OK)
	{
		printf("C_GenerateKey failed: %s\n", ckr_text(rv));
		return -1;
	}

	printf("%s aes key handle: %lu\n", label, *objHandle);
	return 0;
}

int generate_rsa(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_ULONG size,
				 CK_OBJECT_HANDLE_PTR objPubHndl, CK_OBJECT_HANDLE_PTR objPriHandle)
{
	CK_RV rv;
	CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN};
	CK_BYTE publicExponent[] = {0x01, 0x00, 0x00, 0x00, 0x01}; //public exponent - 65537
	CK_UTF8CHAR pubLabel[150];
	CK_UTF8CHAR priLabel[150];
	sprintf(pubLabel, "%s_pub", label);
	sprintf(priLabel, "%s_prv", label);

	CK_ATTRIBUTE attribPub[] =
	{
		{CKA_TOKEN,             &yes,               sizeof(CK_BBOOL)},
		{CKA_PRIVATE,           &no,                sizeof(CK_BBOOL)},
		{CKA_VERIFY,            &yes,               sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,           &yes,               sizeof(CK_BBOOL)},
		{CKA_MODULUS_BITS,      &size,          	sizeof(CK_ULONG)},
		{CKA_PUBLIC_EXPONENT,   &publicExponent,    sizeof(publicExponent)},
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

	rv = pkcs11->C_GenerateKeyPair(session, &mech, attribPub, attribLenPub,
								   attribPri, attribLenPri, objPubHndl, objPriHandle);
	if (rv != CKR_OK)
	{
		printf("C_GenerateKeyPair failed: %s\n", ckr_text(rv));
		return -1;
	}

	printf("%s rsa public key handle: %lu\n", label, *objPubHndl);
	printf("%s rsa private key handle: %lu\n", label, *objPriHandle);
	return 0;
}

int generate_ecdsa(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_BYTE_PTR curve, CK_ULONG size,
				   CK_OBJECT_HANDLE_PTR objPubHndl, CK_OBJECT_HANDLE_PTR objPriHandle)
{
	CK_RV rv;
	CK_MECHANISM mech = {CKM_ECDSA_KEY_PAIR_GEN};
	CK_UTF8CHAR pubLabel[150];
	CK_UTF8CHAR priLabel[150];
	sprintf(pubLabel, "%s_pub", label);
	sprintf(priLabel, "%s_prv", label);

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

	rv = pkcs11->C_GenerateKeyPair(session, &mech, attribPub, attribLenPub, attribPri,
								   attribLenPri, objPubHndl, objPriHandle);
	if (rv != CKR_OK)
	{
		printf("C_GenerateKeyPair failed: %s\n", ckr_text(rv));
		return -1;
	}

	printf("%s ecdsa public key handle: %lu\n", label, *objPubHndl);
	printf("%s ecdsa private key handle: %lu\n", label, *objPriHandle);
	return 0;
}

int create_data(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_UTF8CHAR_PTR value, CK_OBJECT_HANDLE_PTR objHandle)
{
	CK_RV rv;
	CK_UTF8CHAR data_label[150];
	sprintf(data_label, "%s_data", label);
	CK_OBJECT_CLASS objClass = CKO_DATA;

	CK_ATTRIBUTE attrib[] =
	{
		{CKA_CLASS,	    	&objClass,		sizeof(objClass)},
		{CKA_TOKEN,         &yes,       	sizeof(CK_BBOOL)},
		{CKA_PRIVATE,       &yes,       	sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,    &no,        	sizeof(CK_BBOOL)},
		{CKA_VALUE,	   		value,			strlen(value)},
		{CKA_LABEL,         &data_label,    strlen(data_label)}
	};
	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

	rv = pkcs11->C_CreateObject(session, attrib, attribLen, objHandle);
	if (rv != CKR_OK)
	{
		printf("C_CreateObject failed: %s\n", ckr_text(rv));
		return -1;
	}

	printf("%s data handle: %lu\n", label, *objHandle);
	return 0;
}

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
