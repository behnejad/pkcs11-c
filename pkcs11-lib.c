/*
	Creative Commons Attribution-NonCommercial-NoDerivs (CC-BY-NC-ND)
	https://creativecommons.org/licenses/by-nc-nd/4.0/
	The most restrictive creative commons license.
	This only allows people to download and share your work for no commercial gain and for no other purposes.
*/

#include "pkcs11-lib.h"
#include "pkcs11.h"

CK_RV C_Initialize(void * init_args)
{
	return CKR_GENERAL_ERROR;
}

CK_RV C_Finalize(void * pReserved)
{
	return CKR_GENERAL_ERROR;
}

CK_RV C_GetInfo(CK_INFO_PTR info)
{
	return CKR_GENERAL_ERROR;
}

CK_RV C_GetSlotList(unsigned char token_present, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR ulCount)
{
	return CKR_GENERAL_ERROR;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR info)
{
	return CKR_GENERAL_ERROR;
}

static CK_FUNCTION_LIST handlers = {
	.version = {0, 1},
	.C_Initialize = C_Initialize,
	.C_Finalize = C_Finalize,
	.C_GetInfo = C_GetInfo,
	.C_GetFunctionList = C_GetFunctionList,
	.C_GetSlotList = C_GetSlotList,
	.C_GetSlotInfo = C_GetSlotInfo,
	.C_GetTokenInfo = NULL,
	.C_GetMechanismList = NULL,
	.C_GetMechanismInfo = NULL,
	.C_InitToken = NULL,
	.C_InitPIN = NULL,
	.C_SetPIN = NULL,
	.C_OpenSession = NULL,
	.C_CloseSession = NULL,
	.C_CloseAllSessions = NULL,
	.C_GetSessionInfo = NULL,
	.C_GetOperationState = NULL,
	.C_SetOperationState = NULL,
	.C_Login = NULL,
	.C_Logout = NULL,
	.C_CreateObject = NULL,
	.C_CopyObject = NULL,
	.C_DestroyObject = NULL,
	.C_GetObjectSize = NULL,
	.C_GetAttributeValue = NULL,
	.C_SetAttributeValue = NULL,
	.C_FindObjectsInit = NULL,
	.C_FindObjects = NULL,
	.C_FindObjectsFinal = NULL,
	.C_EncryptInit = NULL,
	.C_Encrypt = NULL,
	.C_EncryptUpdate = NULL,
	.C_EncryptFinal = NULL,
	.C_DecryptInit = NULL,
	.C_Decrypt = NULL,
	.C_DecryptUpdate = NULL,
	.C_DecryptFinal = NULL,
	.C_DigestInit = NULL,
	.C_Digest = NULL,
	.C_DigestUpdate = NULL,
	.C_DigestKey = NULL,
	.C_DigestFinal = NULL,
	.C_SignInit = NULL,
	.C_Sign = NULL,
	.C_SignUpdate = NULL,
	.C_SignFinal = NULL,
	.C_SignRecoverInit = NULL,
	.C_SignRecover = NULL,
	.C_VerifyInit = NULL,
	.C_Verify = NULL,
	.C_VerifyUpdate = NULL,
	.C_VerifyFinal = NULL,
	.C_VerifyRecoverInit = NULL,
	.C_VerifyRecover = NULL,
	.C_DigestEncryptUpdate = NULL,
	.C_DecryptDigestUpdate = NULL,
	.C_SignEncryptUpdate = NULL,
	.C_DecryptVerifyUpdate = NULL,
	.C_GenerateKey = NULL,
	.C_GenerateKeyPair = NULL,
	.C_WrapKey = NULL,
	.C_UnwrapKey = NULL,
	.C_DeriveKey = NULL,
	.C_SeedRandom = NULL,
	.C_GenerateRandom = NULL,
	.C_GetFunctionStatus = NULL,
	.C_CancelFunction = NULL,
	.C_WaitForSlotEvent = NULL,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list)
{
	if (list == NULL)
	{
		return CKR_GENERAL_ERROR;
	}

	*list = &handlers;
	return CKR_OK;
}
