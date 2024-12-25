/*
	Creative Commons Attribution-NonCommercial-NoDerivs (CC-BY-NC-ND)
	https://creativecommons.org/licenses/by-nc-nd/4.0/
	The most restrictive creative commons license.
	This only allows people to download and share your work for no commercial gain and for no other purposes.
*/

//
// Created by hooman on 12/14/24.
//

#include "pkcs11-util.h"

#include <stdio.h>
#include <stdlib.h>

const char * pkcs11_ckr_to_str(CK_RV code)
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

void pkcs11_print_slot_info(CK_SLOT_INFO_PTR slot_info)
{
	printf("\\_ Description:      %.*s\n", sizeof(slot_info->slotDescription), slot_info->slotDescription);
	printf("\\_ Manufacture:      %.*s\n", sizeof(slot_info->manufacturerID), slot_info->manufacturerID);
	printf("\\_ Firmware Version: %u.%u\n", slot_info->firmwareVersion.major, slot_info->firmwareVersion.minor);
	printf("\\_ Hardware Version: %u.%u\n", slot_info->hardwareVersion.major, slot_info->hardwareVersion.minor);
	printf("\\_ Flags:            0x%X\n", slot_info->flags);
	pkcs11_print_slot_flags(slot_info->flags);
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
	pkcs11_print_token_flags(token_info->flags);
	printf("\\_ Session:          %lu / %lu\n", token_info->ulSessionCount, token_info->ulMaxSessionCount);
	printf("\\_ Private Memory:   %lu / %lu\n", token_info->ulFreePrivateMemory, token_info->ulTotalPrivateMemory);
	printf("\\_ Free Public:      %lu / %lu\n", token_info->ulFreePublicMemory, token_info->ulTotalPublicMemory);
	printf("\\_ Pin Length:       %lu / %lu\n", token_info->ulMinPinLen, token_info->ulMaxPinLen);
	printf("\\_ RW Session:       %lu / %lu\n", token_info->ulRwSessionCount, token_info->ulMaxRwSessionCount);
}

void pkcs11_print_slot_flags(CK_FLAGS flags)
{
	if (flags & CKF_TOKEN_PRESENT) printf("\\__ CKF_TOKEN_PRESENT\n");
	if (flags & CKF_REMOVABLE_DEVICE) printf("\\__ CKF_REMOVABLE_DEVICE\n");
	if (flags & CKF_HW_SLOT) printf("\\__ CKF_HW_SLOT\n");
	if (flags & CKF_ARRAY_ATTRIBUTE) printf("\\__ CKF_ARRAY_ATTRIBUTE\n");
}

void pkcs11_print_token_flags(CK_FLAGS flags)
{
	if (flags & CKF_RNG) printf("\\__ CKF_RNG\n");
	if (flags & CKF_WRITE_PROTECTED) printf("\\__ CKF_WRITE_PROTECTED\n");
	if (flags & CKF_LOGIN_REQUIRED) printf("\\__ CKF_LOGIN_REQUIRED\n");
	if (flags & CKF_USER_PIN_INITIALIZED) printf("\\__ CKF_USER_PIN_INITIALIZED\n");
	if (flags & CKF_RESTORE_KEY_NOT_NEEDED) printf("\\__ CKF_RESTORE_KEY_NOT_NEEDED\n");
	if (flags & CKF_CLOCK_ON_TOKEN) printf("\\__ CKF_CLOCK_ON_TOKEN\n");
	if (flags & CKF_PROTECTED_AUTHENTICATION_PATH) printf("\\__ CKF_PROTECTED_AUTHENTICATION_PATH\n");
	if (flags & CKF_DUAL_CRYPTO_OPERATIONS) printf("\\__ CKF_DUAL_CRYPTO_OPERATIONS\n");
	if (flags & CKF_TOKEN_INITIALIZED) printf("\\__ CKF_TOKEN_INITIALIZED\n");
	if (flags & CKF_SECONDARY_AUTHENTICATION) printf("\\__ CKF_SECONDARY_AUTHENTICATION\n");
	if (flags & CKF_USER_PIN_COUNT_LOW) printf("\\__ CKF_USER_PIN_COUNT_LOW\n");
	if (flags & CKF_USER_PIN_FINAL_TRY) printf("\\__ CKF_USER_PIN_FINAL_TRY\n");
	if (flags & CKF_USER_PIN_LOCKED) printf("\\__ CKF_USER_PIN_LOCKED\n");
	if (flags & CKF_USER_PIN_TO_BE_CHANGED) printf("\\__ CKF_USER_PIN_TO_BE_CHANGED\n");
	if (flags & CKF_SO_PIN_COUNT_LOW) printf("\\__ CKF_SO_PIN_COUNT_LOW\n");
	if (flags & CKF_SO_PIN_FINAL_TRY) printf("\\__ CKF_SO_PIN_FINAL_TRY\n");
	if (flags & CKF_SO_PIN_LOCKED) printf("\\__ CKF_SO_PIN_LOCKED\n");
	if (flags & CKF_SO_PIN_TO_BE_CHANGED) printf("\\__ CKF_SO_PIN_TO_BE_CHANGED\n");
}

void pkcs11_print_session_flags(CK_FLAGS flags)
{
	if (flags & CKF_RW_SESSION) printf("\\__ CKF_RW_SESSION\n");
	if (flags & CKF_SERIAL_SESSION) printf("\\__ CKF_SERIAL_SESSION\n");
}

void pkcs11_print_otp_flags(CK_FLAGS flags)
{
	if (flags & CKF_NEXT_OTP) printf("\\__ CKF_NEXT_OTP\n");
	if (flags & CKF_EXCLUDE_TIME) printf("\\__ CKF_EXCLUDE_TIME\n");
	if (flags & CKF_EXCLUDE_COUNTER) printf("\\__ CKF_EXCLUDE_COUNTER\n");
	if (flags & CKF_EXCLUDE_CHALLENGE) printf("\\__ CKF_EXCLUDE_CHALLENGE\n");
	if (flags & CKF_EXCLUDE_PIN) printf("\\__ CKF_EXCLUDE_PIN\n");
	if (flags & CKF_USER_FRIENDLY_OTP) printf("\\__ CKF_USER_FRIENDLY_OTP\n");
}

void pkcs11_print_flags(CK_FLAGS flags)
{
	if (flags & CKF_HW) printf("\\___ CKF_HW\n");
	if (flags & CKF_ENCRYPT) printf("\\___ CKF_ENCRYPT\n");
	if (flags & CKF_DECRYPT) printf("\\___ CKF_DECRYPT\n");
	if (flags & CKF_DIGEST) printf("\\___ CKF_DIGEST\n");
	if (flags & CKF_SIGN) printf("\\___ CKF_SIGN\n");
	if (flags & CKF_SIGN_RECOVER) printf("\\___ CKF_SIGN_RECOVER\n");
	if (flags & CKF_VERIFY) printf("\\___ CKF_VERIFY\n");
	if (flags & CKF_VERIFY_RECOVER) printf("\\___ CKF_VERIFY_RECOVER\n");
	if (flags & CKF_GENERATE) printf("\\___ CKF_GENERATE\n");
	if (flags & CKF_GENERATE_KEY_PAIR) printf("\\___ CKF_GENERATE_KEY_PAIR\n");
	if (flags & CKF_WRAP) printf("\\___ CKF_WRAP\n");
	if (flags & CKF_UNWRAP) printf("\\___ CKF_UNWRAP\n");
	if (flags & CKF_DERIVE) printf("\\___ CKF_DERIVE\n");
	if (flags & CKF_EXTENSION) printf("\\___ CKF_EXTENSION\n");
	if (flags & CKF_EC_F_P) printf("\\___ CKF_EC_F_P\n");
	if (flags & CKF_EC_NAMEDCURVE) printf("\\___ CKF_EC_NAMEDCURVE\n");
	if (flags & CKF_EC_UNCOMPRESS) printf("\\___ CKF_EC_UNCOMPRESS\n");
	if (flags & CKF_EC_COMPRESS) printf("\\___ CKF_EC_COMPRESS\n");
}

void pkcs11_print_mechanism(CK_MECHANISM_TYPE mech_type)
{
	if (mech_type == CKM_RSA_PKCS_KEY_PAIR_GEN) printf("\\__ CKM_RSA_PKCS_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_RSA_PKCS) printf("\\__ CKM_RSA_PKCS\n");
	else if (mech_type == CKM_RSA_9796) printf("\\__ CKM_RSA_9796\n");
	else if (mech_type == CKM_RSA_X_509) printf("\\__ CKM_RSA_X_509\n");
	else if (mech_type == CKM_MD2_RSA_PKCS) printf("\\__ CKM_MD2_RSA_PKCS\n");
	else if (mech_type == CKM_MD5_RSA_PKCS) printf("\\__ CKM_MD5_RSA_PKCS\n");
	else if (mech_type == CKM_SHA1_RSA_PKCS) printf("\\__ CKM_SHA1_RSA_PKCS\n");
	else if (mech_type == CKM_RIPEMD128_RSA_PKCS) printf("\\__ CKM_RIPEMD128_RSA_PKCS\n");
	else if (mech_type == CKM_RIPEMD160_RSA_PKCS) printf("\\__ CKM_RIPEMD160_RSA_PKCS\n");
	else if (mech_type == CKM_RSA_PKCS_OAEP) printf("\\__ CKM_RSA_PKCS_OAEP\n");
	else if (mech_type == CKM_RSA_X9_31_KEY_PAIR_GEN) printf("\\__ CKM_RSA_X9_31_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_RSA_X9_31) printf("\\__ CKM_RSA_X9_31\n");
	else if (mech_type == CKM_SHA1_RSA_X9_31) printf("\\__ CKM_SHA1_RSA_X9_31\n");
	else if (mech_type == CKM_RSA_PKCS_PSS) printf("\\__ CKM_RSA_PKCS_PSS\n");
	else if (mech_type == CKM_SHA1_RSA_PKCS_PSS) printf("\\__ CKM_SHA1_RSA_PKCS_PSS\n");
	else if (mech_type == CKM_DSA_KEY_PAIR_GEN) printf("\\__ CKM_DSA_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_DSA) printf("\\__ CKM_DSA\n");
	else if (mech_type == CKM_DSA_SHA1) printf("\\__ CKM_DSA_SHA1\n");
	else if (mech_type == CKM_DSA_SHA224) printf("\\__ CKM_DSA_SHA224\n");
	else if (mech_type == CKM_DSA_SHA256) printf("\\__ CKM_DSA_SHA256\n");
	else if (mech_type == CKM_DSA_SHA384) printf("\\__ CKM_DSA_SHA384\n");
	else if (mech_type == CKM_DSA_SHA512) printf("\\__ CKM_DSA_SHA512\n");
	else if (mech_type == CKM_DH_PKCS_KEY_PAIR_GEN) printf("\\__ CKM_DH_PKCS_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_DH_PKCS_DERIVE) printf("\\__ CKM_DH_PKCS_DERIVE\n");
	else if (mech_type == CKM_X9_42_DH_KEY_PAIR_GEN) printf("\\__ CKM_X9_42_DH_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_X9_42_DH_DERIVE) printf("\\__ CKM_X9_42_DH_DERIVE\n");
	else if (mech_type == CKM_X9_42_DH_HYBRID_DERIVE) printf("\\__ CKM_X9_42_DH_HYBRID_DERIVE\n");
	else if (mech_type == CKM_X9_42_MQV_DERIVE) printf("\\__ CKM_X9_42_MQV_DERIVE\n");
	else if (mech_type == CKM_SHA256_RSA_PKCS) printf("\\__ CKM_SHA256_RSA_PKCS\n");
	else if (mech_type == CKM_SHA384_RSA_PKCS) printf("\\__ CKM_SHA384_RSA_PKCS\n");
	else if (mech_type == CKM_SHA512_RSA_PKCS) printf("\\__ CKM_SHA512_RSA_PKCS\n");
	else if (mech_type == CKM_SHA256_RSA_PKCS_PSS) printf("\\__ CKM_SHA256_RSA_PKCS_PSS\n");
	else if (mech_type == CKM_SHA384_RSA_PKCS_PSS) printf("\\__ CKM_SHA384_RSA_PKCS_PSS\n");
	else if (mech_type == CKM_SHA512_RSA_PKCS_PSS) printf("\\__ CKM_SHA512_RSA_PKCS_PSS\n");
	else if (mech_type == CKM_SHA512_224) printf("\\__ CKM_SHA512_224\n");
	else if (mech_type == CKM_SHA512_224_HMAC) printf("\\__ CKM_SHA512_224_HMAC\n");
	else if (mech_type == CKM_SHA512_224_HMAC_GENERAL) printf("\\__ CKM_SHA512_224_HMAC_GENERAL\n");
	else if (mech_type == CKM_SHA512_224_KEY_DERIVATION) printf("\\__ CKM_SHA512_224_KEY_DERIVATION\n");
	else if (mech_type == CKM_SHA512_256) printf("\\__ CKM_SHA512_256\n");
	else if (mech_type == CKM_SHA512_256_HMAC) printf("\\__ CKM_SHA512_256_HMAC\n");
	else if (mech_type == CKM_SHA512_256_HMAC_GENERAL) printf("\\__ CKM_SHA512_256_HMAC_GENERAL\n");
	else if (mech_type == CKM_SHA512_256_KEY_DERIVATION) printf("\\__ CKM_SHA512_256_KEY_DERIVATION\n");
	else if (mech_type == CKM_SHA512_T) printf("\\__ CKM_SHA512_T\n");
	else if (mech_type == CKM_SHA512_T_HMAC) printf("\\__ CKM_SHA512_T_HMAC\n");
	else if (mech_type == CKM_SHA512_T_HMAC_GENERAL) printf("\\__ CKM_SHA512_T_HMAC_GENERAL\n");
	else if (mech_type == CKM_SHA512_T_KEY_DERIVATION) printf("\\__ CKM_SHA512_T_KEY_DERIVATION\n");
	else if (mech_type == CKM_RC2_KEY_GEN) printf("\\__ CKM_RC2_KEY_GEN\n");
	else if (mech_type == CKM_RC2_ECB) printf("\\__ CKM_RC2_ECB\n");
	else if (mech_type == CKM_RC2_CBC) printf("\\__ CKM_RC2_CBC\n");
	else if (mech_type == CKM_RC2_MAC) printf("\\__ CKM_RC2_MAC\n");
	else if (mech_type == CKM_RC2_MAC_GENERAL) printf("\\__ CKM_RC2_MAC_GENERAL\n");
	else if (mech_type == CKM_RC2_CBC_PAD) printf("\\__ CKM_RC2_CBC_PAD\n");
	else if (mech_type == CKM_RC4_KEY_GEN) printf("\\__ CKM_RC4_KEY_GEN\n");
	else if (mech_type == CKM_RC4) printf("\\__ CKM_RC4\n");
	else if (mech_type == CKM_DES_KEY_GEN) printf("\\__ CKM_DES_KEY_GEN\n");
	else if (mech_type == CKM_DES_ECB) printf("\\__ CKM_DES_ECB\n");
	else if (mech_type == CKM_DES_CBC) printf("\\__ CKM_DES_CBC\n");
	else if (mech_type == CKM_DES_MAC) printf("\\__ CKM_DES_MAC\n");
	else if (mech_type == CKM_DES_MAC_GENERAL) printf("\\__ CKM_DES_MAC_GENERAL\n");
	else if (mech_type == CKM_DES_CBC_PAD) printf("\\__ CKM_DES_CBC_PAD\n");
	else if (mech_type == CKM_DES2_KEY_GEN) printf("\\__ CKM_DES2_KEY_GEN\n");
	else if (mech_type == CKM_DES3_KEY_GEN) printf("\\__ CKM_DES3_KEY_GEN\n");
	else if (mech_type == CKM_DES3_ECB) printf("\\__ CKM_DES3_ECB\n");
	else if (mech_type == CKM_DES3_CBC) printf("\\__ CKM_DES3_CBC\n");
	else if (mech_type == CKM_DES3_MAC) printf("\\__ CKM_DES3_MAC\n");
	else if (mech_type == CKM_DES3_MAC_GENERAL) printf("\\__ CKM_DES3_MAC_GENERAL\n");
	else if (mech_type == CKM_DES3_CBC_PAD) printf("\\__ CKM_DES3_CBC_PAD\n");
	else if (mech_type == CKM_DES3_CMAC_GENERAL) printf("\\__ CKM_DES3_CMAC_GENERAL\n");
	else if (mech_type == CKM_DES3_CMAC) printf("\\__ CKM_DES3_CMAC\n");
	else if (mech_type == CKM_CDMF_KEY_GEN) printf("\\__ CKM_CDMF_KEY_GEN\n");
	else if (mech_type == CKM_CDMF_ECB) printf("\\__ CKM_CDMF_ECB\n");
	else if (mech_type == CKM_CDMF_CBC) printf("\\__ CKM_CDMF_CBC\n");
	else if (mech_type == CKM_CDMF_MAC) printf("\\__ CKM_CDMF_MAC\n");
	else if (mech_type == CKM_CDMF_MAC_GENERAL) printf("\\__ CKM_CDMF_MAC_GENERAL\n");
	else if (mech_type == CKM_CDMF_CBC_PAD) printf("\\__ CKM_CDMF_CBC_PAD\n");
	else if (mech_type == CKM_DES_OFB64) printf("\\__ CKM_DES_OFB64\n");
	else if (mech_type == CKM_DES_OFB8) printf("\\__ CKM_DES_OFB8\n");
	else if (mech_type == CKM_DES_CFB64) printf("\\__ CKM_DES_CFB64\n");
	else if (mech_type == CKM_DES_CFB8) printf("\\__ CKM_DES_CFB8\n");
	else if (mech_type == CKM_MD2) printf("\\__ CKM_MD2\n");
	else if (mech_type == CKM_MD2_HMAC) printf("\\__ CKM_MD2_HMAC\n");
	else if (mech_type == CKM_MD2_HMAC_GENERAL) printf("\\__ CKM_MD2_HMAC_GENERAL\n");
	else if (mech_type == CKM_MD5) printf("\\__ CKM_MD5\n");
	else if (mech_type == CKM_MD5_HMAC) printf("\\__ CKM_MD5_HMAC\n");
	else if (mech_type == CKM_MD5_HMAC_GENERAL) printf("\\__ CKM_MD5_HMAC_GENERAL\n");
	else if (mech_type == CKM_SHA_1) printf("\\__ CKM_SHA_1\n");
	else if (mech_type == CKM_SHA_1_HMAC) printf("\\__ CKM_SHA_1_HMAC\n");
	else if (mech_type == CKM_SHA_1_HMAC_GENERAL) printf("\\__ CKM_SHA_1_HMAC_GENERAL\n");
	else if (mech_type == CKM_RIPEMD128) printf("\\__ CKM_RIPEMD128\n");
	else if (mech_type == CKM_RIPEMD128_HMAC) printf("\\__ CKM_RIPEMD128_HMAC\n");
	else if (mech_type == CKM_RIPEMD128_HMAC_GENERAL) printf("\\__ CKM_RIPEMD128_HMAC_GENERAL\n");
	else if (mech_type == CKM_RIPEMD160) printf("\\__ CKM_RIPEMD160\n");
	else if (mech_type == CKM_RIPEMD160_HMAC) printf("\\__ CKM_RIPEMD160_HMAC\n");
	else if (mech_type == CKM_RIPEMD160_HMAC_GENERAL) printf("\\__ CKM_RIPEMD160_HMAC_GENERAL\n");
	else if (mech_type == CKM_SHA256) printf("\\__ CKM_SHA256\n");
	else if (mech_type == CKM_SHA256_HMAC) printf("\\__ CKM_SHA256_HMAC\n");
	else if (mech_type == CKM_SHA256_HMAC_GENERAL) printf("\\__ CKM_SHA256_HMAC_GENERAL\n");
	else if (mech_type == CKM_SHA384) printf("\\__ CKM_SHA384\n");
	else if (mech_type == CKM_SHA384_HMAC) printf("\\__ CKM_SHA384_HMAC\n");
	else if (mech_type == CKM_SHA384_HMAC_GENERAL) printf("\\__ CKM_SHA384_HMAC_GENERAL\n");
	else if (mech_type == CKM_SHA512) printf("\\__ CKM_SHA512\n");
	else if (mech_type == CKM_SHA512_HMAC) printf("\\__ CKM_SHA512_HMAC\n");
	else if (mech_type == CKM_SHA512_HMAC_GENERAL) printf("\\__ CKM_SHA512_HMAC_GENERAL\n");
	else if (mech_type == CKM_SECURID_KEY_GEN) printf("\\__ CKM_SECURID_KEY_GEN\n");
	else if (mech_type == CKM_SECURID) printf("\\__ CKM_SECURID\n");
	else if (mech_type == CKM_HOTP_KEY_GEN) printf("\\__ CKM_HOTP_KEY_GEN\n");
	else if (mech_type == CKM_HOTP) printf("\\__ CKM_HOTP\n");
	else if (mech_type == CKM_ACTI) printf("\\__ CKM_ACTI\n");
	else if (mech_type == CKM_ACTI_KEY_GEN) printf("\\__ CKM_ACTI_KEY_GEN\n");
	else if (mech_type == CKM_CAST_KEY_GEN) printf("\\__ CKM_CAST_KEY_GEN\n");
	else if (mech_type == CKM_CAST_ECB) printf("\\__ CKM_CAST_ECB\n");
	else if (mech_type == CKM_CAST_CBC) printf("\\__ CKM_CAST_CBC\n");
	else if (mech_type == CKM_CAST_MAC) printf("\\__ CKM_CAST_MAC\n");
	else if (mech_type == CKM_CAST_MAC_GENERAL) printf("\\__ CKM_CAST_MAC_GENERAL\n");
	else if (mech_type == CKM_CAST_CBC_PAD) printf("\\__ CKM_CAST_CBC_PAD\n");
	else if (mech_type == CKM_CAST3_KEY_GEN) printf("\\__ CKM_CAST3_KEY_GEN\n");
	else if (mech_type == CKM_CAST3_ECB) printf("\\__ CKM_CAST3_ECB\n");
	else if (mech_type == CKM_CAST3_CBC) printf("\\__ CKM_CAST3_CBC\n");
	else if (mech_type == CKM_CAST3_MAC) printf("\\__ CKM_CAST3_MAC\n");
	else if (mech_type == CKM_CAST3_MAC_GENERAL) printf("\\__ CKM_CAST3_MAC_GENERAL\n");
	else if (mech_type == CKM_CAST3_CBC_PAD) printf("\\__ CKM_CAST3_CBC_PAD\n");
	else if (mech_type == CKM_CAST5_KEY_GEN) printf("\\__ CKM_CAST5_KEY_GEN\n");
	else if (mech_type == CKM_CAST128_KEY_GEN) printf("\\__ CKM_CAST128_KEY_GEN\n");
	else if (mech_type == CKM_CAST5_ECB) printf("\\__ CKM_CAST5_ECB\n");
	else if (mech_type == CKM_CAST128_ECB) printf("\\__ CKM_CAST128_ECB\n");
	else if (mech_type == CKM_CAST5_CBC) printf("\\__ CKM_CAST5_CBC\n");
	else if (mech_type == CKM_CAST128_CBC) printf("\\__ CKM_CAST128_CBC\n");
	else if (mech_type == CKM_CAST5_MAC) printf("\\__ CKM_CAST5_MAC\n");
	else if (mech_type == CKM_CAST128_MAC) printf("\\__ CKM_CAST128_MAC\n");
	else if (mech_type == CKM_CAST5_MAC_GENERAL) printf("\\__ CKM_CAST5_MAC_GENERAL\n");
	else if (mech_type == CKM_CAST128_MAC_GENERAL) printf("\\__ CKM_CAST128_MAC_GENERAL\n");
	else if (mech_type == CKM_CAST5_CBC_PAD) printf("\\__ CKM_CAST5_CBC_PAD\n");
	else if (mech_type == CKM_CAST128_CBC_PAD) printf("\\__ CKM_CAST128_CBC_PAD\n");
	else if (mech_type == CKM_RC5_KEY_GEN) printf("\\__ CKM_RC5_KEY_GEN\n");
	else if (mech_type == CKM_RC5_ECB) printf("\\__ CKM_RC5_ECB\n");
	else if (mech_type == CKM_RC5_CBC) printf("\\__ CKM_RC5_CBC\n");
	else if (mech_type == CKM_RC5_MAC) printf("\\__ CKM_RC5_MAC\n");
	else if (mech_type == CKM_RC5_MAC_GENERAL) printf("\\__ CKM_RC5_MAC_GENERAL\n");
	else if (mech_type == CKM_RC5_CBC_PAD) printf("\\__ CKM_RC5_CBC_PAD\n");
	else if (mech_type == CKM_IDEA_KEY_GEN) printf("\\__ CKM_IDEA_KEY_GEN\n");
	else if (mech_type == CKM_IDEA_ECB) printf("\\__ CKM_IDEA_ECB\n");
	else if (mech_type == CKM_IDEA_CBC) printf("\\__ CKM_IDEA_CBC\n");
	else if (mech_type == CKM_IDEA_MAC) printf("\\__ CKM_IDEA_MAC\n");
	else if (mech_type == CKM_IDEA_MAC_GENERAL) printf("\\__ CKM_IDEA_MAC_GENERAL\n");
	else if (mech_type == CKM_IDEA_CBC_PAD) printf("\\__ CKM_IDEA_CBC_PAD\n");
	else if (mech_type == CKM_GENERIC_SECRET_KEY_GEN) printf("\\__ CKM_GENERIC_SECRET_KEY_GEN\n");
	else if (mech_type == CKM_CONCATENATE_BASE_AND_KEY) printf("\\__ CKM_CONCATENATE_BASE_AND_KEY\n");
	else if (mech_type == CKM_CONCATENATE_BASE_AND_DATA) printf("\\__ CKM_CONCATENATE_BASE_AND_DATA\n");
	else if (mech_type == CKM_CONCATENATE_DATA_AND_BASE) printf("\\__ CKM_CONCATENATE_DATA_AND_BASE\n");
	else if (mech_type == CKM_XOR_BASE_AND_DATA) printf("\\__ CKM_XOR_BASE_AND_DATA\n");
	else if (mech_type == CKM_EXTRACT_KEY_FROM_KEY) printf("\\__ CKM_EXTRACT_KEY_FROM_KEY\n");
	else if (mech_type == CKM_SSL3_PRE_MASTER_KEY_GEN) printf("\\__ CKM_SSL3_PRE_MASTER_KEY_GEN\n");
	else if (mech_type == CKM_SSL3_MASTER_KEY_DERIVE) printf("\\__ CKM_SSL3_MASTER_KEY_DERIVE\n");
	else if (mech_type == CKM_SSL3_KEY_AND_MAC_DERIVE) printf("\\__ CKM_SSL3_KEY_AND_MAC_DERIVE\n");
	else if (mech_type == CKM_SSL3_MASTER_KEY_DERIVE_DH) printf("\\__ CKM_SSL3_MASTER_KEY_DERIVE_DH\n");
	else if (mech_type == CKM_TLS_PRE_MASTER_KEY_GEN) printf("\\__ CKM_TLS_PRE_MASTER_KEY_GEN\n");
	else if (mech_type == CKM_TLS_MASTER_KEY_DERIVE) printf("\\__ CKM_TLS_MASTER_KEY_DERIVE\n");
	else if (mech_type == CKM_TLS_KEY_AND_MAC_DERIVE) printf("\\__ CKM_TLS_KEY_AND_MAC_DERIVE\n");
	else if (mech_type == CKM_TLS_MASTER_KEY_DERIVE_DH) printf("\\__ CKM_TLS_MASTER_KEY_DERIVE_DH\n");
	else if (mech_type == CKM_TLS_PRF) printf("\\__ CKM_TLS_PRF\n");
	else if (mech_type == CKM_SSL3_MD5_MAC) printf("\\__ CKM_SSL3_MD5_MAC\n");
	else if (mech_type == CKM_SSL3_SHA1_MAC) printf("\\__ CKM_SSL3_SHA1_MAC\n");
	else if (mech_type == CKM_MD5_KEY_DERIVATION) printf("\\__ CKM_MD5_KEY_DERIVATION\n");
	else if (mech_type == CKM_MD2_KEY_DERIVATION) printf("\\__ CKM_MD2_KEY_DERIVATION\n");
	else if (mech_type == CKM_SHA1_KEY_DERIVATION) printf("\\__ CKM_SHA1_KEY_DERIVATION\n");
	else if (mech_type == CKM_SHA256_KEY_DERIVATION) printf("\\__ CKM_SHA256_KEY_DERIVATION\n");
	else if (mech_type == CKM_SHA384_KEY_DERIVATION) printf("\\__ CKM_SHA384_KEY_DERIVATION\n");
	else if (mech_type == CKM_SHA512_KEY_DERIVATION) printf("\\__ CKM_SHA512_KEY_DERIVATION\n");
	else if (mech_type == CKM_PBE_MD2_DES_CBC) printf("\\__ CKM_PBE_MD2_DES_CBC\n");
	else if (mech_type == CKM_PBE_MD5_DES_CBC) printf("\\__ CKM_PBE_MD5_DES_CBC\n");
	else if (mech_type == CKM_PBE_MD5_CAST_CBC) printf("\\__ CKM_PBE_MD5_CAST_CBC\n");
	else if (mech_type == CKM_PBE_MD5_CAST3_CBC) printf("\\__ CKM_PBE_MD5_CAST3_CBC\n");
	else if (mech_type == CKM_PBE_MD5_CAST5_CBC) printf("\\__ CKM_PBE_MD5_CAST5_CBC\n");
	else if (mech_type == CKM_PBE_MD5_CAST128_CBC) printf("\\__ CKM_PBE_MD5_CAST128_CBC\n");
	else if (mech_type == CKM_PBE_SHA1_CAST5_CBC) printf("\\__ CKM_PBE_SHA1_CAST5_CBC\n");
	else if (mech_type == CKM_PBE_SHA1_CAST128_CBC) printf("\\__ CKM_PBE_SHA1_CAST128_CBC\n");
	else if (mech_type == CKM_PBE_SHA1_RC4_128) printf("\\__ CKM_PBE_SHA1_RC4_128\n");
	else if (mech_type == CKM_PBE_SHA1_RC4_40) printf("\\__ CKM_PBE_SHA1_RC4_40\n");
	else if (mech_type == CKM_PBE_SHA1_DES3_EDE_CBC) printf("\\__ CKM_PBE_SHA1_DES3_EDE_CBC\n");
	else if (mech_type == CKM_PBE_SHA1_DES2_EDE_CBC) printf("\\__ CKM_PBE_SHA1_DES2_EDE_CBC\n");
	else if (mech_type == CKM_PBE_SHA1_RC2_128_CBC) printf("\\__ CKM_PBE_SHA1_RC2_128_CBC\n");
	else if (mech_type == CKM_PBE_SHA1_RC2_40_CBC) printf("\\__ CKM_PBE_SHA1_RC2_40_CBC\n");
	else if (mech_type == CKM_PKCS5_PBKD2) printf("\\__ CKM_PKCS5_PBKD2\n");
	else if (mech_type == CKM_PBA_SHA1_WITH_SHA1_HMAC) printf("\\__ CKM_PBA_SHA1_WITH_SHA1_HMAC\n");
	else if (mech_type == CKM_WTLS_PRE_MASTER_KEY_GEN) printf("\\__ CKM_WTLS_PRE_MASTER_KEY_GEN\n");
	else if (mech_type == CKM_WTLS_MASTER_KEY_DERIVE) printf("\\__ CKM_WTLS_MASTER_KEY_DERIVE\n");
	else if (mech_type == CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC) printf("\\__ CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC\n");
	else if (mech_type == CKM_WTLS_PRF) printf("\\__ CKM_WTLS_PRF\n");
	else if (mech_type == CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE) printf("\\__ CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE\n");
	else if (mech_type == CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE) printf("\\__ CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE\n");
	else if (mech_type == CKM_TLS10_MAC_SERVER) printf("\\__ CKM_TLS10_MAC_SERVER\n");
	else if (mech_type == CKM_TLS10_MAC_CLIENT) printf("\\__ CKM_TLS10_MAC_CLIENT\n");
	else if (mech_type == CKM_TLS12_MAC) printf("\\__ CKM_TLS12_MAC\n");
	else if (mech_type == CKM_TLS12_KDF) printf("\\__ CKM_TLS12_KDF\n");
	else if (mech_type == CKM_TLS12_MASTER_KEY_DERIVE) printf("\\__ CKM_TLS12_MASTER_KEY_DERIVE\n");
	else if (mech_type == CKM_TLS12_KEY_AND_MAC_DERIVE) printf("\\__ CKM_TLS12_KEY_AND_MAC_DERIVE\n");
	else if (mech_type == CKM_TLS12_MASTER_KEY_DERIVE_DH) printf("\\__ CKM_TLS12_MASTER_KEY_DERIVE_DH\n");
	else if (mech_type == CKM_TLS12_KEY_SAFE_DERIVE) printf("\\__ CKM_TLS12_KEY_SAFE_DERIVE\n");
	else if (mech_type == CKM_TLS_MAC) printf("\\__ CKM_TLS_MAC\n");
	else if (mech_type == CKM_TLS_KDF) printf("\\__ CKM_TLS_KDF\n");
	else if (mech_type == CKM_KEY_WRAP_LYNKS) printf("\\__ CKM_KEY_WRAP_LYNKS\n");
	else if (mech_type == CKM_KEY_WRAP_SET_OAEP) printf("\\__ CKM_KEY_WRAP_SET_OAEP\n");
	else if (mech_type == CKM_CMS_SIG) printf("\\__ CKM_CMS_SIG\n");
	else if (mech_type == CKM_KIP_DERIVE) printf("\\__ CKM_KIP_DERIVE\n");
	else if (mech_type == CKM_KIP_WRAP) printf("\\__ CKM_KIP_WRAP\n");
	else if (mech_type == CKM_KIP_MAC) printf("\\__ CKM_KIP_MAC\n");
	else if (mech_type == CKM_CAMELLIA_KEY_GEN) printf("\\__ CKM_CAMELLIA_KEY_GEN\n");
	else if (mech_type == CKM_CAMELLIA_CTR) printf("\\__ CKM_CAMELLIA_CTR\n");
	else if (mech_type == CKM_ARIA_KEY_GEN) printf("\\__ CKM_ARIA_KEY_GEN\n");
	else if (mech_type == CKM_ARIA_ECB) printf("\\__ CKM_ARIA_ECB\n");
	else if (mech_type == CKM_ARIA_CBC) printf("\\__ CKM_ARIA_CBC\n");
	else if (mech_type == CKM_ARIA_MAC) printf("\\__ CKM_ARIA_MAC\n");
	else if (mech_type == CKM_ARIA_MAC_GENERAL) printf("\\__ CKM_ARIA_MAC_GENERAL\n");
	else if (mech_type == CKM_ARIA_CBC_PAD) printf("\\__ CKM_ARIA_CBC_PAD\n");
	else if (mech_type == CKM_ARIA_ECB_ENCRYPT_DATA) printf("\\__ CKM_ARIA_ECB_ENCRYPT_DATA\n");
	else if (mech_type == CKM_ARIA_CBC_ENCRYPT_DATA) printf("\\__ CKM_ARIA_CBC_ENCRYPT_DATA\n");
	else if (mech_type == CKM_SEED_KEY_GEN) printf("\\__ CKM_SEED_KEY_GEN\n");
	else if (mech_type == CKM_SEED_ECB) printf("\\__ CKM_SEED_ECB\n");
	else if (mech_type == CKM_SEED_CBC) printf("\\__ CKM_SEED_CBC\n");
	else if (mech_type == CKM_SEED_MAC) printf("\\__ CKM_SEED_MAC\n");
	else if (mech_type == CKM_SEED_MAC_GENERAL) printf("\\__ CKM_SEED_MAC_GENERAL\n");
	else if (mech_type == CKM_SEED_CBC_PAD) printf("\\__ CKM_SEED_CBC_PAD\n");
	else if (mech_type == CKM_SEED_ECB_ENCRYPT_DATA) printf("\\__ CKM_SEED_ECB_ENCRYPT_DATA\n");
	else if (mech_type == CKM_SEED_CBC_ENCRYPT_DATA) printf("\\__ CKM_SEED_CBC_ENCRYPT_DATA\n");
	else if (mech_type == CKM_SKIPJACK_KEY_GEN) printf("\\__ CKM_SKIPJACK_KEY_GEN\n");
	else if (mech_type == CKM_SKIPJACK_ECB64) printf("\\__ CKM_SKIPJACK_ECB64\n");
	else if (mech_type == CKM_SKIPJACK_CBC64) printf("\\__ CKM_SKIPJACK_CBC64\n");
	else if (mech_type == CKM_SKIPJACK_OFB64) printf("\\__ CKM_SKIPJACK_OFB64\n");
	else if (mech_type == CKM_SKIPJACK_CFB64) printf("\\__ CKM_SKIPJACK_CFB64\n");
	else if (mech_type == CKM_SKIPJACK_CFB32) printf("\\__ CKM_SKIPJACK_CFB32\n");
	else if (mech_type == CKM_SKIPJACK_CFB16) printf("\\__ CKM_SKIPJACK_CFB16\n");
	else if (mech_type == CKM_SKIPJACK_CFB8) printf("\\__ CKM_SKIPJACK_CFB8\n");
	else if (mech_type == CKM_SKIPJACK_WRAP) printf("\\__ CKM_SKIPJACK_WRAP\n");
	else if (mech_type == CKM_SKIPJACK_PRIVATE_WRAP) printf("\\__ CKM_SKIPJACK_PRIVATE_WRAP\n");
	else if (mech_type == CKM_SKIPJACK_RELAYX) printf("\\__ CKM_SKIPJACK_RELAYX\n");
	else if (mech_type == CKM_KEA_KEY_PAIR_GEN) printf("\\__ CKM_KEA_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_KEA_KEY_DERIVE) printf("\\__ CKM_KEA_KEY_DERIVE\n");
	else if (mech_type == CKM_FORTEZZA_TIMESTAMP) printf("\\__ CKM_FORTEZZA_TIMESTAMP\n");
	else if (mech_type == CKM_BATON_KEY_GEN) printf("\\__ CKM_BATON_KEY_GEN\n");
	else if (mech_type == CKM_BATON_ECB128) printf("\\__ CKM_BATON_ECB128\n");
	else if (mech_type == CKM_BATON_ECB96) printf("\\__ CKM_BATON_ECB96\n");
	else if (mech_type == CKM_BATON_CBC128) printf("\\__ CKM_BATON_CBC128\n");
	else if (mech_type == CKM_BATON_COUNTER) printf("\\__ CKM_BATON_COUNTER\n");
	else if (mech_type == CKM_BATON_SHUFFLE) printf("\\__ CKM_BATON_SHUFFLE\n");
	else if (mech_type == CKM_BATON_WRAP) printf("\\__ CKM_BATON_WRAP\n");
	else if (mech_type == CKM_ECDSA_KEY_PAIR_GEN) printf("\\__ CKM_ECDSA_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_EC_KEY_PAIR_GEN) printf("\\__ CKM_EC_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_ECDSA) printf("\\__ CKM_ECDSA\n");
	else if (mech_type == CKM_ECDSA_SHA1) printf("\\__ CKM_ECDSA_SHA1\n");
	else if (mech_type == CKM_ECDSA_SHA224) printf("\\__ CKM_ECDSA_SHA224\n");
	else if (mech_type == CKM_ECDSA_SHA256) printf("\\__ CKM_ECDSA_SHA256\n");
	else if (mech_type == CKM_ECDSA_SHA384) printf("\\__ CKM_ECDSA_SHA384\n");
	else if (mech_type == CKM_ECDSA_SHA512) printf("\\__ CKM_ECDSA_SHA512\n");
	else if (mech_type == CKM_ECDH1_DERIVE) printf("\\__ CKM_ECDH1_DERIVE\n");
	else if (mech_type == CKM_ECDH1_COFACTOR_DERIVE) printf("\\__ CKM_ECDH1_COFACTOR_DERIVE\n");
	else if (mech_type == CKM_ECMQV_DERIVE) printf("\\__ CKM_ECMQV_DERIVE\n");
	else if (mech_type == CKM_ECDH_AES_KEY_WRAP) printf("\\__ CKM_ECDH_AES_KEY_WRAP\n");
	else if (mech_type == CKM_RSA_AES_KEY_WRAP) printf("\\__ CKM_RSA_AES_KEY_WRAP\n");
	else if (mech_type == CKM_JUNIPER_KEY_GEN) printf("\\__ CKM_JUNIPER_KEY_GEN\n");
	else if (mech_type == CKM_JUNIPER_ECB128) printf("\\__ CKM_JUNIPER_ECB128\n");
	else if (mech_type == CKM_JUNIPER_CBC128) printf("\\__ CKM_JUNIPER_CBC128\n");
	else if (mech_type == CKM_JUNIPER_COUNTER) printf("\\__ CKM_JUNIPER_COUNTER\n");
	else if (mech_type == CKM_JUNIPER_SHUFFLE) printf("\\__ CKM_JUNIPER_SHUFFLE\n");
	else if (mech_type == CKM_JUNIPER_WRAP) printf("\\__ CKM_JUNIPER_WRAP\n");
	else if (mech_type == CKM_FASTHASH) printf("\\__ CKM_FASTHASH\n");
	else if (mech_type == CKM_AES_KEY_GEN) printf("\\__ CKM_AES_KEY_GEN\n");
	else if (mech_type == CKM_AES_ECB) printf("\\__ CKM_AES_ECB\n");
	else if (mech_type == CKM_AES_CBC) printf("\\__ CKM_AES_CBC\n");
	else if (mech_type == CKM_AES_MAC) printf("\\__ CKM_AES_MAC\n");
	else if (mech_type == CKM_AES_MAC_GENERAL) printf("\\__ CKM_AES_MAC_GENERAL\n");
	else if (mech_type == CKM_AES_CBC_PAD) printf("\\__ CKM_AES_CBC_PAD\n");
	else if (mech_type == CKM_AES_CTR) printf("\\__ CKM_AES_CTR\n");
	else if (mech_type == CKM_AES_GCM) printf("\\__ CKM_AES_GCM\n");
	else if (mech_type == CKM_AES_CCM) printf("\\__ CKM_AES_CCM\n");
	else if (mech_type == CKM_AES_CTS) printf("\\__ CKM_AES_CTS\n");
	else if (mech_type == CKM_AES_CMAC) printf("\\__ CKM_AES_CMAC\n");
	else if (mech_type == CKM_AES_CMAC_GENERAL) printf("\\__ CKM_AES_CMAC_GENERAL\n");
	else if (mech_type == CKM_AES_XCBC_MAC) printf("\\__ CKM_AES_XCBC_MAC\n");
	else if (mech_type == CKM_AES_XCBC_MAC_96) printf("\\__ CKM_AES_XCBC_MAC_96\n");
	else if (mech_type == CKM_AES_GMAC) printf("\\__ CKM_AES_GMAC\n");
	else if (mech_type == CKM_BLOWFISH_KEY_GEN) printf("\\__ CKM_BLOWFISH_KEY_GEN\n");
	else if (mech_type == CKM_BLOWFISH_CBC) printf("\\__ CKM_BLOWFISH_CBC\n");
	else if (mech_type == CKM_TWOFISH_KEY_GEN) printf("\\__ CKM_TWOFISH_KEY_GEN\n");
	else if (mech_type == CKM_TWOFISH_CBC) printf("\\__ CKM_TWOFISH_CBC\n");
	else if (mech_type == CKM_BLOWFISH_CBC_PAD) printf("\\__ CKM_BLOWFISH_CBC_PAD\n");
	else if (mech_type == CKM_TWOFISH_CBC_PAD) printf("\\__ CKM_TWOFISH_CBC_PAD\n");
	else if (mech_type == CKM_DES_ECB_ENCRYPT_DATA) printf("\\__ CKM_DES_ECB_ENCRYPT_DATA\n");
	else if (mech_type == CKM_DES_CBC_ENCRYPT_DATA) printf("\\__ CKM_DES_CBC_ENCRYPT_DATA\n");
	else if (mech_type == CKM_DES3_ECB_ENCRYPT_DATA) printf("\\__ CKM_DES3_ECB_ENCRYPT_DATA\n");
	else if (mech_type == CKM_DES3_CBC_ENCRYPT_DATA) printf("\\__ CKM_DES3_CBC_ENCRYPT_DATA\n");
	else if (mech_type == CKM_AES_ECB_ENCRYPT_DATA) printf("\\__ CKM_AES_ECB_ENCRYPT_DATA\n");
	else if (mech_type == CKM_AES_CBC_ENCRYPT_DATA) printf("\\__ CKM_AES_CBC_ENCRYPT_DATA\n");
	else if (mech_type == CKM_GOSTR3410_KEY_PAIR_GEN) printf("\\__ CKM_GOSTR3410_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_GOSTR3410) printf("\\__ CKM_GOSTR3410\n");
	else if (mech_type == CKM_GOSTR3410_WITH_GOSTR3411) printf("\\__ CKM_GOSTR3410_WITH_GOSTR3411\n");
	else if (mech_type == CKM_GOSTR3410_KEY_WRAP) printf("\\__ CKM_GOSTR3410_KEY_WRAP\n");
	else if (mech_type == CKM_GOSTR3410_DERIVE) printf("\\__ CKM_GOSTR3410_DERIVE\n");
	else if (mech_type == CKM_GOSTR3411) printf("\\__ CKM_GOSTR3411\n");
	else if (mech_type == CKM_GOSTR3411_HMAC) printf("\\__ CKM_GOSTR3411_HMAC\n");
	else if (mech_type == CKM_GOST28147_KEY_GEN) printf("\\__ CKM_GOST28147_KEY_GEN\n");
	else if (mech_type == CKM_GOST28147_ECB) printf("\\__ CKM_GOST28147_ECB\n");
	else if (mech_type == CKM_GOST28147) printf("\\__ CKM_GOST28147\n");
	else if (mech_type == CKM_GOST28147_MAC) printf("\\__ CKM_GOST28147_MAC\n");
	else if (mech_type == CKM_GOST28147_KEY_WRAP) printf("\\__ CKM_GOST28147_KEY_WRAP\n");
	else if (mech_type == CKM_DSA_PARAMETER_GEN) printf("\\__ CKM_DSA_PARAMETER_GEN\n");
	else if (mech_type == CKM_DH_PKCS_PARAMETER_GEN) printf("\\__ CKM_DH_PKCS_PARAMETER_GEN\n");
	else if (mech_type == CKM_X9_42_DH_PARAMETER_GEN) printf("\\__ CKM_X9_42_DH_PARAMETER_GEN\n");
	else if (mech_type == CKM_DSA_PROBABLISTIC_PARAMETER_GEN) printf("\\__ CKM_DSA_PROBABLISTIC_PARAMETER_GEN\n");
	else if (mech_type == CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN) printf("\\__ CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN\n");
	else if (mech_type == CKM_AES_OFB) printf("\\__ CKM_AES_OFB\n");
	else if (mech_type == CKM_AES_CFB64) printf("\\__ CKM_AES_CFB64\n");
	else if (mech_type == CKM_AES_CFB8) printf("\\__ CKM_AES_CFB8\n");
	else if (mech_type == CKM_AES_CFB128) printf("\\__ CKM_AES_CFB128\n");
	else if (mech_type == CKM_AES_CFB1) printf("\\__ CKM_AES_CFB1\n");
	else if (mech_type == CKM_SHA224) printf("\\__ CKM_SHA224\n");
	else if (mech_type == CKM_SHA224_HMAC) printf("\\__ CKM_SHA224_HMAC\n");
	else if (mech_type == CKM_SHA224_HMAC_GENERAL) printf("\\__ CKM_SHA224_HMAC_GENERAL\n");
	else if (mech_type == CKM_SHA224_RSA_PKCS) printf("\\__ CKM_SHA224_RSA_PKCS\n");
	else if (mech_type == CKM_SHA224_RSA_PKCS_PSS) printf("\\__ CKM_SHA224_RSA_PKCS_PSS\n");
	else if (mech_type == CKM_SHA224_KEY_DERIVATION) printf("\\__ CKM_SHA224_KEY_DERIVATION\n");
	else if (mech_type == CKM_CAMELLIA_KEY_GEN) printf("\\__ CKM_CAMELLIA_KEY_GEN\n");
	else if (mech_type == CKM_CAMELLIA_ECB) printf("\\__ CKM_CAMELLIA_ECB\n");
	else if (mech_type == CKM_CAMELLIA_CBC) printf("\\__ CKM_CAMELLIA_CBC\n");
	else if (mech_type == CKM_CAMELLIA_MAC) printf("\\__ CKM_CAMELLIA_MAC\n");
	else if (mech_type == CKM_CAMELLIA_MAC_GENERAL) printf("\\__ CKM_CAMELLIA_MAC_GENERAL\n");
	else if (mech_type == CKM_CAMELLIA_CBC_PAD) printf("\\__ CKM_CAMELLIA_CBC_PAD\n");
	else if (mech_type == CKM_CAMELLIA_ECB_ENCRYPT_DATA) printf("\\__ CKM_CAMELLIA_ECB_ENCRYPT_DATA\n");
	else if (mech_type == CKM_CAMELLIA_CBC_ENCRYPT_DATA) printf("\\__ CKM_CAMELLIA_CBC_ENCRYPT_DATA\n");
	else if (mech_type == CKM_AES_KEY_WRAP) printf("\\__ CKM_AES_KEY_WRAP\n");
	else if (mech_type == CKM_AES_KEY_WRAP_PAD) printf("\\__ CKM_AES_KEY_WRAP_PAD\n");
	else if (mech_type == CKM_RSA_PKCS_TPM_1_1) printf("\\__ CKM_RSA_PKCS_TPM_1_1\n");
	else if (mech_type == CKM_RSA_PKCS_OAEP_TPM_1_1) printf("\\__ CKM_RSA_PKCS_OAEP_TPM_1_1\n");
	else if (mech_type == CKM_EC_EDWARDS_KEY_PAIR_GEN) printf("\\__ CKM_EC_EDWARDS_KEY_PAIR_GEN\n");
	else if (mech_type == CKM_EDDSA) printf("\\__ CKM_EDDSA\n");
	else if (mech_type & CKM_VENDOR_DEFINED) printf("\\__ CKM_VENDOR_DEFINED\n");
}

void pkcs11_print_mechanism_info(CK_MECHANISM_INFO_PTR mech_info)
{
	pkcs11_print_flags(mech_info->flags);
	printf("\\___ Key Len: %lu / %lu\n", mech_info->ulMinKeySize, mech_info->ulMaxKeySize);
}