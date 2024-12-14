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
	if (flags & CKF_HW) printf("\\__ CKF_HW");
	if (flags & CKF_ENCRYPT) printf("\\__ CKF_ENCRYPT");
	if (flags & CKF_DECRYPT) printf("\\__ CKF_DECRYPT");
	if (flags & CKF_DIGEST) printf("\\__ CKF_DIGEST");
	if (flags & CKF_SIGN) printf("\\__ CKF_SIGN");
	if (flags & CKF_SIGN_RECOVER) printf("\\__ CKF_SIGN_RECOVER");
	if (flags & CKF_VERIFY) printf("\\__ CKF_VERIFY");
	if (flags & CKF_VERIFY_RECOVER) printf("\\__ CKF_VERIFY_RECOVER");
	if (flags & CKF_GENERATE) printf("\\__ CKF_GENERATE");
	if (flags & CKF_GENERATE_KEY_PAIR) printf("\\__ CKF_GENERATE_KEY_PAIR");
	if (flags & CKF_WRAP) printf("\\__ CKF_WRAP");
	if (flags & CKF_UNWRAP) printf("\\__ CKF_UNWRAP");
	if (flags & CKF_DERIVE) printf("\\__ CKF_DERIVE");
	if (flags & CKF_EXTENSION) printf("\\__ CKF_EXTENSION");
	if (flags & CKF_EC_F_P) printf("\\__ CKF_EC_F_P");
	if (flags & CKF_EC_NAMEDCURVE) printf("\\__ CKF_EC_NAMEDCURVE");
	if (flags & CKF_EC_UNCOMPRESS) printf("\\__ CKF_EC_UNCOMPRESS");
	if (flags & CKF_EC_COMPRESS) printf("\\__ CKF_EC_COMPRESS");
}