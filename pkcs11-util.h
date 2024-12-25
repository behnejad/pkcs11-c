/*
	Creative Commons Attribution-NonCommercial-NoDerivs (CC-BY-NC-ND)
	https://creativecommons.org/licenses/by-nc-nd/4.0/
	The most restrictive creative commons license.
	This only allows people to download and share your work for no commercial gain and for no other purposes.
*/

//
// Created by hooman on 12/14/24.
//

#ifndef CRYPTOKI_TOOL_PKCS11_UTIL_H
#define CRYPTOKI_TOOL_PKCS11_UTIL_H 1

#ifdef __cplusplus
extern "C"
{
#endif

#include "pkcs11.h"

const char * pkcs11_ckr_to_str(CK_RV code);
void pkcs11_print_slot_info(CK_SLOT_INFO_PTR slot_info);
void pkcs11_print_token_info(CK_TOKEN_INFO_PTR token_info);
void pkcs11_print_slot_flags(CK_FLAGS flags);
void pkcs11_print_token_flags(CK_FLAGS flags);
void pkcs11_print_session_flags(CK_FLAGS flags);
void pkcs11_print_otp_flags(CK_FLAGS flags);
void pkcs11_print_flags(CK_FLAGS flags);
void pkcs11_print_mechanism(CK_MECHANISM_TYPE mech_type);
void pkcs11_print_mechanism_info(CK_MECHANISM_INFO_PTR mech_info);

#ifdef __cplusplus
}
#endif

#endif //CRYPTOKI_TOOL_PKCS11_UTIL_H
