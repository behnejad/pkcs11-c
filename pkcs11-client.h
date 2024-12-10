/*
	Creative Commons Attribution-NonCommercial-NoDerivs (CC-BY-NC-ND)
	https://creativecommons.org/licenses/by-nc-nd/4.0/
	The most restrictive creative commons license.
	This only allows people to download and share your work for no commercial gain and for no other purposes.
*/

/**
 * Objects
 * \_ Types:
 * \	\_ Data
 * \	\_ Certificate
 * \	\_ Key
 * \		\_ public key
 * \		\_ private key
 * \		\_ secret key
 * \_ Access Mode:
 * \			\_ private - login required
 * \			\_ public
 * \_ LIfe Time:
 *  		\_ token: 	persist
 *  		\_ session: ephemeral
 *
 * Attributes:
 * \_ Starts with CKA_ ...
 * \_ example:
 * 			\_ Vendor defined starts from 0x80000000
 * 			\_ CKA_TOKEN: 		is persist or not.
 * 			\_ CKA_PRIVATE: 	is login required.
 * 			\_ CKA_LOCAL: 		is generated inside token.
 * 			\_ CKA_CLASS:		type of an object (public/private/secret/data/...) / CKO_ ...
 * 			\_ CKA_KEY_TYPE:	algorithm of key (AES/RSA/3DES/...)/ CKK_ ...
 * 			\_ CKA_SENSITIVE:	is true, not allowed to read objects. cannot make sensitive to none sensitive.
 * 			\_ CKA_EXTRACTABLE:	can be wrapped to extract. cannot make non-extractable to extractable.
 * 			\_ CKA_MODIFIABLE:	can be changed. cannot make read-only to be changeable.
 * 			\_ CKA_ENCRYPT:		permit to encrypt. cannot be set to private key.
 * 			\_ CKA_DECRYPT:		permit to decrypt. cannot be set to public key.
 * 			\_ CKA_SIGN:		permit to sign data. cannot be set to public key.
 * 			\_ CKA_VERIFY:		permit to verify. cannot be set to private key.
 * 			\_ CKA_WRAP:		permit key to be wrapp.
 * 			\_ CKA_UNWRAP:		permit key to be un-wrapp.
 * 			\_ CKA_DERIVE:		permit to derive from another key.
 * 			\_ CKA_ALWAYS_SENSITIVE: readonly.
 * 			\_ CKA_NEVER_EXTRACTABLE: readonly.
 *
 * Created objects:
 * \_ CKA_LOCAL: false
 * \_ CKA_NEVER_EXTRACTABLE: false
 * \_ CKA_ALWAYS_SENSITIVE: false
 */

#ifndef PKCS_IMPL_H
#define PKCS_IMPL_H 1

#include "pkcs11.h"

#include <dlfcn.h>

#define PKCS11_DEFAULT_DLOPEN		RTLD_LAZY | RTLD_LOCAL
#define MAX_LABEL_LEN				100

enum
{
	PKCS11_OK							= 0,
	PKCS11_ERR 							= -1,
	PKCS11_ERR_NULL_PTR 				= -2,
	PKCS11_ERR_SESSION_AVAILABLE 		= -3,
	PKCS11_ERR_UNLOAD_LIBRARY	 		= -4,
	PKCS11_ERR_HAS_STATE		 		= -5,
	PKCS11_ERR_WRONG_STATE		 		= -6,
	PKCS11_ERR_LIB_FUNC_NOT_FOUND		= -7,
	PKCS11_ERR_PKCS11					= -8,
};

typedef struct pkcs11_handle_t pkcs11_handle;

#ifdef __cplusplus
extern "C"
{
#endif

const char * pkcs11_get_last_error_str(pkcs11_handle * handle);
pkcs11_handle * pkcs11_load_library(const char * path, int flags);
int pkcs11_load_functions(pkcs11_handle * handle);
int pkcs11_init_library(pkcs11_handle * handle);
int pkcs11_open_session(pkcs11_handle * handle, CK_SLOT_ID slot, CK_FLAGS flags);
int pkcs11_get_slot_list(pkcs11_handle * handle, int has_token, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR slot_count);
int pkcs11_get_slot_info(pkcs11_handle * handle, CK_SLOT_ID slot, CK_SLOT_INFO_PTR info);
void pkcs11_print_slot_info(CK_SLOT_INFO_PTR slot_info);
int pkcs11_get_token_info(pkcs11_handle * handle, CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info);
void pkcs11_print_token_info(CK_TOKEN_INFO_PTR token_info);
int pkcs11_free(pkcs11_handle * handle);

#ifdef __cplusplus
}
#endif

#endif //PKCS_IMPL_H