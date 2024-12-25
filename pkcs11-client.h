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
 * 			\_ CKA_EXTRACTABLE:	can be wrapped to extract. cannot make non-extractable to extractable. does not make value visible
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

#ifndef PKCS11_CLIENT_H
#define PKCS11_CLIENT_H 1

#include "pkcs11.h"

#include <dlfcn.h>

#define PKCS11_DEFAULT_DLOPEN			RTLD_LAZY | RTLD_LOCAL
#define MAX_LABEL_LEN					100
#define MAX_PIN_LEN						16
#define MIN_PIN_LEN						4

#define PUBLIC_OBJECT_POST_FIX			"_pub"
#define PRIVATE_OBJECT_POST_FIX			"_prv"

#ifdef __cplusplus
extern "C"
{
#endif

enum
{
	PKCS11_OK							= 0,
	PKCS11_ERR 							= -1,
	PKCS11_ERR_NULL_PTR 				= -2,
	PKCS11_ERR_WRONG_PARAMETER		 	= -3,
	PKCS11_ERR_UNLOAD_LIBRARY	 		= -4,
	PKCS11_ERR_WRONG_LEN		 		= -5,
	PKCS11_ERR_WRONG_STATE		 		= -6,
	PKCS11_ERR_LIB_FUNC_NOT_FOUND		= -7,
	PKCS11_ERR_PKCS11					= -8,
};

enum
{
	PKCS11_DIGEST_MD5					= CKM_MD5,
	PKCS11_DIGEST_SHA1					= CKM_SHA_1,
	PKCS11_DIGEST_SHA224				= CKM_SHA224,
	PKCS11_DIGEST_SHA256				= CKM_SHA256,
	PKCS11_DIGEST_SHA384				= CKM_SHA384,
	PKCS11_DIGEST_SHA512				= CKM_SHA512,
};

enum
{
	PKCS11_START						= 1 << 0,
	PKCS11_UPDATE						= 1 << 1,
	PKCS11_FINISH						= 1 << 2,
};

typedef struct pkcs11_handle_t pkcs11_handle;

pkcs11_handle * pkcs11_load_library(const char * path, int flags);
int pkcs11_load_functions(pkcs11_handle * handle);
int pkcs11_init_library(pkcs11_handle * handle);
int pkcs11_get_slot_list(pkcs11_handle * handle, int has_token, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR slot_count);
int pkcs11_get_slot_info(pkcs11_handle * handle, CK_SLOT_ID slot, CK_SLOT_INFO_PTR info);
int pkcs11_get_token_info(pkcs11_handle * handle, CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info);
int pkcs11_get_mechanism(pkcs11_handle * handle, CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count);
int pkcs11_get_mechanism_info(pkcs11_handle * handle, CK_SLOT_ID slot, CK_MECHANISM_TYPE mech, CK_MECHANISM_INFO_PTR info);
int pkcs11_open_session(pkcs11_handle * handle, CK_SLOT_ID slot, CK_FLAGS flags);
int pkcs11_login(pkcs11_handle * handle, int user, const char * pin);
int pkcs11_iterate_objects(pkcs11_handle * handle);
int pkcs11_generate_3des(pkcs11_handle * handle, const char * label);
int pkcs11_generate_aes(pkcs11_handle * handle, const char * label, size_t size);
int pkcs11_generate_rsa(pkcs11_handle * handle, const char * label, CK_ULONG size, const char * expo, size_t expo_len);
int pkcs11_generate_ecdsa(pkcs11_handle * handle, const char * label, const char * curve, size_t size);
int pkcs11_delete_object(pkcs11_handle * handle, CK_OBJECT_HANDLE obj_handle);
int pkcs11_create_data(pkcs11_handle * handle, const char * label, const char * value, size_t len);
int pkcs11_create_secret(pkcs11_handle * handle, const char * label, int type, const char * value, size_t len);
int pkcs11_encrypt(pkcs11_handle * handle, CK_OBJECT_HANDLE obj_handle, CK_MECHANISM_PTR mech, const char * buffer, size_t buffer_size, char * out, size_t * out_size);
int pkcs11_encrypt_parted(pkcs11_handle * handle, CK_OBJECT_HANDLE obj_handle, CK_MECHANISM_PTR mech, int state, char * buffer, size_t * size);
int pkcs11_seed_random(pkcs11_handle * handle, char * buffer, size_t size);
int pkcs11_generate_random(pkcs11_handle * handle, char * buffer, size_t size);
int pkcs11_digest(pkcs11_handle * handle, int mode, const char * buffer, size_t buffer_size, char * out, size_t * out_size);
int pkcs11_digest_parted(pkcs11_handle * handle, int mode, int state, char * buffer, size_t * size); // buffer on finish is out buffer
int pkcs11_free(pkcs11_handle * handle);

const char * pkcs11_get_last_error_str(pkcs11_handle * handle);


#ifdef __cplusplus
}
#endif

#endif //PKCS11_CLIENT_H