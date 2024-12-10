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
};

typedef struct pkcs11_handle_t pkcs11_handle;

#ifdef __cplusplus
extern "C"
{
#endif

const char * pkcs11_get_last_error_str(pkcs11_handle * handle);
int pkcs11_free(pkcs11_handle * handle);
pkcs11_handle * pkcs11_load_library(const char * path, int flags);
int pkcs11_init(pkcs11_handle * handle);

int init_pkcs();
int get_slot_count(CK_ULONG_PTR count);
int get_slot(CK_SLOT_ID_PTR list, CK_ULONG_PTR slot_count);
int get_slot_info(CK_SLOT_ID slot);
int open_session(CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR session);
int login(CK_SESSION_HANDLE session, int user, const char * pin);
int logout(CK_SESSION_HANDLE session);
int close_session(CK_SESSION_HANDLE session);
int finalize();
int unload_library();
int generate_3des(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_OBJECT_HANDLE_PTR objHandle);
int generate_aes(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_ULONG size, CK_OBJECT_HANDLE_PTR objHandle);
int generate_rsa(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_ULONG size,
				 CK_OBJECT_HANDLE_PTR objPubHndl, CK_OBJECT_HANDLE_PTR objPriHandle);
int generate_ecdsa(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_BYTE_PTR curve, CK_ULONG size,
				   CK_OBJECT_HANDLE_PTR objPubHndl, CK_OBJECT_HANDLE_PTR objPriHandle);
int create_data(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR label, CK_UTF8CHAR_PTR value, CK_OBJECT_HANDLE_PTR objHandle);
int seed_random(CK_SESSION_HANDLE session, CK_BYTE_PTR data_ptr, CK_ULONG size);
int generate_random(CK_SESSION_HANDLE session, CK_BYTE_PTR data_ptr, CK_ULONG size);


#ifdef __cplusplus
}
#endif

#endif //PKCS_IMPL_H