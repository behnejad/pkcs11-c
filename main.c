/*
	Creative Commons Attribution-NonCommercial-NoDerivs (CC-BY-NC-ND)
	https://creativecommons.org/licenses/by-nc-nd/4.0/
	The most restrictive creative commons license.
	This only allows people to download and share your work for no commercial gain and for no other purposes.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <execinfo.h>
#include <getopt.h>

#include "pkcs11-client.h"
#include "pkcs11-util.h"

#define MAX_SLOT_COUNT		50
#define MAX_MECH_COUNT		100
#define STACK_FRAMES		30

#define EPASS3000			1
#define	RASTIN				0

void print_hex(const char * tag, const char * data, size_t len)
{
	printf("%s: ", tag);
	for (size_t i = 0; i < len; ++i)
		printf("%02X", (unsigned char) data[i]);
	printf("\n");
}

void signal_handler(int signal)
{
	void *array[STACK_FRAMES];
	printf("got signal: %d", signal);
	int size = backtrace(array, STACK_FRAMES);
	char **strings = (char **) backtrace_symbols(array, size);

	for (int i = 0; i < size; ++i)
	{
		printf("%02d %s\n", i, strings[i]);
	}

	free(strings);
}

struct option opts[] =
{
	{"wide", 1, 0, 'w'},
	{0, 0, 0, 0}
};

int main(int argc, char * argv[])
{
	int option_val = 0;
	int opindex = 0;

	while ((option_val = getopt_long(argc, argv, "", opts, &opindex)) != -1)
	{
		switch (option_val)
		{
		}
	}

	signal(SIGILL, signal_handler);
	signal(SIGABRT, signal_handler);
	signal(SIGFPE, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGBUS, signal_handler);
	signal(SIGSTKFLT, signal_handler);

	int ret_code = -1;
	pkcs11_handle * handle = NULL;
	CK_SLOT_ID slot_list[MAX_SLOT_COUNT];
	CK_ULONG total_slot = MAX_SLOT_COUNT;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;
	CK_MECHANISM_INFO mech_info;
	CK_MECHANISM_TYPE mech_list[MAX_MECH_COUNT];
	CK_ULONG total_mech = MAX_MECH_COUNT;
	const char publicExponent[] = {0x01, 0x00, 0x00, 0x00, 0x01}; //public exponent - 65537
	const char curve[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}; // hex representation for secp384r1 curve.
	// b83e48cfb59f2872f3a325e8ed264c6ebf18da8e56a6982f
	const char key[] = "\xb8\x3e\x48\xcf\xb5\x9f\x28\x72\xf3\xa3\x25\xe8\xed\x26\x4c\x6e\xbf\x18\xda\x8e\x56\xa6\x98\x2f";
	char iv[8] = {0};
	char buffer[1024] = {0};
	size_t buffer_size = 0;

#if EPASS3000 == 1
	const char * SO_PIN = "rockey";
	const char * USER_PIN = "1234";
	const char * lib_path = "../feitian/libshuttle_p11v220.so";
#elif RASTIN == 1
	const char * SO_PIN = "rastin";
	const char * USER_PIN = "1234";
	const char * lib_path = "../feitian/libRastinPKCS11.so";
#else
	const char * SO_PIN = "5528999";
	const char * USER_PIN = "123456";
	const char * lib_path = "/usr/local/lib/softhsm/libsofthsm2.so";
#endif

	handle = pkcs11_load_library(lib_path, PKCS11_DEFAULT_DLOPEN);
	if (handle == NULL) return -1;
	if (pkcs11_load_functions(handle) != 0) goto exit;
	if (pkcs11_init_library(handle) != 0) goto exit;
	if (pkcs11_get_slot_list(handle, 1, slot_list, &total_slot) != 0) goto exit;
	for (CK_LONG i = 0; 0 && i < total_slot; ++i){
		if (pkcs11_get_slot_info(handle, slot_list[i], &slot_info) == 0)
			pkcs11_print_slot_info(&slot_info);

		if (pkcs11_get_token_info(handle, slot_list[i], &token_info) == 0)
			pkcs11_print_token_info(&token_info);

		total_mech = MAX_MECH_COUNT;
		printf("\\_ Mechanisms:\n");
		if (pkcs11_get_mechanism(handle, slot_list[i], mech_list, &total_mech) == 0)
			for (CK_ULONG j = 0; j < total_mech; ++j)
			{
				pkcs11_print_mechanism(mech_list[j]);
				if (pkcs11_get_mechanism_info(handle, slot_list[i], mech_list[j], &mech_info) == 0)
					pkcs11_print_mechanism_info(&mech_info);
			}
		printf("____\n");
	}
	if (pkcs11_open_session(handle, slot_list[0], CKF_SERIAL_SESSION | CKF_RW_SESSION) != 0) goto exit;
	if (pkcs11_login(handle, CKU_USER, USER_PIN) != 0) goto exit;
	if (pkcs11_iterate_objects(handle) != 0) goto exit;
//	if (pkcs11_login(handle, CKU_SO, SO_PIN) != 0) goto exit;
//	if (pkcs11_delete_object(handle, 32769) != 0) goto exit;
//	if (pkcs11_generate_3des(handle, "gen_3des_1") != 0) goto exit;
//	if (pkcs11_generate_aes(handle, "gen_aes_1", 128) != 0) goto exit;
//	if (pkcs11_generate_rsa(handle, "gen_rsa_1", 2048, publicExponent, sizeof(publicExponent)) != 0) goto exit;
//	if (pkcs11_generate_ecdsa(handle, "gen_ecdsa_1", curve, sizeof(curve)) != 0) goto exit;
//	if (pkcs11_create_data(handle, "gen_data_1", data, strlen(data)) != 0) goto exit;
//	if (pkcs11_create_secret(handle, "sec_1", CKK_DES3, key, 24) != 0) goto exit;
//	if (pkcs11_seed_random(handle, buffer, sizeof(buffer)) != 0) goto exit;
//	if (pkcs11_generate_random(handle, buffer, sizeof(buffer)) != 0) goto exit;

//	buffer_size = sizeof(buffer);
//	if (pkcs11_digest(handle, PKCS11_DIGEST_SHA1, "hello world!", 12, buffer, &buffer_size) != 0) goto exit;

//	if (pkcs11_digest_parted(handle, PKCS11_DIGEST_SHA1, PKCS11_START, NULL, NULL) != 0) goto exit;
//	buffer_size = 6;
//	if (pkcs11_digest_parted(handle, PKCS11_DIGEST_SHA1, PKCS11_UPDATE, "hello ", &buffer_size) != 0) goto exit;
//	buffer_size = 6;
//	if (pkcs11_digest_parted(handle, PKCS11_DIGEST_SHA1, PKCS11_UPDATE, "world!", &buffer_size) != 0) goto exit;
//	buffer_size = sizeof buffer;
//	if (pkcs11_digest_parted(handle, PKCS11_DIGEST_SHA1, PKCS11_FINISH, buffer, &buffer_size) != 0) goto exit;

//	buffer_size = sizeof(buffer);
//	CK_MECHANISM mech = {CKM_DES3_CBC_PAD, &iv, sizeof(iv)};
//	if (pkcs11_encrypt(handle, 32769, &mech, "Hello World!", 12, buffer, &buffer_size) != 0) goto exit;
//	print_hex(">>", buffer, buffer_size);

	ret_code = 0;
exit:
	printf("STATUS: %s\n", pkcs11_get_last_error_str(handle));
	pkcs11_free(handle);
	return ret_code;
}
