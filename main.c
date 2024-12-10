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

#define MAX_SLOT_COUNT		50
#define STACK_FRAMES		30

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

	// ePass3003
//	const char * SO_PIN = "rockey";
//	const char * USER_PIN = "1234";
//	const char * lib_path = "../feitian/libshuttle_p11v220.so";

	// rastin talaee
//	const char * SO_PIN = "rastin";
//	const char * USER_PIN = "1234";
//	const char * lib_path = "../feitian/libRastinPKCS11.so";

	// SoftHSM
//	const char * SO_PIN = "5528999";
	const char * USER_PIN = "123456";
	const char * lib_path = "/usr/local/lib/softhsm/libsofthsm2.so";

	handle = pkcs11_load_library(lib_path, PKCS11_DEFAULT_DLOPEN);
	if (handle == NULL) return -1;
	if (pkcs11_load_functions(handle) != 0) goto exit;
	if (pkcs11_init_library(handle) != 0) goto exit;
	if (pkcs11_get_slot_list(handle, 1, slot_list, &total_slot) != 0) goto exit;
	for (CK_LONG i = 0; i < total_slot; ++i)
	{
		if (pkcs11_get_slot_info(handle, slot_list[i], &slot_info) == 0)
			pkcs11_print_slot_info(&slot_info);
		printf("\\____\n");
		if (pkcs11_get_token_info(handle, slot_list[i], &token_info) == 0)
			pkcs11_print_token_info(&token_info);
	}
	if (pkcs11_open_session(handle, slot_list[0], CKF_SERIAL_SESSION | CKF_RW_SESSION) != 0) goto exit;


//	if (open_session(slot_list[0], &session) != 0) goto exit_finalize;

//	if (login(session, CKU_SO, SO_PIN) != 0) goto exit_session;
//	if (login(session, CKU_USER, USER_PIN) != 0) goto exit_session;

//	CK_OBJECT_HANDLE obj_handle, obj_public_handle, obj_private_handle;

//	generate_3des(session, "gen_3des_1", &obj_handle);
//	generate_aes(session, "gen_aes_1", 128, &obj_handle);
//	generate_rsa(session, "gen_rsa_1", 2048, &obj_public_handle, &obj_private_handle);
//	CK_BYTE curve[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}; // hex representation for secp384r1 curve.
//	generate_ecdsa(session, "gen_ecdsa_1", curve, sizeof(curve), &obj_public_handle, &obj_private_handle);

//	create_data(session, "gen_data_1", "random value",  &obj_handle);

//	char buffer[10] = {0};
//	seed_random(session, buffer, sizeof(buffer));
//	generate_random(session, buffer, sizeof(buffer));



	ret_code = 0;
exit:
	printf("STATUS: %s\n", pkcs11_get_last_error_str(handle));
	pkcs11_free(handle);
	return ret_code;
}
