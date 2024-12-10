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

#include "pkcs11-impl.h"

#define MAX_SLOT_COUNT		50

#define STACK_FRAMES					30

void signal_handler(int signal)
{
	void *array[STACK_FRAMES];
	printf("got signal: %d", signal);
	int size = backtrace(array, STACK_FRAMES);
	char **strings = (char **) backtrace_symbols(array, size);

	for (int i = 0; i < size; ++i)
	{
		printf("%02ld %s\n", i, strings[i]);
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

	if (argc != 2)
	{
		printf("wrong number of parameters\n");
		printf("usage: ./binary path_to_cryptoki.so \n", argv[0]);
		return -1;
	}

	signal(SIGILL, signal_handler);
	signal(SIGABRT, signal_handler);
	signal(SIGFPE, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGBUS, signal_handler);
	signal(SIGSTKFLT, signal_handler);

	int ret_code = -1;
	CK_SLOT_ID slot_list[MAX_SLOT_COUNT];
	CK_ULONG total_slot = MAX_SLOT_COUNT;
	CK_SESSION_HANDLE session;

	// ePass3003
//	const char * SO_PIN = "rockey";
//	const char * USER_PIN = "1234";
//	const char * libPath = "../feitian/libshuttle_p11v220.so";

	// rastin talaee
	const char * SO_PIN = "rastin";
	const char * USER_PIN = "1234";
	const char * libPath = "../feitian/libRastinPKCS11.so";

	// SoftHSM
//	const char * SO_PIN = "5528999";
//	const char * USER_PIN = "123456";
//	const char * libPath = "/usr/local/lib/softhsm/libsofthsm2.so";

//	if (load_library(argv[1]) != 0) goto exit_unload;
	if (load_library(libPath) != 0) goto exit_unload;

	if (init_pkcs_library() != 0) goto exit_unload;

	if (init_pkcs() != 0) goto exit_finalize;

	if (get_slot_count(&total_slot) != 0) goto exit_finalize;

	if (get_slot(slot_list, &total_slot) != 0) goto exit_finalize;

	for (CK_LONG i = 0; i < total_slot; ++i) get_slot_info(slot_list[i]);

	if (open_session(slot_list[0], &session) != 0) goto exit_finalize;

//	if (login(session, CKU_SO, SO_PIN) != 0) goto exit_session;
	if (login(session, CKU_USER, USER_PIN) != 0) goto exit_session;

	CK_OBJECT_HANDLE obj_handle, obj_public_handle, obj_private_handle;

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

exit_logout:
	logout(session);
exit_session:
	close_session(session);
exit_finalize:
	finalize();
exit_unload:
	unload_library();

	return ret_code;
}
