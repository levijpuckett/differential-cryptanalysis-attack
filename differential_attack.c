#include <stdio.h>
#include <stdlib.h>

#include "toy_cipher.h"

void test_cipher(void)
{
	for (int i = 0; i < 0xFFFF+1; ++i)
	{
		if (i != cipher_decrypt(cipher_encrypt(i)))
		{
			printf("Failed on %x\n", i);
		}
	}
}

int main(void)
{
	uint16_t final_round_subkey = cipher_init();
	printf("Final round subkey: %u\n", final_round_subkey);

	for (int i = 0; i < 200; ++i)
	{
		// test cipher with many different keys.
		test_cipher();
		cipher_init();
	}
	return 0;
}
