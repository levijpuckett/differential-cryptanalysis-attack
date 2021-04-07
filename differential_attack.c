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

void generate_difference_distribution_table()
{
	printf("\n\nDifference Distribution Table\n");
	char * ylabel = "Input Difference ";
	char * xlabel = "                     Output Difference";
	printf("%s\n         ", xlabel);
	for (uint8_t y = 0; y < 0xF+1; ++y)
	{
		printf("%2x ", y);
	}
	printf("\n        ________________________________________________\n");
	for (uint8_t x = 0; x < 0xF+1; ++x)
	{
		size_t dy_count[16] = {};
		difference_pair_count(x, dy_count);
		printf("%c || %x | ", ylabel[x], x);
		for (int i = 0; i < 16; ++i)
		{
			printf("%2zu ", dy_count[i]);
		}
		printf("\n");
	}
	printf("\n");
}

int main(void)
{
	uint16_t final_round_subkey = cipher_init();
	printf("Final round subkey: %x\n", final_round_subkey);

	/*
	// test cipher with many different keys.
	for (int i = 0; i < 200; ++i)
	{
		test_cipher();
		cipher_init();
	}
	*/
	generate_difference_distribution_table();

	return 0;
}
