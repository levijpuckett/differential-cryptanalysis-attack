#include <stdio.h>
#include <stdlib.h>

#include "toy_cipher.h"

/*
 * Simple test of the cipher structure: encrypt and decrypt every possible plaintext
 */
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

/*
 * Generate and display the difference distribution table for the s-box 
 * in the toy cipher (every s-box is the same in our cipher)
 */
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

/*
 * Performs the differential attack as described in the paper.
 * The plaintext difference input 0x0B00 is used. The input to the last round s-boxes will be 0x0606
 * with probability 27/1024.
 *
 * We generate a number of plaintexts pairs satisfying the desired input differential.
 *
 * For each pair, the ciphertext differential is partially decrypted using the target partial subkey value.
 * When the input to the last round satisfies the characteristic, the count for that target partial subkey 
 * is incremented. Every possible target subkey is tried (256 possibilities).
 *
 * Parameters:
 * partial_subkey_counts - an array to be populated with the counts for each target subkey.
 * iterations - number of plaintext pairs to generate for the attack.
 * 
 * Returns:
 * The key determinted to be most likely to true partial subkey.
 */
uint8_t differential_attack(size_t * partial_subkey_counts, size_t iterations)
{
	printf("Attacking cipher...\n");
	
	// input plaintext differential
	uint16_t delta_p = 0x0B00;

	for (int i = 0; i < iterations; ++i)
	{
		// generate a plaintext input pair with difference delta_p
		uint16_t p1 = (uint16_t) rand();
		uint16_t p2 = p1 ^ delta_p;

		// encrypt the plaintexts
		uint16_t c1 = cipher_encrypt(p1);
		uint16_t c2 = cipher_encrypt(p2);

		// only compute the input to the last round if all other s-box outputs are 0
		if (((c1 ^ c2) & 0xF0F0) == 0)
		{
			// For every possible target partial subkey,
			// partially decrypt ciphertext to find right/wrong pairs.
			for (unsigned int k = 0; k < 256; ++k)
			{
				// split k to get the top and bottom half of the target partial subkey
				// 0xab -> 0x0a0b to line up with the relevant s-boxes.
				uint16_t key = ((k & (0xF << 4)) << 4) | ((k & 0xF) << 0);

				// unmix with the partial key
				uint16_t v1 = c1 ^ key;
				uint16_t v2 = c2 ^ key;

				// step backwards through the last s-boxes
				uint16_t u1 = sub_inverse(v1);
				uint16_t u2 = sub_inverse(v2);

				// determine if a right pair occured by finding the input difference 
				// and comparing it to the expected input difference
				// if this is a right pair, increment the count for this subkey
				if ((u1 ^ u2) == 0x0606) { partial_subkey_counts[k]++; }
			}
		}
	}

	// find max occurance of target subkey and return that key
	size_t max = partial_subkey_counts[0];
	uint8_t key = 0;

	for (int i = 1; i < 256; ++i)
	{
		if (partial_subkey_counts[i] > max)
		{
			max = partial_subkey_counts[i];
			key = i;
		}
	}

	// output results
	printf("Attack complete. Found partial subkey (%x, %x) with count %zu\n\n", 
			(key & 0xF0) >> 4, (key & 0x0F), max);

	return key;
}

int main(void)
{
	// Initialize the cipher and get the final round key (which we will attempt to recover a portion of)
	uint16_t final_round_subkey = cipher_init();
	printf("Final round subkey: %x\n", final_round_subkey);

	/*
	// test cipher with many different keys.
	for (int i = 0; i < 200; ++i)
	{
		test_cipher(); // test on every plaintext
		cipher_init(); // new keys
	}
	*/

	// Output the difference distribution table
	generate_difference_distribution_table();

	size_t partial_target_subkey_counts[256] = {};
	size_t iterations = 5000;

	// recover a shard of the final round key
	uint8_t key = differential_attack(partial_target_subkey_counts, iterations);

	printf("True partial subkey bits: (%x, %x)\n", (final_round_subkey & 0x0F00) >> 8,
												 (final_round_subkey & 0x000F));
	printf("Recovered key: (%x, %x) | count: %zu\n", (key & 0xF0) >> 4,
												   (key & 0x0F), partial_target_subkey_counts[key]);
	printf("Recovered key occured with probability %.3f\n",
			((float)partial_target_subkey_counts[key] / (float)iterations));

	printf("Expected probability is 27/1024 (%.3f)\n", 27.0 / 1024.0);

	return 0;
}
