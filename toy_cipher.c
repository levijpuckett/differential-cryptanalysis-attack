#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

static const uint8_t s_box_substitution[] = { 
	0xE, 0x4, 0xD, 0x1,
	0x2, 0xF, 0xB, 0x8,
	0x3, 0xA, 0x6, 0xC,
	0x5, 0x9, 0x0, 0x7 };

static uint8_t s_box_substitution_inverse[16] = {};

static const uint8_t s_box_permutation[] = {
	 0,  4,  8, 12,
	 1,  5,  9, 13,
	 2,  6, 10, 14,
	 3,  7, 11, 15 };

static uint8_t s_box_permutation_inverse[16] = {};

static const uint8_t cipher_num_rounds = 4;

static const size_t num_keys = cipher_num_rounds + 1; // +1 for last round key
static uint16_t round_keys[num_keys] = {};

/*
 * cipher_init initializes the cipher structure, and returns the last round subkey.
 */
uint16_t cipher_init()
{
	printf("\n");
	printf("Initializing cipher...\n");
	// invert substitution
	printf("Building inverse s-box substitution:\n");
	for (int i = 0; i < 16; ++i)
	{
		s_box_substitution_inverse[s_box_substitution[i]] = i;

		if (i % 4 == 0 && i > 0) { printf("\n"); }
		printf("%x -> %x | ", i, s_box_substitution[i]);
		printf("%x -> %x    ", s_box_substitution[i], s_box_substitution_inverse[s_box_substitution[i]]);
	}

	printf("\n\nBuilding inverse s-box permutation:\n");
	for (int i = 0; i < 16; ++i)
	{
		s_box_permutation_inverse[s_box_permutation[i]] = i;

		if (i % 4 == 0 && i > 0) { printf("\n"); }
		printf("%x -> %x | ", i, s_box_permutation[i]);
		printf("%x -> %x    ", s_box_permutation[i], s_box_permutation_inverse[s_box_permutation[i]]);
	}

	printf("\nGenerating keys...\n");
	srand(time(NULL));
	for (int i = 0; i < num_keys; ++i)
	{
		// init 5 round keys
		round_keys[i] = (uint16_t) rand();
		printf("Round %d key: %x\n", i, round_keys[i]);
	}
	printf("Cipher initialized.\n");
	printf("\n");

	// return last round key
	return round_keys[num_keys - 1];
}

/*
 * Perform a forward substitution pass through an s-box
 */
static uint16_t sub_forward(uint16_t input)
{
	uint16_t output = 0;
	for (int n = 0; n < 4; ++n)
	{
		output |= s_box_substitution[(input & (0xF << n*4)) >> n*4] << n*4;
	}
	return output;
}

/*
 * Perform an forward permutation pass through an s-box
 */
static uint16_t permute_forward(uint16_t input)
{
	uint16_t output = 0;
	for (int j = 0; j < 16; j++)
	{
		// get jth bit, send to position indicated in s_box_permutation
		output |= ((input & (1 << j)) >> j) << s_box_permutation[j];
	}
	return output;
}

/*
 * Perform an inverse substitution pass through an s-box
 */
static uint16_t sub_inverse(uint16_t input)
{
	uint16_t output = 0;
	for (int n = 0; n < 4; ++n)
	{
		output |= s_box_substitution_inverse[(input & (0xF << n*4)) >> n*4] << n*4;
	}
	return output;
}

/*
 * Perform an inverse permutation pass through an s-box
 */
static uint16_t permute_inverse(uint16_t input)
{
	uint16_t output = 0;
	for (int j = 0; j < 16; j++)
	{
		// get jth bit, send to position indicated in s_box_permutation
		output |= ((input & (1 << j)) >> j) << s_box_permutation_inverse[j];
	}
	return output;
}

/*
 * return ciphertext of the provided plaintext
 */
uint16_t cipher_encrypt(uint16_t plaintext)
{
	uint16_t c = plaintext;
	for (int i = 0; i < cipher_num_rounds - 1; ++i)
	{
		// XOR with current round key
		c ^= round_keys[i];

		// s-box substitution
		c = sub_forward(c);

		// s-box permutation
		c = permute_forward(c);
	}
	// last round has no permutation.
	c ^= round_keys[num_keys - 2];
	c = sub_forward(c);
	c ^= round_keys[num_keys - 1];

	return c;
}

/* 
 * return plaintext of the provided ciphertext
 */
uint16_t cipher_decrypt(uint16_t ciphertext)
{
	// last round has no permutation.
	uint16_t p = ciphertext;
	p ^= round_keys[num_keys - 1];
	p = sub_inverse(p);
	p ^= round_keys[num_keys - 2];

	for (int i = cipher_num_rounds - 2; i >= 0; --i)
	{
		
		p = permute_inverse(p);
		p = sub_inverse(p);
		p ^= round_keys[i];
	}

	return p;
}

/*
 * Generate difference count of each delta_y given delta_x.
 * count must point to an array of size 16.
 *
 * This function generates one row of the difference distribution table.
 */
void difference_pair_count(uint8_t delta_x, size_t * count)
{
	for (uint8_t x = 0; x < 0xF + 1; ++x)
	{
		uint8_t y1 = sub_forward(x);
		uint8_t y2 = sub_forward(x ^ delta_x);
		count[y1^y2]++;
	}
}
