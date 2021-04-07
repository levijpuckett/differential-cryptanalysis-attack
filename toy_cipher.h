#include <stdint.h>

/*
 * cipher_init initializes the cipher structure, and returns the last round subkey.
 */
uint16_t cipher_init();

/*
 * return ciphertext of the provided plaintext
 */
uint16_t cipher_encrypt(uint16_t plaintext);

/* 
 * return plaintext of the provided ciphertext
 */
uint16_t cipher_decrypt(uint16_t ciphertext);

/*
 * Perform an inverse substitution pass through an s-box
 * This function is not static to allow for the partial decryption in the differential attack.
 */
uint16_t sub_inverse(uint16_t input);

/*
 * Generate difference count of each delta_y given delta_x.
 * count must point to an array of size 16.
 *
 * This function generates one row of the difference distribution table.
 */
void difference_pair_count(uint8_t delta_x, size_t * count);
