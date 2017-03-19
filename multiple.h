#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>



#ifndef BN_UINT_MAX
#define BN_UINT_MAX 0xffffffff
#endif

/**
 * Basic limb type. Note that some calculations rely on unsigned overflow wrap-around of this type.
 * As a result, only unsigned types should be used here, and the RADIX, HALFRADIX above should be
 * changed as necessary. Unsigned integer should probably be the most efficient word type, and this
 * is used by GMP for example.
 */
#if BN_UINT_MAX == 0xffffffff
typedef uint32_t word;
typedef uint64_t dword;
#elif BN_UINT_MAX == 0xffff
typedef uint16_t word;
typedef uint32_t dword;
#elif BN_UINT_MAX == 0xff
typedef uint8_t word;
typedef uint16_t dword;
#endif



/**
 * Structure for representing multiple precision integers. This is a base "word" LSB
 * representation. In this case the base, word, is 2^32. Length is the number of words
 * in the current representation. Length should not allow for trailing zeros (Things like
 * 000124). The capacity is the number of words allocated for the limb data.
 */
typedef struct _bignum {
	int length;
	int capacity;
	word* data;
} bignum;


/**
 * Initialize a bignum structure. This is the only way to safely create a bignum
 * and should be called where-ever one is declared. (We realloc the memory in all
 * other cases which is technically safe but may cause problems when we go to free
 * it.)
 */
bignum* bignum_init(void);

/**
 * Free resources used by a bignum. Use judiciously to avoid memory leaks.
 */
void bignum_deinit(bignum* b);

/**
 * Check if the given bignum is zero
 */
int bignum_iszero(bignum* b);

/**
 * Check if the given bignum is nonzero.
 */
int bignum_isnonzero(bignum* b);

/**
 * Copy from source bignum into destination bignum.
 */
void bignum_copy(bignum* source, bignum* dest);

/**
 * Load a bignum from a base 10 string. Only pure numeric strings will work.
 */
void bignum_fromstring(bignum* b, char* string);

/**
 * Load a bignum from an unsigned integer.
 */
void bignum_fromint(bignum* b, word num);

/**
 * Print a bignum to stdout as base 10 integer. This is done by
 * repeated division by 10. We can make it more efficient by dividing by
 * 10^9 for example, then doing single precision arithmetic to retrieve the
 * 9 remainders
 */
void bignum_print(bignum* b);

/**
 * Check if two bignums are equal.
 */
int bignum_equal(bignum* b1, bignum* b2);

/**
 * Check if bignum b1 is greater than b2
 */
int bignum_greater(bignum* b1, bignum* b2);

/**
 * Check if bignum b1 is less than b2
 */
int bignum_less(bignum* b1, bignum* b2);

/**
 * Check if bignum b1 is greater than or equal to b2
 */
int bignum_geq(bignum* b1, bignum* b2);

/**
 * Check if bignum b1 is less than or equal to b2
 */
int bignum_leq(bignum* b1, bignum* b2);

/**
 * Perform an in place add into the source bignum. That is source += add
 */
void bignum_iadd(bignum* source, bignum* add);

/**
 * Add two bignums by the add with carry method. result = b1 + b2
 */
void bignum_add(bignum* result, bignum* b1, bignum* b2);
/**
 * Perform an in place subtract from the source bignum. That is, source -= sub
 */
void bignum_isubtract(bignum* source, bignum* sub);

/**
 * Subtract bignum b2 from b1. result = b1 - b2. The result is undefined if b2 > b1.
 * This uses the basic subtract with carry method
 */
void bignum_subtract(bignum* result, bignum* b1, bignum* b2);

/**
 * Perform an in place multiplication into the source bignum. That is source *= mult
 */
void bignum_imultiply(bignum* source, bignum* mult);

/**
 * Multiply two bignums by the naive school method. result = b1 * b2. I have experimented
 * with FFT mult and Karatsuba but neither was looking to be  more efficient than the school
 * method for reasonable number of digits. There are some improvments to be made here,
 * especially for squaring which can cut out half of the operations.
 */
void bignum_multiply(bignum* result, bignum* b1, bignum* b2);

/**
 * Perform an in place divide of source. source = source/div.
 */
void bignum_idivide(bignum *source, bignum *div);

/**
 * Perform an in place divide of source, also producing a remainder.
 * source = source/div and remainder = source - source/div.
 */
void bignum_idivider(bignum* source, bignum* div, bignum* remainder);

/**
 * Calculate the remainder when source is divided by div.
 */
void bignum_remainder(bignum* source, bignum *div, bignum* remainder);

/**
 * Modulate the source by the modulus. source = source % modulus
 */
void bignum_imodulate(bignum* source, bignum* modulus);

/**
 * Divide two bignums by naive long division, producing both a quotient and remainder.
 * quotient = floor(b1/b2), remainder = b1 - quotient * b2. If b1 < b2 the quotient is
 * trivially 0 and remainder is b2.
 */
void bignum_divide(bignum* quotient, bignum* remainder, bignum* b1, bignum* b2);

/**
 * Perform modular exponentiation by repeated squaring. This will compute
 * result = base^exponent mod modulus
 */
void bignum_modpow(bignum* base, bignum* exponent, bignum* modulus, bignum* result);

/**
 * Compute the gcd of two bignums. result = gcd(b1, b2)
 */
void bignum_gcd(bignum* b1, bignum* b2, bignum* result);

/**
 * Compute the inverse of a mod m. Or, result = a^-1 mod m.
 */
void bignum_inverse(bignum* a, bignum* m, bignum* result);
/**
 * Compute the jacobi symbol, J(ac, nc).
 */
int bignum_jacobi(bignum* ac, bignum* nc);

/**
 * Check whether a is a Euler witness for n. That is, if a^(n - 1)/2 != Ja(a, n) mod n
 */
int solovayPrime(int a, bignum* n);

/**
 * Test if n is probably prime, by repeatedly using the Solovay-Strassen primality test.
 */
int probablePrime(bignum* n, int k);

/**
 * Generate a random prime number, with a specified number of digits.
 * This will generate a base 10 digit string of given length, convert it
 * to a bignum and then do an increasing search for the first probable prime.
 */
void randPrime(int numDigits, bignum* result);

/**
 * Choose a random public key exponent for the RSA algorithm. The exponent will
 * be less than the modulus, n, and coprime to phi.
 */
void randExponent(bignum* phi, int n, bignum* result);


/**
 * Encode the message m using public exponent and modulus, result = m^e mod n
 */
void encode(bignum* m, bignum* e, bignum* n, bignum* result);
/**
 * Decode cryptogram c using private exponent and public modulus, result = c^d mod n
 */
void decode(bignum* c, bignum* d, bignum* n, bignum* result);
