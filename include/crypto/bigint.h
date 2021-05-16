#ifndef BIGINT_H
#define BIGINT_H

#include "types.h"
#include "rng.h"
#include <gmpxx.h>


namespace crypto
{

typedef mpz_class BigInt;

namespace bigint
{

size_t size(const BigInt &num, int base = 2);
Bytes to_bytes(const BigInt &num, ENDIAN endian = ENDIAN::BIG);
BigInt from_bytes(const Byte *data, size_t size, ENDIAN endian = ENDIAN::BIG);
BigInt from_bytes(const Bytes &data, ENDIAN endian = ENDIAN::BIG);

bool is_prime(const BigInt &n);
BigInt generate_prime(int bit_len);
BigInt extgcd(const BigInt &a, const BigInt &b, BigInt &x, BigInt &y);
BigInt mod_inverse(const BigInt &a, const BigInt &m);

} // namespace bigint

namespace random
{

BigInt get_bigint(int bit_len);

} // namespace random

} // namespace crypto

#endif // BIGINT_H
