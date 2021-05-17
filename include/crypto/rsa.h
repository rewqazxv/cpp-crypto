#ifndef RSA_H
#define RSA_H

#include "bigint.h"


namespace crypto::rsa
{

struct Key { BigInt exp, mod; };
struct KeyPair { Key public_key, private_key; };

KeyPair keygen(int key_bit_length = 2048);
BigInt rsa(const BigInt &data, const Key &key);

} // namespace crypto::rsa

#endif // RSA_H
