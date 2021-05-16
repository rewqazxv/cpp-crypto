#include "crypto/rsa.h"


namespace crypto::rsa
{

KeyPair keygen(int key_bit_length)
{
    if (key_bit_length < 2048)
        throw std::invalid_argument("key length cannot be less than 2048 bits");
    BigInt e = 65537, d, n, p, q, r;
    do {
        p = bigint::generate_prime(key_bit_length / 2);
        q = bigint::generate_prime(key_bit_length / 2);
    } while (p == q);
    n = p * q;
    r = (p - 1) * (q - 1);
    d = bigint::mod_inverse(e, r);
    return KeyPair{
        {e, n}, // public_key
        {d, n} // private_key
    };
}

BigInt rsa(const BigInt &data, const Key &key)
{
    BigInt res;
    mpz_powm(res.get_mpz_t(), data.get_mpz_t(), key.exp.get_mpz_t(), key.mod.get_mpz_t());
    return res;
}

} // namespace crypto::rsa
