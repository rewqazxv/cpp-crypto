#include "crypto/bigint.h"

#include <cassert>
#include <memory>
using std::unique_ptr;
using std::make_unique;


namespace crypto::bigint
{

size_t size(const BigInt &num, int base)
{
    return mpz_sizeinbase(num.get_mpz_t(), base);
}

Bytes to_bytes(const BigInt &num, ENDIAN endian)
{
    if (num < 0)
        throw(std::invalid_argument("the number to be encoded cannot be negative"));
    size_t sz = bigint::size(num, 256);
    Bytes res(sz, 0);
    size_t writed = 0;
    mpz_export(res.data(), &writed, endian, 1, 0, 0, num.get_mpz_t());
    assert(sz == writed || (num == 0 && sz == 1 && writed == 0));
    return res;
}

BigInt from_bytes(const Byte *data, size_t size, ENDIAN endian)
{
    BigInt res;
    mpz_import(res.get_mpz_t(), size, endian, 1, 0, 0, data);
    return res;
}

BigInt from_bytes(const Bytes &data, ENDIAN endian)
{
    return from_bytes(data.data(), data.size(), endian);
}

namespace
{
// init a non-cryptographic random BigInt generator
unique_ptr<gmp_randclass> init_gmp_randclass()
{
    static const int SEED_SIZE = 16;
    auto res = make_unique<gmp_randclass>(gmp_randinit_mt);
    res->seed(from_bytes(random::get_bytes(SEED_SIZE)));
    return res;
}
} // anonymous namespace

bool is_prime(const BigInt &n)
{
    static const int TEST_ROUND = 100;
    static const BigInt two = 2;
    static auto gmprand = init_gmp_randclass(); // non-cryptographic

    if (n == 2 || n == 3 || n == 5 || n == 7 || n == 11) return true;
    if (n < 2 || (n % 2) == 0 || (n % 3) == 0 || (n % 5) == 0 || (n % 7) == 0 || (n % 11) == 0) return false;
    int s = 0;
    BigInt d = n - 1;
    while ((d & 1) == 0) {s++; d >>= 1;}

    for (int i = 0; i < TEST_ROUND; i++) {
        BigInt a = gmprand->get_z_range(n - 2) + 2;
        BigInt x, y;
        mpz_powm(x.get_mpz_t(), a.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
        for (int j = 0; j < s; j++) {
            mpz_powm(y.get_mpz_t(), x.get_mpz_t(), two.get_mpz_t(), n.get_mpz_t());
            if (y == 1 && x != 1 && x != n - 1)
                return false;
            x = y;
        }
        if (x != 1) return false;
    }
    return true;
}

BigInt generate_prime(int bit_len)
{
    BigInt res = random::get_bigint(bit_len) |= 1;
    while (!is_prime(res)) res += 2;
    return res;
}

BigInt extgcd(const BigInt &a, const BigInt &b, BigInt &x, BigInt &y)
{
    BigInt d = a;
    if (b != 0) {
        d = extgcd(b, a % b, y, x);
        y -= (a / b) * x;
    } else {
        x = 1;
        y = 0;
    }
    return d;
}

BigInt mod_inverse(const BigInt &a, const BigInt &m)
{
    BigInt x, y;
    extgcd(a, m, x, y);
    return (m + x % m) % m;
}

} // namespace crypto::bigint


namespace crypto::random
{

BigInt get_bigint(int bit_len)
{
    if (bit_len <= 0)
        return 0;
    int size = bit_len / 8 + !!(bit_len % 8);
    int drop_bits = size * 8 - bit_len;
    Bytes random_bytes = get_bytes(size);
    random_bytes[0] |= 0x80;
    BigInt res = bigint::from_bytes(random_bytes, ENDIAN::BIG) >> drop_bits;
    return res;
}

} // namespace crypto::random
