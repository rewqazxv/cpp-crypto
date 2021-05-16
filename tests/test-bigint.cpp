#include <gtest/gtest.h>

#include "crypto/bigint.h"
using namespace crypto;

#include <map>
using std::map;


TEST(BigInt, size)
{
    Bytes data = {0x20, 4, 2, 1};
    BigInt x = bigint::from_bytes(data, ENDIAN::BIG);
    ASSERT_EQ(bigint::size(x), 30);
    ASSERT_EQ(bigint::size(x, 256), 4);
}

TEST(BigInt, from_bytes)
{
    // positive
    {
        Bytes a = {4, 3, 2, 1};
        ASSERT_EQ(67305985, bigint::from_bytes(a));
        ASSERT_EQ(67305985, bigint::from_bytes(a, ENDIAN::BIG));
        ASSERT_EQ(16909060, bigint::from_bytes(a, ENDIAN::LITTLE));
    }

    // zero
    {
        Bytes a = {0};
        ASSERT_EQ(0, bigint::from_bytes(a));
        ASSERT_EQ(0, bigint::from_bytes(a, ENDIAN::BIG));
        ASSERT_EQ(0, bigint::from_bytes(a, ENDIAN::LITTLE));
    }

    // multiple zero
    {
        Bytes a = {0, 0, 0, 0, 0};
        ASSERT_EQ(a.size(), 5);
        ASSERT_EQ(0, bigint::from_bytes(a));
        ASSERT_EQ(0, bigint::from_bytes(a, ENDIAN::BIG));
        ASSERT_EQ(0, bigint::from_bytes(a, ENDIAN::LITTLE));
    }

    // leading zero, big endlian
    {
        Bytes a = {0, 0, 0, 0, 33};
        ASSERT_EQ(a.size(), 5);
        ASSERT_EQ(33, bigint::from_bytes(a));
        ASSERT_EQ(33, bigint::from_bytes(a, ENDIAN::BIG));
    }

    // leading zero, little endlian
    {
        Bytes a = {44, 0, 0, 0, 0};
        ASSERT_EQ(a.size(), 5);
        ASSERT_EQ(44, bigint::from_bytes(a, ENDIAN::LITTLE));
    }
}

TEST(BigInt, to_bytes)
{
    // positive
    {
        BigInt x = 0x04030201;
        Bytes big_order = {4, 3, 2, 1};
        Bytes little_order = {1, 2, 3, 4};
        ASSERT_EQ(big_order, bigint::to_bytes(x));
        ASSERT_EQ(big_order, bigint::to_bytes(x, ENDIAN::BIG));
        ASSERT_EQ(little_order, bigint::to_bytes(x, ENDIAN::LITTLE));
    }

    // zero
    {
        BigInt x = 0;
        Bytes res = {0};
        ASSERT_EQ(res, bigint::to_bytes(x));
        ASSERT_EQ(res, bigint::to_bytes(x, ENDIAN::BIG));
        ASSERT_EQ(res, bigint::to_bytes(x, ENDIAN::LITTLE));
    }

    // negative
    {
        BigInt x = -111;
        ASSERT_LT(x, 0);
        ASSERT_THROW(bigint::to_bytes(x), std::invalid_argument);
        ASSERT_THROW(bigint::to_bytes(x, ENDIAN::BIG), std::invalid_argument);
        ASSERT_THROW(bigint::to_bytes(x, ENDIAN::LITTLE), std::invalid_argument);
    }
}

TEST(BigInt, random)
{
    // common
    {
        int bit_len = 415411;
        BigInt x = random::get_bigint(bit_len);
        BigInt y = random::get_bigint(bit_len);
        ASSERT_EQ(bit_len, bigint::size(x));
        ASSERT_EQ(bit_len, bigint::size(y));
        ASSERT_NE(x, y);
    }

    // frequency
    {
        int bit_len = 9;
        int round = 10000;
        map<int, int> cnt;
        while (round--) {
            BigInt x = random::get_bigint(bit_len);
            cnt[x.get_ui()]++;
        }
        ASSERT_EQ(cnt.size(), 1 << (bit_len - 1));
        ASSERT_EQ(cnt.begin()->first, 1 << (bit_len - 1));
        ASSERT_EQ(cnt.rbegin()->first, (1 << bit_len) - 1);
    }
}

TEST(BigInt, is_prime)
{
    map<BigInt, bool> prime = {
        {1, false},
        {4, false},
        {16, false},
        {25, false},
        {249310081, false},
        {45219927, false},
        {2, true},
        {3, true},
        {5, true},
        {11927, true},
        {20903, true},
        {10010069, true},
        {45219929, true}
    };
    for (const auto &i : prime) {
        ASSERT_EQ(i.second, bigint::is_prime(i.first));
    }
}

TEST(BigInt, generate_prime)
{
    int bit_len = 2155;
    BigInt x = bigint::generate_prime(bit_len);
    BigInt y = bigint::generate_prime(bit_len);
    ASSERT_EQ(bit_len, bigint::size(x));
    ASSERT_EQ(bit_len, bigint::size(y));
    ASSERT_TRUE(bigint::is_prime(x));
    ASSERT_TRUE(bigint::is_prime(y));
    ASSERT_NE(x, y);
}

TEST(BigInt, mod_inverse)
{
    ASSERT_EQ(bigint::mod_inverse(3, 11), 4);
    ASSERT_EQ(bigint::mod_inverse(15, 65537), 30584);
}
