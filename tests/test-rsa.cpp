#include <gtest/gtest.h>

#include "crypto/rsa.h"
using namespace crypto;


// consume too much time
// TEST(rsa, keygen)
// {
//     ASSERT_THROW(rsa::keygen(2047), std::invalid_argument);

//     int key_bit_length = 2568;
//     auto keys1 = rsa::keygen(key_bit_length);
//     int real_size = bigint::size(keys1.public_key.mod);
//     ASSERT_EQ(keys1.public_key.exp, 65537);
//     ASSERT_TRUE(real_size == key_bit_length || real_size == key_bit_length - 1);
//     ASSERT_EQ(keys1.public_key.mod, keys1.private_key.mod);

//     auto keys2 = rsa::keygen(key_bit_length);
//     ASSERT_NE(keys2.public_key.mod, keys1.public_key.mod);
// }

TEST(rsa, rsa)
{
    auto keys = rsa::keygen();
    Bytes data = "hello rsa"_bytes;

    BigInt raw = bigint::from_bytes(data);
    BigInt encrypted = rsa::rsa(raw, keys.public_key);
    BigInt decrypted = rsa::rsa(encrypted, keys.private_key);

    ASSERT_NE(raw, encrypted);
    ASSERT_EQ(raw, decrypted);

    Bytes data2 = bigint::to_bytes(decrypted);
    ASSERT_EQ(data2, data);
}
