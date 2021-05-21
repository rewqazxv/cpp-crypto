#include <gtest/gtest.h>

#include "crypto/aes.h"
#include "crypto/rng.h"
using namespace crypto;


TEST(aes, key_size)
{
    Bytes key;
    key = random::get_bytes(15);
    ASSERT_THROW(AES{key}, std::invalid_argument);
    key = random::get_bytes(17);
    ASSERT_THROW(AES{key}, std::invalid_argument);
    key = random::get_bytes(16);
    ASSERT_NO_THROW(AES{key});
}

TEST(aes, aes)
{
    Bytes key = "long time no see"_str_bytes;
    AES aes(key);

    Bytes raw = "test AES-128 raw"_str_bytes;

    Bytes encrypted = raw;
    aes.encrypt(encrypted.data());

    Bytes decrypted = encrypted;
    aes.decrypt(decrypted.data());

    ASSERT_NE(raw, encrypted);
    ASSERT_EQ(raw, decrypted);

    Bytes expected_encrypted = "608988e669a6f0c26ada3938020e87aa"_hex_bytes;
    ASSERT_EQ(encrypted, expected_encrypted);
}
