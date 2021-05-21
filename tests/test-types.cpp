#include <gtest/gtest.h>

#include "crypto/types.h"
using namespace crypto;

#include <string>
using namespace std;


TEST(types, bytes_string_literal)
{
    string raw = "hello world!";
    Bytes a = "hello world!"_str_bytes;
    ASSERT_EQ(raw, string(a.begin(), a.end()));
}

TEST(types, bytes_hex_literal)
{
    {
        Bytes a = " 00      00   0 0 0a1 c2b    "_hex_bytes;
        Bytes b = {0x0, 0x0, 0x0, 0xa, 0x1c, 0x2b};
        ASSERT_EQ(a, b);
    }

    {
        ASSERT_THROW(Bytes a = "00 00 00 0a 1c 2"_hex_bytes, invalid_argument);
    }
}
