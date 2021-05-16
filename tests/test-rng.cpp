#include <gtest/gtest.h>

#include "crypto/rng.h"
using namespace crypto;


TEST(rng, random_bytes)
{
    int size = 13;
    auto a = random::get_bytes(size);
    auto b = random::get_bytes(size);
    ASSERT_EQ(a.size(), size);
    ASSERT_EQ(b.size(), size);
    ASSERT_NE(a, b);
}
