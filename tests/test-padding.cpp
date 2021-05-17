#include <gtest/gtest.h>

#include "crypto/padding.h"
#include "crypto/aes.h"
#include "crypto/types.h"
using namespace crypto;


template <typename Method>
static Bytes pad(Method method, const Bytes &data)
{
    Bytes res = data;
    res.resize(method.BLOCK_SIZE);
    method.pad(res.data(), data.size());
    return res;
}

template <typename Method>
static Bytes unpad(Method method, const Bytes &data)
{
    Bytes res = data;
    int sz = method.unpad(res.data());
    res.resize(sz);
    return res;
}

TEST(padding, padding)
{
    padding::PKCS7 pkcs7(AES::BLOCK_SIZE);
    for (const Bytes &raw : {
             ""_bytes,
             "1"_bytes,
             "1234"_bytes,
             "123456789abcdef"_bytes
         }) {
        Bytes padded = pad(pkcs7, raw);
        Bytes expected_padded = raw;
        expected_padded.resize(16, 16 - raw.size());
        ASSERT_EQ(padded, expected_padded);
        Bytes unpadded = unpad(pkcs7, padded);
        ASSERT_EQ(raw, unpadded);
    }
}
