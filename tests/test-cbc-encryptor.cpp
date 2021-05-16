#include <gtest/gtest.h>

#include "crypto/cbc.h"
#include "crypto/aes.h"
#include "crypto/bigint.h"
using namespace crypto;

#include <algorithm>
using std::min;


TEST(aes_128_cbc_encrypt, 0)
{
    Bytes raw = ""_bytes;
    Bytes expected = "9d14aaae0326c678a486c74763ec6cd3"_hex;
    Bytes key = "long time no see"_bytes;
    Bytes iv = "abcdefghijklmnop"_bytes;
    auto aes_cbc = CbcMode<AES>::Encryptor(iv.data(), key);

    Bytes res(aes_cbc.output_buffer_size(raw.size()));
    SignedSize sz = aes_cbc.use(raw.data(), raw.size(), res.data(), res.size());
    ASSERT_EQ(sz, 0);
    sz += aes_cbc.finish(res.data() + sz, res.size() - sz);
    res.resize(sz);
    ASSERT_EQ(res, expected);
}

TEST(aes_128_cbc_encrypt, 1)
{
    Bytes raw = "1"_bytes;
    Bytes expected = "C742DD0F19ABAE9D3C79FB3784F4420F"_hex;
    Bytes key = "long time no see"_bytes;
    Bytes iv = "abcdefghijklmnop"_bytes;
    auto aes_cbc = CbcMode<AES>::Encryptor(iv.data(), key);

    Bytes res(aes_cbc.output_buffer_size(raw.size()));
    SignedSize sz = aes_cbc.use(raw.data(), raw.size(), res.data(), res.size());
    ASSERT_EQ(sz, 0);
    sz += aes_cbc.finish(res.data() + sz, res.size() - sz);
    res.resize(sz);
    ASSERT_EQ(res, expected);
}

TEST(aes_128_cbc_encrypt, 16)
{
    Bytes raw = "vvwqeasdcveehytj"_bytes;
    Bytes expected = "48931E91F44D04F875E7319E058D40C54982CC3BB23AB40A57506582E2AB977E"_hex;
    Bytes key = "long time no see"_bytes;
    Bytes iv = "abcdefghijklmnop"_bytes;
    auto aes_cbc = CbcMode<AES>::Encryptor(iv.data(), key);

    Bytes res(aes_cbc.output_buffer_size(raw.size()));
    res.resize(aes_cbc.finish(raw.data(), raw.size(), res.data(), res.size()));
    ASSERT_EQ(res, expected);
}

TEST(aes_128_cbc_encrypt, long_one_time)
{
    Bytes raw = "In cryptography, a block cipher mode of operation is an algorithm that uses a block cipher to provide information security such as confidentiality or authenticity. A block cipher by itself is only suitable for the secure cryptographic transformation (encryption or decryption) of one fixed-length group of bits called a block. A mode of operation describes how to repeatedly apply a cipher's single-block operation to securely transform amounts of data larger than a block."_bytes;
    Bytes expected = "66F8A6C96EEF3A3C68D510BC7962F0A0A566FEE112DAE8B8483813BFBDC856B18E16B86CD0E0A70D78A04FADEE6A6A7F6628A27467484C296C811E7C8238AE9089E17364CBDE19C70C9E8AB16DBE09B32A9FA1C58425E87D9EF35B249EC71C4B334CDD3DAB914595B3029532E2D2258149F66714353354CCDB0B9075654CE321065F0E89F9D07CA57F0F15E198DAEA9B977380D1AA10A1E45FA3FE85CF9D3C3952D200055B5FADB1DB68D9F9205F2A9ACEE9E78DA950A5082F489CE6CF795DC8EA391C877817E0E29720BAC95ABB6E7226599D6A63A249080AFAD7E7901F133992E1542138EC67D3C4A56C6526A34CEFD779E42B4B67D3CA86256E535CE01D72967FEEF4DE9AB9B0BCBFB05885693849775254D2862BF630DAE9B590146C72B8267B44527019ECCE78C77419F0D63E31125CCEFCF85BDB7CC6D7F84AE22FF04363BF4995CC5020B927B9CE005478DB1C78F8ACF35B53389658F35A9079425C86E38788ACA53D500F56808D1382ACF649DD4E0CB37DBD8849ECABAF2253F9C4221C743DA55C1FBB0B19399D9BBF728C5EBC93B1C07BA6FACDA4E3B9E6DCBA1A3DA3D0BC8EEDA81109EA27E00E606E7BD23098D83507CC7708A38E284C8B4298EB6B4DDDAA3C6239A65D209FA657710A49CCE275CD3485B9B1559C1864B8C85D95"_hex;
    Bytes key = "long time no see"_bytes;
    Bytes iv = "abcdefghijklmnop"_bytes;
    CbcMode<AES>::Encryptor derived(iv.data(), key);
    CbcMode<AES> &aes_cbc = derived;

    Bytes res(aes_cbc.output_buffer_size(raw.size()));
    res.resize(aes_cbc.finish(raw.data(), raw.size(), res.data(), res.size()));
    ASSERT_EQ(res, expected);
}

TEST(aes_128_cbc_encrypt, long_separately)
{
    Bytes raw = "In cryptography, a block cipher mode of operation is an algorithm that uses a block cipher to provide information security such as confidentiality or authenticity. A block cipher by itself is only suitable for the secure cryptographic transformation (encryption or decryption) of one fixed-length group of bits called a block. A mode of operation describes how to repeatedly apply a cipher's single-block operation to securely transform amounts of data larger than a block."_bytes;
    Bytes expected = "66F8A6C96EEF3A3C68D510BC7962F0A0A566FEE112DAE8B8483813BFBDC856B18E16B86CD0E0A70D78A04FADEE6A6A7F6628A27467484C296C811E7C8238AE9089E17364CBDE19C70C9E8AB16DBE09B32A9FA1C58425E87D9EF35B249EC71C4B334CDD3DAB914595B3029532E2D2258149F66714353354CCDB0B9075654CE321065F0E89F9D07CA57F0F15E198DAEA9B977380D1AA10A1E45FA3FE85CF9D3C3952D200055B5FADB1DB68D9F9205F2A9ACEE9E78DA950A5082F489CE6CF795DC8EA391C877817E0E29720BAC95ABB6E7226599D6A63A249080AFAD7E7901F133992E1542138EC67D3C4A56C6526A34CEFD779E42B4B67D3CA86256E535CE01D72967FEEF4DE9AB9B0BCBFB05885693849775254D2862BF630DAE9B590146C72B8267B44527019ECCE78C77419F0D63E31125CCEFCF85BDB7CC6D7F84AE22FF04363BF4995CC5020B927B9CE005478DB1C78F8ACF35B53389658F35A9079425C86E38788ACA53D500F56808D1382ACF649DD4E0CB37DBD8849ECABAF2253F9C4221C743DA55C1FBB0B19399D9BBF728C5EBC93B1C07BA6FACDA4E3B9E6DCBA1A3DA3D0BC8EEDA81109EA27E00E606E7BD23098D83507CC7708A38E284C8B4298EB6B4DDDAA3C6239A65D209FA657710A49CCE275CD3485B9B1559C1864B8C85D95"_hex;
    Bytes key = "long time no see"_bytes;
    Bytes iv = "abcdefghijklmnop"_bytes;
    CbcMode<AES>::Encryptor derived(iv.data(), key);
    CbcMode<AES> &aes_cbc = derived;

    const Byte *input_buffer = raw.data();
    const SignedSize input_buffer_size = 67;
    ASSERT_TRUE(bigint::is_prime(input_buffer_size));

    Bytes res;
    Bytes output_buffer(aes_cbc.output_buffer_size(input_buffer_size));

    for (Byte *input_end = raw.data() + raw.size(); input_buffer < input_end; input_buffer += input_buffer_size) {
        SignedSize data_size = min(input_buffer_size, input_end - input_buffer);
        SignedSize writed = aes_cbc.use(input_buffer, data_size, output_buffer.data(), output_buffer.size());
        res.insert(res.end(), output_buffer.data(), output_buffer.data() + writed);
    }
    output_buffer.resize(aes_cbc.finish(output_buffer.data(), output_buffer.size()));
    res.insert(res.end(), output_buffer.begin(), output_buffer.end());

    ASSERT_EQ(res, expected);
}
