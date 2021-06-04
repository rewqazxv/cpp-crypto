#include <benchmark/benchmark.h>

#include "crypto/crypto.h"
using namespace crypto;


static const Bytes raw = crypto::random::get_bytes(10000000); // 10mb
static const Bytes key = "long time no see"_str_bytes;
static const Bytes iv = "abcdefghijklmnop"_str_bytes;
static Bytes encrypted;


static void aes_128_cbc_encrypt(benchmark::State &state)
{
    Bytes res;
    for (auto _ : state) {
        auto aes_cbc = CbcMode<AES>::Encrypter(iv.data(), key);
        res.clear();
        res.resize(aes_cbc.output_buffer_size(raw.size()));
        res.resize(aes_cbc.finish(raw.data(), raw.size(), res.data(), res.size()));
    }
    encrypted = std::move(res);
}
BENCHMARK(aes_128_cbc_encrypt);


static void aes_128_cbc_decrypt(benchmark::State &state)
{
    Bytes res;
    for (auto _ : state) {
        auto aes_cbc = CbcMode<AES>::Decrypter(iv.data(), key);
        res.clear();
        res.resize(aes_cbc.output_buffer_size(encrypted.size()));
        res.resize(aes_cbc.finish(encrypted.data(), encrypted.size(), res.data(), res.size()));
    }
    if (res != raw)
        throw std::runtime_error("decrypted data not equal to raw data");
}
BENCHMARK(aes_128_cbc_decrypt);


static void aes_128_cbc_decrypt_separately(benchmark::State &state)
{
    Bytes res;
    for (auto _ : state) {
        auto aes_cbc = CbcMode<AES>::Decrypter(iv.data(), key);
        res.clear();
        res.resize(aes_cbc.output_buffer_size(encrypted.size()));

        const Byte *input_buffer = encrypted.data();
        const SignedSize input_buffer_size = 2048;
        SignedSize written = 0;

        for (const Byte *input_end = encrypted.data() + encrypted.size(); input_buffer < input_end; input_buffer += input_buffer_size) {
            SignedSize data_size = std::min(input_buffer_size, input_end - input_buffer);
            written += aes_cbc.use(input_buffer, data_size, res.data() + written, res.size() - written);
        }
        written += aes_cbc.finish(res.data() + written, res.size() - written);
        res.resize(written);
    }
    if (res != raw)
        throw std::runtime_error("decrypted data not equal to raw data");
}
BENCHMARK(aes_128_cbc_decrypt_separately);
