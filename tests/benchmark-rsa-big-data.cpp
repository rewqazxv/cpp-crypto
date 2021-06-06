#include <benchmark/benchmark.h>

#include "crypto/crypto.h"
using namespace crypto;


static const Bytes raw = crypto::random::get_bytes(10000000); // 10mb
static const int KEY_LENGTH = 2048;
static const rsa::KeyPair key_pair = rsa::keygen(KEY_LENGTH);
static Bytes encrypted;


static void rsa_encrypt_big_data(benchmark::State &state)
{
    Bytes res;
    SignedSize input_group_size = KEY_LENGTH / 8 - 11;
    for (auto _ : state) {
        res.clear();
        for (const Byte *input_buffer = raw.data(), *input_end = raw.data() + raw.size();
             input_buffer < input_end;
             input_buffer += input_group_size) {
            SignedSize data_size = std::min(input_group_size, input_end - input_buffer);
            auto input = bigint::from_bytes(input_buffer, data_size);
            input |= BigInt(1) << (data_size * 8);
            auto output = bigint::to_bytes(rsa::rsa(input, key_pair.public_key), ENDIAN::LITTLE);
            output.resize(KEY_LENGTH / 8, 0);
            res.insert(res.end(), output.begin(), output.end());
        }
    }
    encrypted = std::move(res);
}
BENCHMARK(rsa_encrypt_big_data);


static void rsa_decrypt_big_data(benchmark::State &state)
{
    Bytes res;
    SignedSize group_size = KEY_LENGTH / 8;
    for (auto _ : state) {
        res.clear();
        for (const Byte *input_buffer = encrypted.data(), *input_end = encrypted.data() + encrypted.size();
             input_buffer < input_end;
             input_buffer += group_size) {
            auto input = bigint::from_bytes(input_buffer, group_size, ENDIAN::LITTLE);
            auto output = bigint::to_bytes(rsa::rsa(input, key_pair.private_key));
            if (output.at(0) != 1)
                throw std::runtime_error("decrypt error");
            res.insert(res.end(), output.begin() + 1, output.end());
        }
        if (res != raw)
            throw std::runtime_error("decrypted data not equal to raw data");
    }
}
BENCHMARK(rsa_decrypt_big_data);
