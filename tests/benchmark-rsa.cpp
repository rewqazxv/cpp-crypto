#include <benchmark/benchmark.h>

#include "crypto/crypto.h"
using namespace crypto;


static const Bytes raw = crypto::random::get_bytes(255);
static const rsa::KeyPair key_pair = rsa::keygen(2048);
static Bytes encrypted;


static void rsa_encrypt(benchmark::State &state)
{
    Bytes res;
    for (auto _ : state) {
        auto input = bigint::from_bytes(raw);
        input |= BigInt(1) << (raw.size() * 8); // bytes to bigint encode
        res = bigint::to_bytes(rsa::rsa(input, key_pair.public_key));
    }
    encrypted = std::move(res);
}
BENCHMARK(rsa_encrypt);


static void rsa_decrypt(benchmark::State &state)
{
    Bytes res;
    for (auto _ : state) {
        res = bigint::to_bytes(rsa::rsa(bigint::from_bytes(encrypted), key_pair.private_key), ENDIAN::LITTLE);
        if (res.back() != 1)
            throw std::runtime_error("decrypt error"); // bigint to bytes decode check
        res.pop_back();
        std::reverse(res.begin(), res.end());
    }
    if (res != raw)
        throw std::runtime_error("decrypted data not equal to raw data");
}
BENCHMARK(rsa_decrypt);
