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
        res = bigint::to_bytes(rsa::rsa(bigint::from_bytes(raw), key_pair.public_key));
    }
    encrypted = std::move(res);
}
BENCHMARK(rsa_encrypt);


static void rsa_decrypt(benchmark::State &state)
{
    Bytes res;
    for (auto _ : state) {
        res = bigint::to_bytes(rsa::rsa(bigint::from_bytes(encrypted), key_pair.private_key));
    }
    if (res != raw)
        throw std::runtime_error("decrypted data not equal to raw data");
}
BENCHMARK(rsa_decrypt);
