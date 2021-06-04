#include <benchmark/benchmark.h>

#include "crypto/crypto.h"
using namespace crypto;

#include <random>


static Bytes generate_data(size_t size)
{
    std::random_device rd;
    std::mt19937_64 reng(rd());
    std::uniform_int_distribution<int> dist(0, 0xff);

    Bytes res(size);
    for (size_t i = 0; i < size; i++)
        res[i] = dist(reng);
    return res;
}

static constexpr int RANDOM_SIZE = 10000000; // 10mb

static void random_data_prng(benchmark::State &state)
{
    for (auto _ : state) {
        auto res = generate_data(RANDOM_SIZE);
        if (res.size() != RANDOM_SIZE)
            throw std::runtime_error("random size error");
    }
}
BENCHMARK(random_data_prng);

static void random_data_csprng(benchmark::State &state)
{
    for (auto _ : state) {
        auto res = crypto::random::get_bytes(RANDOM_SIZE);
        if (res.size() != RANDOM_SIZE)
            throw std::runtime_error("random size error");
    }
}
BENCHMARK(random_data_csprng);
