cmake_minimum_required(VERSION 3.5)

project(crypto_tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)
add_executable(crypto_tests
    test-bigint.cpp
    test-rng.cpp
    test-rsa.cpp
    test-aes.cpp
    test-padding.cpp
    test-cbc-encryptor.cpp
    test-cbc-decryptor.cpp
)
target_link_libraries(crypto_tests
PRIVATE
    gtest
    gtest_main
    crypto
)

find_package(benchmark REQUIRED)
add_executable(crypto_benchmark
    benchmark-aes128cbc.cpp
)
target_link_libraries(crypto_benchmark
PRIVATE
    benchmark::benchmark
    benchmark::benchmark_main
    crypto
)
