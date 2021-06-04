cmake_minimum_required(VERSION 3.5)

project(crypto_tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(crypto_tests
    test-bigint.cpp
    test-rng.cpp
    test-rsa.cpp
    test-aes.cpp
    test-padding.cpp
    test-cbc-encrypter.cpp
    test-cbc-decrypter.cpp
    test-types.cpp
)
target_link_libraries(crypto_tests
PRIVATE
    gtest
    gtest_main
    crypto
)

add_executable(crypto_benchmark
    benchmark-aes128cbc.cpp
    benchmark-rsa.cpp
    benchmark-random.cpp
)
target_link_libraries(crypto_benchmark
PRIVATE
    benchmark
    benchmark_main
    crypto
)
if(WIN32)
    target_link_libraries(crypto_benchmark PRIVATE Shlwapi)
endif()
