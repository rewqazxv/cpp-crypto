cmake_minimum_required(VERSION 3.5)

project(crypto LANGUAGES CXX)

if(EXISTS ${CMAKE_SOURCE_DIR}/conanbuildinfo.cmake)
    include(conanbuildinfo.cmake)
    conan_basic_setup()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(crypto
    src/types.cpp
    src/bigint.cpp
    src/rng.cpp
    src/rsa.cpp
    src/aes.cpp
)
target_include_directories(crypto PUBLIC include)
target_link_libraries(crypto
PUBLIC
    gmp
    gmpxx
)
if(WIN32)
target_link_libraries(crypto PRIVATE Bcrypt)
endif()

add_subdirectory(tests)
