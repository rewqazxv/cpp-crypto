#ifndef TYPES_H
#define TYPES_H

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <ostream>


namespace crypto
{

typedef std::uint8_t Byte;
typedef std::vector<Byte> Bytes;

// convenient functions for debug and test use
Bytes operator""_str_bytes(const char *s, std::size_t sz);
Bytes operator""_hex_bytes(const char *s, std::size_t sz);
std::ostream &operator<<(std::ostream &out, const Bytes &data);

enum ENDIAN {
    BIG = 1,
    LITTLE = -1
};

typedef int64_t SignedSize;

} // namespace crypto

#endif // TYPES_H
