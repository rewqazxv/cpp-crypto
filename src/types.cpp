#include "crypto/types.h"

#include "crypto/bigint.h"

#include <cctype>
#include <iomanip>
using namespace std;


namespace crypto
{

Bytes operator""_bytes(const char *s, size_t sz)
{
    return Bytes(s, s + sz);
}

Bytes operator""_hex(const char *s, size_t sz)
{
    if (sz & 1)
        throw std::invalid_argument("hex literal for Bytes requires even-length string");
    return bigint::to_bytes(BigInt(s, 16));
}

ostream &operator<<(ostream &out, const Bytes &data)
{
    ios state(nullptr);
    out << "{";

    out << "size: " << data.size() << ", ";

    out << "data: [";
    state.copyfmt(out);
    out << hex << uppercase << setfill('0');
    for (size_t i = 0; i < data.size(); i++) {
        out << setw(2) << int(data[i]);
        if (i != data.size() - 1) out << ' ';
    }
    out.copyfmt(state);
    out << "]";

    bool is_string = false;
    for (auto i : data)
        if (isalnum(i)) {
            is_string = true;
            break;
        }
    if (is_string) {
        out << ", string: \"";
        for (auto i : data) {
            if (isalnum(i) || i == ' ') {
                out << char(i);
            } else {
                state.copyfmt(out);
                out << "\\x" << hex << uppercase << setfill('0') << setw(2) << int(i);
                out.copyfmt(state);
            }
        }
        out << "\"";
    }

    out << "}";
    return out;
}

} // namespace crypto
