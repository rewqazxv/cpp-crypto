#include "crypto/types.h"

#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <algorithm>
using namespace std;


namespace crypto
{

Bytes operator""_str_bytes(const char *s, size_t sz)
{
    return Bytes(s, s + sz);
}

Bytes operator""_hex_bytes(const char *_s, size_t _sz)
{
    string str;
    str.resize(_sz);
    str.erase(copy_if(_s, _s + _sz, str.begin(), [](const char ch) {
        return !isspace(ch);
    }), str.end());

    if (str.size() & 1)
        throw std::invalid_argument("hex literal for Bytes requires even-length string");
    Bytes res(str.size() / 2);
    Byte buffer[3];
    for (size_t i = 0; i < str.size(); i += 2) {
        buffer[0] = str[i];
        buffer[1] = str[i + 1];
        buffer[2] = 0;
        res[i / 2] = strtoul((char *)buffer, nullptr, 16);
    }
    return res;
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
