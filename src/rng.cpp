#include "crypto/rng.h"


#if defined(__linux__)
#include <sys/random.h>
#include <cassert>

namespace crypto::random
{

Bytes get_bytes(int size)
{
    Bytes res(size);
    ssize_t cnt = 0;
    do {
        ssize_t sz = getrandom(res.data() + cnt, size - cnt, 0);
        if (sz < 0)
            throw std::runtime_error("linux getrandom() error");
        cnt += sz;
    } while (cnt < size);
    assert(cnt == size);
    return res;
}

} // namespace crypto::random
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>

namespace crypto::random
{

Bytes get_bytes(int size)
{
    Bytes res(size);
    NTSTATUS status = BCryptGenRandom(NULL, res.data(), res.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
        throw std::runtime_error("windows BCryptGenRandom call error");
    return res;
}

} // namespace crypto::random
#else
// todo
#endif
