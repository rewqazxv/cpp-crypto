#ifndef RNG_H
#define RNG_H

#include "types.h"


namespace crypto::random
{

// CSPRNG, depends on operating system
Bytes get_bytes(int size);

} // namespace crypto::random

#endif // RNG_H
