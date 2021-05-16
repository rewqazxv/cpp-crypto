#ifndef AES_H
#define AES_H

#include <memory>
#include "types.h"


namespace crypto
{

class AES
{
    Byte keymat[11][16];
public:
    static const int BLOCK_SIZE = 16;

    AES(const Byte *key, int size);
    AES(const Bytes &key);

    void encrypt(Byte block[BLOCK_SIZE]) const;
    void decrypt(Byte block[BLOCK_SIZE]) const;
}; // class AES

} // namespace crypto

#endif // AES_H
