#ifndef PADDING_H
#define PADDING_H

#include "types.h"


namespace crypto::padding
{

struct PKCS7 {
    const int BLOCK_SIZE;

    explicit PKCS7(const int block_size): BLOCK_SIZE(block_size) {}

    void pad(Byte *data, int size) const
    {
        assert(size < BLOCK_SIZE);
        Byte extend = BLOCK_SIZE - size;
        for (int i = size; i < BLOCK_SIZE; i++)
            data[i] = extend;
    }

    int unpad(const Byte *block) const
    {
        Byte extend = block[BLOCK_SIZE - 1];
        if (!(extend >= 1 && extend <= BLOCK_SIZE))
            throw std::domain_error("padding value invalid");
        for (int i = 1; i < extend; i++)
            if (block[BLOCK_SIZE - 1 - i] != extend)
                throw std::domain_error("padding data error");
        return BLOCK_SIZE - extend;
    }
}; // struct PKCS7

} // namespace crypto::padding

#endif // PADDING_H
