#ifndef CBC_H
#define CBC_H

#include "types.h"
#include "padding.h"
#include <algorithm>
#include <utility>


namespace crypto
{

template<typename Method, typename PaddingMode = padding::PKCS7>
class CbcMode
{
public:
    static const int BLOCK_SIZE = Method::BLOCK_SIZE;
    static constexpr SignedSize output_buffer_size(const SignedSize input_size)
    { return input_size + 2 * BLOCK_SIZE; }

    template <typename...MethodArgs>
    CbcMode(
        const Byte iv_block[BLOCK_SIZE],
        MethodArgs &&...method_args
    ): method(std::forward<MethodArgs>(method_args)...), padding_mode(BLOCK_SIZE)
    {
        if (!iv_block)
            throw std::invalid_argument("iv block cannot be null");
        saved_xor_block.assign(iv_block, iv_block + BLOCK_SIZE);
        cache.reserve(BLOCK_SIZE);
    }
    CbcMode(const CbcMode &) = delete;
    virtual ~CbcMode() = default;

    virtual SignedSize use(const Byte *input, SignedSize input_size, Byte *output, SignedSize output_size) = 0;
    virtual SignedSize finish(Byte *output, SignedSize output_size) = 0;
    virtual SignedSize finish(const Byte *input, SignedSize input_size, Byte *output, SignedSize output_size)
    {
        SignedSize writed = use(input, input_size, output, output_size);
        writed += finish(output + writed, output_size - writed);
        return writed;
    }

    class Encryptor;
    class Decryptor;

protected:
    const Method method;
    const PaddingMode padding_mode;
    Bytes saved_xor_block; // iv if first use
    Bytes cache;
}; // template class CbcMode


template<typename Method, typename PaddingMode>
class CbcMode<Method, PaddingMode>::Encryptor: public CbcMode<Method, PaddingMode>
{
    void cbc_encrypt(Byte *block, const Byte *xor_block)
    {
        for (int i = 0; i < BLOCK_SIZE; i++)
            block[i] ^= xor_block[i];
        method.encrypt(block);
    }
public:
    using CbcMode::CbcMode;

    // processes [0,inf) bytes, sets cache and saved_xor_block
    SignedSize use(const Byte *input, SignedSize input_size, Byte *output, SignedSize output_size) override
    {
        if (input_size <= 0)
            return 0;

        // integrate input
        SignedSize full_size =  cache.size() + input_size;
        if (output_size < full_size)
            throw std::runtime_error("output buffer too small");
        SignedSize complete_size = full_size / BLOCK_SIZE * BLOCK_SIZE;
        std::copy_n(cache.data(), cache.size(), output);
        std::copy_n(input, input_size, output + cache.size());

        // update cache
        cache.assign(output + complete_size, output + full_size);
        std::fill(output + complete_size, output + full_size, 0); // overwrite unused plain data

        // encrypt each block
        if (complete_size > 0) {
            // load status
            const Byte *last_xor = saved_xor_block.data();

            for (Byte *dst = output, *dst_end = output + complete_size; dst != dst_end; dst += BLOCK_SIZE) {
                cbc_encrypt(dst, last_xor);
                last_xor = dst;
            }

            // save status
            saved_xor_block.assign(last_xor, last_xor + BLOCK_SIZE);
        }

        return complete_size;
    }

    using CbcMode::finish;

    // padding the last block, after which this object will be unavailable
    SignedSize finish(Byte *output, SignedSize output_size) override
    {
        if (output_size < BLOCK_SIZE)
            throw std::runtime_error("output buffer too small");
        std::copy_n(cache.data(), cache.size(), output);
        padding_mode.pad(output, cache.size());
        cbc_encrypt(output, saved_xor_block.data());
        return BLOCK_SIZE;
    }
}; // template class CbcMode::Encryptor


template<typename Method, typename PaddingMode>
class CbcMode<Method, PaddingMode>::Decryptor: public CbcMode<Method, PaddingMode>
{
    void cbc_decrypt(Byte *block, const Byte *xor_block)
    {
        method.decrypt(block);
        for (int i = 0; i < BLOCK_SIZE; i++)
            block[i] ^= xor_block[i];
    }
public:
    using CbcMode::CbcMode;

    SignedSize use(const Byte *input, SignedSize input_size, Byte *output, SignedSize output_size) override
    {
        if (input_size <= 0)
            return 0;

        // integrate input
        SignedSize full_size =  cache.size() + input_size;
        if (output_size < full_size)
            throw std::runtime_error("output buffer too small");
        SignedSize complete_size = (full_size - 1) / BLOCK_SIZE * BLOCK_SIZE; // reserve 1 block
        std::copy_n(cache.data(), cache.size(), output);
        std::copy_n(input, input_size, output + cache.size());

        // update cache
        cache.assign(output + complete_size, output + full_size);

        // decrypt each block
        if (complete_size > 0) {
            Byte *output_end = output + complete_size;

            // save last encrypted block
            Byte pre_xor_block[BLOCK_SIZE];
            std::copy_n(saved_xor_block.data(), BLOCK_SIZE, pre_xor_block);
            saved_xor_block.assign(output_end - BLOCK_SIZE, output_end);

            // decrypt data in reverse order
            for (Byte *dst = output_end - BLOCK_SIZE, *dst_end = output - BLOCK_SIZE; dst != dst_end; dst -= BLOCK_SIZE) {
                Byte *xor_block = dst == output ? pre_xor_block : dst - BLOCK_SIZE;
                cbc_decrypt(dst, xor_block);
            }
        }

        return complete_size;
    }

    using CbcMode::finish;

    SignedSize finish(Byte *output, SignedSize output_size) override
    {
        if (output_size < BLOCK_SIZE)
            throw std::runtime_error("output buffer too small");
        if (cache.size() != BLOCK_SIZE)
            throw std::domain_error("incomplete data");
        std::copy_n(cache.data(), cache.size(), output);
        cbc_decrypt(output, saved_xor_block.data());
        return padding_mode.unpad(output);
    }
}; // template class CbcMode::Decryptor

} // namespace crypto

#endif // CBC_H
