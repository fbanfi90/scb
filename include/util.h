// Copyright (C) 2022 Fabio Banfi. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/evp.h>

void ecb_encrypt(const uint8_t* key, const uint8_t* ptx, uint8_t* ctx,
                 const size_t len)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    for (size_t i = 0; i < len / 16; ++i)
        AES_encrypt(ptx + i * 16, ctx + i * 16, &aes_key);   
}

size_t block_diff(const uint8_t* in0, const uint8_t* in1, const size_t len)
{
    size_t d = 0;

    for (size_t i = 0; i < len / 16; ++i)
    {
        for (size_t j = 0; j < 16; ++j)
        {
            if (in0[16 * i + j] != in1[16 * i + j])
            {
                ++d;
                break;
            }
        }
    }
    
    return d;
}

#endif