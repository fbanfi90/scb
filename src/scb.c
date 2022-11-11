// Copyright (C) 2022 Fabio Banfi. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

#include <openssl/aes.h>
#include <openssl/md4.h>
#include <openssl/sha.h>

#include "hashmap.h"
#include "scb.h"

typedef struct hash_to_count { size_t hash; size_t count; } hash_to_count;
typedef struct hash_to_block { size_t hash; uint8_t* block; } hash_to_block;

int compare_int(const void* in0, const void* in1, void* udata)
{
    return *(size_t*)in0 - *(size_t*)in1;
}

uint64_t hash_int(const void* item, uint64_t seed0, uint64_t seed1)
{
    return hashmap_sip((size_t*)item, sizeof(size_t), seed0, seed1);
}

void block_encode(const uint8_t* key, const uint8_t* ptx, uint8_t* ctx)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(ptx, ctx, &aes_key);      
}

void block_decode(const uint8_t* key, const uint8_t* ctx, uint8_t* ptx)
{
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    AES_decrypt(ctx, ptx, &aes_key);
}

void block_hash(const uint8_t* in, uint8_t* out)
{
#ifndef USE_SHA
    MD4(in, 16, out);
#else
    uint8_t hash[32];

    //SHA256(in, 16, hash); // slower
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, in, 16);
    SHA256_Final(hash, &sha);
    
    memcpy(out, hash, 16);
#endif
}

size_t bytes_to_int(const uint8_t* in, const size_t max)
{
    size_t out = 0;
    for (size_t i = 0; i < max; ++i)
        out += in[15 - i] * ((size_t)1 << 8 * i);
    return out;
}

void block_xor(const uint8_t* in0, const uint8_t* in1, uint8_t* out)
{
    for (size_t i = 0; i < 16; ++i)
        out[i] = in0[i] ^ in1[i];
}

void scb_block_encrypt(const uint8_t* key, const uint8_t* ptx, uint8_t* ctx,
                       const size_t max_count, const size_t max_hash,
                       scb_state* mem)
{
    uint8_t hash_[16];
    block_hash(ptx, hash_);
    size_t hash = bytes_to_int(hash_, max_hash);
    hash_to_count* h2c = hashmap_get(*mem, &(hash_to_count){ .hash = hash });
    
    if (h2c == NULL)
    {
        block_encode(key, ptx, ctx);
        hashmap_set(*mem, &(hash_to_count){ .hash = hash, .count = 0 });
    }
    else
    {
        for (size_t j = 0; j < max_count; ++j)
            hash_[15 - max_hash - j] = ((h2c->count) >> j * 8) & 0xFF;
        for (size_t j = 0; j < 16 - max_count - max_hash; ++j)
            hash_[j] = 0;
        
        uint8_t xor_[16];
        block_xor(key, hash_, xor_);
        block_encode(key, xor_, ctx);
        hashmap_set(*mem, &(hash_to_count){ .hash = hash,
                                            .count = h2c->count + 1 });
    }
}

void scb_block_decrypt(const uint8_t* key, const uint8_t* ctx, uint8_t* ptx,
                       const size_t max_count, const size_t max_hash,
                       scb_state* mem)
{
    uint8_t xor_[16];
    block_decode(key, ctx, ptx);
    block_xor(key, ptx, xor_);
    
    bool rep = true;
    for (size_t j = 0; j < 16 - (max_count + max_hash); ++j)
    {
        if (xor_[j] != 0)
        {
            rep = false;
            break;
        }
    }
    
    size_t hash = bytes_to_int(xor_, max_hash);
    hash_to_block* h2b = hashmap_get(*mem, &(hash_to_block){ .hash = hash });

    if (rep && h2b != NULL)
    {
        memcpy(ptx, h2b->block, 16 * sizeof(uint8_t));
    }
    else
    {
        uint8_t hash_[16];
        block_hash(ptx, hash_);
        
        size_t hash = bytes_to_int(hash_, max_hash);
        hashmap_set(*mem, &(hash_to_block){ .hash = hash, .block = ptx });
    }
}

void scb_encrypt(const uint8_t* key, const uint8_t* ptx, uint8_t* ctx,
                 const size_t len, const size_t max_count,
                 const size_t max_hash, scb_state* mem)
{
    if (*mem == NULL)
        *mem = hashmap_new(sizeof(hash_to_count), 0, 0, 0, hash_int,
                           compare_int, NULL, NULL);
    
    size_t l = ceil(len / 16.);
    for (size_t i = 0; i < l - 1; ++i)
        scb_block_encrypt(key, ptx + i * 16, ctx + i * 16, max_count,
                          max_hash, mem);
    
    size_t m = len % 16;
    if (m == 0)
    {
        scb_block_encrypt(key, ptx + (l - 1) * 16, ctx + (l - 1) * 16,
                          max_count, max_hash, mem);
    }
    else
    {
        uint8_t block[16];
        memcpy(ctx + (l - 1) * 16, ctx + (l - 2) * 16, m * sizeof(uint8_t));
        memcpy(block, ptx + (l - 1) * 16, m * sizeof(uint8_t));
        memcpy(block + m, ctx + (l - 2) * 16 + m, (16 - m) * sizeof(uint8_t));
        scb_block_encrypt(key, block, ctx + (l - 2) * 16, max_count,
                          max_hash, mem);
    }
}

void scb_decrypt(const uint8_t* key, const uint8_t* ctx, uint8_t* ptx,
                 const size_t len, const size_t max_count,
                 const size_t max_hash, scb_state* mem)
{
    if (*mem == NULL)
        *mem = hashmap_new(sizeof(hash_to_block), 0, 0, 0, hash_int,
                           compare_int, NULL, NULL);
    
    size_t l = ceil(len / 16.);
    for (size_t i = 0; i < l - 1; ++i)
        scb_block_decrypt(key, ctx + i * 16, ptx + i * 16, max_count,
                          max_hash, mem);
    
    size_t m = len % 16;
    if (m == 0)
    {
        scb_block_decrypt(key, ctx + (l - 1) * 16, ptx + (l - 1) * 16,
                          max_count, max_hash, mem);
    }
    else
    {
        uint8_t block[16];
        memcpy(ptx + (l - 1) * 16, ptx + (l - 2) * 16, m * sizeof(uint8_t));
        memcpy(block, ctx + (l - 1) * 16, m * sizeof(uint8_t));
        memcpy(block + m, ptx + (l - 2) * 16 + m, (16 - m) * sizeof(uint8_t));
        scb_block_decrypt(key, block, ptx + (l - 2) * 16, max_count,
                          max_hash, mem);
    }
}