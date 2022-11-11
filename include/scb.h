// Copyright (C) 2022 Fabio Banfi. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#ifndef SCB_H
#define SCB_H

#include <stdint.h>

#define USE_SHA // Use MD4 if undefined (faster).

#include "hashmap.h"

typedef struct hashmap* scb_state;

void scb_encrypt(const uint8_t* key, const uint8_t* ptx, uint8_t* ctx,
                 const size_t len, const size_t max_count,
                 const size_t max_hash, scb_state* mem);

void scb_decrypt(const uint8_t* key, const uint8_t* ctx, uint8_t* ptx,
                 const size_t len, const size_t max_count,
                 const size_t max_hash, scb_state* mem);

#endif