// Copyright (C) 2022 Fabio Banfi. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "scb.h"
#include "util.h"

int encrypt_file(size_t max_count, size_t max_hash, char* key_path,
                 char* ptx_path, bool verbose)
{
    if (max_count + max_hash > 16)
    {
        printf("Need max_count + max_hash <= 16.\n");
        return -2;
    }
    
    uint8_t key[16];
    FILE* key_file = fopen(key_path, "rb");
    if (key_file == NULL)
    {
        printf("File \"%s\" not found.\n", key_path);
        return -3;
    }
    fseek(key_file, 0, SEEK_END);
    size_t len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);
    if (len < 16)
    {
        printf("File \"%s\" must contain at least 16 bytes.\n", key_path);
        return -4;
    }
    fread(key, sizeof(uint8_t), 16, key_file);
    fclose(key_file);

    FILE* ptx_file = fopen(ptx_path, "rb");
    if (ptx_file == NULL)
    {
        printf("File \"%s\" not found.\n", ptx_path);
        return -5;
    }
    fseek(ptx_file, 0, SEEK_END);
    len = ftell(ptx_file);
    fseek(ptx_file, 0, SEEK_SET);
    uint8_t* ptx = (uint8_t*)malloc(len);
    fread(ptx, sizeof(*ptx), len, ptx_file);
    fclose(ptx_file);
    
    uint8_t* ctx = (uint8_t*)malloc(len);
    scb_state mem = NULL;
    if (verbose)
        printf("SCB encrypting ... ");
    scb_encrypt(key, ptx, ctx, len, max_count, max_hash, &mem);
    if (verbose)
        printf(len <= ((size_t)1 << max_count * 8) ?
               "Done (SECURE: %zu <= %zu).\n" :
               "Done (INSECURE: %zu > %zu).\n",
               len, (size_t)1 << max_count * 8);
    
    char* ctx_path = (char*)malloc((strlen(ptx_path) + 10) * sizeof(*ptx_path));
    char max_count_str[2];
    char max_hash_str[2];
    sprintf(max_count_str, "%zu", max_count);
    sprintf(max_hash_str, "%zu", max_hash);
    strcpy(ctx_path, ptx_path);
    strcat(ctx_path, ".enc_");
    strcat(ctx_path, max_count_str);
    strcat(ctx_path, "_");
    strcat(ctx_path, max_hash_str);

    FILE* ctx_file = fopen(ctx_path, "wb");
    fwrite(ctx, sizeof(*ctx), len, ctx_file);
    fclose(ctx_file);

    free(ptx);
    free(ctx);
    free(ctx_path);

    return 0;
}

int encrypt_file_check(size_t max_count, size_t max_hash, char* key_path,
                       char* ptx_path)
{
    if (max_count + max_hash > 16)
    {
        printf("Need max_count + max_hash <= 16.\n");
        return -2;
    }
    
    uint8_t key[16];
    FILE* key_file = fopen(key_path, "rb");
    if (key_file == NULL)
    {
        printf("File \"%s\" not found.\n", key_path);
        return -3;
    }
    fseek(key_file, 0, SEEK_END);
    size_t len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);
    if (len < 16)
    {
        printf("File \"%s\" must contain at least 16 bytes.\n", key_path);
        return -4;
    }
    fread(key, sizeof(uint8_t), 16, key_file);
    fclose(key_file);

    FILE* ptx_file = fopen(ptx_path, "rb");
    if (ptx_file == NULL)
    {
        printf("File \"%s\" not found.\n", ptx_path);
        return -5;
    }
    fseek(ptx_file, 0, SEEK_END);
    len = ftell(ptx_file);
    fseek(ptx_file, 0, SEEK_SET);
    uint8_t* ptx = (uint8_t*)malloc(len);
    fread(ptx, sizeof(*ptx), len, ptx_file);
    fclose(ptx_file);
    
    uint8_t* ctx = (uint8_t*)malloc(len);
    uint8_t* dec = (uint8_t*)malloc(len);
    scb_state mem_enc = NULL;
    scb_state mem_dec = NULL;
    printf("SCB encrypting ... ");
    scb_encrypt(key, ptx, ctx, len, max_count, max_hash, &mem_enc);
    scb_decrypt(key, ctx, dec, len, max_count, max_hash, &mem_dec);
    printf(len <= ((size_t)1 << max_count * 8) ?
           "Done (SECURE: %zu <= %zu; ERRORS: %zu).\n" :
           "Done (INSECURE: %zu > %zu; ERRORS: %zu).\n",
           len, (size_t)1 << max_count * 8, block_diff(ptx, dec, len));
    
    char* ctx_path = (char*)malloc((strlen(ptx_path) + 10) * sizeof(*ptx_path));
    char max_count_str[2];
    char max_hash_str[2];
    sprintf(max_count_str, "%zu", max_count);
    sprintf(max_hash_str, "%zu", max_hash);
    strcpy(ctx_path, ptx_path);
    strcat(ctx_path, ".enc_");
    strcat(ctx_path, max_count_str);
    strcat(ctx_path, "_");
    strcat(ctx_path, max_hash_str);

    FILE* ctx_file = fopen(ctx_path, "wb");
    fwrite(ctx, sizeof(*ctx), len, ctx_file);
    fclose(ctx_file);

    free(ptx);
    free(ctx);
    free(dec);
    free(ctx_path);
    
    return 0;
}

int decrypt_file(size_t max_count, size_t max_hash, char* key_path,
                 char* ctx_path, bool verbose)
{
    if (max_count + max_hash > 16)
    {
        printf("Need max_count + max_hash <= 16.\n");
        return -2;
    }

    uint8_t key[16];
    FILE* key_file = fopen(key_path, "rb");
    if (key_file == NULL)
    {
        printf("File \"%s\" not found.\n", key_path);
        return -3;
    }
    fseek(key_file, 0, SEEK_END);
    size_t len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);
    if (len < 16)
    {
        printf("File \"%s\" must contain at least 16 bytes.\n", key_path);
        return -4;
    }
    fread(key, sizeof(uint8_t), 16, key_file);
    fclose(key_file);

    FILE* ctx_file = fopen(ctx_path, "rb");
    if (ctx_file == NULL)
    {
        printf("File \"%s\" not found.\n", ctx_path);
        return -5;
    }
    fseek(ctx_file, 0, SEEK_END);
    len = ftell(ctx_file);
    fseek(ctx_file, 0, SEEK_SET);
    uint8_t* ctx = (uint8_t*)malloc(len);
    fread(ctx, sizeof(*ctx), len, ctx_file);
    fclose(ctx_file);
    
    uint8_t* dec = (uint8_t*)malloc(len);
    scb_state mem = NULL;
    if (verbose)
        printf("SCB decrypting ... ");
    scb_decrypt(key, ctx, dec, len, max_count, max_hash, &mem);
    if (verbose)
        printf("Done.\n");
    
    char* dec_path = (char*)malloc((strlen(ctx_path) + 5) * sizeof(*ctx_path));
    strcpy(dec_path, ctx_path);
    strcat(dec_path, ".dec");
    
    FILE* dec_file = fopen(dec_path, "wb");
    fwrite(dec, sizeof(*dec), len, dec_file);
    fclose(dec_file);

    free(ctx);
    free(dec);
    free(dec_path);

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc == 6 || argc == 7)
    {
        size_t max_count; // SEC (sigma / 8)
        size_t max_hash; // COR (tau / 8)
        int ret = sscanf(argv[2], "%zu", &max_count);
        if (ret != 1 || max_count < 1 || max_count > 16)
        {
            printf("max_count and max_hash must be values between 1 and 16.\n");
            return -1;
        }
        ret = sscanf(argv[3], "%zu", &max_hash);
        if (ret != 1 || max_hash < 1 || max_hash > 16)
        {
            printf("max_count and max_hash must be values between 1 and 16.\n");
            return -1;
        }
        
        bool verbose = argc == 7 && !strncmp(argv[6], "verbose", 7);
        if (!strncmp(argv[1], "enc+", 4))
            return encrypt_file_check(max_count, max_hash, argv[4], argv[5]);
        else if (!strncmp(argv[1], "enc", 3))
            return encrypt_file(max_count, max_hash, argv[4], argv[5], verbose);
        else if (!strncmp(argv[1], "dec", 3))
            return decrypt_file(max_count, max_hash, argv[4], argv[5], verbose);
    }
    
    printf("Usage: scb_file enc[+]|dec max_count max_hash key_path " \
           "input_file [verbose]\n");
    
    return 0;
}