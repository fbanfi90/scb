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

#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image.h"
#include "stb_image_write.h"

int encrypt_image(size_t max_count, size_t max_hash, char* key_path,
                  char* ptx_path, bool verbose)
{
    if (max_count + max_hash > 16)
    {
        printf("Need max_count + max_hash <= 16.\n");
        return -2;
    }

    size_t len = strlen(ptx_path);
    if (len < 4 || strncmp(ptx_path + len - 4, ".png", 4))
    {
        printf("File \"%s\" must end in \".png\".\n", ptx_path);
        return -3;
    }
    
    uint8_t key[16];
    FILE* key_file = fopen(key_path, "rb");
    if (key_file == NULL)
    {
        printf("File \"%s\" not found.\n", key_path);
        return -4;
    }
    fseek(key_file, 0, SEEK_END);
    len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);
    if (len < 16)
    {
        printf("File \"%s\" must contain at least 16 bytes.\n", key_path);
        return -5;
    }
    fread(key, sizeof(uint8_t), 16, key_file);
    fclose(key_file);

    int width, height, bpp;
    uint8_t* ptx = stbi_load(ptx_path, &width, &height, &bpp, 3);
    if (ptx == NULL)
    {
        printf("File \"%s\" not found or not a valid PNG image.\n", ptx_path);
        return -6;
    }
    stbi_image_free(ptx);
    ptx = stbi_load(ptx_path, &width, &height, &bpp, bpp);

    len = width * height * bpp;
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
    
    char* suffix = (char*)malloc(14 * sizeof(*suffix));
    char max_count_str[2];
    char max_hash_str[2];
    sprintf(max_count_str, "%zu", max_count);
    sprintf(max_hash_str, "%zu", max_hash);
    strcpy(suffix, ".enc_");
    strcat(suffix, max_count_str);
    strcat(suffix, "_");
    strcat(suffix, max_hash_str);
    strcat(suffix, ".png");
    ptx_path[strlen(ptx_path) - 4] = 0;
    strcat(ptx_path, suffix);
    stbi_write_png(ptx_path, width, height, bpp, ctx, bpp * width);

    stbi_image_free(ptx);
    free(ctx);
    free(suffix);

    return 0;
}

int encrypt_image_check(size_t max_count, size_t max_hash, char* key_path,
                        char* ptx_path)
{
    if (max_count + max_hash > 16)
    {
        printf("Need max_count + max_hash <= 16.\n");
        return -2;
    }

    size_t len = strlen(ptx_path);
    if (len < 4 || strncmp(ptx_path + len - 4, ".png", 4))
    {
        printf("File \"%s\" must end in \".png\".\n", ptx_path);
        return -3;
    }
    
    uint8_t key[16];
    FILE* key_file = fopen(key_path, "rb");
    if (key_file == NULL)
    {
        printf("File \"%s\" not found.\n", key_path);
        return -4;
    }
    fseek(key_file, 0, SEEK_END);
    len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);
    if (len < 16)
    {
        printf("File \"%s\" must contain at least 16 bytes.\n", key_path);
        return -5;
    }
    fread(key, sizeof(uint8_t), 16, key_file);
    fclose(key_file);

    int width, height, bpp;
    uint8_t* ptx = stbi_load(ptx_path, &width, &height, &bpp, 3);
    if (ptx == NULL)
    {
        printf("File \"%s\" not found or not a valid PNG image.\n", ptx_path);
        return -6;
    }
    stbi_image_free(ptx);
    ptx = stbi_load(ptx_path, &width, &height, &bpp, bpp);

    len = width * height * bpp;
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
    
    char* suffix = (char*)malloc(14 * sizeof(*suffix));
    char max_count_str[2];
    char max_hash_str[2];
    sprintf(max_count_str, "%zu", max_count);
    sprintf(max_hash_str, "%zu", max_hash);
    strcpy(suffix, ".enc_");
    strcat(suffix, max_count_str);
    strcat(suffix, "_");
    strcat(suffix, max_hash_str);
    strcat(suffix, ".png");
    ptx_path[strlen(ptx_path) - 4] = 0;
    strcat(ptx_path, suffix);
    stbi_write_png(ptx_path, width, height, bpp, ctx, bpp * width);

    stbi_image_free(ptx);
    free(ctx);
    free(dec);
    free(suffix);

    return 0;
}

int decrypt_image(size_t max_count, size_t max_hash, char* key_path,
                  char* ctx_path, bool verbose)
{
    if (max_count + max_hash > 16)
    {
        printf("Need max_count + max_hash <= 16.\n");
        return -2;
    }

    size_t len = strlen(ctx_path);
    if (len < 4 || strncmp(ctx_path + len - 4, ".png", 4))
    {
        printf("File \"%s\" must end in \".png\".\n", ctx_path);
        return -3;
    }
    
    uint8_t key[16];
    FILE* key_file = fopen(key_path, "rb");
    if (key_file == NULL)
    {
        printf("File \"%s\" not found.\n", key_path);
        return -4;
    }
    fseek(key_file, 0, SEEK_END);
    len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);
    if (len < 16)
    {
        printf("File \"%s\" must contain at least 16 bytes.\n", key_path);
        return -5;
    }
    fread(key, sizeof(uint8_t), 16, key_file);
    fclose(key_file);
    
    int width, height, bpp;
    uint8_t* ctx = stbi_load(ctx_path, &width, &height, &bpp, 3);
    if (ctx == NULL)
    {
        printf("File \"%s\" not found or not a valid PNG image.\n", ctx_path);
        return -6;
    }
    stbi_image_free(ctx);
    ctx = stbi_load(ctx_path, &width, &height, &bpp, bpp);

    len = width * height * bpp;
    uint8_t* dec = (uint8_t*)malloc(len);
    scb_state mem = NULL;
    if (verbose) printf("SCB decrypting ... ");
    scb_decrypt(key, ctx, dec, len, max_count, max_hash, &mem);
    if (verbose) printf("Done.\n");

    char* suffix = (char*)malloc(9 * sizeof(*suffix));
    strcpy(suffix, ".dec.png");
    ctx_path[strlen(ctx_path) - 4] = 0;
    strcat(ctx_path, suffix);
    stbi_write_png(ctx_path, width, height, bpp, dec, bpp * width);

    stbi_image_free(ctx);
    free(dec);
    free(suffix);

    return 0;
}

int ecb_encrypt_image(char* key_path, char* ptx_path, bool verbose)
{
    size_t len = strlen(ptx_path);
    if (len < 4 || strncmp(ptx_path + len - 4, ".png", 4))
    {
        printf("File \"%s\" must end in \".png\".\n", ptx_path);
        return -3;
    }
    
    uint8_t key[16];
    FILE* key_file = fopen(key_path, "rb");
    if (key_file == NULL)
    {
        printf("File \"%s\" not found.\n", key_path);
        return -4;
    }
    fseek(key_file, 0, SEEK_END);
    len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);
    if (len < 16)
    {
        printf("File \"%s\" must contain at least 16 bytes.\n", key_path);
        return -5;
    }
    fread(key, sizeof(uint8_t), 16, key_file);
    fclose(key_file);

    int width, height, bpp;
    uint8_t* ptx = stbi_load(ptx_path, &width, &height, &bpp, 3);
    if (ptx == NULL)
    {
        printf("File \"%s\" not found or not a valid PNG image.\n", ptx_path);
        return -6;
    }
    stbi_image_free(ptx);
    ptx = stbi_load(ptx_path, &width, &height, &bpp, bpp);

    len = width * height * bpp;
    uint8_t* ecb = (uint8_t*)malloc(len);
    if (verbose) printf("ECB encrypting ... ");
    ecb_encrypt(key, ptx, ecb, len);
    if (verbose) printf("Done.\n");

    char* suffix = (char*)malloc(9 * sizeof(*suffix));
    strcpy(suffix, ".ecb.png");
    ptx_path[strlen(ptx_path) - 4] = 0;
    strcat(ptx_path, suffix);
    stbi_write_png(ptx_path, width, height, bpp, ecb, bpp * width);

    stbi_image_free(ptx);
    free(ecb);
    free(suffix);

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
            return encrypt_image_check(max_count, max_hash, argv[4], argv[5]);
        else if (!strncmp(argv[1], "enc", 3))
            return encrypt_image(max_count, max_hash, argv[4], argv[5],
                                 verbose);
        else if (!strncmp(argv[1], "dec", 3))
            return decrypt_image(max_count, max_hash, argv[4], argv[5],
                                 verbose);
        else if (!strncmp(argv[1], "ecb", 3))
            return ecb_encrypt_image(argv[4], argv[5], verbose);
    }

    printf("Usage: scb_image enc[+]|dec|ecb max_count max_hash key_path " \
           "input_file.png [verbose]\n");
    
    return 0;
}