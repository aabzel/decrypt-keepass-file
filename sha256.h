/* Sha256.h -- SHA-256 Hash
2010-06-11 : Igor Pavlov : Public domain */

#ifndef __CRYPTO_SHA256_H
#define __CRYPTO_SHA256_H

#include <stdint.h>
#include <stdlib.h>

typedef struct sha256_t {
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[64];
} sha256_t;

void sha256_hash (unsigned char *buf, const unsigned char *data, size_t size);

#endif
