/*
 * Copyright (c) 2016, mod0keecrack
 *    Thorsten Schroeder <ths at modzero dot ch>
 *
 * All rights reserved.
 *
 * This file is part of mod0keecrack.
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Thorsten Schroeder <ths at modzero dot ch> wrote this file. As long as you
 * retain this notice you can do whatever you want with this stuff. If we meet
 * some day, and you think this stuff is worth it, you can buy me a beer in
 * return. Thorsten Schroeder.
 *
 * NON-MILITARY-USAGE CLAUSE
 * Redistribution and use in source and binary form for military use and
 * military research is not permitted. Infringement of these clauses may
 * result in publishing the source code of the utilizing applications and
 * libraries to the public. As this software is developed, tested and
 * reviewed by *international* volunteers, this clause shall not be refused
 * due to the matter of *national* security concerns.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE DDK PROJECT BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * File: crypto-ms.c
 * Description: Platform specific implementation of keepassx crypto functions
 *              on Microsoft Windows.
 */

#include <stdbool.h>
#include <stdio.h>

#include "aes256.h"
#include "helper.h"
#include "parse_keepass.h"

// 32 byte
int aes_transformkey (kdbx_header_entry_t *hdr, uint8_t *inOutTransformedKey, size_t tkeylen) {
    int ret = 1;
    if (0 < tkeylen) {
        ret = 1;
        uint64_t rounds = 0;
        // struct AES_ctx ctx;
        uint32_t returnlen;
        uint8_t cipher[32];
        // AES_init_ctx(&ctx, hdr[TRANSFORM_SEED].data);
        printf ("\n[*] transform_rounds: %u", (unsigned int)hdr[TRANSFORM_ROUNDS].qw);
        for (rounds = 0; rounds < hdr[TRANSFORM_ROUNDS].qw; rounds++) {
            AES256MainECB (hdr[TRANSFORM_SEED].data, inOutTransformedKey, tkeylen, cipher, &returnlen, true);
            memcpy (inOutTransformedKey, cipher, 32);
        }
    }

    return ret;
}

bool aes_decrypt_check (kdbx_header_entry_t *hdr, uint8_t *masterkey, kdbx_payload_t *payload) {
    bool res = false;
    printf ("\n[*] Master key\n");
    print_hex_buf (masterkey, 32);
    uint32_t returnlen = 0;
    memcpy (payload->decrypted, payload->encrypted, payload->len);

    printf ("\n[*] before decrypt\n");
    print_hex_buf (payload->encrypted, hdr[STREAM_START_BYTES].len);

    AES256MainCBC (masterkey, hdr[ENCRYPTION_IV].data, payload->encrypted, 32, payload->decrypted, &returnlen, false);

    if (BLOCK_SIZE != returnlen) {
        return false;
    }
    printf ("\n[*] after decrypt\n");
    print_hex_buf (payload->decrypted, hdr[STREAM_START_BYTES].len);

    printf ("\n[*] stream start data\n");
    print_hex_buf (hdr[STREAM_START_BYTES].data, hdr[STREAM_START_BYTES].len);

    if (0 == memcmp (payload->decrypted, hdr[STREAM_START_BYTES].data, hdr[STREAM_START_BYTES].len)) {
        res = true;
        payload->decrypted = malloc (hdr[STREAM_START_BYTES].len);
        memcpy (payload->decrypted, payload->encrypted, hdr[STREAM_START_BYTES].len);
    } else {
        printf ("\n[!] key error\n");
    }
    return res;
}

bool aes_decrypt_payload (kdbx_header_entry_t *hdr, uint8_t *masterkey, kdbx_payload_t *payload) {

    uint32_t cur_block_num = 0;
    uint32_t block_num = payload->len / BLOCK_SIZE;
    printf ("\n[*] number of blocks %u \n", block_num);

    uint32_t returnlen = 0;

    memset (payload->decrypted, 0, payload->len);

    AES256MainCBC (masterkey, hdr[ENCRYPTION_IV].data, &payload->encrypted[cur_block_num * BLOCK_SIZE], payload->len,
                   &payload->decrypted[cur_block_num * BLOCK_SIZE], &returnlen, false);
    if (payload->len != returnlen) {
        printf ("\n[!] Unabele to decrypt");
        return false;
    }

    printf ("\n");

    return true;
}
