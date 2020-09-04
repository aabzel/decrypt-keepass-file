
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
