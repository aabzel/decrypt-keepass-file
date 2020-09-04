#ifndef PARSE_KEE_PASS_H
#define PARSE_KEE_PASS_H

#include "arrays.h"
#include "custom_type.h"

#include <stdio.h>

#define BLOCK_SIZE 32U

#define SIGNATURE 0x9AA2D903

#define KEEPASS_1X (0xB54BFB65)
#define KEEPASS_2X_PRE_RELEASE (0xB54BFB66)
#define KEEPASS_2X_POST_RELEASE (0xB54BFB67)

#define ID_END_OF_HEADER (0x00u)
#define ID_COMMENT (0x01u)
#define ID_CIPHER (0x02u)
#define ID_COMPRESSION_FLAGS (0x03u)
#define ID_MASTER_SEED (0x04u)
#define ID_TRANSFORM_SEED (0x05u)
#define ID_TRANSFORM_ROUNDS (0x06u)
#define ID_ENCRYPTION_IV (0x07u)
#define ID_PROTECTED_STREAM_KEY (0x08u)
#define ID_STREAM_START_BYTES (0x09u)
#define ID_INNER_RANDOM_STREAM (0x0Au)

// typedef uintmax_t off_t;

enum kdbx_headerid {
    END,
    COMMENT,
    CIPHERID,
    COMPRESSIONFLAGS,
    MASTER_SEED,    // 4
    TRANSFORM_SEED, // 5
    TRANSFORM_ROUNDS,
    ENCRYPTION_IV,
    PROTECTEDSTREAMKEY,
    STREAM_START_BYTES,  // 9
    INNERRANDOMSTREAMID, // 10
    HEADER_ID_COUNT      // 11
};

typedef struct kdbx_header {
    uint32_t magic;
    uint32_t identifier;
    uint16_t minor_version;
    uint16_t major_version;
} kdbx_header_t;

typedef struct kdbx_payload {
    uint64_t offset_start;
    uint64_t pos;
    uint64_t len;
    uint8_t *encrypted;
    uint8_t *decrypted;

} kdbx_payload_t;

typedef struct kdbx_header_entry {
    uint8_t id;
    uint16_t len;
    uint8_t *data;
    uint32_t dw;
    uint64_t qw;
} kdbx_header_entry_t;

typedef struct kdbx_block_header_entry {
    uint32_t id;
    uint8_t read_sha256[32];
    uint32_t len;
} kdbx_block_header_entry_t;

typedef struct kdbx_data {
    kdbx_header_t header;
    size_t data_len;
    uint8_t *data;
} kbdx_data_t;

typedef struct kdbx_database {
    kdbx_header_t fileheader;
    kdbx_header_entry_t kdbxheader[HEADER_ID_COUNT];
    kdbx_payload_t payload;
} kdbx_database_t;

typedef struct xKeePassFileHeader_t {
    uint8_t transform_seed[32];
    uint64_t transform_rounds;
    uint8_t master_seed[32];
    uint32_t compression_flags;
    uint8_t encryption_iv[32];
    uint8_t stream_start_bytes[32];
} KeePassFileHeader_t;

extern KeePassFileHeader_t keePassHeader;

bool try_to_open_kdbx_file (char *file_name, char *pass_word);

#endif /* PARSE_KEE_PASS_H */
