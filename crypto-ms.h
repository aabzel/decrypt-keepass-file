

#ifndef _CRYPTO_H
#define _CRYPTO_H

// implementation in platform specific files: crypto-XX.c
int aes_transformkey (kdbx_header_entry_t *hdr, uint8_t *tkey, size_t tkeylen);
int aes_decrypt_check (kdbx_header_entry_t *hdr, uint8_t *masterkey, kdbx_payload_t *p);

#endif
