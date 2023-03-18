#ifndef STREAMCRYPT_H
#define STREAMCRYPT_H

#include <sodium.h>

int stream_encrypt(const int infd,
                   const int outfd,
                   const uint8_t w[crypto_core_ristretto255_BYTES],
                   const uint8_t dek[crypto_secretbox_KEYBYTES]);
int stream_decrypt(const int infd,
                   const int outfd,
                   const uint8_t w[crypto_core_ristretto255_BYTES],
                   const uint8_t dek[crypto_secretbox_KEYBYTES]);
#endif // STREAMCRYPT_H
