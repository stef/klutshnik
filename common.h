#ifndef TUOKMS_COMMON_H
#define TUOKMS_COMMON_H

#include <stdint.h>
#include <sodium.h>

int uokms_encrypt(const uint8_t yc[crypto_core_ristretto255_BYTES],
                  const uint8_t *obj, const size_t obj_len,
                  uint8_t w[crypto_core_ristretto255_BYTES], uint8_t *ciphertext);

int uokms_update_w(const uint8_t delta[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t w[crypto_core_ristretto255_BYTES]);

#endif // TUOKMS_COMMON_H
