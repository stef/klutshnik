#ifndef TUOKMS_COMMON_H
#define TUOKMS_COMMON_H

#include <stdint.h>
#include <sodium.h>

int uokms_encrypt(const uint8_t yc[crypto_core_ristretto255_BYTES],
                  const uint8_t *obj, const size_t obj_len,
                  uint8_t w[crypto_core_ristretto255_BYTES], uint8_t *ciphertext);

int uokms_blind(const uint8_t w[crypto_core_ristretto255_BYTES],
                uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                uint8_t blinded[crypto_core_ristretto255_BYTES]);

int uokms_evaluate(const uint8_t kc[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t alpha[crypto_core_ristretto255_BYTES],
                   uint8_t beta[crypto_core_ristretto255_BYTES]);

int uokms_decrypt(const uint8_t *ciphertext, const size_t ct_len,
                  const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                  const uint8_t beta[crypto_core_ristretto255_BYTES],
                  uint8_t *plaintext);

int uokms_update_w(const uint8_t delta[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t w[crypto_core_ristretto255_BYTES]);

#endif // TUOKMS_COMMON_H
