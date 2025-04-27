#ifndef TUOKMS_H
#define TUOKMS_H

#include <stdint.h>
#include <sodium.h>

int klutshnik_stream_encrypt(const uint8_t yc[crypto_core_ristretto255_BYTES],
                             const int infd,
                             const int outfd);

int klutshnik_decrypt_get_dek(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                              const uint8_t c[crypto_core_ristretto255_SCALARBYTES],
                              const uint8_t d[crypto_core_ristretto255_SCALARBYTES],
                              const uint8_t yc[crypto_core_ristretto255_BYTES],
                              const uint8_t beta[crypto_core_ristretto255_BYTES],
                              const uint8_t verifier_beta[crypto_core_ristretto255_BYTES],
                              uint8_t dek[crypto_secretbox_KEYBYTES]);

int klutshnik_verify_zk_proof(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                              const uint8_t c[crypto_core_ristretto255_SCALARBYTES],
                              const uint8_t d[crypto_core_ristretto255_SCALARBYTES],
                              const uint8_t yc[crypto_core_ristretto255_BYTES],
                              const uint8_t beta[crypto_core_ristretto255_BYTES],
                              const uint8_t verifier_beta[crypto_core_ristretto255_BYTES],
                              uint8_t gk[crypto_core_ristretto255_BYTES]);
#endif // TUOKMS_H
