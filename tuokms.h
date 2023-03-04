#ifndef TUOKMS_H
#define TUOKMS_H

#include <stdint.h>
#include <sodium.h>

int tuokms_evaluate(const uint8_t kc[crypto_core_ristretto255_SCALARBYTES],
                    const uint8_t alpha[crypto_core_ristretto255_BYTES],
                    const uint8_t verifier[crypto_core_ristretto255_BYTES],
                    uint8_t beta[crypto_core_ristretto255_BYTES],
                    uint8_t verifier_beta[crypto_core_ristretto255_BYTES]);
#endif // TUOKMS_H
