#include <stdint.h>
#include <sodium.h>
#include "utils.h"

int uokms_encrypt(const uint8_t yc[crypto_core_ristretto255_BYTES],
                   const uint8_t *obj, const size_t obj_len,
                   uint8_t w[crypto_core_ristretto255_BYTES], uint8_t *ciphertext) {
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(r);

  // certified public value for client
  crypto_scalarmult_ristretto255_base(w, r);

  uint8_t tmp[crypto_core_ristretto255_BYTES];
  if(crypto_scalarmult_ristretto255(tmp, r, yc)) return 1;

  uint8_t dek[crypto_secretbox_KEYBYTES];
  crypto_generichash(dek, sizeof dek, tmp, sizeof tmp, NULL, 0);

  // nonce
  randombytes_buf(ciphertext, crypto_secretbox_NONCEBYTES);
  crypto_secretbox_easy(ciphertext+crypto_secretbox_NONCEBYTES, obj, obj_len, ciphertext, dek);

  return 0;
}

int uokms_blind(const uint8_t w[crypto_core_ristretto255_BYTES],
                uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                uint8_t blinded[crypto_core_ristretto255_BYTES]) {
  // check if w is a valid point
  if(!crypto_core_ristretto255_is_valid_point(w)) return 1;

  crypto_core_ristretto255_scalar_random(r);

  if(crypto_scalarmult_ristretto255(blinded, r, w)) return 1;

  return 0;
}

int uokms_evaluate(const uint8_t kc[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t alpha[crypto_core_ristretto255_BYTES],
                   uint8_t beta[crypto_core_ristretto255_BYTES]) {
  // check if w is a valid point
  if(!crypto_core_ristretto255_is_valid_point(alpha)) return 1;

  if(crypto_scalarmult_ristretto255(beta, kc, alpha)) return 1;
  return 0;
}

int uokms_decrypt(const uint8_t *ciphertext, const size_t ct_len,
                  const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                  const uint8_t beta[crypto_core_ristretto255_BYTES],
                  uint8_t *plaintext) {
  // check if beta is a valid point
  if(!crypto_core_ristretto255_is_valid_point(beta)) {
    fail("failed invalid beta");
    return 1;
  }

  // 1/r
  uint8_t r_inv[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_invert(r_inv, r);

  // beta * 1/r
  uint8_t tmp[crypto_core_ristretto255_BYTES];
  if(crypto_scalarmult_ristretto255(tmp, r_inv, beta)) {
    fail("failed to divide by r");
    return 1;
  }

  // H(beta * 1/r)
  uint8_t dek[crypto_secretbox_KEYBYTES];
  crypto_generichash(dek, sizeof dek, tmp, sizeof tmp, NULL, 0);

  if (crypto_secretbox_open_easy(plaintext, ciphertext+crypto_secretbox_NONCEBYTES, ct_len-crypto_secretbox_NONCEBYTES, ciphertext, dek) != 0) {
    /* message forged! */
    fail("failed message forged");
    return 1;
  }

  return 0;
}

int uokms_update_w(const uint8_t delta[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t w[crypto_core_ristretto255_BYTES]) {
  if(crypto_scalarmult_ristretto255(w, delta, w)) {
    fail("failed to update w");
    return 1;
  }
  return 0;
}
