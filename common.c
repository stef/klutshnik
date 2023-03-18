#include <stdint.h>
#include <sodium.h>
#include <unistd.h>
#include "utils.h"
#include "streamcrypt.h"

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

int uokms_stream_encrypt(const uint8_t yc[crypto_core_ristretto255_BYTES],
                         const int infd,
                         const int outfd) {
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(r);

  // certified public value for client
  uint8_t w[crypto_core_ristretto255_BYTES];
  crypto_scalarmult_ristretto255_base(w, r);

  write(outfd, w, crypto_core_ristretto255_BYTES);

  uint8_t tmp[crypto_core_ristretto255_BYTES];
  if(crypto_scalarmult_ristretto255(tmp, r, yc)) return 1;

  uint8_t dek[crypto_secretbox_KEYBYTES];
  crypto_generichash(dek, sizeof dek, tmp, sizeof tmp, NULL, 0);

  return stream_encrypt(infd, outfd, dek);
}

int uokms_update_w(const uint8_t delta[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t w[crypto_core_ristretto255_BYTES]) {
  if(crypto_scalarmult_ristretto255(w, delta, w)) {
    fail("failed to update w");
    return 1;
  }
  return 0;
}
