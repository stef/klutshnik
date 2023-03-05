#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "utils.h"


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

void uokms_update_kc(uint8_t kc[crypto_core_ristretto255_SCALARBYTES],
                    uint8_t yc[crypto_core_ristretto255_BYTES],
                    uint8_t delta[crypto_core_ristretto255_SCALARBYTES]) {
  uint8_t kc_new[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(kc_new);

  crypto_scalarmult_ristretto255_base(yc, kc_new);

  uint8_t kc_new_inv[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_invert(kc_new_inv, kc_new);

  crypto_core_ristretto255_scalar_mul(delta, kc, kc_new_inv);

  memcpy(kc, kc_new, sizeof kc_new);
}

#ifdef UNIT_TEST
int main(void) {
  const int debug=1;
  
  // setup
  // client key
  uint8_t kc[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(kc);

  // certified public value for client
  uint8_t yc[crypto_core_ristretto255_BYTES];
  crypto_scalarmult_ristretto255_base(yc, kc);
  dump(yc, sizeof yc, "pubkey         ");

  // encrypt
  uint8_t w[crypto_core_ristretto255_BYTES];
  const uint8_t plaintext[]="hello world";
  const size_t pt_len=sizeof(plaintext);
  uint8_t ciphertext[pt_len+crypto_secretbox_NONCEBYTES+crypto_secretbox_MACBYTES];
  uokms_encrypt(yc, plaintext, pt_len, w, ciphertext);

  // decrypt
  // client blinds
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uokms_blind(w, r, alpha);

  // server
  uint8_t beta[crypto_core_ristretto255_BYTES];
  if(uokms_evaluate(kc, alpha, beta)) {
    printf("failed at uokms_evaluate\n");
    return 1;
  }

  // client unblinds and decrypts
  uint8_t plaintext1[pt_len];
  if(uokms_decrypt(ciphertext, sizeof ciphertext, r, beta, plaintext1)) {
    printf("failed at uokms_decrypt\n");
    return 1;
  }

  if(memcmp(plaintext,plaintext1,pt_len)!=0) {
    printf("failed at comparing plaintexts\n");
    return 1;
  }

  // update key
  uint8_t delta[crypto_core_ristretto255_SCALARBYTES];
  uokms_update_kc(kc,yc,delta);
  uokms_update_w(delta, w);
  dump(yc, sizeof yc, "updated pubkey ");

  // decrypt again, with updated key
  // client blinds
  uokms_blind(w, r, alpha);

  // server
  if(uokms_evaluate(kc, alpha, beta)) {
    printf("failed at uokms_evaluate\n");
    return 1;
  }

  // client unblinds and decrypts
  if(uokms_decrypt(ciphertext, sizeof ciphertext, r, beta, plaintext1)) {
    printf("failed at uokms_decrypt\n");
    return 1;
  }

  if(memcmp(plaintext,plaintext1,pt_len)!=0) {
    printf("failed at comparing plaintexts\n");
    return 1;
  }

  fprintf(stderr, "\e[0;32meverything correct!\e[0m\n");

  return 0;
}
#endif //UNIT_TEST
