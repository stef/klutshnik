#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "streamcrypt.h"
#include "utils.h"

//const int debug=0;
//int klutshnik_blind(const uint8_t w[crypto_core_ristretto255_BYTES],
//                 uint8_t r[crypto_core_ristretto255_SCALARBYTES],
//                 uint8_t c[crypto_core_ristretto255_SCALARBYTES],
//                 uint8_t d[crypto_core_ristretto255_SCALARBYTES],
//                 uint8_t blinded[crypto_core_ristretto255_BYTES],
//                 uint8_t verifier[crypto_core_ristretto255_BYTES]) {
//  // check if w is a valid point
//  if(!crypto_core_ristretto255_is_valid_point(w)) return 1;
//
//  crypto_core_ristretto255_scalar_random(r);
//  if(crypto_scalarmult_ristretto255(blinded, r, w)) return 1;
//
//  crypto_core_ristretto255_scalar_random(c);
//  if(crypto_scalarmult_ristretto255(verifier, c, w)) return 1;
//  crypto_core_ristretto255_scalar_random(d);
//  uint8_t tmp[crypto_core_ristretto255_BYTES];
//  crypto_scalarmult_ristretto255_base(tmp, d);
//  crypto_core_ristretto255_add(verifier, verifier, tmp);
//
//  return 0;
//}

//int klutshnik_evaluate(const uint8_t kc[crypto_core_ristretto255_SCALARBYTES],
//                    const uint8_t alpha[crypto_core_ristretto255_BYTES],
//                    const uint8_t verifier[crypto_core_ristretto255_BYTES],
//                    uint8_t beta[crypto_core_ristretto255_BYTES],
//                    uint8_t verifier_beta[crypto_core_ristretto255_BYTES]) {
//  // check if alpha is a valid point
//  if(!crypto_core_ristretto255_is_valid_point(alpha)) return 1;
//  if(crypto_scalarmult_ristretto255(beta, kc, alpha)) return 1;
//
//  if(!crypto_core_ristretto255_is_valid_point(verifier)) return 1;
//  if(crypto_scalarmult_ristretto255(verifier_beta, kc, verifier)) return 1;
//
//  return 0;
//}

int klutshnik_verify_zk_proof(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t c[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t d[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t yc[crypto_core_ristretto255_BYTES],
                           const uint8_t beta[crypto_core_ristretto255_BYTES],
                           const uint8_t verifier_beta[crypto_core_ristretto255_BYTES],
                           uint8_t gk[crypto_core_ristretto255_BYTES]) {
  // check if beta is a valid point
  if(!crypto_core_ristretto255_is_valid_point(beta)) {
    fail("invalid beta");
    return 1;
  }
  if(!crypto_core_ristretto255_is_valid_point(verifier_beta)) {
    fail("invalid verifier_beta");
    return 1;
  }

  // 1/r
  uint8_t r_inv[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_invert(r_inv, r);

  // beta * 1/r
  if(crypto_scalarmult_ristretto255(gk, r_inv, beta)) {
    fail("to divide by r");
    return 1;
  }

  uint8_t tmp[crypto_core_ristretto255_BYTES];
  uint8_t c_inv[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_invert(c_inv, c);
  uint8_t d_neg[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_negate(d_neg, d);
  // tmp = verifier_beta ^ (1/c)
  if(crypto_scalarmult_ristretto255(tmp, c_inv, verifier_beta)) {
    fail("to divide by c");
    return 1;
  }
  uint8_t tmp1[crypto_core_ristretto255_BYTES];
  crypto_core_ristretto255_scalar_mul(d_neg,d_neg,c_inv);
  // tmp1 = yc^(-d/c)
  if(crypto_scalarmult_ristretto255(tmp1, d_neg, yc)) {
    fail("to scalar multiply by -d/c");
    return 1;
  }
  // tmp = verifer_beta^(1/c)*yc^(-d/c)
  crypto_core_ristretto255_add(tmp, tmp1, tmp);
  if(memcmp(tmp, gk, crypto_core_ristretto255_BYTES)!=0) {
    fail("to verify zk proof");
    return 2;
  }
  return 0;
}

int klutshnik_decrypt_get_dek(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t c[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t d[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t yc[crypto_core_ristretto255_BYTES],
                           const uint8_t beta[crypto_core_ristretto255_BYTES],
                           const uint8_t verifier_beta[crypto_core_ristretto255_BYTES],
                           uint8_t dek[crypto_secretbox_KEYBYTES]) {
  uint8_t gk[crypto_core_ristretto255_BYTES];
  int ret = klutshnik_verify_zk_proof(r, c, d, yc, beta, verifier_beta, gk);
  if(ret!=0) return ret;

  // H(beta * 1/r)
  crypto_generichash(dek, crypto_secretbox_KEYBYTES, gk, sizeof gk, NULL, 0);
  return 0;
}

//int klutshnik_stream_decrypt(const int infd, const int outfd,
//                   const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
//                   const uint8_t c[crypto_core_ristretto255_SCALARBYTES],
//                   const uint8_t d[crypto_core_ristretto255_SCALARBYTES],
//                   const uint8_t yc[crypto_core_ristretto255_BYTES],
//                   const uint8_t beta[crypto_core_ristretto255_BYTES],
//                   const uint8_t verifier_beta[crypto_core_ristretto255_BYTES]) {
//  uint8_t dek[crypto_secretbox_KEYBYTES];
//  if(klutshnik_decrypt_get_dek(r,c,d,yc,beta,verifier_beta, dek)) {
//    fail("getting dek");
//    return 1;
//  }
//
//  if(stream_decrypt(infd,outfd, dek) != 0) {
//    /* message forged! */
//    fail("message forged");
//    return 1;
//  }
//
//  return 0;
//}

int klutshnik_stream_encrypt(const uint8_t yc[crypto_core_ristretto255_BYTES],
                         const int infd,
                         const int outfd) {
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(r);

  // certified public value for client
  uint8_t w[crypto_core_ristretto255_BYTES];
  if(crypto_scalarmult_ristretto255_base(w, r)) return 1;

  if(crypto_core_ristretto255_BYTES!=write(outfd, w, crypto_core_ristretto255_BYTES)) return 1;

  uint8_t tmp[crypto_core_ristretto255_BYTES];
  if(crypto_scalarmult_ristretto255(tmp, r, yc)) return 1;

  uint8_t dek[crypto_secretbox_KEYBYTES];
  crypto_generichash(dek, sizeof dek, tmp, sizeof tmp, NULL, 0);

  return stream_encrypt(infd, outfd, dek);
}
