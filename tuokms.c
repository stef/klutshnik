#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "dkg.h"
#include "toprf.h"
#include "thmult.h"
#include "utils.h"
#include "streamcrypt.h"

const int debug=1;

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_BYTES];
} __attribute((packed)) TOPRF_Part;

static void topart(TOPRF_Part *r, const TOPRF_Share *s) {
  r->index=s->index;
  crypto_scalarmult_ristretto255_base(r->value, s->value);
}

int tuokms_pubkey(const uint8_t n, const uint8_t threshold,
                  const TOPRF_Share kc_shares[n][2],
                  uint8_t yc[crypto_core_ristretto255_BYTES]) {
  // todo implement 2nd part of the dlog paper!

  uint8_t responses[threshold][TOPRF_Part_BYTES];
  for(int i=0;i<threshold;i++) {
    topart((TOPRF_Part *) responses[i], &kc_shares[i][0]);
  }
  if(toprf_thresholdmult(threshold, responses, yc)) {
    fail("to calculate public dkg key");
    return 1;
  }

  return 0;
}

int tuokms_dkg(const uint8_t n, const uint8_t threshold,
               TOPRF_Share kc_shares[n][2],
               uint8_t yc[crypto_core_ristretto255_BYTES]) {

  uint8_t commitments[n][threshold][crypto_core_ristretto255_BYTES];
  TOPRF_Share shares[n][n][2];

  for(int i=0;i<n;i++) { // every kms runs dkg_start for themselves
    if(dkg_start(n, threshold, commitments[i], shares[i])) {
      fail("dkg_start for %d",i);
      return 1;
    }
  }

  // each Pi sends s_ij, and s'_ij to Pj
  // basically we are transposing here the shares matrix above
  TOPRF_Share sent_shares[n][2];
  for(int i=0;i<n;i++) {
    for(int j=0;j<n;j++) {
      memcpy(&sent_shares[j][0], &shares[j][i][0], sizeof(TOPRF_Share));
      memcpy(&sent_shares[j][1], &shares[j][i][1], sizeof(TOPRF_Share));
    }

    uint8_t complaints[n];
    memset(complaints, 0, sizeof complaints);
    uint8_t complaints_len=0;
    if(dkg_verify_commitments(n,threshold,i+1,commitments,sent_shares,complaints, &complaints_len)) return 1;
    // todo handle complaints, build qual set
    uint8_t qual[n+1];
    for(int i=0;i<n;i++) qual[i]=i+1; //everyone qualifies
    qual[n]=0;
    kc_shares[i][0].index=i+1;
    kc_shares[i][1].index=i+1;
    // finalize dkg
    dkg_finish(n,qual,sent_shares,i+1,&kc_shares[i][0],&kc_shares[i][1]);
  }

  // we recalculate yc elsewhere when rotating keys
  if(yc==NULL) return 0;

  // calculate public "key"
  if(tuokms_pubkey(n, threshold, kc_shares, yc)) return 1;

  return 0;
}

int tuokms_update(const uint8_t n, const uint8_t threshold,
                  TOPRF_Share kc_shares[n][2],
                  uint8_t yc[crypto_core_ristretto255_BYTES],
                  uint8_t w[crypto_core_ristretto255_BYTES]) {
  // The distributed update protocol assumes that n servers S1, . . . , Sn have a sharing (k1, . . . , kn)
  // of a key k. (see kc_shares parameter)

  // To produce a new key k′ the servers jointly generate a sharing ρ1, . . . , ρn of a random
  // secret ρ ∈ Zq and
  TOPRF_Share kc_new[n][2];
  if(tuokms_dkg(n,threshold, kc_new, NULL)) {
    fail("update dkg");
    return 1;
  }

  // run distributed multiplication to generate shares
  // k′_1, ... , k′_n of the new key defined as k′ = ρ · k.

  uint8_t mulshares[n][n][TOPRF_Share_BYTES];
  for(unsigned i=0;i<n;i++) {
    if(toprf_mpc_mul_start((uint8_t*)kc_shares[i], (uint8_t*)kc_new[i], n, threshold, mulshares[i])) return 1;
  }

  uint8_t indexes[n];
  for(unsigned i=0; i<n; i++) indexes[i]=i+1;
  for(unsigned i=0;i<n;i++) {
    uint8_t shares[n][TOPRF_Share_BYTES];
    for(unsigned j=0; j<n;j++) {
      memcpy(shares[j], mulshares[j][i], TOPRF_Share_BYTES);
      //dump(mulshares[j][i], TOPRF_Share_BYTES, "mulsharesx");
      //dump(shares[i], TOPRF_Share_BYTES, "sharesx");
    }
    toprf_mpc_mul_finish(n, indexes, i+1, shares, (uint8_t*)&kc_shares[i][0]);
  }

  // Finally, each server Si sends to C and/or StS its share ρi from which the recipient
  // reconstructs ρ and sets ∆ := ρ−1 [= k′/k]

  uint8_t p[crypto_core_ristretto255_SCALARBYTES];
  dkg_reconstruct(threshold, kc_new, p);

  uint8_t delta[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_invert(delta, p);
  uokms_update_w(delta, w);

  // recalculate yc
  if(tuokms_pubkey(n, threshold, kc_shares, yc)) return 1;

  return 0;
}

int tuokms_blind(const uint8_t w[crypto_core_ristretto255_BYTES],
                 uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                 uint8_t c[crypto_core_ristretto255_SCALARBYTES],
                 uint8_t d[crypto_core_ristretto255_SCALARBYTES],
                 uint8_t blinded[crypto_core_ristretto255_BYTES],
                 uint8_t verifier[crypto_core_ristretto255_BYTES]) {
  // check if w is a valid point
  if(!crypto_core_ristretto255_is_valid_point(w)) return 1;

  crypto_core_ristretto255_scalar_random(r);
  if(crypto_scalarmult_ristretto255(blinded, r, w)) return 1;

  crypto_core_ristretto255_scalar_random(c);
  if(crypto_scalarmult_ristretto255(verifier, c, w)) return 1;
  crypto_core_ristretto255_scalar_random(d);
  uint8_t tmp[crypto_core_ristretto255_BYTES];
  crypto_scalarmult_ristretto255_base(tmp, d);
  crypto_core_ristretto255_add(verifier, verifier, tmp);

  return 0;
}

int tuokms_evaluate(const uint8_t kc[crypto_core_ristretto255_SCALARBYTES],
                    const uint8_t alpha[crypto_core_ristretto255_BYTES],
                    const uint8_t verifier[crypto_core_ristretto255_BYTES],
                    uint8_t beta[crypto_core_ristretto255_BYTES],
                    uint8_t verifier_beta[crypto_core_ristretto255_BYTES]) {
  // check if w is a valid point
  if(!crypto_core_ristretto255_is_valid_point(alpha)) return 1;
  if(crypto_scalarmult_ristretto255(beta, kc, alpha)) return 1;

  if(!crypto_core_ristretto255_is_valid_point(verifier)) return 1;
  if(crypto_scalarmult_ristretto255(verifier_beta, kc, verifier)) return 1;

  return 0;
}

int tuokms_decrypt_get_dek(const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t c[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t d[crypto_core_ristretto255_SCALARBYTES],
                           const uint8_t yc[crypto_core_ristretto255_BYTES],
                           const uint8_t beta[crypto_core_ristretto255_BYTES],
                           const uint8_t verifier_beta[crypto_core_ristretto255_BYTES],
                           uint8_t dek[crypto_secretbox_KEYBYTES]) {
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
  uint8_t gk[crypto_core_ristretto255_BYTES];
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
    fail("to divide by c");
    return 1;
  }
  // tmp = verifer_beta^(1/c)*yc^(-d/c)
  crypto_core_ristretto255_add(tmp, tmp1, tmp);
  if(memcmp(tmp, gk, sizeof gk)!=0) {
    fail("to verify dek");
    // todo return something special so that caller can if threshold setting check which server response was invalid
    return 1;
  }

  // H(beta * 1/r)
  crypto_generichash(dek, crypto_secretbox_KEYBYTES, gk, sizeof gk, NULL, 0);
  return 0;
}

int tuokms_decrypt(const uint8_t *ciphertext, const size_t ct_len,
                   const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t c[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t d[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t yc[crypto_core_ristretto255_BYTES],
                   const uint8_t beta[crypto_core_ristretto255_BYTES],
                   const uint8_t verifier_beta[crypto_core_ristretto255_BYTES],
                   uint8_t *plaintext) {
  uint8_t dek[crypto_secretbox_KEYBYTES];
  if(tuokms_decrypt_get_dek(r,c,d,yc,beta,verifier_beta, dek)) {
    fail("getting dek");
    return 1;
  }

  if (crypto_secretbox_open_easy(plaintext, ciphertext+crypto_secretbox_NONCEBYTES, ct_len-crypto_secretbox_NONCEBYTES, ciphertext, dek) != 0) {
    /* message forged! */
    fail("message forged");
    return 1;
  }

  return 0;
}

int tuokms_stream_decrypt(const int infd, const int outfd,
                   const uint8_t w[crypto_core_ristretto255_BYTES],
                   const uint8_t r[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t c[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t d[crypto_core_ristretto255_SCALARBYTES],
                   const uint8_t yc[crypto_core_ristretto255_BYTES],
                   const uint8_t beta[crypto_core_ristretto255_BYTES],
                   const uint8_t verifier_beta[crypto_core_ristretto255_BYTES]) {
  uint8_t dek[crypto_secretbox_KEYBYTES];
  if(tuokms_decrypt_get_dek(r,c,d,yc,beta,verifier_beta, dek)) {
    fail("getting dek");
    return 1;
  }

  if(stream_decrypt(infd,outfd, w, dek) != 0) {
    /* message forged! */
    fail("message forged");
    return 1;
  }

  return 0;
}

int main(void) {
  // initialize
  // client key
  uint8_t n=5, threshold=3;
  // certified public value for client
  uint8_t yc[crypto_core_ristretto255_BYTES];
  TOPRF_Share kc_shares[n][2];
  if(tuokms_dkg(n,threshold, kc_shares, yc)) {
    fail("initial dkg");
    return 1;
  }
  dump(yc, sizeof yc, "pubkey         ");

  /////////////////////////////////////////////////////////////////////////////////////

  // encrypt
  uint8_t w[crypto_core_ristretto255_BYTES];
  const uint8_t plaintext[]="hello world";
  const size_t pt_len=sizeof(plaintext);
  uint8_t ciphertext[pt_len+crypto_secretbox_NONCEBYTES+crypto_secretbox_MACBYTES];
  uokms_encrypt(yc, plaintext, pt_len, w, ciphertext);

  /////////////////////////////////////////////////////////////////////////////////////

  // decrypt
  // client blinds
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  uint8_t c[crypto_core_ristretto255_SCALARBYTES];
  uint8_t d[crypto_core_ristretto255_SCALARBYTES];
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint8_t verifier[crypto_core_ristretto255_BYTES];
  tuokms_blind(w, r, c, d, alpha, verifier);

  // server
  // calculate points of shares
  // this really happens at each peer separately
  uint8_t xresps[n][TOPRF_Part_BYTES];
  uint8_t vresps[n][TOPRF_Part_BYTES];
  for(size_t i=0;i<n;i++) { // we calculate all, but we don't need all
    xresps[i][0]=kc_shares[i][0].index;
    vresps[i][0]=kc_shares[i][0].index;
    if(tuokms_evaluate(kc_shares[i][0].value, alpha, verifier, xresps[i]+1, vresps[i]+1)) {
      fail("at uokms_evaluate");
      return 1;
    }
  }
  // we only select the first t shares, should be rather random
  uint8_t beta[crypto_core_ristretto255_BYTES];
  uint8_t verifier_beta[crypto_core_ristretto255_BYTES];
  if(toprf_thresholdmult(threshold, xresps, beta)) return 1;
  if(toprf_thresholdmult(threshold, vresps, verifier_beta)) return 1;

  // client unblinds and decrypts
  uint8_t plaintext1[pt_len];
  if(tuokms_decrypt(ciphertext, sizeof ciphertext, r, c, d, yc, beta, verifier_beta, plaintext1)) {
    fail("at uokms_decrypt");
    return 1;
  }

  if(memcmp(plaintext,plaintext1,pt_len)!=0) {
    fail("at comparing plaintexts");
    return 1;
  }

  /////////////////////////////////////////////////////////////////////////////////////

  // update key
  tuokms_update(n,threshold,kc_shares,yc,w);
  dump(yc, sizeof yc, "updated pubkey ");

  /////////////////////////////////////////////////////////////////////////////////////

  // decrypt again, with updated key
  // client blinds
  tuokms_blind(w, r, c, d, alpha, verifier);

  // server
  for(size_t i=0;i<n;i++) { // we calculate all, but we don't need all
    xresps[i][0]=kc_shares[i][0].index;
    vresps[i][0]=kc_shares[i][0].index;
    if(tuokms_evaluate(kc_shares[i][0].value, alpha, verifier, xresps[i]+1, vresps[i]+1)) {
      fail("at uokms_evaluate");
      return 1;
    }
  }
  // we only select the first t shares, should be rather random
  if(toprf_thresholdmult(threshold, xresps, beta)) return 1;
  if(toprf_thresholdmult(threshold, vresps, verifier_beta)) return 1;

  // client unblinds and decrypts
  if(tuokms_decrypt(ciphertext, sizeof ciphertext, r, c, d, yc, beta, verifier_beta, plaintext1)) {
    fail("at uokms_decrypt");
    return 1;
  }

  if(memcmp(plaintext,plaintext1,pt_len)!=0) {
    fail("at comparing plaintexts");
    return 1;
  }

  fprintf(stderr, "\e[0;32meverything correct!\e[0m\n");

  return 0;
}
