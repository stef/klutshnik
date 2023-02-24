#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "dkg.h"
#include "toprf.h"
#include "thmult.h"
#include "utils.h"

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

  uint8_t responses[threshold][TOPRF_Part_BYTES];
  for(int i=0;i<threshold;i++) {
    topart((TOPRF_Part *) responses[i], &kc_shares[i][0]);
  }
  if(toprf_thresholdmult(threshold, responses, yc)) {
    fail("failed to calculate public dkg key");
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
      fail("failed dkg_start for %d",i);
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
    fail("failed update dkg");
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

int main(void) {
  // initialize
  // client key
  uint8_t n=5, threshold=3;
  // certified public value for client
  uint8_t yc[crypto_core_ristretto255_BYTES];
  TOPRF_Share kc_shares[n][2];
  if(tuokms_dkg(n,threshold, kc_shares, yc)) {
    fail("failed initial dkg");
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
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uokms_blind(w, r, alpha);

  // server
  uint8_t beta[crypto_core_ristretto255_BYTES];
  // calculate points of shares
  // this really happens at each peer separately
  uint8_t xresps[n][TOPRF_Part_BYTES];
  for(size_t i=0;i<n;i++) { // we calculate all, but we don't need all
    xresps[i][0]=kc_shares[i][0].index;
    if(uokms_evaluate(kc_shares[i][0].value, alpha, xresps[i]+1)) {
      fail("failed at uokms_evaluate");
      return 1;
    }
  }
  // we only select the first t shares, should be rather random
  if(toprf_thresholdmult(threshold, xresps, beta)) return 1;

  // client unblinds and decrypts
  uint8_t plaintext1[pt_len];
  if(uokms_decrypt(ciphertext, sizeof ciphertext, r, beta, plaintext1)) {
    fail("failed at uokms_decrypt");
    return 1;
  }

  if(memcmp(plaintext,plaintext1,pt_len)!=0) {
    fail("failed at comparing plaintexts");
    return 1;
  }

  /////////////////////////////////////////////////////////////////////////////////////

  // update key
  tuokms_update(n,threshold,kc_shares,yc,w);
  dump(yc, sizeof yc, "updated pubkey ");

  /////////////////////////////////////////////////////////////////////////////////////

  // decrypt again, with updated key
  // client blinds
  uokms_blind(w, r, alpha);

  // server
  for(size_t i=0;i<n;i++) { // we calculate all, but we don't need all
    xresps[i][0]=kc_shares[i][0].index;
    if(uokms_evaluate(kc_shares[i][0].value, alpha, xresps[i]+1)) {
      fail("failed at uokms_evaluate");
      return 1;
    }
  }
  // we only select the first t shares, should be rather random
  if(toprf_thresholdmult(threshold, xresps, beta)) return 1;

  // client unblinds and decrypts
  if(uokms_decrypt(ciphertext, sizeof ciphertext, r, beta, plaintext1)) {
    fail("failed at uokms_decrypt");
    return 1;
  }

  if(memcmp(plaintext,plaintext1,pt_len)!=0) {
    fail("failed at comparing plaintexts");
    return 1;
  }

  fprintf(stderr, "\e[0;32meverything correct!\e[0m\n");

  return 0;
}
