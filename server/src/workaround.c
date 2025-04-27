#include "oprf/stp-dkg.h"
#include "oprf/toprf.h"
#include "oprf/toprf-update.h"
#include <stdlib.h>
#include <string.h>

// zig cannot align data at 64Byte (or anything beyond 16 bytes really)
// see https://github.com/ziglang/zig/issues/8452

// thus we have to workaround this by allocating/freeing and accessing
// the data in c which the zig cc backend (clang) handles correctly.
STP_DKG_PeerState* new_stp_dkg_peerstate(void) {
  return aligned_alloc(64,sizeof(STP_DKG_PeerState));
}

void extract_stp_dkg_share(const STP_DKG_PeerState *ctx, uint8_t share[TOPRF_Share_BYTES*2]) {
  memcpy(share, &ctx->share, TOPRF_Share_BYTES*2);
}

void del_stp_dkg_peerstate(STP_DKG_PeerState **peer) {
  if(*peer!=NULL) free(*peer);
  *peer = NULL;
}

TOPRF_Update_PeerState* new_toprf_update_peerstate(void) {
  return aligned_alloc(64,sizeof(TOPRF_Update_PeerState));
}

void toprf_update_peerstate_set_n(TOPRF_Update_PeerState *peer, const uint8_t n) {
   peer->n = n;
}

void toprf_update_peerstate_set_t(TOPRF_Update_PeerState *peer, const uint8_t t) {
   peer->t = t;
}

void del_toprf_update_peerstate(TOPRF_Update_PeerState **peer) {
  if(*peer!=NULL) free(*peer);
  *peer = NULL;
}
