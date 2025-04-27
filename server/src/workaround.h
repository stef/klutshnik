#ifndef workaround_h
#define workaround_h

#include <oprf/stp-dkg.h>
#include <oprf/toprf.h>
#include <oprf/toprf-update.h>
#include <stdint.h>

STP_DKG_PeerState* new_stp_dkg_peerstate(void);
void extract_stp_dkg_share(const STP_DKG_PeerState *ctx, uint8_t share[TOPRF_Share_BYTES*2]);
void del_stp_dkg_peerstate(STP_DKG_PeerState **peer);

TOPRF_Update_PeerState* new_toprf_update_peerstate(void);
void toprf_update_peerstate_set_n(TOPRF_Update_PeerState *peer, const uint8_t n);
void toprf_update_peerstate_set_t(TOPRF_Update_PeerState *peer, const uint8_t t);
void del_toprf_update_peerstate(TOPRF_Update_PeerState **peer);
#endif // workaround_h
