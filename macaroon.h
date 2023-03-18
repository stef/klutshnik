#ifndef MACAROON_H
#define MACAROON_H

#include <sodium.h>
#include <stdint.h>

typedef enum {
  NULL_CAVEAT,
  KEYID_CAVEAT,
  PUBKEY_CAVEAT,
  EXPIRY_CAVEAT,
  PRIVLEVEL_CAVEAT//,
  //NOTBEFORE_CAVET, // todo
  //SOURCEIP_MASK    // todo
} __attribute__ ((__packed__)) CaveatType;

typedef enum {
  ALL_OPS,
  UPDATE_OP,
  EVAL_OP,
  NO_OP
} __attribute__ ((__packed__)) PrivilegeLevel;

typedef struct {
  uint8_t mac[crypto_auth_BYTES]; // the signature
  uint16_t len;                   // length of the complete macaroon
  uint8_t size;                   // number of caveats
  uint8_t nonce[24];              // this is really a unique macaroon id, probably needs to be tied to a user
  CaveatType caveats[];
} __attribute__ ((__packed__)) Macaroon;

typedef struct {
  uint8_t keyid[16];
  uint8_t pubkey[crypto_core_ristretto255_BYTES];
  PrivilegeLevel level;
} CaveatContext;

typedef struct {
  int caveats_left;
  const void *current_caveat;
  const void *end;
} CaveatIter;

typedef struct {
  CaveatType type;
  uint8_t keyid[16];
} __attribute__ ((__packed__)) Keyid_Caveat;

typedef struct {
  CaveatType type;
  uint8_t pubkey[crypto_core_ristretto255_BYTES];
} __attribute__ ((__packed__)) Pubkey_Caveat;

typedef struct {
  CaveatType type;
  time_t expires;
} __attribute__ ((__packed__)) Expiry_Caveat;

typedef struct {
  CaveatType type;
  PrivilegeLevel level;
} __attribute__ ((__packed__)) Privilege_Caveat;

typedef struct {
  CaveatType type;
  const void *data;
} Caveats;

int macaroon_valid(const uint8_t mk[crypto_auth_KEYBYTES], const Macaroon *m, const CaveatContext* ctx);
int add_caveat(const Macaroon *m0, const CaveatType type, const void *data, uint8_t *m1buf);
void iter_caveat(const Macaroon *m, CaveatIter *iter);
const Keyid_Caveat* filter_keyids(CaveatIter *iter);
const Pubkey_Caveat* filter_pubkeys(CaveatIter *iter);
const Expiry_Caveat* filter_expiry(CaveatIter *iter);
const Privilege_Caveat* filter_privlevel(CaveatIter *iter);
size_t macaroon_size(const Caveats caveats[]);
int macaroon(const uint8_t mk[crypto_auth_KEYBYTES],
             const size_t idlen, const uint8_t id[idlen],
             const Caveats caveats[], Macaroon *m);
void load_authkey(const char *path, uint8_t key[crypto_auth_KEYBYTES]);

#endif // MACAROON_H
