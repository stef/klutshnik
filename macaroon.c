#include <stdio.h>
#include <sodium.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "utils.h"
#include "macaroon.h"


/*
 * caveats:
 *
 * keyid = xxxxx
 * pubkey = xxxxx
 * time < xxxxx
 * operation in {eval, update}
 *
 */

static void get_key(const uint8_t mk[crypto_auth_KEYBYTES], const Macaroon *m, uint8_t key[crypto_auth_KEYBYTES]) {
  //fprintf(stderr, "get_key\n");
  //dump(mk, crypto_auth_KEYBYTES, "mk ");
  //dump(m->nonce, sizeof m->nonce, "nonce ");
  crypto_auth(key, m->nonce, sizeof m->nonce, mk);
  //dump(key, crypto_auth_KEYBYTES, "key ");
}

void new_macaroon(const uint8_t mk[crypto_auth_KEYBYTES], const size_t idlen, const uint8_t id[idlen], Macaroon *m) {
  m->len=sizeof(m->len) + sizeof(m->mac) + sizeof(m->size) + sizeof(m->nonce);
  if(id==NULL) {
    randombytes_buf(m->nonce, sizeof m->nonce);
  } else {
    crypto_generichash(m->nonce,sizeof m->nonce,id,idlen,mk,crypto_auth_KEYBYTES);
  }
  m->size = 0;

  uint8_t key[crypto_auth_KEYBYTES]={0};
  get_key(mk, m, key);
  //dump(key,sizeof key, "key ");

  const size_t signed_bytes = m->len - sizeof(m->mac);
  crypto_auth(m->mac,(uint8_t*) &m->len, signed_bytes, key);
  //dump(m->mac, sizeof m->mac, "mac  ");
}

int macaroon_valid(const uint8_t mk[crypto_auth_KEYBYTES], const Macaroon *m, const CaveatContext* ctx) {
  //fprintf(stderr, "valid?\n");
  size_t signed_bytes = offsetof(Macaroon,caveats) - sizeof(m->mac);
  //dump((uint8_t*)m,m->len, "vm  ");

  uint8_t m1buf[m->len];
  memcpy(m1buf,m,m->len);
  Macaroon *m1=(Macaroon*) m1buf;
  m1->size = 0;
  m1->len = offsetof(Macaroon,caveats);

  uint8_t key[crypto_auth_KEYBYTES]={0};
  get_key(mk, m1, key);
  //dump(key,sizeof key, "key ");
  crypto_auth(m1->mac,(uint8_t*) &m1->len, signed_bytes, key);
  //dump(m1->mac, sizeof m1->mac, "mac ");

  const void * ptr = m->caveats;
  size_t datalen=0;
  for(int i=0;i<m->size;i++) {
    switch(*((CaveatType*)ptr)) {

    case(EXPIRY_CAVEAT): {
      ptr++;
      datalen=sizeof(Expiry_Caveat) - sizeof(CaveatType);
      const time_t now = time(NULL);
      if( *((time_t*)ptr) < now) {
        fail("expired");
        fprintf(stderr, "caveat time: %ld < %ld (diff %ld) %d\n", *((time_t*)ptr), now,
                *((time_t*)ptr) - now, *((time_t*)ptr) < now);
        return 0;
      }
      break;
    }

    case(KEYID_CAVEAT): {
      ptr++;
      datalen=sizeof(Keyid_Caveat) - sizeof(CaveatType);
      if(ctx!=NULL && memcmp(ctx->keyid, ptr, datalen)!=0) {
        fail("keyid");
        dump(ctx->keyid, sizeof ctx->keyid, "keyid have ");
        dump(ptr, datalen, "keyid need ");
        return 0;
      }
      break;
    }
    case(PUBKEY_CAVEAT): {
      ptr++;
      datalen=sizeof(Pubkey_Caveat) - sizeof(CaveatType);
      if(ctx!=NULL && memcmp(ctx->pubkey, ptr, datalen)!=0) {
        fail("keyid");
        dump(ctx->pubkey, sizeof ctx->pubkey, "pubkey have ");
        dump(ptr, datalen, "pubkey need ");
        return 0;
      }
      break;
    }
    case(PRIVLEVEL_CAVEAT): {
      ptr++;
      datalen=sizeof(Privilege_Caveat) - sizeof(CaveatType);
      if(ctx!=NULL && ctx->level > *((PrivilegeLevel*) ptr)) {
        fail("privilege level");;
        fprintf(stderr, "need: %d, have %d\n", *((PrivilegeLevel*) ptr), ctx->level);
        return 0;
      }
      break;
    }
    default: {
      fail("invalid caveat type: %d", *((CaveatType*)ptr));
      return 0;
    }
    }
    ptr+=datalen;
    signed_bytes+=1+datalen;
    m1->len+=1+datalen;
    m1->size++;
    //dump(m1->mac, sizeof m1->mac, "mackey: ");
    //dump((const uint8_t*) &m1->len, signed_bytes, "macing: ");
    crypto_auth(m1->mac,(const uint8_t*) &m1->len, signed_bytes, m1->mac);
    //dump(m1->mac, sizeof m1->mac, "new mac ");
  }
  if(ptr>(((void*)m)+m->len)) {
    return 0;
  }

  if(sodium_memcmp(m1->mac,m->mac,sizeof m1->mac)!=0) {
    fail("invalid mac signature");
    dump(m1->mac, sizeof m1->mac, "mac1 ");
    dump(m->mac, sizeof m->mac, "mac  ");
    return 0;
  }

  return 1;
}

int add_caveat(const Macaroon *m0, const CaveatType type, const void *data, uint8_t *m1buf) {
  //fprintf(stderr, "adding caveat\n");
  //dump((uint8_t*)m0,m0->len, "vm0 ");
  memcpy(m1buf, m0, m0->len);

  Macaroon *m1=(Macaroon*) m1buf;
  m1buf[m0->len]=type;
  m1->size++;
  m1->len+=sizeof(CaveatType);
  size_t datalen=0;
  switch(type) {
  case(EXPIRY_CAVEAT): {
    datalen=sizeof(Expiry_Caveat) - sizeof(CaveatType);
    break;
  }
  case(KEYID_CAVEAT): {
    datalen=sizeof(Keyid_Caveat) - sizeof(CaveatType);
    break;
  }
  case(PUBKEY_CAVEAT): {
    datalen=sizeof(Pubkey_Caveat) - sizeof(CaveatType);
    break;
  }
  case(PRIVLEVEL_CAVEAT): {
    datalen=sizeof(Privilege_Caveat) - sizeof(CaveatType);
    break;
  }
  default: {
    fail("invalid caveat type: %d", type);
    return 0;
  }
  }

  memcpy(m1buf+m1->len, data, datalen);
  m1->len+=datalen;

  const size_t signed_bytes = m1->len - sizeof(m1->mac);
  //dump(m1->mac, sizeof m1->mac, "mackey: ");
  //dump((const uint8_t*) &m1->len, signed_bytes, "macing: ");
  crypto_auth(m1->mac,(uint8_t*) &m1->len, signed_bytes, m1->mac);
  //dump(m1->mac, sizeof m1->mac, "new mac ");

  return 0;
}

void iter_caveat(const Macaroon *m, CaveatIter *iter) {
  iter->caveats_left = m->size;
  iter->current_caveat = &m->caveats;
  iter->end = (((void*)m)+m->len);
}

static const void* next_caveat(CaveatIter *iter) {
  const void* res = iter->current_caveat;
  if(iter->caveats_left<=0) return 0;
  if(iter->end < iter->current_caveat) return (void*)-1;

  CaveatType type = *((CaveatType *) iter->current_caveat);
  size_t datalen=0;
  switch(type) {
  case(EXPIRY_CAVEAT): {
    datalen=sizeof(Expiry_Caveat);
    break;
  }
  case(KEYID_CAVEAT): {
    datalen=sizeof(Keyid_Caveat);
    break;
  }
  case(PUBKEY_CAVEAT): {
    datalen=sizeof(Pubkey_Caveat);
    break;
  }
  case(PRIVLEVEL_CAVEAT): {
    datalen=sizeof(Privilege_Caveat);
    break;
  }
  default: {
    fail("invalid caveat type: %d", type);
    return (void*)-1;
  }
  }
  iter->current_caveat+=datalen;
  iter->caveats_left--;
  return res;
}

static const void* filter_caveats(CaveatIter *iter, const CaveatType type) {
  const void* res;
  CaveatType cur_type;
  do {
    res = next_caveat(iter);
    if(res==NULL || res==((void*)-1)) return res;
    cur_type = *((CaveatType *) res);
  } while(cur_type!=type);
  return res;
}

const Keyid_Caveat* filter_keyids(CaveatIter *iter) {
  return (const Keyid_Caveat*) filter_caveats(iter,KEYID_CAVEAT);
}

const Pubkey_Caveat* filter_pubkeys(CaveatIter *iter) {
  return (const Pubkey_Caveat*) filter_caveats(iter,PUBKEY_CAVEAT);
}

const Expiry_Caveat* filter_expiry(CaveatIter *iter) {
  return (const Expiry_Caveat*) filter_caveats(iter,EXPIRY_CAVEAT);
}

const Privilege_Caveat* filter_privlevel(CaveatIter *iter) {
  return (const Privilege_Caveat*) filter_caveats(iter,PRIVLEVEL_CAVEAT);
}

void dump_macaroon(const Macaroon *m, const uint8_t mk[crypto_auth_KEYBYTES]) {
  dump((uint8_t*)m, m->len, "raw ");
  char *valid="?";
  if(mk!=NULL) {
    valid = macaroon_valid(mk,m,NULL)?"valid":"invalid";
  }
  dump(m->mac, sizeof m->mac, "mac[%s]:\t\t", valid);
  fprintf(stderr, "length:\t\t\t%d bytes\n", m->len);
  dump(m->nonce, sizeof m->nonce, "id:\t\t\t");
  fprintf(stderr, "number of caveats:\t%d\n", m->size);
  const void *ptr = m->caveats;
  size_t datalen = 0;
  for(int i=0;i<m->size;i++) {
    switch(*((CaveatType*)ptr)) {
    case(EXPIRY_CAVEAT): {
      datalen=sizeof(Expiry_Caveat) - sizeof(CaveatType);
      ptr++;
      struct tm *tmp;
      tmp = localtime((time_t*)ptr);
      if (tmp == NULL) {
        perror("localtime");
        return;
      }
      char date[21];
      if(!strftime(date,sizeof date -1, "%Y-%m-%d %H:%M:%S", tmp)) {
        fail("time doesn't fit into allocated string buffer");
        return;
      }
      fprintf(stderr, "expires:\t\t%s (%ld)\n", date, *((time_t*)ptr));
      break;
    }
    case(KEYID_CAVEAT): {
      datalen=sizeof(Keyid_Caveat) - sizeof(CaveatType);
      ptr++;
      dump(ptr, datalen, "keyid:\t\t\t");
      break;
    }
    case(PUBKEY_CAVEAT): {
      datalen=sizeof(Pubkey_Caveat) - sizeof(CaveatType);
      ptr++;
      dump(ptr, datalen, "pubkey:\t\t\t");
      break;
    }
    case(PRIVLEVEL_CAVEAT): {
      datalen=sizeof(Privilege_Caveat) - sizeof(CaveatType);
      ptr++;
      fprintf(stderr, "privilege level:\t%d\n", *((PrivilegeLevel*) ptr));
      break;
    }
    default: {
      fail("invalid caveat type: %d", *((CaveatType*)ptr));
      return;
    }
    }
    ptr+=datalen;
  }
  if(ptr>(((void*)m)+m->len)) {
    fprintf(stderr, "sizeof macaroon %d is smaller than the %ld caveats need\n", m->len, ptr - (((void*)m)+m->len));
  }
}

size_t macaroon_size(const Caveats caveats[]) {
  size_t result = sizeof(Macaroon);
  for(int i=0;caveats[i].type!=NULL_CAVEAT;i++) {
    switch(caveats[i].type) {
    case(EXPIRY_CAVEAT): {
      result+=sizeof(Expiry_Caveat);
      break;
    }
    case(KEYID_CAVEAT): {
      result+=sizeof(Keyid_Caveat);
      break;
    }
    case(PUBKEY_CAVEAT): {
      result+=sizeof(Pubkey_Caveat);
      break;
    }
    case(PRIVLEVEL_CAVEAT): {
      result+=sizeof(Privilege_Caveat);
      break;
    }
    default: {
      fail("invalid caveat type: %d", caveats[i].type);
      return 0;
    }
    }
  }
  return result;
}

int macaroon(const uint8_t mk[crypto_auth_KEYBYTES], const size_t idlen, const uint8_t id[idlen], const Caveats caveats[], Macaroon *m) {
  new_macaroon(mk, idlen, id, m);
  uint8_t *mbuf = (uint8_t*) m;
  size_t datalen;
  for(int i=0;caveats[i].type!=NULL_CAVEAT;i++) {
    switch(caveats[i].type) {
    case(EXPIRY_CAVEAT): {
      datalen=sizeof(Expiry_Caveat) - sizeof(CaveatType);
      break;
    }
    case(KEYID_CAVEAT): {
      datalen=sizeof(Keyid_Caveat) - sizeof(CaveatType);
      break;
    }
    case(PUBKEY_CAVEAT): {
      datalen=sizeof(Pubkey_Caveat) - sizeof(CaveatType);
      break;
    }
    case(PRIVLEVEL_CAVEAT): {
      datalen=sizeof(Privilege_Caveat) - sizeof(CaveatType);
      break;
    }
    default: {
      fail("invalid caveat type: %d", caveats[i].type);
      return 1;
    }
    }
    //fprintf(stderr,"adding caveat type: %d, len(%ld)\n", caveats[i].type, datalen);
    //dump(caveats[i].data, datalen, "caveat value ");

    mbuf[m->len]=caveats[i].type;
    m->len+=sizeof(CaveatType);

    memcpy(mbuf+m->len, caveats[i].data, datalen);
    m->size++;
    m->len+=datalen;

    const size_t signed_bytes = m->len - sizeof(m->mac);
    //dump(m->mac, sizeof m->mac, "mackey: ");
    //dump((const uint8_t*) &m->len, signed_bytes, "macing: ");
    crypto_auth(m->mac,(const uint8_t*) &m->len, signed_bytes, m->mac);
    //dump(m->mac, sizeof m->mac, "new mac ");
  }
  return 0;
}

void load_authkey(const char *path, uint8_t key[crypto_auth_KEYBYTES]) {
  int fd = open(path, O_RDONLY);
  if(fd==-1) {
    perror("failed to open auth key file");
    exit(1);
  }
  if(crypto_auth_KEYBYTES != read(fd, key, crypto_auth_KEYBYTES)) {
    fprintf(stderr, "failed to read 32 bytes from \"%s\" containing auth key", path);
    exit(1);
  }
  close(fd);
}

#ifdef UNIT_TEST
const uint8_t debug = 1;

int test(void) {
  uint8_t masterkey[crypto_auth_KEYBYTES];
  randombytes_buf(masterkey, sizeof masterkey);

  Macaroon m0={0};
  new_macaroon(masterkey, 0, NULL, &m0);
  dump_macaroon(&m0, masterkey);

  // serialize and deserialize
  dump((uint8_t*)&m0,m0.len, "m0 ");
  char m0b64[sodium_base64_ENCODED_LEN(m0.len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING)];
  sodium_bin2base64(m0b64, sizeof m0b64, (uint8_t*) &m0, m0.len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  printf("%s\n", m0b64);
  uint8_t m0x[sizeof(m0b64) / 4 * 3];
  size_t m0x_len;
  const char *end;
  if(sodium_base642bin(m0x, sizeof m0x,
                       m0b64, sizeof(m0b64),
                       NULL, &m0x_len, &end,
                       sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
    fail("base64 %ld, %d, %p %p", m0x_len, m0.len, end, m0x);
    return 1;
  }

  if(memcmp(m0x,&m0,m0x_len)!=0) {
    dump((uint8_t*)&m0, m0.len, "m0  ");
    dump(m0x, m0x_len, "m0x ");
    return 1;
  }

  CaveatContext ctx;
  randombytes_buf(ctx.pubkey, sizeof ctx.pubkey);
  dump(ctx.pubkey, sizeof ctx.pubkey, "pubkey ");
  randombytes_buf(ctx.keyid, sizeof ctx.keyid);
  dump(ctx.keyid, sizeof ctx.keyid, "keyid ");
  ctx.level = UPDATE_OP;

  if(!macaroon_valid(masterkey, (Macaroon*) &m0x, &ctx)) {
    fail("verify macaroon");
  }

  const time_t future=time(NULL) + 1;
  uint8_t m1buf[m0.len + sizeof(Expiry_Caveat)];
  fprintf(stderr,"m1buflen: %ld\n\n",sizeof m1buf);
  add_caveat(&m0, EXPIRY_CAVEAT, &future, m1buf);

  if(!macaroon_valid(masterkey, (Macaroon*) &m1buf, &ctx)) {
    fail("verify future macaroon");
  }
  Macaroon *m1=(Macaroon*) m1buf;
  dump_macaroon(m1, masterkey);

  const time_t past=time(NULL) - 5;
  uint8_t m2buf[m0.len + sizeof(Expiry_Caveat)];
  Macaroon *m2=(Macaroon*) m2buf;
  add_caveat(&m0, EXPIRY_CAVEAT, &past, m2buf);
  dump_macaroon(m2, masterkey);

  if(!macaroon_valid(masterkey, (Macaroon*) &m2buf, &ctx)) {
    fail("verify past macaroon");
  }

  uint8_t m3buf[m1->len + sizeof(Pubkey_Caveat)];
  add_caveat(m1, PUBKEY_CAVEAT, ctx.pubkey, m3buf);
  Macaroon *m3=(Macaroon*) m3buf;
  dump_macaroon(m3, masterkey);

  if(!macaroon_valid(masterkey, (Macaroon*) &m3buf, &ctx)) {
    fail("verify pubkey/future macaroon");
  }

  uint8_t m4buf[m3->len + sizeof(Keyid_Caveat)];
  add_caveat(m3, KEYID_CAVEAT, ctx.keyid, m4buf);
  Macaroon *m4=(Macaroon*) m4buf;
  dump_macaroon(m4, masterkey);

  if(!macaroon_valid(masterkey, (Macaroon*) &m4buf, &ctx)) {
    fail("verify pubkey/keyid/future macaroon");
  }


  fprintf(stderr, "create complex macaroon in one go\n");
  Caveats caveats[] = {
    {EXPIRY_CAVEAT, &future},
    {PUBKEY_CAVEAT, ctx.pubkey},
    {KEYID_CAVEAT, ctx.keyid},
    {NULL_CAVEAT, 0}
  };
  uint8_t noise_pubkey[32];
  randombytes_buf(noise_pubkey, sizeof noise_pubkey);
  uint8_t m5buf[macaroon_size(caveats)];
  Macaroon *m5=(Macaroon*) m5buf;
  if(macaroon(masterkey, sizeof noise_pubkey, noise_pubkey, caveats, (Macaroon*) &m5buf)) {
    return 1;
  }
  dump_macaroon(m5, masterkey);

  if(!macaroon_valid(masterkey, m5, &ctx)) {
    fail("verify complex macaroon");
  }

  char m5b64[sodium_base64_ENCODED_LEN(m5->len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING)];
  sodium_bin2base64(m5b64, sizeof m5b64, m5buf, m5->len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  printf("%s\n", m5b64);

  uint8_t m5x[sizeof(m5b64) / 4 * 3 + 1];
  size_t m5x_len;
  if(sodium_base642bin(m5x, sizeof m5x,
                       m5b64, sizeof(m5b64),
                       NULL, &m5x_len, &end,
                       sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
    fail("base64 %ld, %d, %p %p", m5x_len, m5->len, end, m5x);
    return 1;
  }

  Macaroon *m6=(Macaroon*) m5x;
  dump_macaroon(m6, masterkey);

  if(!macaroon_valid(masterkey, m6, &ctx)) {
    fail("verify deserialized complex macaroon");
  }

  return 0;
}
#endif // UNIT_TEST

#ifdef WITH_MAIN
const int debug = 1;

void usage(const char **argv) {
  printf("usage:\n");
  printf("%s create -a <authkey> [-u uid] [-e <seconds>] [-k <keyid>] [-p <pubkey>] [-o <privlevel>]\n", argv[0] );
  printf("%s dump\n", argv[0]);
  printf("%s verify -a <authkey>\n", argv[0]);
  printf("%s narrow [uid] [-e <seconds>] [-k <keyid>] [-p <pubkey>] [-o <privlevel>]\n", argv[0]);
}

void parse_args(const int argc, const char **argv,
                const char ** authkey, uint8_t **uid, size_t *uid_len,
                time_t **secs, uint8_t **keyid, uint8_t **pubkey,
                PrivilegeLevel **privlevel) {
  for(int i=2;i<argc;i++) {
    if(memcmp(argv[i],"-a", 3)==0) {
      *authkey=argv[++i];
    } else if(memcmp(argv[i],"-u", 3)==0) {
      i++;
      *uid_len = strlen(argv[i])/2;
      *uid = malloc(*uid_len);
      const char *end=0;
      size_t bin_len;
      if(0!=sodium_hex2bin(*uid, *uid_len, argv[i], *uid_len*2, NULL, &bin_len, &end)) {
        fail("hex2bin uid");
        exit(1);
      };
      if(bin_len!=*uid_len || end != argv[i]+(*uid_len*2)) {
        fail("incomplete keyid");
        exit(1);
      }
    } else if(memcmp(argv[i],"-e", 3)==0) {
      i++;
      *secs = malloc(sizeof(time_t));
      **secs = atoll(argv[i]);
      if(**secs < time(NULL)) {
        fail("expiry date is in the past");
        exit(1);
      }
    } else if(memcmp(argv[i],"-k", 3)==0) {
      i++;
      if(strlen(argv[i])!=32) {
        fail("keyid is not of correct size");
        exit(1);
      }
      *keyid = malloc(16);
      const char *end=0;
      size_t bin_len;
      if(0!=sodium_hex2bin(*keyid, 16, argv[i], 32, NULL, &bin_len, &end)) {
        fail("hex2bin keyid");
        exit(1);
      };
      if(bin_len!=16 || end != argv[i]+32) {
        fail("incomplete keyid");
        exit(1);
      }
    } else if(memcmp(argv[i],"-p", 3)==0) {
      i++;
      if(strlen(argv[i])!=crypto_core_ristretto255_BYTES*2) {
        fail("pubkey is not of correct size");
        exit(1);
      }
      *pubkey = malloc(crypto_core_ristretto255_BYTES);
      const char *end=0;
      size_t bin_len;
      if(0!=sodium_hex2bin(*pubkey, crypto_core_ristretto255_BYTES,
                           argv[i], crypto_core_ristretto255_BYTES*2, NULL,
                           &bin_len, &end)) {
        fail("hex2bin pubkey");
        exit(1);
      };
      if(bin_len!=crypto_core_ristretto255_BYTES || end != argv[i]+crypto_core_ristretto255_BYTES*2) {
        fail("incomplete pubkey");
        exit(1);
      }
    } else if(memcmp(argv[i],"-o", 3)==0) {
      i++;
      *privlevel= malloc(1);
      *(uint8_t*) *privlevel = atoi(argv[i]);
    } else {
      fprintf(stderr, "invalid param: \"%s\"", argv[i]);
      usage(argv);
      exit(1);
    }
  }
}
#endif // WITH_MAIN

#if(defined WITH_MAIN || defined UNIT_TEST)
int main(const int argc, const char **argv) {
#ifdef  UNIT_TEST
  return test();
#else // UNIT_TEST
  if(argc<2) {
    usage(argv);
    return 0;
  }

  const char *authkey=NULL;
  time_t *secs=NULL;
  uint8_t *keyid=NULL, *pubkey=NULL,  *uid=NULL;
  PrivilegeLevel *privlevel=NULL;
  size_t uid_len;
  parse_args(argc,argv,&authkey,&uid,&uid_len,&secs,&keyid,&pubkey,&privlevel);

  if(memcmp(argv[1], "create", 7)==0) {
    if(authkey==NULL) {
      fail("must provide auth key using -a parameter");
      exit(1);
    }

    int caveats_len = 0;
    if(secs!=NULL) caveats_len++;
    if(keyid!=NULL) caveats_len++;
    if(pubkey!=NULL) caveats_len++;
    if(privlevel!=NULL) caveats_len++;

    Caveats caveats[caveats_len+1];
    memset(caveats,0,sizeof caveats);
    int i=0;
    if(secs!=NULL) {
      caveats[i].type=EXPIRY_CAVEAT;
      caveats[i].data=secs;
      i++;
    }
    if(keyid!=NULL) {
      caveats[i].type=KEYID_CAVEAT;
      caveats[i].data=keyid;
      i++;
    }
    if(pubkey!=NULL) {
      caveats[i].type=PUBKEY_CAVEAT;
      caveats[i].data=pubkey;
      i++;
    }
    if(privlevel!=NULL) {
      caveats[i].type=PRIVLEVEL_CAVEAT;
      caveats[i].data=privlevel;
      i++;
    }

    uint8_t mbuf[macaroon_size(caveats)];
    Macaroon *m=(Macaroon*) mbuf;

    uint8_t akey[crypto_auth_KEYBYTES];
    load_authkey(authkey, akey);

    if(macaroon(akey, uid_len, uid, caveats, (Macaroon*) &mbuf)) {
      fail("creating macaroon");
      exit(1);
    }
    char mb64[sodium_base64_ENCODED_LEN(m->len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING)];
    sodium_bin2base64(mb64, sizeof mb64, (uint8_t*) m, m->len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    printf("%s\n", mb64);
  } else if(memcmp(argv[1], "dump", 5)==0) {
    char mb64[65535]={0};
    const size_t mb64_len = read(0, mb64, 65535);
    if(mb64_len < sodium_base64_ENCODED_LEN(sizeof(Macaroon), sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
      fail("macaroon too short");
      exit(1);
    }

    uint8_t mbuf[mb64_len / 4 * 3 + 1];
    size_t m_len;
    const char *end;
    if(sodium_base642bin(mbuf, sizeof mbuf,
                         mb64, sizeof(mb64),
                         NULL, &m_len, &end,
                         sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
      fail("deserialize macaroon");
      return 1;
    }
    Macaroon *m=(Macaroon*) mbuf;

    if(authkey!=NULL) {
      uint8_t akey[crypto_auth_KEYBYTES];
      load_authkey(authkey, akey);
      dump_macaroon(m, akey);
    } else {
      dump_macaroon(m, NULL);
    }
  } else if(memcmp(argv[1], "verify", 7)==0) {
    if(authkey==NULL) {
      fail("must provide auth key using -a parameter");
      exit(1);
    }
    char mb64[65535]={0};
    const size_t mb64_len = read(0, mb64, 65535);
    if(mb64_len < sodium_base64_ENCODED_LEN(sizeof(Macaroon), sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
      fail("macaroon too short");
      exit(1);
    }

    uint8_t mbuf[mb64_len / 4 * 3 + 1];
    size_t m_len;
    const char *end;
    if(sodium_base642bin(mbuf, sizeof mbuf,
                         mb64, sizeof(mb64),
                         NULL, &m_len, &end,
                         sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
      fail("deserialize macaroon");
      return 1;
    }
    Macaroon *m=(Macaroon*) mbuf;

    uint8_t akey[crypto_auth_KEYBYTES];
    load_authkey(authkey, akey);
    return !macaroon_valid(akey, m, NULL);
  } else if(memcmp(argv[1], "narrow", 7)==0) {
    char mb64[65535]={0};
    const size_t mb64_len = read(0, mb64, 65535);
    if(mb64_len < sodium_base64_ENCODED_LEN(sizeof(Macaroon), sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
      fail("macaroon too short");
      exit(1);
    }
    uint8_t mbuf[mb64_len / 4 * 3 + 1 +  + sizeof(Expiry_Caveat) + sizeof(Pubkey_Caveat) + sizeof(Keyid_Caveat) + sizeof(Privilege_Caveat)];
    size_t m_len;
    const char *end;
    if(sodium_base642bin(mbuf, sizeof mbuf,
                         mb64, sizeof(mb64),
                         NULL, &m_len, &end,
                         sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
      fail("deserialize macaroon");
      return 1;
    }
    Macaroon *m=(Macaroon*) mbuf;

    if(secs!=NULL) {
      CaveatIter iter;
      iter_caveat(m, &iter);
      const Expiry_Caveat *ec;
      while ((ec=filter_expiry(&iter))!=NULL && ec!=(void*)-1) {
        if(ec->expires < *secs) {
          fail("expiry date is later than already set in macaroon (%ld < %ld)", ec->expires, secs);
          return 1;
        }
      }
      if(ec==(void*)-1) {
        fail("iterated past macaroon while sanity checking");
        return 1;
      }
      add_caveat(m, EXPIRY_CAVEAT, secs, mbuf);
    }

    if(keyid!=NULL) {
      CaveatIter iter;
      iter_caveat(m, &iter);
      const Keyid_Caveat *kidc=filter_keyids(&iter);
      if(kidc==(void*)-1) {
        fail("iterated past macaroon while sanity checking");
        return 1;
      }
      if(kidc!=NULL) {
        fail("macaroon has already a keyid constraint");
        dump(kidc->keyid,16,"keyid: ");
        return 1;
      }
      add_caveat(m, KEYID_CAVEAT, keyid, mbuf);
    }

    if(pubkey!=NULL) {
      CaveatIter iter;
      iter_caveat(m, &iter);
      const Pubkey_Caveat *pkc=filter_pubkeys(&iter);
      if(pkc==(void*)-1) {
        fail("iterated past macaroon while sanity checking");
        return 1;
      }
      if(pkc!=NULL) {
        fail("macaroon has already a pubkey constraint");
        dump(pkc->pubkey,sizeof pkc->pubkey,"pubkey: ");
        return 1;
      }
      add_caveat(m, PUBKEY_CAVEAT, pubkey, mbuf);
    }

    if(privlevel!=NULL) {
      if(*privlevel < ALL_OPS || *privlevel >=NO_OP) {
        fail("privilege level out of range: %d", *privlevel);
        exit(1);
      }
      CaveatIter iter;
      iter_caveat(m, &iter);
      const Privilege_Caveat *plc;

      while((plc=filter_privlevel(&iter))!=NULL && plc!=(void*)-1) {
        if(plc->level > *privlevel) {
          fail("privilege level (%d) is higher than already restricted to(%d)", *privlevel, plc->level);
          return 1;
        }
      }
      if(plc==(void*)-1) {
        fail("iterated past macaroon while sanity checking");
        return 1;
      }

      add_caveat(m, PRIVLEVEL_CAVEAT, privlevel, mbuf);
    }

    // serialize m
    sodium_bin2base64(mb64, sizeof mb64, mbuf, m->len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    printf("%s\n", mb64);
  }

  return 0;
#endif // UNIT_TEST
}

#endif // WITH_MAIN
