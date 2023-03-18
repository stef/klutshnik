#include <sodium.h>
#include <unistd.h>
#include <stdio.h>

#include "utils.h"

// Implements the STREAM construction from https://eprint.iacr.org/2015/189
// Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
// by Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár

#define BLOCK_SIZE (1<<16)

#ifdef UNIT_TEST
const int debug = 1;
#else
extern int debug;
#endif //UNIT_TEST

int stream_encrypt(const int infd,
                   const int outfd,
                   const uint8_t dek[crypto_secretbox_KEYBYTES]) {
  uint8_t nonce[crypto_secretbox_NONCEBYTES]={0};
  // synthetically derive nonce from w
  randombytes_buf(nonce, crypto_secretbox_NONCEBYTES/2);
  write(outfd,nonce,crypto_secretbox_NONCEBYTES/2);

  uint8_t buf[BLOCK_SIZE + crypto_secretbox_MACBYTES];
  ssize_t buf_len;

  while(1) {
    buf_len = read(infd, buf, BLOCK_SIZE);
    if(buf_len==-1) {
      perror("failed to read plaintext from filedescriptor");
      return 1;
    }
    if(buf_len != BLOCK_SIZE) {
      // last block
      fprintf(stderr,"%ld != %d\n", buf_len, BLOCK_SIZE);
      nonce[sizeof nonce - 1] = 1;
      //if(debug) {
      //  fprintf(stderr, "encrypt last block\n");
      //  dump(buf, buf_len, "buf ");
      //  dump(nonce, sizeof nonce, "nonce ");
      //  dump(dek, crypto_secretbox_KEYBYTES, "dek ");
      //}
      crypto_secretbox_easy(buf, buf, buf_len, nonce, dek);
      write(outfd, buf, buf_len+crypto_secretbox_MACBYTES);
      break;
    }
    if(debug) fprintf(stderr, "encrypt next block\n");
    crypto_secretbox_easy(buf, buf, buf_len, nonce, dek);
    write(outfd, buf, buf_len+crypto_secretbox_MACBYTES);
    // nonce[half:-1]++
    sodium_increment(nonce + crypto_secretbox_NONCEBYTES/2, crypto_secretbox_NONCEBYTES/2 - 1);
  }
  return 0;
}

int stream_decrypt(const int infd,
                   const int outfd,
                   const uint8_t dek[crypto_secretbox_KEYBYTES]) {
  uint8_t nonce[crypto_secretbox_NONCEBYTES]={0};
  // synthetically derive nonce from w
  read(infd,nonce,crypto_secretbox_NONCEBYTES/2);

  ssize_t buf_len;
  uint8_t buf[BLOCK_SIZE + crypto_secretbox_MACBYTES];

  while(1) {
    buf_len = read(infd, buf, sizeof buf);
    if(buf_len<0) {
      perror("failed to read ciphertext from filedescriptor");
      return 1;
    }
    if((size_t) buf_len < sizeof buf) {
      // final block
      nonce[sizeof nonce - 1] = 1;
      if(debug) {
        fprintf(stderr, "decrypt last block\n");
        dump(buf, buf_len, "buf ");
        dump(nonce, sizeof nonce, "nonce ");
        dump(dek, crypto_secretbox_KEYBYTES, "dek ");
      }
      if(crypto_secretbox_open_easy(buf, buf, buf_len, nonce, dek) != 0) {
        fail("failed message forged");
        return 1;
      }
      write(outfd, buf, buf_len-crypto_secretbox_MACBYTES);
      break;
    }
    if(debug) fprintf(stderr, "decrypt next block\n");
    if(crypto_secretbox_open_easy(buf, buf, buf_len, nonce, dek) != 0) {
      fail("failed message forged");
      return 1;
    }
    write(outfd, buf, buf_len-crypto_secretbox_MACBYTES);
    // nonce[half:-1]++
    sodium_increment(nonce + crypto_secretbox_NONCEBYTES/2, crypto_secretbox_NONCEBYTES/2 - 1);
  }


  return 0;
}


#ifdef UNIT_TEST
#include <string.h>
int main(void) {
  int encrypt[2], mitm[2], decrypt[2];

  if(pipe(encrypt)!=0) {
    perror("failed to open encrypt pipe");
    return 1;
  }
  if(pipe(mitm)!=0) {
    perror("failed to open encrypt pipe");
    return 1;
  }
  if(pipe(decrypt)!=0) {
    perror("failed to open encrypt pipe");
    return 1;
  }

  fprintf(stderr, "[1] initiaizing pt0\n");
  uint8_t pt0[(1<<10)*4];
  for(int i=0; i<sizeof pt0; i++) pt0[i]=i;
  uint8_t pt1[sizeof pt0];

  fprintf(stderr, "[2] sending pt0\n");
  write(encrypt[1],pt0,sizeof pt0);

  fprintf(stderr, "[3] initializing w\n");
  uint8_t w[crypto_core_ristretto255_BYTES];
  randombytes_buf(w,sizeof w);
  fprintf(stderr, "[4] initializing dek\n");
  uint8_t dek[crypto_secretbox_KEYBYTES];
  randombytes_buf(dek,sizeof dek);

  fprintf(stderr, "[5] encrypting stream\n");
  if(stream_encrypt(encrypt[0], mitm[1], w, dek)) {
    fail("encryption test");
    return 1;
  }

  fprintf(stderr, "[6] decrypting stream\n");
  if(stream_decrypt(mitm[0], decrypt[1], w, dek)) {
    fail("decryption test");
    return 1;
  }

  fprintf(stderr, "[7] reading pt1\n");
  read(decrypt[0], pt1, sizeof pt1);

  fprintf(stderr, "[8] comparing pt0 & pt1\n");
  if(memcmp(pt0,pt1,sizeof pt1)!=0) {
    fail("compare pt0 & pt1");
    return 1;
  }


  return 0;
}
#endif // UNIT_TEST
