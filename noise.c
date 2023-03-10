#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <noise/protocol.h>

#include "utils.h"

#define MAX_MESSAGE_LEN 4096

uint8_t key[32];

static NoiseCipherState *send_cipher = 0;
static NoiseCipherState *recv_cipher = 0;

int noise_send(const int fd, const void *msg, const size_t size) {
  NoiseBuffer mbuf;
  int err;
  if(size>MAX_MESSAGE_LEN) {
    fail("message too large: %ld", size);
    return -1;
  }
  uint8_t message[MAX_MESSAGE_LEN + 2];
  memcpy(message+2, msg, size);
  noise_buffer_set_inout(mbuf, message + 2, size, sizeof(message) - 2);
  err = noise_cipherstate_encrypt(send_cipher, &mbuf);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("noise_send", err);
    return -1;
  }
  message[0] = (uint8_t)(mbuf.size >> 8);
  message[1] = (uint8_t)mbuf.size;
  size_t len;
  if((len = write(fd, message, mbuf.size+2)) != mbuf.size+2) {
    fail("truncated noise_send: %ld instead of %ld", len, mbuf.size+2);
    return -1;
  }
  return size;
}

int noise_read(const int fd, void *msg, const size_t size) {
  NoiseBuffer mbuf;
  int err;
  if(size>MAX_MESSAGE_LEN) {
    fail("message too large: %ld", size);
    return -1;
  }
  uint8_t message[MAX_MESSAGE_LEN + 2];

  size_t len=read(fd, message, 2);
  if(len==-1 || len!=2) {
    perror("read size of msg failed");
    return -1;
  }
  uint16_t msg_size = message[0] << 8 | message[1];
  if(msg_size!=size+16) {
    fail("message is bigger than buffer we got: %ld>%ld", msg_size, size+16);
    return -1;
  }
  if(read(fd,message+2,msg_size)!=msg_size) {
    fail("truncated message");
    return -1;
  }

  /* Decrypt the incoming message */
  noise_buffer_set_input(mbuf, message + 2, msg_size);
  err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("read", err);
    return 1;
  }
  memcpy(msg, mbuf.data, mbuf.size);

  return mbuf.size;
}

int noise_setup(const int fd, uint8_t client_pubkey[32]) {
  const char protocol[] = "Noise_XK_25519_ChaChaPoly_BLAKE2b";
  NoiseHandshakeState *handshake;
  int err;
  err = noise_handshakestate_new_by_name (&handshake, protocol, NOISE_ROLE_RESPONDER);
  if (err != NOISE_ERROR_NONE) {
    noise_perror(protocol, err);
    return 1;
  }

  NoiseDHState *dh;
  dh = noise_handshakestate_get_local_keypair_dh(handshake);
  err = noise_dhstate_set_keypair_private(dh, key, 32);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("set server private noise key", err);
    noise_handshakestate_free(handshake);
    return 1;
  }
  err = noise_handshakestate_start(handshake);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("start handshake", err);
    noise_handshakestate_free(handshake);
    return 1;
  }

  uint8_t msg1[48];
  if(read(fd,msg1,sizeof msg1)!=sizeof msg1) {
    fail("failed to read msg1 in noise handshake");
    noise_handshakestate_free(handshake);
    return 1;
  }

  NoiseBuffer mbuf;
  noise_buffer_set_input(mbuf, msg1, sizeof msg1);
  err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("read handshake msg1 from client", err);
    noise_handshakestate_free(handshake);
    return 1;
  }

  // server responds
  uint8_t msg2[48];
  noise_buffer_set_output(mbuf, msg2, sizeof(msg2));
  err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("write handshake msg2", err);
    noise_handshakestate_free(handshake);
    return 1;
  }
  if(sizeof msg2!=write(fd, msg2, sizeof msg2)) {
    noise_perror("send handshake msg2", err);
    noise_handshakestate_free(handshake);
    return 1;
  }

  // wait for client reply
  uint8_t msg3[64];
  if(read(fd,msg3,sizeof msg3)!=sizeof msg3) {
    fail("failed to recv msg3 in noise handshake");
    noise_handshakestate_free(handshake);
    return 1;
  }

  noise_buffer_set_input(mbuf, msg3, sizeof msg3);
  err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("read client handshake1", err);
    noise_handshakestate_free(handshake);
    return 1;
  }

  if (noise_handshakestate_get_action(handshake) != NOISE_ACTION_SPLIT) {
    fail("noise protocol handshake failed\n");
    noise_handshakestate_free(handshake);
    return 1;
  }

  err = noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
  if (err != NOISE_ERROR_NONE) {
    noise_handshakestate_free(handshake);
    noise_perror("split to start data transfer", err);
    return 1;
  }

  dh = noise_handshakestate_get_remote_public_key_dh(handshake);
  err=noise_dhstate_get_public_key(dh, client_pubkey, 32); // 32 ugh!
  if (err != NOISE_ERROR_NONE) {
    noise_perror("failed to get client pubkey", err);
    noise_handshakestate_free(handshake);
    return 1;
  }
  dump(client_pubkey, 32, "client pubkey: "); // 32 ugh!

  noise_handshakestate_free(handshake);
  handshake = 0;

  return 0;
}

int kms_noise_init(const char* path) {
  if (noise_init() != NOISE_ERROR_NONE) {
    fail("Noise initialization");
    return 1;
  }

  int fd = open(path,'r');
  if(read(fd,key,32) != 32) {
    fail("reading private key");
    return 1;
  };
  close(fd);

  return 0;
}
