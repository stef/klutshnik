#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "utils.h"
#include "XK_25519_ChaChaPoly_BLAKE2b/XK.h"

#define MAX_MESSAGE_LEN 4096

uint8_t key[32];

typedef Noise_XK_device_t        device;
typedef Noise_XK_session_t       session;
typedef Noise_XK_peer_t          peer;
typedef Noise_XK_encap_message_t encap_message;
typedef Noise_XK_rcode           rcode;
typedef uint32_t              peer_id;

#define RETURN_IF_ERROR(e, msg) if (!(e)) { fail(msg); return 1; }

static int load_authkeys(const char *path, device *dev) {
  FILE *stream;
  char *line = NULL;
  size_t len = 0;
  ssize_t nread;
  int ret = 0;

  stream = fopen(path, "r");
  if (stream == NULL) {
    perror("fopen authorized_keys file");
    return 1;
  }

  while ((nread = getline(&line, &len, stream)) != -1) {
    int i;
    for(i=0;i<nread;i++) {
      if(line[i]==' ') break;
    }
    if(i!=44) {
      fail("invalid authorized key size: %d, \"%s\"\n", i, line);
      ret = 1;
      goto exit;
    }
    uint8_t key[32];
    const char *end;
    size_t key_len;
    if(sodium_base642bin(key, sizeof key,
                       line, i,
                       NULL, &key_len, &end,
                       sodium_base64_VARIANT_ORIGINAL_NO_PADDING)) {
      fail("base64 %ld, %p %p", key_len, end, key);
      ret = 1;
      goto exit;
    }
    line[nread-1]=0;
    //dump(key,sizeof key, "loading key for %s: ", &line[i+1]);
    if (!Noise_XK_device_add_peer(dev, (uint8_t*) &line[i+1], key)) {
      ret = 1;
      goto exit;
    }
  }

exit:
  free(line);
  fclose(stream);
  return ret;
}

int noise_send(const int fd, session *session, const uint8_t *msg, const size_t size) {
  if(size>MAX_MESSAGE_LEN) {
    fail("message too large: %ld", size);
    return -1;
  }

  encap_message *encap_msg;
  uint32_t cipher_msg_len;
  uint8_t *cipher_msg;
  rcode res;

  encap_msg = Noise_XK_pack_message_with_conf_level(NOISE_XK_CONF_STRONG_FORWARD_SECRECY, size, (uint8_t*) msg);
  res = Noise_XK_session_write(encap_msg, session, &cipher_msg_len, &cipher_msg);
  RETURN_IF_ERROR(Noise_XK_rcode_is_success(res), "noise_send");
  Noise_XK_encap_message_p_free(encap_msg);

  uint8_t message[MAX_MESSAGE_LEN + 2];
  memcpy(message+2, cipher_msg, cipher_msg_len);
  if(cipher_msg_len>0) free(cipher_msg);

  message[0] = (uint8_t) (cipher_msg_len >> 8);
  message[1] = (uint8_t) cipher_msg_len;
  size_t len;
  if((len = write(fd, message, cipher_msg_len+2)) != cipher_msg_len+2) {
    fail("truncated noise_send: %ld instead of %ld", len, cipher_msg_len+2);
    return -1;
  }
  return size;
}

int noise_read(const int fd, session *session, void *msg, const size_t size) {
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
  if(msg_size>MAX_MESSAGE_LEN) {
    fail("message is bigger than max message size: %ld>%ld", msg_size, MAX_MESSAGE_LEN);
    return -1;
  }
  if(size>0 && msg_size!=size+16) {
    fail("message is bigger than buffer we got: %ld>%ld", msg_size, size+16);
    return -1;
  }
  if(read(fd,message+2,msg_size)!=msg_size) {
    fail("truncated message");
    return -1;
  }

  /* Decrypt the incoming message */
  encap_message *encap_msg;
  uint32_t plain_msg_len;
  uint8_t *plain_msg;
  rcode res = Noise_XK_session_read(&encap_msg, session, msg_size, message+2);
  RETURN_IF_ERROR(Noise_XK_rcode_is_success(res), "noise_read message");
  RETURN_IF_ERROR(
                  Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg,
                                                          NOISE_XK_AUTH_KNOWN_SENDER_NO_KCI,
                                                          encap_msg),
                  "Unpack message 2");
  Noise_XK_encap_message_p_free(encap_msg);
  memcpy(msg, plain_msg, plain_msg_len);
  if (plain_msg_len > 0) free(plain_msg);

  return plain_msg_len;
}

int noise_setup(const int fd, session **sn, uint8_t client_pubkey[32]) {
  rcode res;
  encap_message *encap_msg=NULL;
  uint32_t cipher_msg_len;
  uint8_t *cipher_msg=NULL;
  uint32_t plain_msg_len;
  uint8_t *plain_msg=NULL;

  uint8_t dummy[32]={0};
  device *dev = Noise_XK_device_create(0, NULL, NULL, dummy, key);
  // todo configure
  if(load_authkeys("config/authorized_keys",dev)) return 1;

  *sn = Noise_XK_session_create_responder(dev);
  RETURN_IF_ERROR(*sn, "session creation");

  uint8_t msg1[48];
  if(read(fd,msg1,sizeof msg1)!=sizeof msg1) {
    fail("failed to read msg1 in noise handshake");
    // todo ? noise_handshakestate_free(handshake);
    return 1;
  }

  res = Noise_XK_session_read(&encap_msg, *sn, sizeof msg1, msg1);
  RETURN_IF_ERROR(Noise_XK_rcode_is_success(res), "Receive message 0");
  RETURN_IF_ERROR(Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg,
                                                          NOISE_XK_AUTH_ZERO, encap_msg),
                  "Unpack message 0");
  Noise_XK_encap_message_p_free(encap_msg);
  if (plain_msg_len > 0) {
    // we don't expect a message. so we abort our protocol
    fail("msg1 of handshake was not empty");
    free(plain_msg);
    free(*sn);
    *sn=NULL;
    plain_msg=NULL;
    return 1;
  }

  // server responds
  encap_msg = Noise_XK_pack_message_with_conf_level(NOISE_XK_CONF_ZERO, 0, NULL);
  res = Noise_XK_session_write(encap_msg, *sn, &cipher_msg_len, &cipher_msg);
  RETURN_IF_ERROR(Noise_XK_rcode_is_success(res), "Send message 1");
  Noise_XK_encap_message_p_free(encap_msg);

  if(cipher_msg_len!=write(fd, cipher_msg, cipher_msg_len)) {
    free(cipher_msg);
    free(*sn);
    *sn=NULL;
    return 1;
  }
  if(cipher_msg_len > 0) free(cipher_msg);

  // wait for client reply
  uint8_t msg3[64];
  if(read(fd,msg3,sizeof msg3)!=sizeof msg3) {
    fail("failed to recv msg3 in noise handshake");
    free(*sn);
    *sn=NULL;
    return 1;
  }

  res = Noise_XK_session_read(&encap_msg, *sn, sizeof msg3, msg3);
  RETURN_IF_ERROR(Noise_XK_rcode_is_success(res), "Receive message 2");

  // digging out peers spub:
  peer_id peer_id = Noise_XK_session_get_peer_id(*sn);
  Noise_XK_peer_t *peer = Noise_XK_device_lookup_peer_by_id(dev, peer_id);
  Noise_XK_peer_get_static(client_pubkey, peer);
  dump(client_pubkey, 32, "peers spub: ");

  RETURN_IF_ERROR(
                  Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg,
                                                          NOISE_XK_AUTH_KNOWN_SENDER_NO_KCI,
                                                          encap_msg),
                  "Unpack message 2");
  Noise_XK_encap_message_p_free(encap_msg);
  if (plain_msg_len > 0) {
    // we don't expect a message, so we just drop it
    fail("msg3 of handshake was not empty");
    free(plain_msg);
    free(*sn);
    *sn=NULL;
    return 1;
  }

  return 0;
}

int kms_noise_init(const char* path) {
  int fd = open(path,'r');
  if(read(fd,key,32) != 32) {
    fail("reading private key");
    return 1;
  };
  close(fd);

  return 0;
}
