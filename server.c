#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>    // open
#include <sys/stat.h> // fchmod
#include <sys/wait.h> // waitpid
#include <errno.h>    // errno
#include <stdarg.h>   // va_*

#include "dkg.h"
#include "thmult.h"
#include "utils.h"
#include "tuokms.h"
#include <noise/protocol.h>

#define MAX_MESSAGE_LEN 4096

const int max_kids = 5;

uint8_t key[32];
NoiseCipherState *send_cipher = 0;
NoiseCipherState *recv_cipher = 0;
uint8_t client_pubkey[32];

typedef enum {
  NoOp = 0,
  DKG,
  Evaluate,
  TUOKMS_Update
} __attribute__ ((__packed__)) OpCode_t;

typedef struct {
  uint8_t version;
  OpCode_t type;
  uint8_t index;
  uint8_t t;
  uint8_t n;
  uint8_t keyid[16];
} __attribute__ ((__packed__)) TParams_t;

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_BYTES];
} __attribute((packed)) TOPRF_Part;

static void tohex(const ssize_t len, const uint8_t in[len], char out[len*2]) {
  char *ptr=out;
  for(ssize_t i=0;i<len;i++,ptr+=2) {
    sprintf(ptr, "%02x", in[i]);
  }
}

static void info(const int level, const TParams_t *params, const char* msg, ...) {
  va_list args;
  va_start(args, msg);
  if(level>0) printf("\e[0;31merror ");
  if(params) {
    char keyid[33];
    tohex(16, params->keyid, keyid);
    keyid[32]=0;
    printf("[%02x:%s] ", params->index, keyid);
  }
  vprintf(msg, args);
  va_end(args);
  if(level>0) printf("\e[0m\n");
  printf("\n");
}

static int save(const TParams_t params, const TOPRF_Share share[2], const size_t clen, const uint8_t commitments[clen], const int create) {
  char fname[sizeof("shares/")+(sizeof params.keyid)*2 + 3/*index*/];
  char *ptr = fname;
  memcpy(ptr,"shares/",7);
  ptr+=7;
  tohex(sizeof params.keyid, params.keyid, ptr);
  ptr+=(sizeof params.keyid)*2;
  sprintf(ptr,"-%02x", params.index);
  int fd;
  if(create) {
    fd = open(fname, O_CREAT | O_EXCL | O_WRONLY);
  } else {
    fd = open(fname, O_WRONLY);
  }
  if(fd == -1) {
    if(create) perror("failed to create share file");
    else perror("failed to open share file");
    return(1);
  }
  if(fchmod(fd,0600)==-1) {
    perror("failed to chmod(0600) share file");
    close(fd);
    return(1);
  }
  if(write(fd, share, sizeof(TOPRF_Share)*2) != sizeof(TOPRF_Share)*2) {
    perror("failed to write share");
    close(fd);
    return 1;
  };
  if(write(fd, commitments, clen) != clen) {
    perror("failed to write commitments");
    close(fd);
    return 1;
  }
  close(fd);
  return 0;
}

static int load(const TParams_t params, TOPRF_Share share[2], uint8_t commitments[params.t][crypto_core_ristretto255_BYTES]) {
  char fname[sizeof("shares/")+(sizeof params.keyid)*2 + 3/*index*/];
  char *ptr = fname;
  memcpy(ptr,"shares/",7);
  ptr+=7;
  tohex(sizeof params.keyid, params.keyid, ptr);
  ptr+=(sizeof params.keyid)*2;
  sprintf(ptr,"-%02x", params.index);
  int fd = open(fname, O_RDONLY);
  if(fd == -1) {
    perror("failed to open share file");
    return(1);
  }
  // verify size of share
  struct stat st;
  if(fstat(fd, &st)!=0) {
    perror("couldn't stat share");
    return 1;
  };
  const ssize_t slen=(sizeof(TOPRF_Share)*2)+(params.t*crypto_core_ristretto255_BYTES);
  if(st.st_size!= slen) {
    fprintf(stderr, "invalid share size: %ld, expected: %ld", st.st_size, slen);
  }
  if(read(fd, share, sizeof(TOPRF_Share)*2) != sizeof(TOPRF_Share)*2) {
    perror("failed to write share");
    close(fd);
    return 1;
  };
  const size_t clen=params.t*crypto_core_ristretto255_BYTES;
  if(read(fd, commitments, clen) != clen) {
    perror("failed to read commitments");
    close(fd);
    return 1;
  }
  close(fd);
  return 0;
}

static int noise_send(const int fd, const void *msg, const size_t size) {
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

static int noise_read(const int fd, void *msg, const size_t size) {
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

static int dkg(const int fd, const TParams_t params,
               uint8_t commitments[params.t][crypto_core_ristretto255_BYTES],
               TOPRF_Share share[2]) {
  ssize_t len;
  struct {
    uint8_t commitments[params.t][crypto_core_ristretto255_BYTES];
    TOPRF_Share shares[params.n][2];
  } __attribute__ ((__packed__)) dsresp;

  if(dkg_start(params.n, params.t, dsresp.commitments, dsresp.shares)) {
    fail("dkg_start");
    return 1;
  }
  len = noise_send(fd,(char*)&dsresp,sizeof(dsresp));
  if(len==-1) {
    fail("send dkg_start response");
    return 1;
  }
  //fprintf(stderr, "sent %ld bytes as response\n", len);

  struct {
    uint8_t commitments[params.n][params.t][crypto_core_ristretto255_BYTES];
    TOPRF_Share shares[params.n][2];
  } __attribute__ ((__packed__)) dspeers;

  //fprintf(stderr, "expecting %ld bytes as peers response\n", sizeof(dspeers));
  len = noise_read(fd, (char*) &dspeers, sizeof dspeers);
  if(len==-1) {
    perror("recv dkg_start dspeers failed");
    return 1;
  } else if(len != sizeof dspeers) {
    fail("invalid dkg start dspeers");
    return 1;
  }

  struct {
    uint8_t len;
    uint8_t complaints[params.n];
  } complaints;
  memset(&complaints, 0, sizeof complaints);

  if(dkg_verify_commitments(params.n,params.t,params.index,dspeers.commitments,dspeers.shares,complaints.complaints,&complaints.len)) {
    fail("verify commitments, complaints %d", complaints.len);
    return 1;
  }

  // todo handle complaints, build qual set
  //fprintf(stderr,"complaints: %d\n", complaints.len);

  uint8_t qual[params.n+1];
  for(int i=0;i<params.n;i++) qual[i]=i+1; //everyone qualifies
  qual[params.n]=0;

  share[0].index=params.index;
  share[1].index=params.index;
  // finalize dkg
  dkg_finish(params.n,qual,dspeers.shares,params.index,&share[0],&share[1]);
  memcpy(commitments, dsresp.commitments, sizeof dsresp.commitments);
  return 0;
}

static int dkg_handler(const int fd, const TParams_t params) {
  info(0, &params, "dkg");

  uint8_t commitments[params.t][crypto_core_ristretto255_BYTES];
  TOPRF_Share share[2];
  if(dkg(fd, params, commitments, share)) return 1;

  if(save(params, share, sizeof commitments, (uint8_t*) commitments, 1)) return 1;

  noise_send(fd,&share, sizeof share);

  return 0;
}

static int evaluate(const int fd, const TParams_t params) {
  info(0, &params, "evaluate");
  ssize_t len;

  uint8_t commitments[params.t][crypto_core_ristretto255_BYTES];
  TOPRF_Share share[2];
  if(load(params, share, commitments)) return 1;

  struct {
    uint8_t alpha[crypto_core_ristretto255_BYTES];
    uint8_t verifier[crypto_core_ristretto255_BYTES];
  } __attribute__ ((__packed__)) eval_params;

  len = noise_read(fd, (char*) &eval_params, sizeof eval_params);

  if(len==-1) {
    perror("recv evaluate params failed");
    return 1;
  } else if(len != sizeof eval_params) {
    fail("invalid evaluate params");
    return 1;
  }

  struct {
    TOPRF_Part beta;
    TOPRF_Part verifier;
  } resp;
  resp.beta.index=share[0].index;
  resp.verifier.index=share[0].index;
  if(tuokms_evaluate(share[0].value, eval_params.alpha, eval_params.verifier, resp.beta.value, resp.verifier.value)) {
    fail("at tuokms_evaluate");
    return 1;
  }
  len = noise_send(fd,(char*)&resp,sizeof(resp));
  if(len==-1) {
    fail("send eval response");
    return 1;
  }

  return 0;
}

static int update(const int fd, const TParams_t params) {
  info(0, &params, "update");
  ssize_t len;

  // generate new shares
  uint8_t commitments_new[params.t][crypto_core_ristretto255_BYTES];
  TOPRF_Share share_new[2];
  if(dkg(fd, params, commitments_new, share_new)) return 1;

  noise_send(fd,&share_new, sizeof share_new);

  // load old shares
  uint8_t commitments[params.t][crypto_core_ristretto255_BYTES];
  TOPRF_Share share[2];
  if(load(params, share, commitments)) return 1;

  // multiply shares
  uint8_t mulshares[params.n][sizeof(TOPRF_Share)];
  if(toprf_mpc_mul_start((uint8_t*)share, (uint8_t*)share_new, params.n, params.t, mulshares)) return 1;

  len = noise_send(fd,mulshares,sizeof(mulshares));
  if(len==-1) {
    fail("send mulshares");
    return 1;
  }

  // receive shares from others
  uint8_t shares[params.n][TOPRF_Share_BYTES];
  len = noise_read(fd, (char*) &shares, sizeof shares);
  if(len==-1) {
    perror("recv evaluate tparams failed");
    return 1;
  } else if(len != sizeof shares) {
    fail("invalid multiplied shares: %ld, expected %ld", len, sizeof shares);
    return 1;
  }

  // todo figure out where to get indexes from
  uint8_t indexes[params.n];
  for(unsigned i=0; i<params.n; i++) indexes[i]=i+1;
  toprf_mpc_mul_finish(params.n, indexes, params.index, shares, (uint8_t*)&share[0]);

  if(save(params, share, sizeof commitments, (uint8_t*) commitments, 0)) return 1;

  noise_send(fd,&share, sizeof(TOPRF_Share));

  return 0;
}

static int noise_setup(const int fd) {
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
  err=noise_dhstate_get_public_key(dh, client_pubkey, sizeof client_pubkey);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("failed to get client pubkey", err);
    noise_handshakestate_free(handshake);
    return 1;
  }
  // todo authorize pubkey
  dump(client_pubkey, sizeof client_pubkey, "client pubkey: ");

  noise_handshakestate_free(handshake);
  handshake = 0;

  return 0;
}

static int handler(const int fd) {
  if(noise_setup(fd)) return 1;
  TParams_t params;
  ssize_t len = noise_read(fd, (char*) &params, sizeof params);
  if(len==-1) {
    perror("recv failed");
  } else if(len == sizeof params) {

    switch(params.type) {
    case(DKG): {
      dkg_handler(fd,params);
      break;
    }
    case(Evaluate): {
      evaluate(fd,params);
      break;
    }
    case(TUOKMS_Update): {
      update(fd,params);
      break;
    }
    default:;
    }
  } // else invalid recv!

  shutdown(fd, SHUT_WR);
  close(fd);
  return 0;
}

void mainloop(const int port) {
  int sockfd, connfd;
  pid_t pid;
  struct sockaddr_in servaddr;

  // socket create and verification
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd == -1) {
    perror("socket creation failed...\n");
    exit(0);
  }
  if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("setsockopt(SO_REUSEADDR) failed");
    exit(0);
  }

  const struct timeval to={
    .tv_sec = 3,
    .tv_usec = 0
  };
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof to);
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof to);

  // assign IP, PORT
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);

  // Binding newly created socket to given IP and verification
  if((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) {
    perror("socket bind failed...\n");
    exit(0);
  }

  // Now server is ready to listen and verification
  if ((listen(sockfd, 5)) != 0) {
    perror("Listen failed...\n");
    exit(0);
  }
  //fprintf(stderr,"[%d] sockfd: %d\n", port, sockfd);

  int status;
  while(1) {
    // Accept the data packet from client and verification
    connfd = accept(sockfd, NULL, NULL);
    //fprintf(stderr,"[%d] connfd: %d\n", port, connfd);
    if(connfd < 0) {
      if(errno==EAGAIN || errno==EWOULDBLOCK) {
        pid=waitpid(-1, &status, WNOHANG);
        continue;
      }
      perror("server accept failed...\n");
      exit(0);
    }

    // Function for chatting between client and server
	if((pid = fork()) == 0) {
      close(sockfd);
      if(handler(connfd)) {
        fprintf(stderr, "handler error. abort\n");
        exit(1);
      }
      exit(0);
    } else if(pid==-1) {
      perror("fork failed");
      exit(1);
    }
    pid=waitpid(-1, &status, WNOHANG);
  }

  // After chatting close the socket
  close(sockfd);
}

void usage(const char** argv) {
  printf("%s port privkey\n", argv[0]);
  exit(1);
}

int main(const int argc, const char** argv) {
  if(argc<3) usage(argv);

  const int port=atoi(argv[1]);
  info(0, NULL, "starting on port %d", port);

  if (noise_init() != NOISE_ERROR_NONE) {
    fail("Noise initialization");
    return 1;
  }

  int fd = open(argv[2],'r');
  if(read(fd,key,32) != 32) {
    fail("reading private key");
    return 1;
  };
  close(fd);

  mainloop(port);
  return 0;
}
