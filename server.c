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
#include <noise/protocol.h>

#include "dkg.h"
#include "thmult.h"
#include "utils.h"
#include "tuokms.h"
#include "noise.h"

const int max_kids = 5;

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

static int save(const TParams_t params, const TOPRF_Share *share, const int create) {
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
  if(write(fd, share, sizeof(TOPRF_Share)) != sizeof(TOPRF_Share)) {
    perror("failed to write share");
    close(fd);
    return 1;
  };
  close(fd);
  return 0;
}

static int load(const TParams_t params, TOPRF_Share *share) {
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
  if(st.st_size!= sizeof(TOPRF_Share)) {
    fprintf(stderr, "invalid share size: %ld, expected: %ld", st.st_size, sizeof(TOPRF_Share));
  }
  if(read(fd, share, sizeof(TOPRF_Share)) != sizeof(TOPRF_Share)) {
    perror("failed to write share");
    close(fd);
    return 1;
  };
  close(fd);
  return 0;
}

static int dkg(const int fd, const TParams_t params,
               TOPRF_Share *share) {
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

  share->index=params.index;
  // finalize dkg
  TOPRF_Share delme; // ignore the commitment share
  dkg_finish(params.n,qual,dspeers.shares,params.index,share,&delme);
  return 0;
}

static int dkg_handler(const int fd, const TParams_t params) {
  info(0, &params, "dkg");

  TOPRF_Share share;
  if(dkg(fd, params, &share)) return 1;

  if(save(params, &share, 1)) return 1;

  noise_send(fd,&share, sizeof share);

  return 0;
}

static int evaluate(const int fd, const TParams_t params) {
  info(0, &params, "evaluate");
  ssize_t len;

  TOPRF_Share share;
  if(load(params, &share)) return 1;

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
  resp.beta.index=share.index;
  resp.verifier.index=share.index;
  if(tuokms_evaluate(share.value, eval_params.alpha, eval_params.verifier, resp.beta.value, resp.verifier.value)) {
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
  TOPRF_Share share_new;
  if(dkg(fd, params, &share_new)) return 1;

  noise_send(fd,&share_new, sizeof share_new);

  // load old shares
  TOPRF_Share share;
  if(load(params, &share)) return 1;

  // multiply shares
  uint8_t mulshares[params.n][sizeof(TOPRF_Share)];
  if(toprf_mpc_mul_start((uint8_t*)&share, (uint8_t*)&share_new, params.n, params.t, mulshares)) return 1;

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
  toprf_mpc_mul_finish(params.n, indexes, params.index, shares, (uint8_t*)&share);

  if(save(params, &share, 0)) return 1;

  noise_send(fd,&share, sizeof(TOPRF_Share));

  return 0;
}

static int handler(const int fd) {
  uint8_t client_pubkey[32];
  if(noise_setup(fd, client_pubkey)) return 1;
  // todo authorize pubkey
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

  if(kms_noise_init(argv[2])) return 1;

  mainloop(port);
  return 0;
}
