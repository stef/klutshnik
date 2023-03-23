#ifndef KMS_NOISE
#define KMS_NOISE
#include <stdlib.h>
#include <stdint.h>
#include "XK_25519_ChaChaPoly_BLAKE2b/XK.h"

typedef Noise_XK_session_t       session;

int kms_noise_init(const char* path);
int noise_setup(const int fd, session **session, uint8_t client_pubkey[32]);
int noise_read(const int fd, session *session, void *msg, const size_t size);
int noise_send(const int fd, session *session, const uint8_t *msg, const size_t size);
#endif // KMS_NOISE
