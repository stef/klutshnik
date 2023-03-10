#ifndef KMS_NOISE
#define KMS_NOISE
#include <stdlib.h>
#include <stdint.h>

int kms_noise_init(const char* path);
int noise_setup(const int fd, uint8_t client_pubkey[32]);
int noise_read(const int fd, void *msg, const size_t size);
int noise_send(const int fd, const void *msg, const size_t size);
#endif // KMS_NOISE
