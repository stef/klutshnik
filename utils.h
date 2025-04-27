#ifndef KLUTSHNIK_UTILS_H
#define KLUTSHNIK_UTILS_H

#include <sodium.h>
#include <stdint.h>

void dump(const uint8_t *p, const size_t len, const char* msg, ...);
void fail(char* msg, ...);

#endif // KLUTSHNIK_UTILS_H
