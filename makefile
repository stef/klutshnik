CFLAGS=-I../toprf -Inoise-c/include -march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro -ftrapv -Wl,-z,noexecstack
LDFLAGS=../toprf/liboprf.a -lsodium noise-c/src/protocol/libnoiseprotocol.a -lcrypto
CC=gcc
SOEXT=so
STATICEXT=a

all: tuokms uokms libkms.so kms

asan: CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -g -fstack-protector-strong -fpic -fstack-clash-protection -fcf-protection=full -Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

libkms.so: tuokms.c uokms.c thmult.c matrices.c common.c utils.c
	$(CC) -shared $(CFLAGS) -Wl,-soname,libkms.so -o libkms.$(SOEXT) $^ $(LDFLAGS)

kms: server.c
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -L. -lkms

tuokms: tuokms.c thmult.c matrices.c common.c utils.c
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

uokms: uokms.c common.c utils.c
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -f *.o tuokms uokms kms

PHONY: clean
