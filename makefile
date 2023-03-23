INCLUDES=-I../toprf -IXK_25519_ChaChaPoly_BLAKE2b -I$(HACL_HOME)/dist/karamel/include -I$(HACL_HOME)/dist/karamel/krmllib/dist/minimal
CFLAGS=-march=native -Wall -O2 -g -fstack-protector-strong -DWITH_SODIUM -D_FORTIFY_SOURCE=2 \
		 -fasynchronous-unwind-tables -fpic -fstack-clash-protection -fcf-protection=full \
		 -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro \
		 -ftrapv -Wl,-z,noexecstack $(INCLUDES)
LDFLAGS=../toprf/liboprf.a XK_25519_ChaChaPoly_BLAKE2b/libnoiseapi.a -lsodium  -lcrypto
CC=gcc
SOEXT=so
STATICEXT=a

all: libkms.so kms

asan: CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 -DWITH_SODIUM \
	-g -fstack-protector-strong -fpic -fstack-clash-protection -fcf-protection=full \
	-Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

libkms.so: tuokms.c uokms.c thmult.c matrices.c common.c utils.c streamcrypt.c
	$(CC) -shared $(CFLAGS) -Wl,-soname,libkms.so -o libkms.$(SOEXT) $^ $(LDFLAGS)

kms: server.c noise.o macaroon.c XK_25519_ChaChaPoly_BLAKE2b/libnoiseapi.a
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -L. -lkms

noise.o: noise.c
	gcc -c $(CFLAGS) -o $@ $^

tuokms: tuokms.c thmult.c matrices.c common.c utils.c
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

uokms: uokms.c common.c utils.c
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

XK_25519_ChaChaPoly_BLAKE2b/libnoiseapi.a: XK_25519_ChaChaPoly_BLAKE2b/XK.c XK_25519_ChaChaPoly_BLAKE2b/Noise_XK.c 
	$(MAKE) -C XK_25519_ChaChaPoly_BLAKE2b libnoiseapi.a

clean:
	@rm -f *.o tuokms uokms kms 

PHONY: clean
