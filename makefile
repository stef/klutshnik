INCLUDES=$(shell pkgconf --cflags liboprf)
CFLAGS?=-march=native -Wall -O2 -g \
       -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
       -Wformat=2 -Wconversion -Wimplicit-fallthrough \
		 -fasynchronous-unwind-tables -fpic -fstack-clash-protection \
		 -Werror=format-security -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,relro \
		 -ftrapv -Wl,-z,noexecstack -D_BSD_SOURCE -D_DEFAULT_SOURCE

#LDFLAGS?=/usr/lib/liboprf.a /usr/lib/liboprf-noiseXK.a -lsodium
LIBS=-loprf -lsodium
CC?=gcc
SOEXT?=so
STATICEXT?=a
SOVER=0

UNAME := $(shell uname -s)
ARCH := $(shell uname -m)
ifeq ($(UNAME),Darwin)
   SOEXT=dylib
   SOFLAGS=-Wl,-install_name,$(DESTDIR)$(PREFIX)/lib/libklutshnik.$(SOEXT)
else
   CFLAGS+=-Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines \
           -fsanitize=signed-integer-overflow -fsanitize-undefined-trap-on-error
           #-fstrict-flex-arrays=3 -mbranch-protection=standard
   SOEXT=so
   SOFLAGS=-Wl,-soname,libklutshnik.$(SOEXT).$(SOVER)
   ifeq ($(ARCH),x86_64)
      CFLAGS+=-fcf-protection=full
   endif

   ifeq ($(ARCH),parisc64)
   else ifeq ($(ARCH),parisc64)
   else
      CFLAGS+=-fstack-clash-protection
   endif
endif


all: libklutshnik.so libklutshnik.pc

asan: CFLAGS=-fsanitize=address -static-libasan -g -march=native -Wall -O2 \
	-g -fstack-protector-strong -fpic -fstack-clash-protection -fcf-protection=full \
	-Werror=format-security -Werror=implicit-function-declaration -Wl, -z,noexecstack
asan: LDFLAGS+= -fsanitize=address -static-libasan
asan: all

SOURCES=streamcrypt.c tuokms.c utils.c
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

libklutshnik.$(SOEXT): $(SOURCES)
	$(CC) -fPIC -shared $(CPPFLAGS) $(CFLAGS) $(INCLUDES) $(SOFLAGS) -o libklutshnik.$(SOEXT) $^ $(LDFLAGS) $(LIBS)

libklutshnik.$(STATICEXT): $(OBJECTS)
	$(AR) rcs $@ $^

libklutshnik.pc:
	echo "prefix=$(PREFIX)" >libklutshnik.pc
	cat libklutshnik.pc0 >>libklutshnik.pc

install: $(DESTDIR)$(PREFIX)/lib/libklutshnik.$(SOEXT) \
         $(DESTDIR)$(PREFIX)/lib/libklutshnik.$(STATICEXT) \
         $(DESTDIR)$(PREFIX)/lib/pkgconfig/libklutshnik.pc \
         $(DESTDIR)$(PREFIX)/include/klutshnik/streamcrypt.h \
         $(DESTDIR)$(PREFIX)/include/klutshnik/tuokms.h

uninstall: $(DESTDIR)$(PREFIX)/lib/libklutshnik.$(SOEXT) $(DESTDIR)$(PREFIX)/lib/libklutshnik.$(STATICEXT) \
	        $(DESTDIR)$(PREFIX)/include/klutshnik/streamcrypt.h $(DESTDIR)$(PREFIX)/include/klutshnik/tuokms.h \
	rm $^
	rmdir $(PREFIX)/include/klutshnik/

$(DESTDIR)$(PREFIX)/lib/libklutshnik.$(SOEXT): libklutshnik.$(SOEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp $< $@.$(SOVER)
	ln -sf $@.$(SOVER) $@

$(DESTDIR)$(PREFIX)/lib/libklutshnik.$(STATICEXT): libklutshnik.$(STATICEXT)
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp $< $@

$(DESTDIR)$(PREFIX)/lib/pkgconfig/libklutshnik.pc: libklutshnik.pc
	mkdir -p $(DESTDIR)$(PREFIX)/lib/pkgconfig
	cp $< $@

$(DESTDIR)$(PREFIX)/include/klutshnik/streamcrypt.h: streamcrypt.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/klutshnik
	cp $< $@

$(DESTDIR)$(PREFIX)/include/klutshnik/tuokms.h: tuokms.h
	mkdir -p $(DESTDIR)$(PREFIX)/include/klutshnik
	cp $< $@

test: libklutshnik.$(SOEXT) libklutshnik.$(STATICEXT)
	make -C tests tests

clean:
	@rm -f *.o libklutshnik.$(STATICEXT) libklutshnik.$(SOEXT) libklutshnik.pc

%.o: %.c
	$(CC) $(CFLAGS) -fPIC $(INCLUDES) -c $< -o $@

PHONY: clean
