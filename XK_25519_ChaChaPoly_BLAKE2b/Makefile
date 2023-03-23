# A basic Makefile that KaRaMeL copies in the output directory; this is not
# guaranteed to work and will only work well for very simple projects. This
# Makefile uses:
# - the custom C files passed to your krml invocation
# - the custom C flags passed to your krml invocation
# - the -o option passed to your krml invocation

LDFLAGS=-lsodium
#LDFLAGS=-L$(HACL_HOME)/dist/gcc-compatible -levercrypt
USER_TARGET=xk-ex
USER_CFLAGS= -DWITH_SODIUM -I..
#USER_CFLAGS=
USER_C_FILES=
ALL_C_FILES=Noise_XK.c XK.c
ALL_H_FILES=Noise_XK.h XK.h

ifeq (,$(HACL_HOME))
  $(error please define HACL_HOME to point to the root of your HACL* git checkout)
endif

CFLAGS 	+= -I. -I $(HACL_HOME)/dist/karamel/include -I $(HACL_HOME)/dist/karamel/krmllib/dist/minimal
CFLAGS 	+= -Wall -Wextra -Werror -std=c11 -Wno-unused-variable \
  -Wno-unknown-warning-option -Wno-unused-but-set-variable \
  -Wno-unused-parameter -Wno-infinite-recursion \
  -g -fwrapv -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM
ifeq ($(shell uname),Linux)
CFLAGS 	+= -Wl,--error-unresolved-symbols
else
CFLAGS 	+= -fPIC
endif
CFLAGS 	+= $(USER_CFLAGS)

SOURCES += $(ALL_C_FILES) $(USER_C_FILES)
OBJS 	+= $(patsubst %.c,%.o,$(SOURCES))

all: libnoiseapi.a

other: libnoiseapi.so $(USER_TARGET)

$(USER_TARGET): $(OBJS)
	cc $(CFLAGS) $^ xk-ex.c ../utils.c -o $@ $(LDFLAGS)

AR ?= ar

%.a: $(OBJS)
	$(AR) cr $@ $^

%.so:
	$(CC) $(CFLAGS) -shared -o $@ $^

%.d: %.c
	@set -e; rm -f $@; \
	  $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	  sed 's,\($(notdir $*)\)\.o[ :]*,$(dir $@)\1.o $@ : ,g' < $@.$$$$ > $@; \
	  rm -f $@.$$$$

include $(patsubst %.c,%.d,$(SOURCES))

clean:
	rm -rf *.o *.d $(USER_TARGET) *.so *.a
