# template src/Makefile
# $Id$

include ../../../config/config.mk
BEECRYPT=beecrypt-4.1.2

all: build

build: config-${TARGET}
	$(MAKE) -C ${BEECRYPT} CROSS_COMPILE=$(TARGET)- DESTDIR=$(PREFIX)
	$(TARGET)-gcc -static  -I${BEECRYPT} -o keygen keygen.c ${BEECRYPT}/.libs/libbeecrypt.a -lpthread

config-${TARGET}:
	cd ${BEECRYPT} ; \
	./configure --prefix=/ --host=arm-linux --without-cplusplus --without-java --without-python
	touch $@


clean:
	$(MAKE) -C ${BEECRYPT} distclean || true
	rm -f config-${TARGET}

install: build
#ifeq ($(PREFIX),)
#	@echo "PREFIX not specified"
#	@exit 1
#else
#	@echo "Installing to $(PREFIX)"
#	$(MAKE) -C $(lastword $(wildcard src/*)) CROSS_COMPILE=$(TARGET)- DESTDIR=$(abspath $(PREFIX)) install
#endif

# unpack should NOT be phony
.PHONY: all clean install build

