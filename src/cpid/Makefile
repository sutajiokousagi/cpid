# template src/Makefile
# $Id$

include ../../../config/config.mk
AUTH_DIR=auth

all: build

build:
	$(MAKE) -C ${AUTH_DIR} CROSS_COMPILE=$(TARGET)- DESTDIR=$(PREFIX)
	$(TARGET)-gcc -I${AUTH_DIR} -c -o crypto.o crypto.c
	$(TARGET)-gcc -c -o hal.o hal.c
	$(TARGET)-gcc -c -o main.o main.c
	$(TARGET)-gcc -c -o makePackets.o makePackets.c
	$(TARGET)-gcc -o cpemu crypto.o hal.o main.o makePackets.o auth/beecrypt412_sm.a



clean:
	$(MAKE) -C ${AUTH_DIR} clean || true
	rm -f *.o

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

