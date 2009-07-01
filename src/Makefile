# template src/Makefile
# $Id$

include ../../config/config.mk

all: build

build:
	$(MAKE) -C cpid CROSS_COMPILE=$(TARGET)- DESTDIR=$(PREFIX)

clean:
	-rm -rf src unpack

install: build
ifeq ($(PREFIX),)
	@echo "PREFIX not specified"
	@exit 1
else
	@echo "Installing to $(PREFIX)"
	$(MAKE) -C cpid CROSS_COMPILE=$(TARGET)- DESTDIR=$(abspath $(PREFIX)) install PREFIX=$(abspath $(PREFIX))
endif

# unpack should NOT be phony
.PHONY: all clean install build

