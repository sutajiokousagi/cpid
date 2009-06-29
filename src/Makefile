# template src/Makefile
# $Id$

include ../../config/config.mk

# Extras to build
TARBALL=template-110.tar.gz

all: build

build: unpack
	$(MAKE) -C $(lastword $(wildcard src/*)) CROSS_COMPILE=$(TARGET)- DESTDIR=$(PREFIX)

unpack: $(TARBALL)
	@echo "Unpacking $(TARBALL) to src"
	-mkdir src
	cd src; tar xzf ../$(TARBALL)
	touch $@

clean:
	-rm -rf src unpack

install: build
ifeq ($(PREFIX),)
	@echo "PREFIX not specified"
	@exit 1
else
	@echo "Installing to $(PREFIX)"
	$(MAKE) -C $(lastword $(wildcard src/*)) CROSS_COMPILE=$(TARGET)- DESTDIR=$(abspath $(PREFIX)) install
endif

# unpack should NOT be phony
.PHONY: all clean install build

