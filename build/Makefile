# $Id$
# Empty project Makefile

include ../../config/config.mk

export PLATFORM_TARGET=$(TARGET)-$(CNPLATFORM)
EXPORTS=$(abspath ../exports)
OUTPUT=$(abspath ../output/$(PLATFORM_TARGET))
TARGET_EXPORTS=$(EXPORTS)/$(PLATFORM_TARGET)
LINUX_FROM_SRC=$(abspath $(firstword $(wildcard ../../linux*))/src)


# Set DIFFREV=-r2798:2833 to compare specific revisions
DIFFREV=
# Set DIFFDIR=../src to compare only source
DIFFDIR=..

all:

help:
	@echo "Meta-targets:"
	@echo "help build-all clean-all commit"
	@echo "Build process uses:"
	@echo " make -C build clean-all PRODUCTION=1"
	@echo " make -C build build-all PRODUCTION=1"
	@echo "Utility targets:"
	@echo "diff"

clean:
	# modify this section accordingly
	#$(MAKE) -C ../src KERNDIR=$(LINUX_FROM_SRC) clean

exports:

clean-exports:

build-all:
	# modify this section accordingly
	#$(MAKE) -C ../src KERNDIR=$(LINUX_FROM_SRC) build
	#$(MAKE) -C ../src KERNDIR=$(LINUX_FROM_SRC) PREFIX=$(INSTALL_DIR)/rfs1 install

clean-all:
	$(MAKE) clean
	$(MAKE) clean-exports

commit:
	export COMMIT_TIME="$(shell date +'%d-%b-%Y %H%M %Z')" ; cd ../exports ; echo "Auto-commit Production=$(PRODUCTION) $${COMMIT_TIME}" >>autocommit.log ; svn commit -m"Automated export checkin by build process at $${COMMIT_TIME}"

diff:
	echo -e "Build x.x, $(shell date +'%d-%b-%Y %H%M %Z')\n\n* change 1...\n" >../tmp
	cd $(DIFFDIR) ; svn diff $(DIFFREV) --extensions '--unified --ignore-all-space --ignore-eol-style' >>tmp


.PHONY: all help clean exports clean-exports build-all clean-all diff

