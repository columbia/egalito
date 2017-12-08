# Makefile for dependencies

SHELL=/bin/bash

include ../env.mk

# 'next' as of 11/13/17 returns wrong imm for backward TBZ/TBNZ
capstone-VERSION=$(if $(filter aarch64,$(P_ARCH)),3.0.4,next)

.PHONY: all rtld capstone distorm3 clean realclean
all: rtld capstone distorm3
	-@touch built
clean:
	-$(call short-make,rtld,clean)
	-@rm -f built
realclean:
	-$(call short-make,rtld,clean)
	-$(call short-make,distorm3/make/linux,clean)
	-$(call short-make,capstone,clean)
	-@rm -f built

rtld:
	$(call short-make,rtld)
distorm3:
	$(call short-make,distorm3/make/linux) CC='gcc -Wno-missing-braces'

# directly use make to install to 'lib'
CAPSTONE_INSTALL := $(abspath capstone/install)
capstone:
	-@cd capstone \
		&& rm -fr install \
		&& git checkout $(capstone-VERSION) >& /dev/null \
		&& $(MAKE) \
		&& env PREFIX=$(CAPSTONE_INSTALL) $(MAKE) install \
		&& git checkout next >& /dev/null
