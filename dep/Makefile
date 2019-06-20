# Makefile for dependencies

include ../env.mk

# 'next' as of 11/13/17 returns wrong imm for backward TBZ/TBNZ
capstone-VERSION=$(if $(filter aarch64,$(P_ARCH)),3.0.4,egalito)

.PHONY: all rtld ifunc capstone keystone distorm3 pe-parse clean realclean
all: rtld ifunc capstone keystone distorm3 pe-parse
	-@touch built
clean:
	-$(call short-make,rtld,clean)
	-$(call short-make,ifunc,clean)
	-@rm -f built
realclean:
	-$(call short-make,rtld,clean)
	-$(call short-make,ifunc,clean)
	-$(call short-make,distorm3/make/linux,clean)
	-$(call short-make,capstone,clean)
	-@rm -rf keystone/build
	-@rm -rf pe-parse/build
	-@rm -f built

ifeq ($(USE_LOADER),1)
rtld:
	$(call short-make,rtld)
else
rtld:
endif
ifunc:
	$(call short-make,ifunc)
distorm3:
	$(call short-make,distorm3/make/linux) CC='gcc -Wno-missing-braces'

ifeq ($(CROSS_ANALYZE),1)
CROSS2 =
else
CROSS2 = $(CROSS)
endif

# directly use make to install to 'lib'
CAPSTONE_INSTALL := $(abspath capstone/install)
capstone:
	@cd capstone \
		&& rm -fr install \
		&& git checkout $(capstone-VERSION) > /dev/null 2>&1 \
		&& env CAPSTONE_ARCHS='x86 aarch64' $(MAKE) CROSS=$(CROSS2) \
		&& env CAPSTONE_ARCHS='x86 aarch64' PREFIX=$(CAPSTONE_INSTALL) $(MAKE) CROSS=$(CROSS2) install

ifeq ($(USE_KEYSTONE),1)
keystone:
	-@cd keystone \
		&& mkdir build \
		&& cd build \
		&& ../make-share.sh \
		&& ../make-lib.sh
else
keystone:
endif

ifeq ($(USE_WIN64_PE),1)
pe-parse:
	-@cd pe-parse \
		&& mkdir build \
		&& cd build \
		&& cmake .. \
	    && $(MAKE)
else
pe-parse:
endif
