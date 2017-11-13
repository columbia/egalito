# Makefile for dependencies

include ../env.mk

.PHONY: all clean realclean
all: distorm rtld
clean:
	-$(call short-make,rtld,clean)
realclean:
	-$(call short-make,rtld,clean)
	-@rm -rf distorm3

rtld:
	$(call short-make,rtld)
distorm:
	-@unzip -qo distorm3.zip
	$(call short-make,distorm3/make/linux) CC='gcc -Wno-missing-braces'
