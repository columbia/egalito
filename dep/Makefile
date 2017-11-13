# Makefile for dependencies

include ../env.mk

.PHONY: all rtld capstone distorm3 clean realclean
all: rtld capstone distorm3
	-@touch built
clean:
	-$(call short-make,rtld,clean)
realclean:
	-$(call short-make,rtld,clean)
	-$(call short-make,distorm3,clean)
	-$(call short-make,capstone,clean)
	-@rm built

rtld:
	$(call short-make,rtld)
distorm3:
	$(call short-make,distorm3/make/linux) CC='gcc -Wno-missing-braces'
capstone:
	-@cd capstone && ./make.sh
