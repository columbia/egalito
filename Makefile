# root Makefile for egalito
# to change settings, see env.mk

ifdef USE_CONFIG
	include $(USE_CONFIG)
	export
endif

ifneq ($(MAKEVERBOSE),)
    MAKE += --no-print-directory
    short-make = @+echo '>>>' MAKE -C ${1} ${2} ;\
        $(MAKE) -C ${1} ${2} && echo '<<<' MAKE -C ${1} ${2}
else
    short-make = +$(MAKE) -C ${1} ${2}
endif

.PHONY: all config src test app clean realclean
all: dep src test app
	@true
src: dep | config
	$(call short-make,src)
test: src
	$(call short-make,test)
	$(call short-make,test/example)
	$(call short-make,test/binary all symlinks)
app: src | test
	$(call short-make,app)
dep: dep/built  # note: dep is not phony
dep/built:
	$(call short-make,dep)

config:
	$(call short-make,config)

clean realclean:
	$(call short-make,app,clean)
	$(call short-make,src,clean)
	$(call short-make,test,$@)
	$(call short-make,test/example,clean)
	$(call short-make,test/binary,clean)
	$(call short-make,dep,$@)
	$(call short-make,config,clean)
