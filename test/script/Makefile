P_ARCH := $(shell uname -m)

define x86_only
$(if $(filter x86_64,$(P_ARCH)),$1)
endef

define aarch64_only
$(if $(filter aarch64,$(P_ARCH)),$1)
endef

define arch_dep
$(if $(filter x86_64,$(P_ARCH)), $1 x86_64-debian, $1 aarch64-openSuSE)
endef

.PHONY: test
test:
	$(call x86_only,./detectnull.sh)
	./hello.sh
	./codeform.sh
	./dwarf-diff.sh
	./codeform-dwarf-syms.sh
	./jumptable-rtl.sh
	./codeform-s.sh
	./verify-redzone.sh
	./argv.sh
	./environ.sh
	./islower.sh
	$(call arch_dep,./jumptable-libc.sh)
	$(call aarch64_only,./codeform-debloat.sh)
