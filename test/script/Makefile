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
	./hello.sh
	./argv.sh
	./islower.sh
	./jumptable-rtl.sh
	$(call arch_dep,./jumptable-libc.sh)
	./environ.sh
	./codeform.sh
	./dwarf-diff.sh
	./codeform-dwarf-syms.sh
	./codeform-s.sh
	./verify-redzone.sh
	./codeform-debloat.sh
	./hello-process.sh
	./hello-thread.sh
	./nginx.sh
	./nginx-thread.sh

jt:
	$(call arch_dep,./jumptable-libc.sh)
