P_ARCH := $(shell uname -m)

define x86_only
$(if $(filter x86_64,$(P_ARCH)),$1)
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
	./islower.sh
	$(call x86_only,./jumptable-libc.sh)
