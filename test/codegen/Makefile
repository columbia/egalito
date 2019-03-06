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
	./run-build.sh -m hello 
	./run-build.sh -m jumptable
	./run-system.sh -m /bin/ls
	./run-system.sh -m /bin/cat
	./run-system.sh -m /bin/gzip
	./run-system.sh -m /bin/grep
	./run-system.sh -m /usr/bin/env
	./run-system.sh -m /usr/bin/make
	./run-system.sh -m /usr/bin/dpkg
	./run-system.sh -m /usr/bin/find
