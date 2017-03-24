# Makefile for test cases

CC = gcc

CFLAGS	= -fPIE -pie -O2
STATIC_CFLAGS = -static

ADDCFLAGS-hi5 = -nostdlib -ffreestanding

P_ARCH := $(shell uname -m)
ifeq (aarch64,$(P_ARCH))
	CFLAGS += -DARCH_AARCH64
	STATIC_CFLAGS += -DARCH_AARCH64
	BUILDDIR = build_aarch64/
else ifeq (x86_64,$(P_ARCH))
	CFLAGS += -DARCH_X86_64
	STATIC_CFLAGS += -DARCH_X86_64 -no-pie
	BUILDDIR = build_x86_64/
else
$(error Unsupported platform, we only handle aarch64 and x86_64)
endif

space =
empty = $(space) $(space)
TARGET_NAMES = hello hi0 hi5 jumptable fp stack
TARGETS = $(addprefix $(BUILDDIR),$(TARGET_NAMES))
TARGETS-q = $(addsuffix -q,$(TARGETS))
TARGETS-static = $(filter-out hi5-static,$(addsuffix -static,$(TARGETS)))

ALL_TARGETS = $(TARGETS)
ALL_TARGETS += $(TARGETS-q)
ALL_TARGETS += $(TARGETS-static)

.PHONY: all targets targets-q targets-static

all: $(ALL_TARGETS)

$(ALL_TARGETS): | $(BUILDDIR)
$(BUILDDIR):
	mkdir -p $@

targets: $(TARGETS)
targets-q: $(TARGETS-q)
targets-static: $(TARGETS-static)

define dep_rule
$$(BUILDDIR)$1: $2
$$(BUILDDIR)$1-q: $2
$$(BUILDDIR)$1-static: $2
endef

$(eval $(call dep_rule,hello,hello.c))
$(eval $(call dep_rule,hi0,hi0.c hi0-s.S))
$(eval $(call dep_rule,hi5,hi5.c hi5-s.S))
$(eval $(call dep_rule,jumptable,jumptable.c))
$(eval $(call dep_rule,fp,fp.c))
$(eval $(call dep_rule,stack,stack.c))

addcflags = $(ADDCFLAGS-$(firstword $(subst -, ,$1)))

$(BUILDDIR)%-static:
	$(CC) $(STATIC_CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@
$(BUILDDIR)%-q:
	$(CC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@ -Wl,-q
$(BUILDDIR)%:
	$(CC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@

.PHONY: clean
clean:
	-$(RM) -rf $(BUILDDIR)
