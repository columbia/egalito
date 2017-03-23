# Makefile for test cases

CC = gcc

CFLAGS	= -fPIE -pie -O2
STATIC_CFLAGS =

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
TARGET_NAMES = hello hi0 jumptable fp stack
TARGETS = $(addprefix $(BUILDDIR),$(TARGET_NAMES))
TARGETS-q = $(addsuffix -q,$(TARGETS))
TARGETS-static = $(addsuffix -static,$(TARGETS))

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
$(eval $(call dep_rule,jumptable,jumptable.c))
$(eval $(call dep_rule,fp,fp.c))
$(eval $(call dep_rule,stack,stack.c))

$(BUILDDIR)%-static:
	$(CC) $(STATIC_CFLAGS) $^ -o $@ -static
$(BUILDDIR)%-q:
	$(CC) $(CFLAGS) $^ -o $@ -Wl,-q
$(BUILDDIR)%:
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	-$(RM) -rf $(BUILDDIR)
