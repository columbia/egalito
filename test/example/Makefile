# Makefile for test cases
include ../../env.mk

CFLAGS	= -fPIE -pie -O2
STATIC_CFLAGS = -static

ADDCFLAGS-hi5 = -nostdlib -ffreestanding

ifeq (aarch64,$(P_ARCH))
	CFLAGS += -DARCH_AARCH64
	STATIC_CFLAGS += -DARCH_AARCH64
	BUILDDIR = build_aarch64/
else ifeq (x86_64,$(P_ARCH))
	CFLAGS += -DARCH_X86_64
	STATIC_CFLAGS += -DARCH_X86_64
	BUILDDIR = build_x86_64/
else ifeq (arm,$(P_ARCH))
	CFLAGS += -DARCH_ARM
	STATIC_CFLAGS += -DARCH_ARM
	BUILDDIR = build_arm/
else
$(error Unsupported platform, we only handle aarch64 and x86_64)
endif

space =
empty = $(space) $(space)
TARGET_NAMES = hello hi0 hi5 jumptable fp stack log stderr islower getenv
TARGETS = $(addprefix $(BUILDDIR),$(TARGET_NAMES))
TARGETS-q = $(addsuffix -q,$(TARGETS))
TARGETS-strip = $(filter-out hi5-strip,$(addsuffix -strip,$(TARGETS)))
TARGETS-static = $(filter-out hi5-static,$(addsuffix -static,$(TARGETS)))
TARGETS-obj = $(addprefix $(BUILDDIR), hello-obj)

LONE_TARGETS = hellocpp

ALL_TARGETS = $(TARGETS)
ALL_TARGETS += $(TARGETS-q)
ALL_TARGETS += $(TARGETS-strip)
ALL_TARGETS += $(TARGETS-static)
ALL_TARGETS += $(TARGETS-obj)
ALL_TARGETS += $(LONE_TARGETS)

.PHONY: all targets targets-q targets-strip targets-static

all: $(ALL_TARGETS)

$(ALL_TARGETS): | $(BUILDDIR)
$(BUILDDIR):
	mkdir -p $@

targets: $(TARGETS)
targets-q: $(TARGETS-q)
targets-strip: $(TARGETS-strip)
targets-static: $(TARGETS-static)
targets-obj: $(TARGETS-obj)

define dep_rule
$$(BUILDDIR)$1: $2
$$(BUILDDIR)$1-q: $2
$$(BUILDDIR)$1-strip: $2
$$(BUILDDIR)$1-static: $2
endef

$(eval $(call dep_rule,hello,hello.c))
$(eval $(call dep_rule,hi0,hi0.c hi0-s.S))
$(eval $(call dep_rule,hi5,hi5.c hi5-s.S))
$(eval $(call dep_rule,jumptable,jumptable.c))
$(eval $(call dep_rule,fp,fp.c))
$(eval $(call dep_rule,stack,stack.c))
$(eval $(call dep_rule,log,log.c))
$(eval $(call dep_rule,stderr,stderr.c))
$(eval $(call dep_rule,hellocpp,hellocpp.cpp))
$(eval $(call dep_rule,islower,islower.c))
$(eval $(call dep_rule,getenv,getenv.c))

$(BUILDDIR)hello-obj: hello-obj.c

addcflags = $(ADDCFLAGS-$(firstword $(subst -, ,$1)))

$(BUILDDIR)%-static:
	$(CC) $(STATIC_CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@
$(BUILDDIR)%-strip:
	$(CC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@ -s
$(BUILDDIR)%-q:
	$(CC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@ -Wl,-q
$(BUILDDIR)%-obj:
	$(CC) -c $^ -o $@
$(BUILDDIR)%:
	$(CC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@

.PHONY: clean
clean:
	-$(RM) -rf $(BUILDDIR) hellocpp
