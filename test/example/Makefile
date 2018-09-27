# Makefile for test cases
include ../../env.mk

MUSLCC_BIN = $(wildcard /usr/local/musl/bin/musl-gcc)
MUSLCC = $(if $(MUSLCC_BIN),$(MUSLCC_BIN),touch $@;echo "--skipping")

CFLAGS	= -fPIE -pie -O2
STATIC_CFLAGS = -static -O2

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
$(error Unsupported platform, we only handle arm, aarch64, and x86_64)
endif

space =
empty = $(space) $(space)
TARGET_NAMES = hello hi0 hi5 jumptable fp stack log stderr islower getenv cfg sandbox-write
TARGETS = $(addprefix $(BUILDDIR),$(TARGET_NAMES))
TARGETS-q = $(addsuffix -q,$(TARGETS))
TARGETS-strip = $(filter-out hi5-strip,$(addsuffix -strip,$(TARGETS)))
TARGETS-static = $(filter-out hi5-static,$(addsuffix -static,$(TARGETS)))
TARGETS-static-q = $(addprefix $(BUILDDIR), hello-static-q)
TARGETS-obj = $(addprefix $(BUILDDIR), hello-obj)
TARGETS-musl = $(addprefix $(BUILDDIR), hello-musl)
TARGETS-musl-static = $(addprefix $(BUILDDIR), hello-musl-static)
TARGETS-musl-static-q = $(addprefix $(BUILDDIR), hello-musl-static-q)
TARGETS-firmware = $(addprefix $(BUILDDIR), firmware)

LONE_TARGETS = hellocpp $(BUILDDIR)detectnull

ALL_TARGETS = $(TARGETS)
ALL_TARGETS += $(TARGETS-q)
ALL_TARGETS += $(TARGETS-strip)
ALL_TARGETS += $(TARGETS-static)
ALL_TARGETS += $(TARGETS-static-q)
ALL_TARGETS += $(TARGETS-obj)
ALL_TARGETS += $(TARGETS-musl)
ALL_TARGETS += $(TARGETS-musl-static)
ALL_TARGETS += $(TARGETS-musl-static-q)
ALL_TARGETS += $(TARGETS-firmware)
ALL_TARGETS += $(LONE_TARGETS)

.PHONY: all targets targets-q targets-strip targets-static
.PHONY: targets-musl targets-musl-static targets-musl-static-q targets-firmware

all: $(ALL_TARGETS)
	@true

$(ALL_TARGETS): | $(BUILDDIR)
$(BUILDDIR):
	mkdir -p $@

targets: $(TARGETS)
targets-q: $(TARGETS-q)
targets-strip: $(TARGETS-strip)
targets-static: $(TARGETS-static)
targets-static-q: $(TARGETS-static-q)
targets-obj: $(TARGETS-obj)
targets-musl: $(TARGETS-musl)
targets-musl-static: $(TARGETS-musl-static)
targets-musl-static-q: $(TARGETS-musl-static-q)
targets-firmware: $(TARGETS-firmware)

define dep_rule
$$(BUILDDIR)$1: $2
$$(BUILDDIR)$1-q: $2
$$(BUILDDIR)$1-strip: $2
$$(BUILDDIR)$1-static: $2
$$(BUILDDIR)$1-static-q: $2
$$(BUILDDIR)$1-musl: $2
$$(BUILDDIR)$1-musl-static: $2
$$(BUILDDIR)$1-musl-static-q: $2
$$(BUILDDIR)$1-firmware: $2
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
$(eval $(call dep_rule,cfg,cfg.c))
$(eval $(call dep_rule,firmware,firmware.c))
$(eval $(call dep_rule,sandbox-write,sandbox-write.c))

$(BUILDDIR)hello-obj: hello-obj.c

addcflags = $(ADDCFLAGS-$(firstword $(subst -, ,$1)))

$(BUILDDIR)%-static:
	$(CC) $(STATIC_CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@
$(BUILDDIR)%-static-q:
	$(CC) $(STATIC_CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@ -Wl,-q
$(BUILDDIR)%-strip:
	$(CC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@ -s
$(BUILDDIR)%-q:
	$(CC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@ -Wl,-q
$(BUILDDIR)%-obj:
	$(CC) -c $^ -o $@
$(BUILDDIR)%-musl:
	$(MUSLCC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@
$(BUILDDIR)%-musl-static:
	$(MUSLCC) $(STATIC_CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@
$(BUILDDIR)%-musl-static-q:
	$(MUSLCC) $(STATIC_CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@ -Wl,-q
$(BUILDDIR)firmware:
	$(MUSLCC) $(STATIC_CFLAGS) -Wl,-z,max-page-size=4096 -Wl,-Ttext-segment=0xC400000 -Wl,--gc-sections -Wl,-verbose -Wl,--print-map $(call addcflags,$(notdir $@)) $^ -o $@ -Wl,-q > $@.map
$(BUILDDIR)%:
	$(CC) $(CFLAGS) $(call addcflags,$(notdir $@)) $^ -o $@

$(BUILDDIR)detectnull: detectnull.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	-@rm -rf $(BUILDDIR) hellocpp
