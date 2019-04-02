# Makefile for egalito test code

include ../../env.mk

CFLAGS      += -I ../../src/ -I ..
CXXFLAGS    += -I ../../src/ -I ..
CLDFLAGS    += -L ../../src/$(BUILDDIR) -legalito -L ../framework -lframework \
	-Wl,-rpath=$(abspath ../../src/$(BUILDDIR)) \
	-Wl,-rpath=$(abspath ../../dep/capstone/install/lib)

CFLAGS      += '-DTESTDIR="../binary/build/"'
CXXFLAGS    += '-DTESTDIR="../binary/build/"'

DEFENSE_SOURCES     = $(wildcard defense/*.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

RUNNER_SOURCES = $(DEFENSE_SOURCES)
RUNNER_OBJECTS = $(call obj-filename,$(RUNNER_SOURCES))
ALL_SOURCES = $(sort $(RUNNER_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

BUILDTREE = $(sort $(dir $(ALL_OBJECTS)))

RUNNER = $(BUILDDIR)runner

OUTPUTS = $(RUNNER)

# Default target
.PHONY: all
all: test-all .symlinks
	@true

test-all: $(OUTPUTS) | rebuild-src

ifeq ($(findstring clean,$(MAKECMDGOALS)),)
Makefile: rebuild-src
endif

$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE):
	@mkdir -p $@

.symlinks: $(OUTPUTS)
	@touch .symlinks
	@echo "LN-S" $(OUTPUTS)
	@ln -sf $(BUILDDIR)runner

.PHONY: rebuild-src
rebuild-src:
	$(call short-make,../../src)

# Dependencies
DEPEND_FILES = $(call dep-filename,$(ALL_SOURCES))
-include $(DEPEND_FILES)

# Programs and libraries
$(RUNNER): $(RUNNER_OBJECTS) | ../../src/libegalito.so
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS)

$(RUNNER): ../../src/$(BUILDDIR)libegalito.so

# Other targets
.PHONY: clean
clean:
	-rm -rf $(BUILDDIR) .symlinks runner
