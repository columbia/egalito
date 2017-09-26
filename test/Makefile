# Makefile for egalito test code

include ../env.mk

CFLAGS      += -I ../src/
CXXFLAGS    += -I ../src/
CLDFLAGS    += -L ../src/$(BUILDDIR) -legalito -Wl,-rpath=../src/$(BUILDDIR)

CFLAGS      += '-DTESTDIR="binary/build/"'
CXXFLAGS    += '-DTESTDIR="binary/build/"'

ANALYSIS_SOURCES    = $(wildcard analysis/*.cpp)
CHUNK_SOURCES       = $(wildcard chunk/*.cpp)
PASS_SOURCES        = $(wildcard pass/*.cpp)
FRAMEWORK_SOURCES   = $(wildcard framework/*.cpp)
INTEGRATION_SOURCES = $(wildcard integration/*.cpp)
ELF_SOURCES         = $(wildcard elf/*.cpp)
DISASM_SOURCES      = $(wildcard disasm/*.cpp)
LOG_SOURCES         = $(wildcard log/*.cpp)
UTIL_SOURCES        = $(wildcard util/*.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

RUNNER_SOURCES = $(FRAMEWORK_SOURCES) $(CHUNK_SOURCES) $(ANALYSIS_SOURCES) \
	$(PASS_SOURCES) $(ELF_SOURCES) $(DISASM_SOURCES) $(LOG_SOURCES) \
	$(INTEGRATION_SOURCES) $(UTIL_SOURCES)
RUNNER_OBJECTS = $(call obj-filename,$(RUNNER_SOURCES))
ALL_SOURCES = $(sort $(RUNNER_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

BUILDTREE = $(sort $(dir $(ALL_OBJECTS)))

RUNNER = $(BUILDDIR)runner

OUTPUTS = $(RUNNER)

# Default target
.PHONY: all
all: test-all .symlinks

test-all: $(OUTPUTS) | rebuild-src

ifeq ($(findstring clean,$(MAKECMDGOALS)),)
Makefile: rebuild-src
endif

$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE):
	@mkdir -p $@

.symlinks: $(OUTPUTS)
	@touch .symlinks
	@echo making symlinks...
	@ln -sf $(BUILDDIR)runner

.PHONY: rebuild-src
rebuild-src:
	$(MAKE) -C ../src

# Dependencies
DEPEND_FILES = $(call dep-filename,$(ALL_SOURCES))
-include $(DEPEND_FILES)

# Programs and libraries
$(RUNNER): $(RUNNER_OBJECTS) | ../src/libegalito.so
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS)

$(RUNNER): ../src/$(BUILDDIR)libegalito.so

# Other targets
.PHONY: clean realclean
clean:
	-rm -f .symlinks runner
	-find $(BUILDDIR) -name framework -prune -o -type f -exec rm {} \;

realclean:
	-rm -rf $(BUILDDIR) .symlinks runner
